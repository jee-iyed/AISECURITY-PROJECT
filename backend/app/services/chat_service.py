import json

from app.db.models import Approval
from app.llm import agent
from app.llm.gemini_client import LLMUnavailable
from app.security.context_guard import analyze_context
from app.security.input_guard import analyze_input, analyze_unfulfilled_action
from app.security.logger import record
from app.security.output_guard import inspect_output
from app.security.risk_engine import assessment
from app.security.tool_guard import validate_tool_call
from app.tools.registry import TOOLS


def chat(db, user, prompt):
    security = analyze_input(prompt, user)
    tool = None
    approval_id = None
    message = "Request blocked by AI Security Gateway."
    if security["decision"] != "BLOCK":
        try:
            history = [{"role": "user", "parts": [{"text": prompt}]}]
            for step in range(6):
                proposal = (
                    agent.propose(prompt, user)
                    if step == 0
                    else agent.propose(prompt, user, history)
                )
                if "name" not in proposal:
                    security = analyze_unfulfilled_action(prompt, user)
                    if security["decision"] != "BLOCK":
                        message = proposal.get("message", "")
                    break
                name = proposal["name"]
                tool = {"name": name, "executed": False}
                security, args = validate_tool_call(
                    db, user, name, proposal.get("arguments", {})
                )
                if security["decision"] == "REQUIRE_APPROVAL":
                    approval = Approval(
                        user_id=user.id, tool_name=name, arguments=json.dumps(args)
                    )
                    db.add(approval)
                    db.flush()
                    approval_id = approval.id
                    message = "Cette modification nécessite une approbation humaine."
                    break
                if security["decision"] != "ALLOW":
                    break
                result = TOOLS[name](db, user, **args)
                tool["executed"] = True
                security = analyze_context(json.dumps(result, ensure_ascii=False))
                if security["decision"] == "BLOCK":
                    break
                # Preserve the original provider content, including thought signatures.
                # Only guarded, context-checked results enter the next model turn.
                if "content" in proposal:
                    record(db, user, prompt, security, name)
                    history.extend(
                        [
                            proposal["content"],
                            {
                                "role": "user",
                                "parts": [
                                    {
                                        "functionResponse": {
                                            "name": name,
                                            "response": {"result": result},
                                        }
                                    }
                                ],
                            },
                        ]
                    )
                else:
                    message = agent.finish(prompt, result, user)
                    break
            else:
                security = assessment(
                    "LLM_UNAVAILABLE", 30, "Agent tool turn limit reached.", "ERROR"
                )
                message = "La demande nécessite trop d'étapes. Veuillez la préciser."
            if security["decision"] not in {"BLOCK", "REQUIRE_APPROVAL"}:
                message, out = inspect_output(message, user)
                if out["decision"] != "ALLOW":
                    security = out
        except LLMUnavailable:
            security = assessment(
                "LLM_UNAVAILABLE",
                30,
                "Gemini unavailable; no fallback action executed.",
                "ERROR",
            )
            message = "Gemini unavailable. Retry later or restart without a key for demo mode."
    record(db, user, prompt, security, tool["name"] if tool else None)
    return {
        "message": message,
        "security": security,
        "tool": tool,
        "approval_id": approval_id,
    }
