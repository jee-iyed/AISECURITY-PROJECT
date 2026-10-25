
from app.llm import agent
from app.llm.gemini_client import LLMUnavailable
from app.security.context_guard import analyze_context, source_for_tool, wrap_untrusted
from app.security.input_guard import analyze_input, analyze_unfulfilled_action
from app.security.logger import new_correlation_id, recent_blocks, record
from app.security.output_guard import inspect_output
from app.security.risk_engine import assessment
from app.security.tool_guard import validate_tool_call
from app.services.approval_service import create_approval
from app.tools.registry import TOOLS


def chat(db, user, prompt):
    correlation_id = new_correlation_id()
    security = analyze_input(prompt, user, recent_blocks=recent_blocks(db, user))
    tool = None
    approval_id = None
    source = "user_prompt"
    # Set once untrusted content with instruction-like text enters this turn;
    # the Tool Guard then refuses every write tool until a new user request.
    tainted = False
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
                    db, user, name, proposal.get("arguments", {}), tainted_context=tainted
                )
                if security["decision"] == "REQUIRE_APPROVAL":
                    approval_id = create_approval(
                        db, user, name, args, security, correlation_id
                    ).id
                    message = "Cette modification nécessite une approbation humaine."
                    break
                if security["decision"] != "ALLOW":
                    break
                result = TOOLS[name](db, user, **args)
                tool["executed"] = True
                content = source_for_tool(name, args, result)
                source = content.source_id
                security = analyze_context(content)
                tainted = tainted or security["tainted"]
                if security["decision"] == "BLOCK":
                    message = (
                        f"La source {content.source_id} a été mise en quarantaine : elle "
                        "contient des instructions adressées à l'assistant. Son contenu "
                        "n'a pas été transmis au modèle."
                    )
                    break
                # Preserve the original provider content, including thought signatures.
                # Only guarded, context-checked results enter the next model turn,
                # wrapped in an envelope that marks them as untrusted data.
                if "content" in proposal:
                    record(
                        db,
                        user,
                        prompt,
                        security,
                        name,
                        correlation_id=correlation_id,
                        source=source,
                    )
                    history.extend(
                        [
                            proposal["content"],
                            {
                                "role": "user",
                                "parts": [
                                    {
                                        "functionResponse": {
                                            "name": name,
                                            "response": wrap_untrusted(content, result),
                                        }
                                    }
                                ],
                            },
                        ]
                    )
                else:
                    message = agent.finish(prompt, result, user, content.metadata())
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
    record(
        db,
        user,
        prompt,
        security,
        tool["name"] if tool else None,
        correlation_id=correlation_id,
        source=source,
        approval_id=approval_id,
        outcome="EXECUTED" if tool and tool["executed"] else None,
    )
    return {
        "message": message,
        "security": security,
        "tool": tool,
        "approval_id": approval_id,
        "correlation_id": correlation_id,
    }
