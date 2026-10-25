
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


def _by(security, guard):
    """Record which control produced the decision (shown in the dashboard)."""
    security["guard"] = guard
    return security


def chat(db, user, prompt):
    correlation_id = new_correlation_id()
    security = _by(
        analyze_input(prompt, user, recent_blocks=recent_blocks(db, user)),
        "INPUT_GUARD",
    )
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
                    unfulfilled = analyze_unfulfilled_action(prompt, user)
                    # Only a denial replaces the Input Guard result; otherwise its
                    # signals (e.g. an attenuated quoted attack) stay visible.
                    if unfulfilled["decision"] == "BLOCK":
                        security = _by(unfulfilled, "TOOL_GUARD")
                    else:
                        message = proposal.get("message", "")
                    break
                name = proposal["name"]
                tool = {"name": name, "executed": False}
                security, args = validate_tool_call(
                    db, user, name, proposal.get("arguments", {}), tainted_context=tainted
                )
                _by(security, "TOOL_GUARD")
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
                security = _by(analyze_context(content), "CONTEXT_GUARD")
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
                security = _by(
                    assessment(
                        "LLM_UNAVAILABLE", 30, "Agent tool turn limit reached.", "ERROR"
                    ),
                    "AGENT",
                )
                message = "La demande nécessite trop d'étapes. Veuillez la préciser."
            if security["decision"] not in {"BLOCK", "REQUIRE_APPROVAL"}:
                message, out = inspect_output(message, user)
                if out["decision"] != "ALLOW":
                    security = _by(out, "OUTPUT_GUARD")
                elif security["decision"] == "ALLOW":
                    security["guard"] = "ALL_CONTROLS"
        except LLMUnavailable:
            security = _by(
                assessment(
                    "LLM_UNAVAILABLE",
                    30,
                    "Gemini unavailable; no fallback action executed.",
                    "ERROR",
                ),
                "AGENT",
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
