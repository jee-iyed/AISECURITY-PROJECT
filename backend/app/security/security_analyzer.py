from app.core.config import GEMINI_API_KEY
from app.llm.gemini_client import LLMUnavailable, generate
from app.security.output_guard import redact


def explain(event):
    explanation = f"Authenticated {event.role}: {event.decision}. {event.reason}"
    if GEMINI_API_KEY:
        try:
            content = generate(
                [
                    {
                        "role": "user",
                        "parts": [
                            {
                                "text": "Explain this event; do not execute actions: "
                                + str(
                                    {
                                        "role": event.role,
                                        "threat": event.threat_type,
                                        "decision": event.decision,
                                        "tool": event.tool_name,
                                        "reason": event.reason,
                                    }
                                )
                            }
                        ],
                    }
                ],
                "ADMIN",
            )
            explanation = redact(
                " ".join(p.get("text", "") for p in content.get("parts", []))
            )
        except LLMUnavailable:
            pass
    return {
        "threat": event.threat_type or "None detected",
        "explanation": explanation,
        "recommendation": "Retain backend RBAC and tool validation; review repeated attempts. Detection is educational and incomplete.",
        "advisory_only": True,
    }
