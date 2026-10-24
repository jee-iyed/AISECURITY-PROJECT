import json

from app.core.config import LOG_DIR
from app.db.models import SecurityEvent
from app.security.output_guard import redact


def record(db, user, prompt, security, tool=None):
    event = SecurityEvent(
        user_id=user.id,
        user_name=user.name,
        role=user.role,
        prompt_preview=redact(prompt)[:240],
        tool_name=tool,
        **{
            k: security[k]
            for k in ["threat_type", "risk_score", "risk_level", "decision", "reason"]
        },
    )
    db.add(event)
    db.flush()
    with (LOG_DIR / "security.jsonl").open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "id": event.id,
                    "timestamp": event.timestamp,
                    "user_id": user.id,
                    "role": user.role,
                    "decision": event.decision,
                    "threat_type": event.threat_type,
                    "tool_name": tool,
                }
            )
            + "\n"
        )
    db.commit()
    return event
