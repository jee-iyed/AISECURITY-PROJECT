import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.core.config import LOG_DIR
from app.db.models import SecurityEvent
from app.security.output_guard import redact

# Window used by the risk engine's history factor.
HISTORY_WINDOW = timedelta(minutes=10)
SIGNAL_FIELDS = ("detector", "threat", "confidence", "evidence", "source", "view", "framing")


def new_correlation_id():
    return uuid.uuid4().hex[:16]


def recent_blocks(db, user, window=HISTORY_WINDOW):
    since = (datetime.now(UTC) - window).isoformat()
    return db.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.user_id == user.id,
            SecurityEvent.decision == "BLOCK",
            SecurityEvent.timestamp >= since,
        )
    )


def _audit_signals(security):
    # Excerpts are dropped: evidence and detector names explain the decision
    # without copying user text (which may contain personal data) into logs.
    return [
        {k: s.get(k) for k in SIGNAL_FIELDS if k in s}
        for s in security.get("signals", [])
    ][:20]


def record(
    db,
    user,
    prompt,
    security,
    tool=None,
    *,
    correlation_id=None,
    source=None,
    approval_id=None,
    outcome=None,
):
    event = SecurityEvent(
        user_id=user.id,
        user_name=user.name,
        role=user.role,
        prompt_preview=redact(prompt)[:240],
        tool_name=tool,
        correlation_id=correlation_id,
        source=source,
        policy_rules=json.dumps(security.get("policy_rules", [])),
        signals=json.dumps(_audit_signals(security)),
        approval_id=approval_id,
        outcome=outcome,
        **{
            k: security[k]
            for k in ["threat_type", "risk_score", "risk_level", "decision", "reason"]
        },
    )
    event.reason = redact(event.reason)
    db.add(event)
    db.flush()
    with (LOG_DIR / "security.jsonl").open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "id": event.id,
                    "event_id": f"EVT-{event.id:06d}",
                    "timestamp": event.timestamp,
                    "correlation_id": correlation_id,
                    "user_id": user.id,
                    "role": user.role,
                    "threat_type": event.threat_type,
                    "risk_score": event.risk_score,
                    "decision": event.decision,
                    "tool_name": tool,
                    "tool": tool,
                    "reason": event.reason,
                    "policy_rules": security.get("policy_rules", []),
                    "source": source,
                    "approval_id": approval_id,
                    "outcome": outcome,
                }
            )
            + "\n"
        )
    db.commit()
    return event
