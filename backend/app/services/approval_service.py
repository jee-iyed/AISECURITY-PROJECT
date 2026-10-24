import json

from fastapi import HTTPException
from sqlalchemy import update

from app.db.models import Approval, User, now
from app.security.logger import record
from app.security.risk_engine import assessment
from app.security.tool_guard import validate_tool_call
from app.tools.registry import TOOLS


def review(db, reviewer, approval_id, approve):
    if reviewer.role != "ADMIN":
        raise HTTPException(403, "Administrator access required")
    claimed = db.execute(
        update(Approval)
        .where(Approval.id == approval_id, Approval.status == "PENDING")
        .values(status="REVIEWING", reviewer_id=reviewer.id, reviewed_at=now())
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Approval missing or already reviewed")
    a = db.get(Approval, approval_id)
    owner = db.get(User, a.user_id)
    result = None
    if not approve:
        a.status = "REJECTED"
        security = assessment(None, 65, "Human reviewer rejected the action.", "REJECT")
    else:
        if owner is None:
            raise HTTPException(409, "Requesting user no longer exists")
        security, args = validate_tool_call(
            db, owner, a.tool_name, json.loads(a.arguments), approved=True
        )
        if security["decision"] == "BLOCK":
            a.status = "BLOCKED"
        else:
            result = TOOLS[a.tool_name](db, owner, **args)
            a.status = "APPROVED"
            security = assessment(
                reason=f"Human approval by administrator {reviewer.id}; authorization revalidated.",
                decision="EXECUTED",
            )
    record(db, owner, "Approval review", security, a.tool_name)
    return {"id": a.id, "status": a.status, "result": result, "security": security}
