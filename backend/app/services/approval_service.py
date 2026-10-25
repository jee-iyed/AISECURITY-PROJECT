import hashlib
import json
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import or_, update

from app.core.config import APPROVAL_TTL_MINUTES, REQUIRE_DISTINCT_APPROVER
from app.db.models import Approval, User, now
from app.security.logger import record
from app.security.risk_engine import assessment, evaluate
from app.security.tool_guard import validate_tool_call
from app.tools.registry import TOOLS


def canonical_arguments(args):
    return json.dumps(args, sort_keys=True, separators=(",", ":"))


def arguments_hash(user_id, tool_name, args):
    """Binds an approval to one requester, one tool and one exact argument set."""
    payload = f"{user_id}|{tool_name}|{canonical_arguments(args)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def create_approval(db, user, name, args, security, correlation_id=None):
    """Persist a pending approval for arguments already validated by Tool Guard."""
    approval = Approval(
        user_id=user.id,
        tool_name=name,
        arguments=canonical_arguments(args),
        arguments_hash=arguments_hash(user.id, name, args),
        expires_at=(
            datetime.now(UTC) + timedelta(minutes=APPROVAL_TTL_MINUTES)
        ).isoformat(),
        risk_score=security["risk_score"],
        reason=security["reason"],
        correlation_id=correlation_id,
    )
    db.add(approval)
    db.flush()
    return approval


def _claim(db, reviewer, approval_id):
    """Atomic PENDING -> REVIEWING transition.

    The conditional UPDATE takes SQLite's write lock; it is committed together
    with the tool execution, so a concurrent reviewer blocks on the lock, then
    finds the row no longer PENDING. A failure before commit rolls the claim
    back to PENDING.
    """
    conditions = [
        Approval.id == approval_id,
        Approval.status == "PENDING",
        or_(Approval.expires_at.is_(None), Approval.expires_at > now()),
    ]
    if REQUIRE_DISTINCT_APPROVER:
        conditions.append(Approval.user_id != reviewer.id)
    return db.execute(
        update(Approval)
        .where(*conditions)
        .values(status="REVIEWING", reviewer_id=reviewer.id, reviewed_at=now())
    ).rowcount


def _explain_failed_claim(db, reviewer, approval_id):
    db.rollback()
    a = db.get(Approval, approval_id)
    if a is None or a.status != "PENDING":
        raise HTTPException(409, "Approval missing or already reviewed")
    if a.expires_at and a.expires_at <= now():
        expired = db.execute(
            update(Approval)
            .where(Approval.id == approval_id, Approval.status == "PENDING")
            .values(status="EXPIRED", reviewer_id=reviewer.id, reviewed_at=now())
        ).rowcount
        if expired:
            owner = db.get(User, a.user_id) or reviewer
            record(
                db,
                owner,
                "Approval review",
                assessment(None, 10, "Approval expired before review.", "EXPIRED"),
                a.tool_name,
                approval_id=a.id,
                outcome="EXPIRED",
            )
        raise HTTPException(410, "Approval expired")
    raise HTTPException(403, "Requester cannot review their own action")


def review(db, reviewer, approval_id, approve):
    if reviewer.role != "ADMIN":
        raise HTTPException(403, "Administrator access required")
    if _claim(db, reviewer, approval_id) != 1:
        _explain_failed_claim(db, reviewer, approval_id)
    a = db.get(Approval, approval_id)
    db.refresh(a)
    owner = db.get(User, a.user_id)
    stored_args = json.loads(a.arguments)
    result = None
    outcome = None
    if owner is None:
        raise HTTPException(409, "Requesting user no longer exists")
    if a.arguments_hash and a.arguments_hash != arguments_hash(
        a.user_id, a.tool_name, stored_args
    ):
        a.status = "BLOCKED"
        security = evaluate(
            authorization_denied=True,
            threat="INTEGRITY_VIOLATION",
            reason="Stored approval arguments do not match their integrity hash.",
            deny_rule="DENY_TAMPERED_APPROVAL",
        )
    elif not approve:
        a.status = "REJECTED"
        security = assessment(None, 65, "Human reviewer rejected the action.", "REJECT")
        outcome = "REJECTED"
    else:
        security, args = validate_tool_call(
            db, owner, a.tool_name, stored_args, approved=True
        )
        if security["decision"] == "BLOCK":
            a.status = "BLOCKED"
        elif args != stored_args:
            a.status = "BLOCKED"
            security = evaluate(
                authorization_denied=True,
                threat="INTEGRITY_VIOLATION",
                reason="Revalidated action differs from the approved action.",
                deny_rule="DENY_APPROVAL_MISMATCH",
            )
        else:
            result = TOOLS[a.tool_name](db, owner, **stored_args)
            a.status = "APPROVED"
            a.executed_at = now()
            a.result = json.dumps(result, ensure_ascii=False)
            outcome = "EXECUTED"
            security = assessment(
                reason=f"Human approval by administrator {reviewer.id}; authorization revalidated.",
                decision="EXECUTED",
            )
            security["policy_rules"] = ["EXECUTE_APPROVED_ACTION"]
    # record() commits the status change and the tool effect in one transaction.
    record(
        db,
        owner,
        "Approval review",
        security,
        a.tool_name,
        correlation_id=a.correlation_id,
        approval_id=a.id,
        outcome=outcome or a.status,
    )
    return {
        "id": a.id,
        "status": a.status,
        "result": result,
        "security": security,
        "reviewer_id": reviewer.id,
    }
