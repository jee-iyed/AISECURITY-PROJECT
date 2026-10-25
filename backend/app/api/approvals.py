import json

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import admin_user
from app.db.database import get_db
from app.db.models import Approval, User
from app.services.approval_service import review

router = APIRouter(prefix="/approvals")


@router.get("")
def approvals(user: User = Depends(admin_user), db: Session = Depends(get_db)):
    return [
        {
            "id": a.id,
            "user": u.name,
            "role": u.role,
            "tool_name": a.tool_name,
            "arguments": json.loads(a.arguments),
            "status": a.status,
            "created_at": a.created_at,
            "risk_score": a.risk_score if a.risk_score is not None else 65,
            "reason": a.reason or "Course-wide room change requires human review.",
            "expires_at": a.expires_at,
            "reviewer_id": a.reviewer_id,
            "reviewed_at": a.reviewed_at,
            "executed_at": a.executed_at,
            "arguments_hash": (a.arguments_hash or "")[:12],
        }
        for a, u in db.execute(
            select(Approval, User)
            .join(User, Approval.user_id == User.id)
            .order_by(Approval.id.desc())
            .limit(500)
        )
    ]


@router.post("/{approval_id}/approve")
def approve(
    approval_id: int, user: User = Depends(admin_user), db: Session = Depends(get_db)
):
    return review(db, user, approval_id, True)


@router.post("/{approval_id}/reject")
def reject(
    approval_id: int, user: User = Depends(admin_user), db: Session = Depends(get_db)
):
    return review(db, user, approval_id, False)
