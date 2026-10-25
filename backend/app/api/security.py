from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import admin_user
from app.db.database import get_db
from app.db.models import SecurityEvent, User
from app.security.security_analyzer import explain
from app.tools.registry import inventory

router = APIRouter(prefix="/security")


@router.get("/events")
def events(
    role: str | None = None,
    threat: str | None = None,
    decision: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
):
    query = select(SecurityEvent)
    for column, value in [
        (SecurityEvent.role, role),
        (SecurityEvent.threat_type, threat),
        (SecurityEvent.decision, decision),
    ]:
        if value:
            query = query.where(column == value)
    return [
        {c.name: getattr(e, c.name) for c in SecurityEvent.__table__.columns}
        for e in db.scalars(query.order_by(SecurityEvent.id.desc()).limit(limit))
    ]


@router.get("/events/{event_id}/analysis")
def analysis(
    event_id: int, user: User = Depends(admin_user), db: Session = Depends(get_db)
):
    event = db.get(SecurityEvent, event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return explain(event)


@router.get("/tools")
def tools(user: User = Depends(admin_user)):
    return inventory()
