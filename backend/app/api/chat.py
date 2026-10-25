from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import current_user
from app.core.rate_limit import enforce
from app.db.database import get_db
from app.db.models import User
from app.schemas.chat import ChatRequest
from app.services.chat_service import chat

router = APIRouter()


@router.post("/chat")
def chat_route(
    body: ChatRequest, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    # Each chat may trigger several Gemini calls; limit per authenticated user.
    enforce("chat", str(user.id))
    return chat(db, user, body.message)
