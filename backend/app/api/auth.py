from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import create_token, current_user
from app.db.database import get_db
from app.db.models import User
from app.db.seed import password_hash
from app.schemas.auth import Login

router = APIRouter()


def public_user(u):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role}


@router.post("/auth/login")
def login(body: Login, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not password_hash.verify(body.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "user": public_user(user),
    }


@router.get("/me")
def me(user: User = Depends(current_user)):
    return public_user(user)
