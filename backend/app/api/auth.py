from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import create_token, current_user
from app.core.rate_limit import client_ip, enforce
from app.db.database import get_db
from app.db.models import User
from app.db.seed import password_hash
from app.schemas.auth import Login

router = APIRouter()
# Verified when the account does not exist so both paths cost one Argon2
# verification: response time does not reveal which emails are registered.
_DUMMY_HASH = password_hash.hash("timing-equalizer-not-a-real-password")


def public_user(u):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role}


@router.post("/auth/login")
def login(body: Login, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower()
    enforce("login_ip", client_ip(request))
    enforce("login_account", email)
    user = db.scalar(select(User).where(User.email == email))
    valid = password_hash.verify(
        body.password, user.hashed_password if user else _DUMMY_HASH
    )
    if not user or not valid:
        raise HTTPException(401, "Invalid credentials")
    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "user": public_user(user),
    }


@router.get("/me")
def me(user: User = Depends(current_user)):
    return public_user(user)
