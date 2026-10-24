from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import JWT_SECRET
from app.db.database import get_db
from app.db.models import User

bearer = HTTPBearer(auto_error=False)


def create_token(user):
    return jwt.encode(
        {
            "sub": str(user.id),
            "role": user.role,
            "exp": datetime.now(UTC) + timedelta(hours=2),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
):
    try:
        if not credentials:
            raise ValueError()
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["sub", "exp"]},
        )
        user = db.get(User, int(payload["sub"]))
        if not user:
            raise ValueError()
        return user
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired authentication")


def admin_user(user: User = Depends(current_user)):
    if user.role != "ADMIN":
        raise HTTPException(403, "Administrator access required")
    return user
