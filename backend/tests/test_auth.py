from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import JWT_SECRET
from app.db.database import SessionLocal
from app.db.models import User


@pytest.mark.parametrize("role", ["STUDENT", "PROFESSOR", "ADMIN"])
def test_login_and_identity(client, headers, role):
    h = headers(role)
    assert client.get("/api/me", headers=h).json()["role"] == role
    with SessionLocal() as db:
        u = db.get(User, {"STUDENT": 1, "PROFESSOR": 2, "ADMIN": 3}[role])
        assert u.hashed_password.startswith("$argon2")


def test_bad_password_and_no_token(client):
    assert (
        client.post(
            "/api/auth/login",
            json={"email": "student@esigelec-demo.fr", "password": "bad"},
        ).status_code
        == 401
    )
    assert client.get("/api/me").status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        "bad",
        jwt.encode(
            {"sub": "1", "exp": datetime.now(UTC) - timedelta(seconds=1)},
            JWT_SECRET,
            algorithm="HS256",
        ),
        jwt.encode(
            {"sub": "1", "exp": datetime.now(UTC) + timedelta(hours=1)},
            "wrong-key-with-at-least-thirty-two-characters",
            algorithm="HS256",
        ),
    ],
)
def test_invalid_jwt(client, token):
    assert (
        client.get("/api/me", headers={"Authorization": "Bearer " + token}).status_code
        == 401
    )


def test_role_from_database_even_if_token_claims_admin(client):
    token = jwt.encode(
        {
            "sub": "1",
            "role": "ADMIN",
            "exp": datetime.now(UTC) + timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    h = {"Authorization": "Bearer " + token}
    assert client.get("/api/me", headers=h).json()["role"] == "STUDENT"
    assert client.get("/api/security/events", headers=h).status_code == 403
