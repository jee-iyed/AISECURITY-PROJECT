import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEST_DIR = ROOT / "work" / "tests"
TEST_DIR.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = "sqlite:///" + str(TEST_DIR / "test.db").replace("\\", "/")
os.environ["DATA_DIR"] = str(TEST_DIR)
os.environ["LOG_DIR"] = str(TEST_DIR / "logs")
os.environ["DEMO_DATA_DIR"] = os.environ.get("DEMO_DATA_DIR", str(ROOT / "demo-data"))
os.environ["GEMINI_API_KEY"] = ""
os.environ["JWT_SECRET"] = "test-only-key-with-at-least-thirty-two-characters"
from fastapi.testclient import TestClient

from app.db.database import Base, engine
from app.main import app


@pytest.fixture(autouse=True)
def reset_gemini_model_health():
    from app.llm import gemini_client

    gemini_client.reset_model_health()
    yield
    gemini_client.reset_model_health()


@pytest.fixture()
def client():
    from app.core import rate_limit

    rate_limit.reset()
    Base.metadata.drop_all(engine)
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def headers(client):
    def login(role):
        response = client.post(
            "/api/auth/login",
            json={
                "email": role.lower() + "@esigelec-demo.fr",
                "password": "DemoPass123!",
            },
        )
        assert response.status_code == 200
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    return login
