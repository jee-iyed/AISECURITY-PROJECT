import httpx
import pytest

from app.db.database import SessionLocal
from app.db.models import Course
from app.llm import agent, gemini_client


def test_gemini_transport_sends_headers_and_schema(monkeypatch):
    def post(url, headers, json, timeout):
        assert url.endswith(":generateContent")
        assert headers["x-goog-api-key"] == "test-key"
        assert json["tools"][0]["functionDeclarations"][0]["name"] == "get_my_schedule"
        assert (
            "Authenticated role: STUDENT"
            in json["systemInstruction"]["parts"][0]["text"]
        )
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "role": "model",
                            "parts": [
                                {
                                    "functionCall": {
                                        "name": "get_my_schedule",
                                        "args": {},
                                    }
                                }
                            ],
                        }
                    }
                ]
            },
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(gemini_client, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(gemini_client.httpx, "post", post)
    assert (
        gemini_client.generate(
            [],
            "STUDENT",
            [{"name": "get_my_schedule", "parametersJsonSchema": {"type": "object"}}],
        )["parts"][0]["functionCall"]["name"]
        == "get_my_schedule"
    )


def test_model_cannot_bypass_guard(client, headers, monkeypatch):
    monkeypatch.setattr(
        agent,
        "propose",
        lambda *args: {
            "name": "update_schedule",
            "arguments": {"course_id": 1, "old_room": "A201", "new_room": "B105"},
        },
    )
    result = client.post(
        "/api/chat",
        headers=headers("STUDENT"),
        json={"message": "Please help with my class"},
    ).json()
    assert result["security"]["decision"] == "BLOCK" and not result["tool"]["executed"]
    with SessionLocal() as db:
        assert db.get(Course, 1).room == "A201"


def test_provider_failure_never_falls_back_to_action(client, headers, monkeypatch):
    def unavailable(*args):
        raise gemini_client.LLMUnavailable()

    monkeypatch.setattr(agent, "propose", unavailable)
    result = client.post(
        "/api/chat", headers=headers("ADMIN"), json={"message": "Change a room"}
    ).json()
    assert result["security"]["decision"] == "ERROR" and result["approval_id"] is None


def test_model_output_is_filtered(client, headers, monkeypatch):
    monkeypatch.setattr(
        agent, "propose", lambda *args: {"message": "api_key=secret-value"}
    )
    result = client.post(
        "/api/chat", headers=headers("STUDENT"), json={"message": "Hello"}
    ).json()
    assert (
        result["security"]["decision"] == "REDACT"
        and "secret-value" not in result["message"]
    )


def test_declarations_follow_permissions():
    from app.core.permissions import PERMISSIONS
    from app.tools.registry import SCHEMAS, declarations_for

    for role, allowed in PERMISSIONS.items():
        declarations = declarations_for(role)
        assert {d["name"] for d in declarations} == allowed
        for declaration in declarations:
            assert (
                declaration["parametersJsonSchema"]
                == SCHEMAS[declaration["name"]].model_json_schema()
            )


def test_gemini_lookup_then_write_requires_approval(client, headers, monkeypatch):
    from sqlalchemy import select

    from app.db.models import Approval, SecurityEvent

    turns = []

    def generate(contents, role, declarations=None):
        assert role == "ADMIN"
        assert "update_schedule" in {d["name"] for d in declarations}
        turns.append(contents[:])
        if len(turns) == 1:
            call = {"name": "get_room_schedule", "args": {"room": "A201"}}
        else:
            response = contents[-1]["parts"][0]["functionResponse"]
            row = response["response"]["result"][0]
            assert row["room"] == "A201" and row["course_id"] == 1
            assert contents[-2]["parts"][1]["thoughtSignature"] == "preserve-me"
            call = {
                "name": "update_schedule",
                "args": {
                    "course_id": row["course_id"],
                    "old_room": row["room"],
                    "new_room": "B105",
                },
            }
        return {
            "role": "model",
            "parts": [
                {"text": "Je vérifie."},
                {"functionCall": call, "thoughtSignature": "preserve-me"},
            ],
        }

    monkeypatch.setattr(agent, "GEMINI_API_KEY", "test")
    monkeypatch.setattr(agent, "generate", generate)
    result = client.post(
        "/api/chat",
        headers=headers("ADMIN"),
        json={"message": "Change la salle A201 vers B105"},
    ).json()
    assert result["security"]["decision"] == "REQUIRE_APPROVAL"
    assert not result["tool"]["executed"]
    assert len(turns) == 2
    with SessionLocal() as db:
        approval = db.get(Approval, result["approval_id"])
        assert approval.status == "PENDING"
        assert db.get(Course, 1).room == "A201"
        event = db.scalar(select(SecurityEvent).order_by(SecurityEvent.id.desc()))
        assert event.threat_type == "SENSITIVE_ACTION"


def test_gemini_room_query_uses_database(client, headers, monkeypatch):
    from datetime import date, timedelta

    day = (date.today() + timedelta(days=1)).isoformat()
    turns = []

    def generate(contents, role, declarations=None):
        turns.append(contents[:])
        if len(turns) == 1:
            return {
                "role": "model",
                "parts": [
                    {
                        "functionCall": {
                            "name": "get_room_schedule",
                            "args": {"room": "B105", "day": day},
                        }
                    }
                ],
            }
        rows = contents[-1]["parts"][0]["functionResponse"]["response"]["result"]
        assert rows == []  # Seeded courses occupy A201, so B105 is free.
        return {
            "role": "model",
            "parts": [{"text": "B105 est disponible : aucun créneau réservé."}],
        }

    monkeypatch.setattr(agent, "GEMINI_API_KEY", "test")
    monkeypatch.setattr(agent, "generate", generate)
    result = client.post(
        "/api/chat",
        headers=headers("ADMIN"),
        json={"message": "La salle B105 est-elle disponible demain ?"},
    ).json()
    assert result["security"]["decision"] == "ALLOW"
    assert result["tool"] == {"name": "get_room_schedule", "executed": True}
    assert "disponible" in result["message"]


def test_student_model_refusal_is_still_blocked(client, headers, monkeypatch):
    from sqlalchemy import select

    from app.db.models import Approval

    monkeypatch.setattr(
        agent,
        "propose",
        lambda *args: {"message": "Je ne peux pas modifier les salles."},
    )
    result = client.post(
        "/api/chat",
        headers=headers("STUDENT"),
        json={"message": "Change la salle A201 vers B105"},
    ).json()
    assert result["security"]["decision"] == "BLOCK"
    assert result["approval_id"] is None
    with SessionLocal() as db:
        assert db.scalar(select(Approval.id)) is None
        assert db.get(Course, 1).room == "A201"


@pytest.mark.parametrize(
    "content",
    [
        None,
        {},
        {"parts": None},
        {"parts": [None]},
        {"parts": []},
        {"parts": [{"text": None}]},
        {"parts": [{"text": " "}]},
        {"parts": [{"functionCall": None}]},
        {"parts": [{"functionCall": {"name": []}}]},
        {"parts": [{"functionCall": {"name": ""}}]},
        {"parts": [{"functionCall": {"name": "update_schedule", "args": []}}]},
        {
            "parts": [
                {"functionCall": {"name": "update_schedule"}},
                {"functionCall": {"name": "get_room_schedule"}},
            ]
        },
    ],
)
def test_malformed_provider_content_fails_closed(content):
    with pytest.raises(gemini_client.LLMUnavailable):
        agent.parse_content(content)


def test_tool_loop_is_bounded(client, headers, monkeypatch):
    turns = []

    def generate(*args):
        turns.append(1)
        return {
            "role": "model",
            "parts": [
                {
                    "functionCall": {
                        "name": "get_room_schedule",
                        "args": {"room": "A201"},
                    }
                }
            ],
        }

    monkeypatch.setattr(agent, "GEMINI_API_KEY", "test")
    monkeypatch.setattr(agent, "generate", generate)
    result = client.post(
        "/api/chat", headers=headers("ADMIN"), json={"message": "Inspect A201"}
    ).json()
    assert len(turns) == 6
    assert result["security"]["decision"] == "ERROR"
    assert result["approval_id"] is None


def test_malformed_write_call_returns_error_without_approval(
    client, headers, monkeypatch
):
    from sqlalchemy import select

    from app.db.models import Approval

    monkeypatch.setattr(agent, "GEMINI_API_KEY", "test")
    monkeypatch.setattr(
        agent,
        "generate",
        lambda *args: {
            "parts": [{"functionCall": {"name": ["update_schedule"], "args": {}}}]
        },
    )
    response = client.post(
        "/api/chat",
        headers=headers("ADMIN"),
        json={"message": "Change la salle A201 vers B105"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["security"]["decision"] == "ERROR"
    assert result["approval_id"] is None
    with SessionLocal() as db:
        assert db.scalar(select(Approval.id)) is None
        assert db.get(Course, 1).room == "A201"
