import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest
from sqlalchemy import select

from app.db.database import SessionLocal
from app.db.models import Approval, Course, SecurityEvent, User
from app.security.tool_guard import validate_tool_call
from app.services import approval_service
from app.tools.policies import TOOL_POLICIES
from app.tools.registry import SCHEMAS, TOOLS, inventory

CHANGE = "Change la salle du cours Cybersecurity de A201 vers B105."
UPDATE = {"course_id": 1, "old_room": "A201", "new_room": "B105"}


def request_change(client, h):
    return client.post("/api/chat", headers=h, json={"message": CHANGE}).json()


def guard(user_id, name, args, **kwargs):
    with SessionLocal() as db:
        return validate_tool_call(db, db.get(User, user_id), name, args, **kwargs)


def test_inventory_complete():
    assert set(TOOL_POLICIES) == set(SCHEMAS) == set(TOOLS)
    for item in inventory():
        assert item["roles"], item["name"]
        assert item["operation"] in {"READ", "WRITE"}
        assert item["arguments_schema"]["additionalProperties"] is False
        if item["operation"] == "WRITE":
            assert item["requires_approval"]


def test_inventory_endpoint_admin_only(client, headers):
    assert client.get("/api/security/tools", headers=headers("STUDENT")).status_code == 403
    names = {t["name"] for t in client.get("/api/security/tools", headers=headers("ADMIN")).json()}
    assert "update_schedule" in names


@pytest.mark.parametrize(
    "name,args",
    [
        ("update_schedule", {**UPDATE, "course_id": True}),
        ("update_schedule", {**UPDATE, "course_id": "1"}),
        ("update_schedule", {**UPDATE, "course_id": 1.0}),
        ("update_schedule", {**UPDATE, "new_room": "Z999"}),
        ("update_schedule", {**UPDATE, "approved": True}),
        ("update_schedule", {"course_id": 1}),
        ("search_student", {"query": "%"}),
        ("search_student", {"query": "x" * 81}),
        ("search_student", {"query": "Karim; DROP TABLE users"}),
        ("get_room_schedule", {"room": "A201", "day": "1990-01-01"}),
        ("find_free_room", {"day": "2026-01-01", "start_time": "16:00", "end_time": "14:00"}),
    ],
)
def test_invalid_arguments_rejected(client, name, args):
    security, validated = guard(3, name, args)
    assert security["decision"] == "BLOCK" and validated is None
    assert security["policy_rules"] == ["DENY_INVALID_ARGUMENTS"]


def test_student_admin_tool_blocked_with_rule(client):
    security, _ = guard(1, "update_schedule", UPDATE)
    assert security["decision"] == "BLOCK"
    assert security["policy_rules"] == ["DENY_UNAUTHORIZED_ACTION"]
    assert security["risk_score"] >= 85


def test_unowned_resource_rejected(client):
    from app.db.models import Professor

    with SessionLocal() as db:
        other = User(name="Other Prof", email="p2@example.test", hashed_password="x", role="PROFESSOR")
        db.add(other)
        db.flush()
        prof = Professor(user_id=other.id, department="Math")
        db.add(prof)
        db.flush()
        db.add(Course(id=50, name="Other", professor_id=prof.id, class_name="ING3", room="B106"))
        db.commit()
    security, _ = guard(2, "get_course_students", {"course_id": 50})
    assert security["decision"] == "BLOCK"
    assert security["threat_type"] == "UNAUTHORIZED_ACTION"


def test_identity_cannot_be_supplied_by_model(client):
    for args in [{"user_id": 3}, {"role": "ADMIN"}, {"student_id": 2}]:
        assert guard(1, "get_my_schedule", args)[0]["decision"] == "BLOCK"


def test_approval_stores_real_risk_and_expiry(client, headers):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    item = next(a for a in client.get("/api/approvals", headers=h).json() if a["id"] == aid)
    assert item["risk_score"] < 60 and item["expires_at"] and item["arguments_hash"]
    with SessionLocal() as db:
        approval = db.get(Approval, aid)
        assert approval.arguments_hash == approval_service.arguments_hash(
            approval.user_id, "update_schedule", json.loads(approval.arguments)
        )


def test_approval_traceability(client, headers):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    result = client.post(f"/api/approvals/{aid}/approve", headers=h).json()
    assert result["status"] == "APPROVED" and result["reviewer_id"] == 3
    with SessionLocal() as db:
        approval = db.get(Approval, aid)
        assert approval.reviewer_id == 3 and approval.executed_at
        event = db.scalar(select(SecurityEvent).where(SecurityEvent.approval_id == aid).order_by(SecurityEvent.id.desc()))
        assert event.outcome == "EXECUTED" and event.decision == "EXECUTED"


def test_expired_approval_rejected(client, headers):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    with SessionLocal() as db:
        db.get(Approval, aid).expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        db.commit()
    assert client.post(f"/api/approvals/{aid}/approve", headers=h).status_code == 410
    assert client.post(f"/api/approvals/{aid}/approve", headers=h).status_code == 409
    with SessionLocal() as db:
        assert db.get(Approval, aid).status == "EXPIRED"
        assert db.get(Course, 1).room == "A201"


def test_tampered_arguments_not_executed(client, headers):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    with SessionLocal() as db:
        db.get(Approval, aid).arguments = json.dumps({**UPDATE, "new_room": "B106"})
        db.commit()
    result = client.post(f"/api/approvals/{aid}/approve", headers=h).json()
    assert result["status"] == "BLOCKED"
    assert result["security"]["policy_rules"] == ["DENY_TAMPERED_APPROVAL"]
    with SessionLocal() as db:
        assert db.get(Course, 1).room == "A201"


def test_executed_action_must_match_approved(client, headers, monkeypatch):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    original = approval_service.validate_tool_call

    def drifting(*args, **kwargs):
        security, validated = original(*args, **kwargs)
        return security, {**validated, "new_room": "B106"}

    monkeypatch.setattr(approval_service, "validate_tool_call", drifting)
    result = client.post(f"/api/approvals/{aid}/approve", headers=h).json()
    assert result["status"] == "BLOCKED"
    with SessionLocal() as db:
        assert db.get(Course, 1).room == "A201"


def test_separation_of_duties_when_enabled(client, headers, monkeypatch):
    from app.core.auth import create_token

    monkeypatch.setattr(approval_service, "REQUIRE_DISTINCT_APPROVER", True)
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    assert client.post(f"/api/approvals/{aid}/approve", headers=h).status_code == 403
    with SessionLocal() as db:
        other = User(name="Second Admin", email="admin2@example.test", hashed_password="x", role="ADMIN")
        db.add(other)
        db.commit()
        token = create_token(other)
    second = {"Authorization": "Bearer " + token}
    assert client.post(f"/api/approvals/{aid}/approve", headers=second).json()["status"] == "APPROVED"


def test_concurrent_mixed_reviews_execute_at_most_once(client, headers, monkeypatch):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]
    calls = []
    original = TOOLS["update_schedule"]
    monkeypatch.setitem(TOOLS, "update_schedule", lambda *a, **k: calls.append(1) or original(*a, **k))
    barrier = Barrier(4)

    def act(action):
        barrier.wait(timeout=10)
        return client.post(f"/api/approvals/{aid}/{action}", headers=h).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(pool.map(act, ["approve", "reject", "approve", "reject"]))
    assert sorted(codes) == [200, 409, 409, 409]
    assert len(calls) <= 1
    with SessionLocal() as db:
        status = db.get(Approval, aid).status
        assert (status == "APPROVED") == (len(calls) == 1)
        assert (db.get(Course, 1).room == "B105") == (status == "APPROVED")


def test_failed_execution_rolls_back_claim(client, headers, monkeypatch):
    h = headers("ADMIN")
    aid = request_change(client, h)["approval_id"]

    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setitem(TOOLS, "update_schedule", boom)
    with pytest.raises(RuntimeError):
        client.post(f"/api/approvals/{aid}/approve", headers=h)
    with SessionLocal() as db:
        assert db.get(Approval, aid).status == "PENDING"
        assert db.get(Course, 1).room == "A201"


def test_invalid_arguments_never_create_approval(client, headers, monkeypatch):
    from app.llm import agent

    monkeypatch.setattr(
        agent, "propose",
        lambda *a: {"name": "update_schedule", "arguments": {**UPDATE, "new_room": "B105", "course_id": "1"}},
    )
    data = client.post("/api/chat", headers=headers("ADMIN"), json={"message": "move it"}).json()
    assert data["security"]["decision"] == "BLOCK" and data["approval_id"] is None
    with SessionLocal() as db:
        assert db.scalar(select(Approval.id)) is None
