from datetime import date, timedelta

import httpx
from sqlalchemy import func, select

from app.db.database import SessionLocal
from app.db.models import Approval, Course, Professor, Schedule, User
from app.db.seed import DEMO_DAYS, refresh_demo_schedule

TODAY = date.today()


def days(offset_from=0, count=DEMO_DAYS, base=TODAY):
    return {(base + timedelta(days=offset_from + i)).isoformat() for i in range(count)}


def schedule_days(db, course_id):
    return set(db.scalars(select(Schedule.day).where(Schedule.course_id == course_id)))


def age_schedule(db, days_back=30):
    """Simulate a database seeded long ago: every session lies in the past."""
    for s in db.scalars(select(Schedule)):
        s.day = (date.fromisoformat(s.day) - timedelta(days=days_back)).isoformat()
    db.commit()


def test_fresh_seed_covers_rolling_window(client):
    with SessionLocal() as db:
        for course_id in (1, 2):
            assert days() <= schedule_days(db, course_id)


def test_refresh_is_additive_idempotent_and_reproducible(client):
    base = date(2027, 3, 1)
    with SessionLocal() as db:
        before = db.scalar(select(func.count(Schedule.id)))
        assert refresh_demo_schedule(db, base) == 2 * DEMO_DAYS
        assert refresh_demo_schedule(db, base) == 0  # idempotent
        assert db.scalar(select(func.count(Schedule.id))) == before + 2 * DEMO_DAYS
        assert days(base=base) <= schedule_days(db, 1)
        slot = db.scalar(
            select(Schedule).where(Schedule.course_id == 1, Schedule.day == base.isoformat())
        )
        assert (slot.start_time, slot.end_time) == ("09:00", "11:00")


def test_stale_database_is_refreshed_without_overwriting(client, headers):
    h = headers("ADMIN")
    aid = client.post(
        "/api/chat",
        headers=h,
        json={"message": "Change la salle du cours Cybersecurity de A201 vers B105."},
    ).json()["approval_id"]
    with SessionLocal() as db:
        age_schedule(db)
        db.get(Course, 2).room = "B106"  # e.g. an earlier approved change
        db.commit()
        old = schedule_days(db, 1)
        added = refresh_demo_schedule(db)
        assert added == 2 * DEMO_DAYS
        assert old <= schedule_days(db, 1)  # history kept
        assert days() <= schedule_days(db, 1)
        assert db.get(Course, 2).room == "B106"  # room not reset
        assert db.get(Approval, aid).status == "PENDING"  # approvals untouched


def test_non_demo_courses_are_never_touched(client):
    with SessionLocal() as db:
        other = User(name="Real Prof", email="real@university.example", hashed_password="x", role="PROFESSOR")
        db.add(other)
        db.flush()
        prof = Professor(user_id=other.id, department="Math")
        db.add(prof)
        db.flush()
        course = Course(name="Cybersecurity", professor_id=prof.id, class_name="ING3", room="B105")
        db.add(course)
        db.commit()
        refresh_demo_schedule(db)
        assert schedule_days(db, course.id) == set()


def test_refresh_can_be_disabled(client, monkeypatch):
    from app.db import seed as seed_module

    monkeypatch.setattr(seed_module, "DEMO_SCHEDULE_REFRESH", False)
    with SessionLocal() as db:
        age_schedule(db)
        seed_module.seed(db)
        assert not days() & schedule_days(db, 1)


def test_tomorrow_works_after_refresh_demo_agent(client, headers):
    """Relative dates resolve against the current date (offline demo agent)."""
    with SessionLocal() as db:
        age_schedule(db)
        refresh_demo_schedule(db)
    tomorrow = (TODAY + timedelta(days=1)).isoformat()
    data = client.post(
        "/api/chat", headers=headers("STUDENT"), json={"message": "Quel est mon emploi du temps demain ?"}
    ).json()
    assert data["security"]["decision"] == "ALLOW"
    assert data["tool"] == {"name": "get_my_schedule", "executed": True}
    assert tomorrow in data["message"]
    assert "Cybersecurity" in data["message"] and "Reseaux" in data["message"]
    free = client.post(
        "/api/chat",
        headers=headers("ADMIN"),
        json={"message": "Quelle salle est libre demain entre 14h et 16h ?"},
    ).json()
    assert free["tool"]["name"] == "find_free_room"
    assert tomorrow in free["message"] and "A201" not in free["message"]  # Reseaux 14-16
    morning = client.post(
        "/api/chat",
        headers=headers("ADMIN"),
        json={"message": "Quelle salle est libre demain entre 12h et 13h ?"},
    ).json()
    assert "A201" in morning["message"]


def test_gemini_receives_current_date_without_network(monkeypatch):
    from app.llm import gemini_client

    seen = []

    def post(url, headers, json, timeout):
        seen.append(json["systemInstruction"]["parts"][0]["text"])
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(gemini_client.httpx, "post", post)
    gemini_client.generate([], "STUDENT")
    assert f"Current date: {TODAY.isoformat()}" in seen[0]


def test_approval_flow_works_on_refreshed_dates(client, headers):
    h = headers("ADMIN")
    with SessionLocal() as db:
        age_schedule(db)
        refresh_demo_schedule(db)
    aid = client.post(
        "/api/chat",
        headers=h,
        json={"message": "Change la salle du cours Cybersecurity de A201 vers B105."},
    ).json()["approval_id"]
    assert client.post(f"/api/approvals/{aid}/approve", headers=h).json()["status"] == "APPROVED"
    assert client.post(f"/api/approvals/{aid}/approve", headers=h).status_code == 409
    with SessionLocal() as db:
        assert db.get(Course, 1).room == "B105"
