import pytest

from app.db.database import SessionLocal
from app.db.models import User
from app.security.tool_guard import validate_tool_call


@pytest.mark.parametrize(
    "name,args",
    [
        ("update_schedule", {"course_id": 1, "old_room": "A201", "new_room": "B105"}),
        ("delete_all", {}),
        ("change_role", {"role": "ADMIN"}),
    ],
)
def test_student_denied(client, name, args):
    with SessionLocal() as db:
        assert (
            validate_tool_call(db, db.get(User, 1), name, args)[0]["decision"]
            == "BLOCK"
        )


@pytest.mark.parametrize(
    "name,args",
    [
        ("get_my_schedule", {"user_id": 3}),
        ("read_course_note", {"filename": "../../.env"}),
        ("get_my_courses", {"role": "ADMIN"}),
    ],
)
def test_untrusted_arguments(client, name, args):
    with SessionLocal() as db:
        assert (
            validate_tool_call(db, db.get(User, 1), name, args)[0]["decision"]
            == "BLOCK"
        )


def test_professor_ownership(client):
    with SessionLocal() as db:
        assert (
            validate_tool_call(
                db, db.get(User, 2), "get_course_students", {"course_id": 999}
            )[0]["decision"]
            == "BLOCK"
        )


def test_admin_requires_approval(client):
    with SessionLocal() as db:
        assert (
            validate_tool_call(
                db,
                db.get(User, 3),
                "update_schedule",
                {"course_id": 1, "old_room": "A201", "new_room": "B105"},
            )[0]["decision"]
            == "REQUIRE_APPROVAL"
        )
