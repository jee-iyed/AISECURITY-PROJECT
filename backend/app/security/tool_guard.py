from pydantic import ValidationError
from sqlalchemy import select

from app.core.permissions import permitted
from app.db.models import Course, Schedule
from app.security.risk_engine import assessment
from app.tools.admin_tools import ROOMS
from app.tools.registry import SCHEMAS
from app.tools.student_tools import scoped_courses


def validate_tool_call(db, user, name, arguments, approved=False):
    if name not in SCHEMAS or not permitted(user.role, name):
        return assessment(
            "TOOL_ABUSE", 95, "Authenticated role cannot invoke this tool."
        ), None
    try:
        args = SCHEMAS[name].model_validate(arguments).model_dump(mode="json")
    except (ValidationError, TypeError):
        return assessment(
            "INVALID_ARGUMENTS", 85, "Tool arguments failed strict validation."
        ), None
    if name == "get_room_schedule" and args["room"] not in ROOMS:
        return assessment("INVALID_ARGUMENTS", 85, "Unknown room."), None
    if name == "find_free_room":
        args["start_time"] = args["start_time"][:5]
        args["end_time"] = args["end_time"][:5]
    if name == "get_course_students" and args["course_id"] not in {
        c.id for c in scoped_courses(db, user)
    }:
        return assessment(
            "UNAUTHORIZED_ACTION", 95, "Course outside professor ownership."
        ), None
    if name == "update_schedule":
        c = db.get(Course, args["course_id"])
        if (
            not c
            or c.room != args["old_room"]
            or args["new_room"] not in ROOMS
            or args["new_room"] == args["old_room"]
        ):
            return assessment(
                "INVALID_ARGUMENTS", 85, "Unknown room/course or stale/no-op change."
            ), None
        sessions = list(db.scalars(select(Schedule).where(Schedule.course_id == c.id)))
        if not sessions:
            return assessment(
                "INVALID_ARGUMENTS", 85, "Course has no scheduled sessions."
            ), None
        for s in sessions:
            conflict = db.scalar(
                select(Schedule.id)
                .join(Course)
                .where(
                    Course.room == args["new_room"],
                    Course.id != c.id,
                    Schedule.day == s.day,
                    Schedule.start_time < s.end_time,
                    Schedule.end_time > s.start_time,
                )
            )
            if conflict:
                return assessment(
                    "INVALID_ARGUMENTS", 85, "Target room has a timetable conflict."
                ), None
        if not approved:
            return assessment(
                "SENSITIVE_ACTION",
                65,
                "Room change affects all sessions and requires human approval.",
                "REQUIRE_APPROVAL",
            ), args
    return assessment(), args
