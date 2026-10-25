from pydantic import ValidationError
from sqlalchemy import select

from app.core.permissions import permitted
from app.db.models import Course, Schedule
from app.security.risk_engine import evaluate
from app.tools.admin_tools import ROOMS
from app.tools.policies import TOOL_POLICIES
from app.tools.registry import SCHEMAS
from app.tools.student_tools import scoped_courses


def _deny(reason, threat="TOOL_ABUSE", sensitivity=None, rule="DENY_UNAUTHORIZED_ACTION"):
    return evaluate(
        authorization_denied=True,
        threat=threat,
        reason=reason,
        tool_sensitivity=sensitivity,
        deny_rule=rule,
    ), None


def _invalid(reason, sensitivity=None):
    return evaluate(
        invalid_arguments=True,
        threat="INVALID_ARGUMENTS",
        reason=reason,
        tool_sensitivity=sensitivity,
    ), None


def validate_tool_call(
    db, user, name, arguments, approved=False, tainted_context=False
):
    """Deterministic gate between a model proposal and execution.

    Order: allowlist + RBAC -> strict schema -> trust boundary -> resource
    authorization -> business constraints -> approval requirement. Identity
    always comes from ``user`` (backend authentication), never from arguments.
    """
    policy = TOOL_POLICIES.get(name)
    if name not in SCHEMAS or policy is None or not permitted(user.role, name):
        return _deny("Authenticated role cannot invoke this tool.")
    level = policy.sensitivity
    try:
        args = SCHEMAS[name].model_validate(arguments).model_dump(mode="json")
    except (ValidationError, TypeError):
        return _invalid("Tool arguments failed strict validation.", level)
    if tainted_context and policy.operation == "WRITE":
        return _deny(
            "Untrusted content with instruction-like text entered this turn; "
            "write tools are disabled until a new user request.",
            threat="INDIRECT_PROMPT_INJECTION",
            sensitivity=level,
            rule="DENY_TAINTED_CONTEXT_ACTION",
        )
    if name == "get_room_schedule" and args["room"] not in ROOMS:
        return _invalid("Unknown room.", level)
    if name == "find_free_room":
        args["start_time"] = args["start_time"][:5]
        args["end_time"] = args["end_time"][:5]
    if name == "get_course_students" and args["course_id"] not in {
        c.id for c in scoped_courses(db, user)
    }:
        return _deny(
            "Course outside professor ownership.",
            threat="UNAUTHORIZED_ACTION",
            sensitivity=level,
        )
    if name == "update_schedule":
        c = db.get(Course, args["course_id"])
        if (
            not c
            or c.room != args["old_room"]
            or args["new_room"] not in ROOMS
            or args["new_room"] == args["old_room"]
        ):
            return _invalid("Unknown room/course or stale/no-op change.", level)
        sessions = list(db.scalars(select(Schedule).where(Schedule.course_id == c.id)))
        if not sessions:
            return _invalid("Course has no scheduled sessions.", level)
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
                return _invalid("Target room has a timetable conflict.", level)
    if policy.requires_approval and not approved:
        return evaluate(
            requires_approval=True,
            threat="SENSITIVE_ACTION",
            reason="Room change affects all sessions and requires human approval.",
            tool_sensitivity=level,
        ), args
    return evaluate(
        tool_sensitivity=level,
        reason="Tool call passed RBAC, schema and resource authorization.",
    ), args
