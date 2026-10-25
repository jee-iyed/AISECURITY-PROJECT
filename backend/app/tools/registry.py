from app.schemas.tools import (
    CourseArgs,
    Empty,
    FreeArgs,
    NoteArgs,
    RoomArgs,
    ScheduleArgs,
    SearchArgs,
    UpdateArgs,
)
from app.tools.admin_tools import (
    find_free_room,
    get_room_schedule,
    search_professor,
    search_student,
    update_schedule,
)
from app.tools.professor_tools import get_course_students
from app.tools.student_tools import get_my_courses, get_my_schedule, read_course_note

SCHEMAS = {
    "get_my_schedule": ScheduleArgs,
    "get_my_courses": Empty,
    "get_course_students": CourseArgs,
    "read_course_note": NoteArgs,
    "search_student": SearchArgs,
    "search_professor": SearchArgs,
    "get_room_schedule": RoomArgs,
    "find_free_room": FreeArgs,
    "update_schedule": UpdateArgs,
}
TOOLS = {
    "get_my_schedule": get_my_schedule,
    "get_my_courses": get_my_courses,
    "get_course_students": get_course_students,
    "read_course_note": read_course_note,
    "search_student": search_student,
    "search_professor": search_professor,
    "get_room_schedule": get_room_schedule,
    "find_free_room": find_free_room,
    "update_schedule": update_schedule,
}


DESCRIPTIONS = {
    "get_my_schedule": "Read the authenticated student's or professor's schedule for a date.",
    "get_my_courses": "Read the authenticated student's courses.",
    "get_course_students": "Read students enrolled in a course owned by the professor.",
    "read_course_note": "Read a permitted course note.",
    "search_student": "Search students by name (administrator only).",
    "search_professor": "Search professors by name (administrator only).",
    "get_room_schedule": "Inspect a room's occupancy and courses. Supply day (YYYY-MM-DD) for availability on a date; omit day to discover course IDs before a room change. An empty result means no scheduled occupancy for that query.",
    "find_free_room": "Find rooms available on a date during a specific start/end time interval.",
    "update_schedule": "Propose moving all sessions of a course from old_room to new_room. Requires course_id from room schedule data. Backend validates conflicts and requires human approval before execution. Never invent a course ID; look up the source room first. If multiple courses match, ask which course to move.",
}


def declarations_for(role):
    from app.core.permissions import permitted

    return [
        {
            "name": name,
            "description": DESCRIPTIONS[name],
            "parametersJsonSchema": schema.model_json_schema(),
        }
        for name, schema in SCHEMAS.items()
        if permitted(role, name)
    ]


def inventory():
    """Security inventory of every tool the model can propose."""
    from app.core.permissions import PERMISSIONS
    from app.tools.policies import TOOL_POLICIES

    return [
        {
            "name": name,
            "description": DESCRIPTIONS[name],
            "arguments_schema": schema.model_json_schema(),
            "roles": sorted(r for r, tools in PERMISSIONS.items() if name in tools),
            "operation": TOOL_POLICIES[name].operation,
            "sensitivity": TOOL_POLICIES[name].sensitivity,
            "resources": TOOL_POLICIES[name].resources,
            "resource_rule": TOOL_POLICIES[name].resource_rule,
            "requires_approval": TOOL_POLICIES[name].requires_approval,
        }
        for name, schema in SCHEMAS.items()
    ]
