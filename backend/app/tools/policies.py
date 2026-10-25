"""Security metadata for every tool exposed to the model (tool inventory).

Roles come from ``app.core.permissions``; this module adds what RBAC alone
cannot express: operation type, sensitivity, the resources reached and
whether a human must approve. ``tests/test_tool_inventory.py`` fails if a tool
is registered without a policy.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolPolicy:
    operation: str  # READ | WRITE
    sensitivity: str  # LOW | MEDIUM | HIGH | CRITICAL (risk engine impact level)
    resources: str
    resource_rule: str
    requires_approval: bool = False


TOOL_POLICIES = {
    "get_my_schedule": ToolPolicy(
        "READ", "LOW", "schedules", "own class (student) or own courses (professor)"
    ),
    "get_my_courses": ToolPolicy(
        "READ", "LOW", "courses", "own class (student) or own courses (professor)"
    ),
    "get_course_students": ToolPolicy(
        "READ",
        "MEDIUM",
        "students (names, class)",
        "course must be owned by the authenticated professor",
    ),
    "read_course_note": ToolPolicy(
        "READ",
        "LOW",
        "demo-data documents (untrusted content)",
        "explicit two-file allowlist; content passes the Context Guard",
    ),
    "search_student": ToolPolicy(
        "READ", "MEDIUM", "user directory (name, email)", "administrators only"
    ),
    "search_professor": ToolPolicy(
        "READ", "MEDIUM", "user directory (name, email)", "administrators only"
    ),
    "get_room_schedule": ToolPolicy(
        "READ", "LOW", "room occupancy", "known rooms only"
    ),
    "find_free_room": ToolPolicy("READ", "LOW", "room occupancy", "known rooms only"),
    "update_schedule": ToolPolicy(
        "WRITE",
        "HIGH",
        "course room for every session",
        "existing course, current room must match, no timetable conflict",
        requires_approval=True,
    ),
}
