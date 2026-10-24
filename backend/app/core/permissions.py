PERMISSIONS = {
    "STUDENT": {"get_my_schedule", "get_my_courses", "read_course_note"},
    "PROFESSOR": {"get_my_schedule", "get_course_students", "read_course_note"},
    "ADMIN": {
        "search_student",
        "search_professor",
        "get_room_schedule",
        "find_free_room",
        "update_schedule",
    },
}


def permitted(role: str, tool_name: str) -> bool:
    return tool_name in PERMISSIONS.get(role, set())
