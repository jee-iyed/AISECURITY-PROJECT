# Tool Inventory

Generated from `app.tools.registry.inventory()`; the live version is served to administrators at `GET /api/security/tools`.
Every schema sets `additionalProperties: false`; integers are strict (no bool/float/string coercion).

| Tool | Roles | Op | Sensitivity | Approval | Resources | Resource rule | Arguments |
|---|---|---|---|---|---|---|---|
| `get_my_schedule` | PROFESSOR, STUDENT | READ | LOW | no | schedules | own class (student) or own courses (professor) | `day` |
| `get_my_courses` | STUDENT | READ | LOW | no | courses | own class (student) or own courses (professor) | none |
| `get_course_students` | PROFESSOR | READ | MEDIUM | no | students (names, class) | course must be owned by the authenticated professor | `course_id` |
| `read_course_note` | PROFESSOR, STUDENT | READ | LOW | no | demo-data documents (untrusted content) | explicit two-file allowlist; content passes the Context Guard | `filename` |
| `search_student` | ADMIN | READ | MEDIUM | no | user directory (name, email) | administrators only | `query`* |
| `search_professor` | ADMIN | READ | MEDIUM | no | user directory (name, email) | administrators only | `query`* |
| `get_room_schedule` | ADMIN | READ | LOW | no | room occupancy | known rooms only | `day`, `room`* |
| `find_free_room` | ADMIN | READ | LOW | no | room occupancy | known rooms only | `day`*, `start_time`*, `end_time`* |
| `update_schedule` | ADMIN | WRITE | HIGH | yes | course room for every session | existing course, current room must match, no timetable conflict | `course_id`*, `old_room`*, `new_room`* |

`*` = required. Descriptions sent to Gemini are in `DESCRIPTIONS` (registry.py).

## Execution order (Tool Guard)

1. Allowlist + RBAC (`PERMISSIONS`) → `DENY_UNAUTHORIZED_ACTION`
2. Strict Pydantic schema → `DENY_INVALID_ARGUMENTS`
3. Trust boundary: WRITE tools refused after tainted untrusted content → `DENY_TAINTED_CONTEXT_ACTION`
4. Resource authorization (ownership, known rooms)
5. Business constraints (stale room, conflicts, no-op)
6. Approval requirement → `REQUIRE_HUMAN_APPROVAL`

On approval: atomic `PENDING→REVIEWING` claim (conditional UPDATE, SQLite write lock held until commit), expiry check, argument-hash integrity check, full revalidation as the original requester, exact match between approved and revalidated arguments, then execution and audit in the same transaction.
