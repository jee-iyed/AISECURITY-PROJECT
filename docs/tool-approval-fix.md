# Tool selection and human approval fix

## Diagnosis

`update_schedule` was already registered and included in the initial Gemini request. It was not missing from backend permissions. The agent stopped after one tool call, then called Gemini for a text-only summary without function declarations or a proper function-response conversation. Consequently a room lookup could not lead to a subsequent write proposal. Room results also lacked the course_id required by UpdateArgs, and tool descriptions were only function names with underscores replaced by spaces. The backend supplied no current date for relative-date requests.

## Changes

- `backend/app/tools/registry.py`: descriptive declarations generated from the existing Pydantic schemas, filtered by the authenticated user's existing role permissions.
- `backend/app/llm/agent.py`: accepts tool conversation history; retains original Gemini model content and thought signatures; handles mixed text/function calls; rejects multiple simultaneous calls without executing them.
- `backend/app/llm/gemini_client.py`: supplies today's backend date alongside the authenticated role.
- `backend/app/llm/system_prompt.py`: instructs data lookups, course discovery, ambiguity clarification, and backend-controlled approval.
- `backend/app/tools/admin_tools.py`: includes course_id in existing room schedule results.
- `backend/app/services/chat_service.py`: bounded six-turn tool conversation using functionResponse results. Every proposal passes Tool Guard. Authorized reads are audited and context-checked before reuse. Approval stops the loop immediately without executing the write.
- `backend/app/security/input_guard.py`: classifies clear unauthorized schedule modification requests as BLOCK when Gemini returns only a text refusal, so refusal is not misleadingly recorded as ALLOW.
- `backend/app/security/tool_guard.py`: also checks that the course has scheduled sessions; classifies valid unapproved writes as SENSITIVE_ACTION / REQUIRE_APPROVAL.
- `backend/app/services/approval_service.py`: additionally requires ADMIN at the service boundary and records successful approval execution as EXECUTED.
- `backend/tests/test_gemini.py`: declaration permissions/schema parity, mixed content, preserved signatures, database-backed availability, lookup followed by approval, and text-refusal authorization regressions.
- `backend/tests/test_security_scenarios.py`: exact student modification and injection requests cannot create approvals or change data.

No authentication, JWT, permission sets, database schema, or frontend redesign changes.

## Security and storage

ADMIN receives search_student, search_professor, get_room_schedule, find_free_room, and update_schedule. STUDENT and PROFESSOR retain precisely their existing tools. Roles come from the database-backed authenticated user; model or prompt claims do not authorize execution.

Each Gemini function call becomes a proposal, passes validate_tool_call, and only ALLOW can invoke TOOLS. update_schedule validates role, schema, course/current room, target room, sessions, and conflicts. Without explicit review it returns REQUIRE_APPROVAL.

A pending Approval stores requester ID, tool name, validated JSON arguments, PENDING status, and timestamp using the existing schema. The requester role is available through its User relationship; the existing approval API supplies the fixed room-change reason and risk 65. The associated SecurityEvent stores the actual reason, risk, category, role and decision. No schema migration is needed.

The admin approval endpoint atomically claims PENDING as REVIEWING, reloads the requester, revalidates the stored action against current permissions and room conflicts, executes the stored tool/arguments, and commits the room change, APPROVED status and audit event together. A repeated claim returns HTTP 409. Rejection changes status to REJECTED and records an audit event without invoking the tool.

## Live findings

Real Gemini, via API and UI, answered the B105 availability question with get_room_schedule / ALLOW and real database results for 2026-10-19.

A201 contains two courses (Cybersecurity and Reseaux). The exact ambiguous prompt "Change la salle A201 vers B105" now discovers these courses and asks which one to move. It does not invent a course ID. For a direct approval request use "Change la salle du cours Cybersecurity de A201 vers B105."

That course-specific request produced update_schedule / REQUIRE_APPROVAL in the UI and pending approval #6. SQLite still showed A201 before review. Clicking Approve changed status to APPROVED and SQLite to B105, with EXECUTED in the security event. Repeating approval #6 returned HTTP 409. The live test leaves Cybersecurity in B105. A reverse request created approval #7; clicking Reject marked it REJECTED and left SQLite at B105.

Screenshot: ../work/tool-approval-verified.png

## Validation

Final isolated backend suite: 58 passed in 13.89 seconds. One existing FastAPI/Starlette httpx deprecation warning. Ruff: all checks passed. This includes the student text-refusal regression, exact student write/injection scenarios, role isolation, approval/rejection, stale approvals, and duplicate approval execution.

`docker compose up -d --build` completed successfully on the final source. Backend healthy; frontend started. Final HTTP checks: /health 200, /docs 200, localhost:5173 200. Final real-Gemini student request "Change la salle A201 vers B105" returned BLOCK / TOOL_ABUSE with no approval created. Real-Gemini student normal schedule used get_my_schedule / ALLOW; the exact injection request returned BLOCK / PROMPT_INJECTION.


Final exact ADMIN prompt verification after Cybersecurity moved: with only Reseaux remaining in A201, "Change la salle A201 vers B105" produced update_schedule / REQUIRE_APPROVAL, executed=false, approval #8. This test-only proposal was rejected, so Reseaux remains in A201 and Cybersecurity remains in B105. The initially ambiguous case still correctly requires clarification.


## Follow-up review

Gemini response parsing now rejects malformed content, non-object function calls, invalid names/arguments, empty text, and multiple simultaneous calls with a controlled LLMUnavailable response before any tool execution. This prevents provider-shape errors from surfacing as unhandled HTTP 500 responses.

Additional tests cover twelve malformed response shapes, the six-turn bound, an invalid write call with no approval/data mutation, two concurrent approvals (one success, one 409, exactly one tool execution), and attempts to approve rejected actions.

Expanded full backend suite: **74 passed in 12.11 seconds**, with the same existing Starlette/httpx deprecation warning. Ruff passed.


Follow-up deployment completed successfully with docker compose up -d --build. All three HTTP endpoints returned 200; the running backend parser was directly verified to reject malformed calls with LLMUnavailable. The final real-Gemini read-only smoke request was blocked by the provider's daily free-tier quota (GenerateRequestsPerDayPerProjectPerModel-FreeTier, 20 requests for the configured model). The backend safely returned ERROR / LLM_UNAVAILABLE with tool=null and no approval. No additional provider requests were made after identifying quota exhaustion. Earlier successful live validations remain documented above.
