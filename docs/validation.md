# Validation record — 16 October 2026

## Completed checks
- Backend suite: **52 passed** on Windows Python 3.11. One upstream Starlette warning deprecates its httpx TestClient adapter; no test failed.
- Python lint: Ruff checks passed. Python source formatted consistently.
- Frontend: Vite production build passed, including role-specific suggestions.
- Docker Compose configuration: valid.
- Live HTTP service: all ten required demo scenarios passed using fictional Student, Professor and Admin accounts.
- Browser: student login; timetable response; injection blocked at score 88 / CRITICAL; admin login; sensitive write pending at 65 / HIGH; approval queue; approved execution; security dashboard; advisory incident explanation.
- Backend health: 200, status ok. FastAPI docs: 200.
- Host persistence: event IDs and JSONL log bytes unchanged across backend process restart.
- Real course room restored to A201 through a second approved change after the browser demonstration; the live scenario suite's proposed change was rejected to preserve the initial room.
- Git initialized on codex/ai-security-gateway. Environment, generated JWT secret, database, logs, dependencies and scratch work confirmed ignored.
- Gemini request contract tested with mocked HTTP; model-proposed unauthorized tools and secret-bearing text remain subject to guards. Provider failure has no silent action fallback.

## Docker environment recovery
The initially installed Docker Desktop failed before starting its Linux engine. The local log reported an inaccessible AF_UNIX/ReparsePoint endpoint at Docker/run/dockerInference, Windows error 1920. This matches [Docker Desktop issue 531](https://github.com/docker/desktop-feedback/issues/531).

After a normal `docker desktop stop`, the two runtime directories were preserved under these names:
- C:/Users/LENOVO/AppData/Local/Docker/run.stale-20261016-191604
- C:/Users/LENOVO/AppData/Local/docker-secrets-engine.stale-20261016-191604

No images, containers, volumes, WSL distributions, VHDX files or settings were deleted or reset. The next startup succeeded and Engine 29.6.2 responded. These are existing Docker runtime artifacts; all project source, data, caches and test results are on D:.

## Container checks
- Both Dockerfiles built successfully.
- `docker compose up --build -d` created and started the backend and frontend.
- Backend health check passed; published ports are localhost:8000 and localhost:5173.
- All ten live HTTP demonstration scenarios passed against the container API.
- Browser loaded the Docker-served frontend and retained the authenticated database-backed identity across the host-to-container transition.
- SQLite event IDs and JSONL byte counts remained unchanged after `docker compose restart backend`.
- An unmounted backend image was inspected: no .env file, database or generated JWT secret was embedded.
- Gemini default updated to gemini-3.8-flash following Google's current new-project model guidance. Live provider access remains untested without a key.
- Python 3.12 Linux container suite: **52 passed, 1 upstream deprecation warning**, in 462.07 seconds.
- The backend image was recreated after updating the model configuration; all prior event IDs remained present and audit logs continued appending.
- Final services: backend healthy on localhost:8000; frontend running on localhost:5173. Both are left running via Docker Compose.
- Demo course remains in A201 and the approval queue has no pending write requests.

## Final checklist
- [x] Project source, data, logs, tests, dependency caches and documentation under D:/AI Security Gateway.
- [x] Backend and frontend Dockerfiles, Compose build, and `docker compose up --build` validated.
- [x] Frontend, backend health, API docs and frontend/API communication verified.
- [x] SQLite and log persistence through restart and backend recreation verified.
- [x] All three role logins, JWT validation and database-backed role integrity tested.
- [x] One assistant, nine scoped tools and offline mode implemented and tested.
- [x] Input, Context, Output and Tool Guards, RBAC and Risk Engine tested.
- [x] Injection, indirect injection, jailbreak, leakage, tool abuse and unauthorized-action scenarios verified.
- [x] Student administrative tool denial and sensitive admin approval execution verified.
- [x] Approval rejection, replay prevention and revalidation tested.
- [x] Security audit events, dashboard, filters, approval UI and incident explanations verified.
- [x] Backend pytest passed on Windows and inside Docker; frontend production bundle passed.
- [x] README, threat model, limitations, fictional demo data and secret exclusions documented.
- [x] Gemini REST integration and failure/authorization contracts tested with mocked HTTP.
- [ ] Live Gemini API request: requires a valid user-supplied key; no actual provider call is claimed.

## Live Gemini limitation
No real Gemini API key was supplied. Offline mode and provider transport/guard contracts are verified, but actual Gemini availability, credentials and model behavior cannot be claimed as validated. Set a valid key in ignored backend/.env and recreate backend to test the live provider.
