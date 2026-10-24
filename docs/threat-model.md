# Threat model: AI Security Gateway

## Scope and layers
**Application:** fictional ESIGELEC accounts, class enrollment, professors, courses, schedules.
**AI:** Gemini or offline selector; exactly one assistant proposes tools and formats results.
**Security (main contribution):** identity, RBAC, guards, scoring, approval, audit, and advisory explanation.

The system runs locally in two Docker containers. SQLite, logs and demo notes use bind mounts. No external actions, arbitrary tools, shell execution, document upload, or role administration are exposed.

## Assets
User accounts and password hashes; authoritative database roles; student/professor data; course schedules; authenticated user context; LLM context and instructions; tool permissions; Gemini/JWT configuration; approval arguments and decisions; audit events.

## Threat actors
Malicious student; malicious professor; compromised authenticated user; malicious external file/database content; accidental misuse. Host/database administrators and dependencies are trusted by this prototype; direct host compromise is outside its containment capability.

## Trust boundaries
1. User → Authentication: signed expiring JWT identifies a database user; database role is reloaded.
2. Authentication → Input Guard: request text carries no authority to change identity.
3. Input Guard → Gemini: normalized rules catch demonstration attacks; prompts remain untrusted even when allowed.
4. Gemini → Agent: model output is a proposal, never executable code or privilege evidence.
5. Agent → Tool Guard: registry allowlist, RBAC, strict argument schema and ownership checks authorize a proposal.
6. Tool Guard → Database: validated fixed Python operations query scoped data; writes require review and revalidation.
7. External Content → Context Guard → Gemini: note and database contents are inspected, then labeled untrusted. Suspicious sources block.
8. Gemini → Output Guard → User: secret-like output is redacted and confidential markers blocked.
9. Human → Approval → Database: admin-only review atomically claims the pending item, rechecks original user and state, then executes once.

## Threat/control mapping
| Threat | Example | Control | Residual risk |
|---|---|---|---|
| Prompt Injection | Ignore all previous rules | Contextual input rules + backend authorization | Wording/encoding can evade detection |
| Indirect Prompt Injection | Poisoned course note tells model to override rules | Two-file allowlist, Context Guard on all results, untrusted-data instructions | Rules cannot identify all malicious semantics |
| Jailbreak | Disable restrictions | Input rules + no model-owned privileges | Novel jailbreaks may pass rules |
| Information Leakage | Request private professor data or secrets | No private-data tool, scoped queries, minimized fields, output redaction | Generated or unknown secrets cannot be reliably recognized |
| Tool Abuse | Student proposes update_schedule | Registry and centralized RBAC | New tools must adopt same execution path |
| Unauthorized Actions | Professor targets someone else's course | Resource ownership checks | Class-level enrollment is simplified |
| Privilege Abuse | Prompt or JWT claims ADMIN | Database role is authoritative each request | Stolen valid admin token remains powerful until expiry |
| Sensitive erroneous action | Admin changes a room | Human approval, known rooms, conflict checks, old-room precondition | Self-review allowed; course-wide effects need reviewer attention |
| Replay/concurrent approval | Approve twice | Conditional PENDING → REVIEWING claim inside write transaction | No queue expiration |
| File traversal | ../../.env as a note | Strict filename enum/pattern; no arbitrary reader | Host tampering outside threat boundary |
| Audit leakage | Put a secret in chat | Redacted previews, metadata-only JSONL, no stored token/password | Unknown freeform secrets may not match filters |
| Model/provider failure | API outage | Timeout, explicit error, no automatic fallback action | No live provider guarantee without key |

## Security controls
JWT authentication; Argon2 password hashing; deterministic deny-by-default RBAC; input validation; external context inspection; output filtering; tool allowlist; strict arguments; resource scope; deterministic risk scoring; human approval; SQLite and JSONL logging; advisory AI incident explanation. SQLAlchemy expressions avoid raw user-built SQL.

## Risk policy
LOW 0–29, MEDIUM 30–59, HIGH 60–84, CRITICAL 85–100. Policy scores communicate educational severity, not likelihood. A 65-point authorized write requires approval; unauthorized tool use scores 95 and blocks. The analyzer has no route to modify policy or execute a tool.

## Verification
pytest checks valid/invalid/expired JWTs, all three role logins, database role integrity, malicious prompts, poisoned notes, output redaction, tool denial, typed arguments, traversal, professor ownership, admin approval, rejection, replay, role changes before review, event logging and admin-only analysis. Docker and browser validation are recorded separately in validation.md. Mock tests never establish that Gemini credentials or the network work.

## Accepted academic limitations
Fictional public accounts; local HTTP; Vite dev server; simple rules; no login throttling, approval expiry, separate reviewer, migrations, tenant isolation, or tamper-proof audit. Student enrollment follows class_name. Updating a course room affects all its sessions. Prompt detection and output redaction are incomplete. LLM classifiers are not reliable security boundaries. Always validate tools in backend code and never put real secrets in prompts. This prototype is not production-ready.
