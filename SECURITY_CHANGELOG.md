# Security Hardening — Progress Notes (Delivery 1)

This is an interim delivery. It is safe to run and test, but is **not yet complete** —
see "Not done yet" below before treating this as production-ready.

## What changed in this delivery

### 1. Authentication (previously: none at all)
- Real JWT-based auth: `POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`
- Passwords hashed with bcrypt (never stored/logged in plaintext)
- Every API router except `/health` and `/auth` now requires a valid bearer token
  (enforced centrally in `app/api/v1/api.py` — see `_auth_required`)
- Per-IP rate limiting on register/login/upload (Redis-backed, `app/core/rate_limit.py`)
- Per-account login lockout after `MAX_LOGIN_ATTEMPTS` failed attempts
- Login/register responses are deliberately generic (never confirm whether an email exists)

### 2. Multi-tenant data isolation — `app/api/v1/endpoints/emails.py` only so far
- Uploads are now tagged with the uploader's `organization_id` / `user_id`
- All read endpoints on `/emails/*` verify the email belongs to the caller's org
  before returning anything (404, not 403, for both "doesn't exist" and "not yours" —
  see `_get_authorized_email_and_evidence`)
- **Note:** emails uploaded before this change (or via any pre-auth test data) have no
  organization attached. They remain visible to everyone rather than becoming
  inaccessible — flagged here so you can decide whether to backfill or purge that data
  before going live with multiple organizations.

### 3. Upload hardening
- Filenames sanitized (no path traversal / null bytes) before being stored as metadata
- Magic-byte content sniffing rejects disguised executables (PE/ELF/Mach-O/PDF) regardless
  of claimed extension — see `_DANGEROUS_TOP_LEVEL_SIGNATURES` in `emails.py`
- Existing size/extension checks kept as-is

### 4. Platform hardening — `app/main.py`, `app/core/config.py`
- `DEBUG` now defaults to `False` (was `True`)
- Startup check (`Settings.validate_production_safety`) refuses to boot in
  production/staging with a default `SECRET_KEY`, `DEBUG=True`, or default DB/MinIO
  credentials — logs a warning in dev, raises in prod
- CORS is an explicit allow-list (`FRONTEND_URL` + `ALLOWED_ORIGINS` env var), never `*`
- Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security` (prod only)
- Request body size capped at 30MB at the middleware level (defense in depth ahead of
  the existing per-upload 25MB check)
- `/docs`, `/redoc`, `/openapi.json` are only served when `DEBUG=True` and not production
- Error responses are uniform and never leak stack traces/paths, regardless of `DEBUG`

### 5. Database
- New migration `0002_seed_rbac_roles.py` seeds the standard role set
  (SYSTEM_ADMIN, INSTITUTION_ADMIN, SECURITY_ANALYST, CYBER_CELL_INVESTIGATOR, USER)

### New environment variables (see updated `.env.example`)
`ACCESS_TOKEN_EXPIRE_MINUTES`, `JWT_ALGORITHM`, `BCRYPT_ROUNDS`, `ALLOW_SELF_SIGNUP`,
`MAX_LOGIN_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES`, `ALLOWED_ORIGINS`.
**`SECRET_KEY` must be regenerated** — don't reuse the sample value.

## Not done yet (next delivery)
- Org-scoping for: `evidence.py`, `campaigns.py`, `graph.py`, `dna.py`, `similarity.py`,
  `scoring.py`, `reports.py`, `jobs.py`, `intelligence.py`, `geo.py`. These currently
  require login (via the global dependency) but don't yet check that the underlying
  email/evidence belongs to the caller's org the way `emails.py` does.
- Frontend: no login screen yet, no axios auth interceptor, no dedicated error pages
  (404 / 500 / session-expired / offline) yet — the React app still assumes an
  open, unauthenticated backend.
- `alembic upgrade head` has not been run against a live database as part of this
  delivery (no DB available in this environment) — please run it, and run the
  existing test suite, before deploying.
- A written security report summarizing all findings/severities is still pending.

## Delivery 2 — cross-tenant IDOR closed (`campaigns.py`, `dna.py`, `geo.py`,
`graph.py`, `intelligence.py`, `jobs.py`, `reports.py`, `scoring.py`, `similarity.py`)

Everything flagged as "Not done yet" above is now fixed, plus two issues found
while doing it that weren't on the original list.

### What was wrong
All nine routers required *authentication* (via the global `_auth_required`
dependency) but not *authorization* — none of their endpoint functions accepted
`current_user` or checked that the email/campaign/job/report UUID in the path
belonged to the caller's organization. Any authenticated user from any org could
read (and in a few cases write) another org's DNA profiles, campaign data, geo/graph
data, jobs, reports, scoring, and similarity links by UUID.

### The fix
- Added three reusable ownership helpers to `app/api/deps.py`:
  `get_authorized_email`, `get_authorized_campaign`, `get_authorized_report`.
  All three resolve the resource and 404 (never 403) if it doesn't belong to
  `current_user.organization_id` — matching the existing `emails.py`/`evidence.py`
  convention, including on the "not yours" vs "doesn't exist" ambiguity.
- Every endpoint in the nine routers now takes `current_user` and calls the
  matching helper before touching the resource.
- `Campaign` had no `organization_id` at all. Added the column
  (migration `0003_add_campaign_organization_id.py`, with a best-effort backfill:
  a campaign is stamped with its members' org only when every member email
  agrees on one; ambiguous or unresolvable campaigns are left `NULL`, which the
  app treats as inaccessible to all orgs rather than visible to everyone — a
  fail-closed default. **Run `alembic upgrade head` before deploying.**)
- `JobRecord` (`app/core/tasks.py`) had no `organization_id`. Added it, stamped
  from `current_user.organization_id` in the one place jobs are created
  (`emails.py` upload flow), and enforced in `jobs.py` get/list/cancel.

### Two stored cross-tenant leaks beyond simple read-IDOR
Fixing endpoint checks alone wasn't enough for two features that compare a
given email against **all emails platform-wide** and persist the result:
- `campaign_service.correlate_email` / `auto_cluster_campaigns` — auto-clustering
  was walking every email on the platform and could permanently link and name
  campaigns out of other orgs' emails.
- `similarity_service.find_and_link_similar_emails` — computed and persisted
  `EmailSimilarityLink` rows (with another org's subject/sender in the
  `evidence` JSON) against candidates platform-wide.

Both now take an `organization_id` parameter and scope their candidate query
through `email_sources.organization_id` (the same authoritative join `emails.py`
already used — note `emails.organization_id` itself is never populated, so
filtering on it directly is a no-op; don't reuse that column for tenant checks).
`get_email_similarity_links` and `get_email_campaign_memberships` also gained a
defense-in-depth org filter on the joined side, in case any links/memberships
predating this fix are still in the database.

### Left intentionally unscoped
`GET /intelligence/domains/{name}`, `GET /intelligence/ips/{ip}`, and
`GET /intelligence/threat/lookup` query indicators (a domain/IP/hash), not
tenant-owned records — any authenticated user can look up any indicator, the
same as before. They now require `current_user` for consistency but perform no
org check, which is correct for this data.

### Not done in this delivery either
- No automated regression tests were added for the ownership checks — the repo
  has no existing test suite for these routers to extend. Recommend adding
  cross-tenant 404 tests (org A token against org B's email/campaign/job/report
  IDs) before relying on this in production.
- Pre-existing rows created before this fix (emails with no `email_sources`
  link, campaigns that couldn't be unambiguously backfilled, jobs from before
  `organization_id` existed) are left inaccessible rather than retroactively
  attributed — audit and backfill manually if that data still matters.

## To run/verify locally
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # then edit SECRET_KEY and DB/MinIO creds
alembic upgrade head
uvicorn app.main:app --reload
```
Then `POST /api/v1/auth/register` with `{"email":"...","password":"...","organization_name":"...","full_name":"..."}`
to create your first account, and use the returned `access_token` as a `Bearer` token
for everything else.

## Delivery 3 — VAPT remediation (MVP-01 through MVP-08)

Remediates every finding in `MailinteL_MVP_VAPT_Report.md`.

- **MVP-01 (High, default secrets):** removed the committed `backend/.env`
  (kept only `.env.example`); added `.gitignore` so `.env` can't be
  re-committed; `Settings.validate_production_safety()` now catches
  placeholder-style secrets generally (not just one exact literal — the
  previous check let the actual `CHANGE-ME...` value in `backend/.env` slip
  through unnoticed because it happened to be over the 32-char length
  threshold) and hard-fails whenever the app is bound to listen beyond
  localhost with dev-grade settings, not only when `APP_ENV=production`.
- **MVP-02 / MVP-03 (High, IDOR):** `get_authorized_email`,
  `get_authorized_campaign`, and `get_authorized_report`
  (`app/api/deps.py`) now fail **closed** — a record with no resolvable,
  non-null owning organization is 404 to every caller, not just callers from
  a different org. The same fail-open-on-null-org pattern was also present
  and fixed in `jobs.py`'s job lookup/cancel.
- **MVP-04 (High, missing RBAC):** added an explicit role matrix
  (`ANALYST_ROLES`, `ADMIN_ROLES` in `app/api/deps.py`) and applied
  `require_roles(...)` server-side to evidence integrity verification, job
  cancellation, and campaign/report mutation & export — previously any
  active org member regardless of role could reach these.
- **MVP-05 (High, build blocker):** `frontend/src/utils/sanitizeEmailHtml.ts`
  now imports DOMPurify's own `Config` type instead of the old
  `DOMPurify.Config` shape, and the now-conflicting `@types/dompurify`
  devDependency (dompurify >=3.0 ships its own types) was removed from
  `package.json`. `npm run build` verified clean.
- **MVP-06 (Medium, open self-signup):** `ALLOW_SELF_SIGNUP` now defaults to
  `False` in code; `.env.example` documents it as an explicit, deliberate
  opt-in rather than something left on by omission.
- **MVP-07 (Medium, health disclosure):** `app/api/v1/endpoints/health.py`
  now exposes `public_router` (only `GET /health`, returning `{"status":
  "ok"}`) and `protected_router` (`/db`, `/storage`, `/redis`, `/ready`,
  `/detailed` — all the routes that previously leaked hosts, ports, bucket
  names, runtime/platform info, and demo credentials to anonymous callers).
  `api.py` mounts the protected set behind `Depends(get_current_user)`.
  **Note:** this also moves `/health/ready` behind auth, per the report's
  recommendation — if your orchestrator's readiness probe calls that route
  anonymously, point it at `/health` (liveness) or provision it a token.
- **MVP-08 (Medium, unpinned deps):** `backend/requirements.in` now holds the
  loose version bounds (source of truth), and `backend/requirements.txt` is
  the `pip-compile`-generated, fully pinned lock file — regenerate it with
  `pip-compile --output-file=requirements.txt requirements.in` after editing
  `requirements.in`. Locking surfaced a real, otherwise-silent break: the
  latest `bcrypt` (>=4.1) is incompatible with `passlib` 1.7.4 (last released
  2020) and raises `ValueError: password cannot be longer than 72 bytes` the
  first time a password is hashed — `requirements.in` now pins
  `bcrypt>=4.0.1,<4.1.0` to avoid it. Verified end-to-end: fresh venv install
  from the locked `requirements.txt`, app import, and an actual
  hash/verify round-trip all pass.

### Retest checklist (from the VAPT report) — run live against Postgres 16 + pgvector, Redis, and a booted app instance

- [x] **`alembic upgrade head` then `pip install -r backend/requirements.txt` on a
  clean checkout — confirm identical versions on a second run.** Two independent
  clean venvs, same `requirements.txt` — `pip freeze` diffs identical (51
  packages, zero drift). `alembic upgrade head` runs clean end-to-end on an
  empty DB (3 migrations, all 5 RBAC roles seeded) and is a true no-op on a
  second run.
- [x] **Two-org matrix: org A token against org B's (and against orphaned/null-owner)
  email, campaign, job, and report IDs — confirm 404 and no side effects.**
  Registered two real tenants (Org A, Org B) via `/auth/register`, created a
  real campaign (`POST /campaigns`), a real job (`job_manager.create_job`,
  persisted through the same Redis the app reads), and a real report (linked
  via `campaign_id`, since `Report` has no direct `organization_id` — ownership
  resolves transitively through `get_authorized_report`). Org B's admin token
  and a no-org ("orphaned") user both get `404` on every one of Org A's
  resources (`GET /campaigns/{id}`, `GET /jobs/{id}`, `POST
  /jobs/{id}/cancel`, `GET /reports/{id}`) — no data or side effects leak.
  Separately created null-owner (`organization_id=None`) campaign, job, and
  report records: **every** authenticated caller — including Org A's own
  admin — gets `404` on those, confirming the fail-closed-on-null-owner
  behavior from MVP-02/03 holds for campaigns, jobs, *and* reports, not just
  emails. Sanity check: Org A's admin still gets `200` on its own campaign/job,
  so the 404s above are real tenant isolation, not a broken route.
  60/60 automated checks passed.
- [x] **Each role (`USER`, `SECURITY_ANALYST`, `CYBER_CELL_INVESTIGATOR`,
  `INSTITUTION_ADMIN`, `SYSTEM_ADMIN`) against every route gated by
  `require_roles` — positive and negative cases, via direct API calls.**
  Provisioned one real, logged-in user per role inside Org A (register +
  direct DB membership insert, since there's no invite endpoint yet — no
  hand-crafted tokens, every token came from the real `/auth/login`). Hit
  every one of the 9 routes currently behind `require_roles(*ANALYST_ROLES)`
  (`POST /campaigns`, `POST/DELETE /campaigns/{id}/emails/{id}`, `POST
  /campaigns/auto-cluster`, `POST /evidence/{id}/verify`, `POST
  /jobs/{id}/cancel`, `POST /reports/email/{id}`, `GET
  /reports/email/{id}/export`, `POST /reports/campaign/{id}`) with all 5
  roles: `USER` gets `403` on all 9 (confirmed negative case); the four
  analyst-and-up roles never get `403` on any of them (confirmed positive
  case — the role gate runs before resource lookup, so a nonexistent
  resource ID still cleanly isolates "does the gate block this role" from
  "does the resource exist"). **Note:** `ADMIN_ROLES` is defined in
  `app/api/deps.py` but not yet applied to any route — nothing to retest
  there, but worth flagging as a gap if any route is meant to be
  admin-only rather than analyst-and-up.
- [ ] Hostile email HTML through the rebuilt frontend — confirm no script
  execution, no remote fetches, `srcdoc`/`javascript:` neutralized. **Not
  retested live** — needs a browser + the actual frontend build, which is
  out of scope for a backend-only sandbox retest.
- [x] `GET /health` anonymously (expect only `{"status":"ok"}`); `GET
  /health/detailed` anonymously (expect 401).


## Delivery 4 — RBAC v2 cross-organization controls

- `CYBER_CELL_INVESTIGATOR` and `SYSTEM_ADMIN` now use an explicit cross-org role set rather than inheriting organization-only filters. Resource authorization remains fail-closed and returns 404 for absent/unresolvable resources.
- `SYSTEM_ADMIN` may be a pure platform account without an `organization_members` row via `users.is_platform_admin`; migration `0004_platform_admin_flag.py` adds the durable flag.
- Only `SYSTEM_ADMIN` reaches `/platform/*`, including granting `CYBER_CELL_INVESTIGATOR` and `SYSTEM_ADMIN`; institution admins cannot grant cross-org roles through `/users`.
- Cross-org reads and user-management actions enqueue `AuditLog` records, with audit failures isolated from the primary request.
- List routes support all-organization views with optional organization narrowing for cross-org roles while preserving USER personal scope and analyst organization scope.
