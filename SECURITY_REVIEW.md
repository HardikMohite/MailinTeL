# MailinteL — Security Review

**Scope & method:** static source-code review of the uploaded codebase
(`frontend/` + `backend/`) performed in an isolated, network-disabled
sandbox. This was **not** a dynamic penetration test / VAPT — there is no
running instance to attack, no network egress from this environment, and no
authorization to test infrastructure that isn't mine to test. What follows
is a manual code audit: real findings, grounded in the actual source, not a
generic checklist. Treat this as the "SAST" half of a normal security
process; a real VAPT (dynamic scanning + manual exploitation against a
staging deployment, ideally by a third party) is still worth doing before
this goes anywhere production-adjacent, and this report tells you what to
point it at first.

Two issues below were fixed directly in this pass because they were
unambiguous, well-scoped, and low-risk to change. Everything else is
reported with enough detail to fix, not fixed silently.

---

## Fixed in this pass

### 1. [CRITICAL] Cross-tenant IDOR in `backend/app/api/v1/endpoints/evidence.py`

All four evidence endpoints — `GET /evidence/{id}`, `GET
/evidence/{id}/download`, `POST /evidence/{id}/verify`, `GET
/evidence/{id}/custody` — looked up `EvidenceObject` by ID only:

```python
stmt = select(EvidenceObject).where(EvidenceObject.id == evidence_id)
```

with no check that the evidence belonged to the caller's organization. Every
route in this file only required *a* valid token (via the router-level
`get_current_user` dependency), not that the token's organization matched
the resource's organization. Concretely, **any authenticated user from any
organization who knew or obtained an evidence UUID could**:

- read full evidence metadata,
- generate a presigned download URL for the raw stored file (full
  cross-tenant file exfiltration),
- trigger integrity verification (reveals hash details),
- read the complete chain-of-custody log.

This is exactly the class of bug the `emails.py` endpoints already guard
against — that file has a documented `_get_authorized_email_and_evidence`
helper doing `Email -> EmailSource.organization_id` comparison and returning
a generic 404 (never 403) on mismatch, specifically so a 404 can't be used
to enumerate which IDs exist in other tenants. `evidence.py` just never got
the same treatment.

**Fix applied:** added an equivalent `_get_authorized_evidence()` helper
(same join pattern: `EvidenceObject -> Email -> EmailSource.organization_id`,
same "404 either way" behavior) and routed all four endpoints through it,
each now taking `current_user: CurrentUser = Depends(get_current_user)`.

### 2. [HIGH] Stored XSS via unsanitized email HTML rendering (frontend)

`AnalysisWorkspace.tsx` rendered the *analyzed email's own HTML body*
straight into the DOM:

```tsx
<div dangerouslySetInnerHTML={{ __html: structureData.html_body.substring(0, 1000) }} />
```

— labeled "Sanitized HTML Body", but nothing was actually sanitized, only
truncated to 1000 characters. Since this tool's entire purpose is opening
and analyzing phishing/BEC emails, `html_body` is by definition
attacker-controlled, frequently hostile content. An analyst opening a
malicious sample would execute the sender's JavaScript in the app's own
origin — which, combined with the bearer token living in `localStorage`
(see `services/authStorage.ts`), is a direct path to session-token theft.
Even ignoring script execution, live `<img>`/`background` loads from a
phishing email are a classic "the target opened this" tracking-pixel
beacon straight back to the attacker.

**Fix applied:** added `frontend/src/utils/sanitizeEmailHtml.ts` (DOMPurify)
and wired it into the render path. Policy: strips `script`, `style`,
`iframe`, `object`, `embed`, `form`, `link`, `meta`, `base`; strips all
event handlers (DOMPurify default); and strips `src`/`srcset`/`background`/
`poster` unless they're `data:`/`cid:` (i.e. no live network fetches from
inside a rendered email body). `dompurify` + `@types/dompurify` were added
to `frontend/package.json` — **run `npm install` before building**, and
regenerate `package-lock.json` (it couldn't be refreshed in this sandbox,
no network access here).

---

## Flagged, not fixed — same bug class, needs the same treatment

A quick grep for `organization_id` across every router shows the ownership
check that fixed `evidence.py` above simply doesn't exist yet in most of
the API surface:

| File | `organization_id` references |
|---|---|
| `emails.py` | 7 (has the pattern) |
| `evidence.py` | 4 (fixed above) |
| `campaigns.py` | **0** |
| `dna.py` | **0** |
| `geo.py` | **0** |
| `graph.py` | **0** |
| `intelligence.py` | **0** |
| `jobs.py` | **0** |
| `reports.py` | **0** |
| `scoring.py` | **0** |
| `similarity.py` | **0** |

This strongly suggests the same cross-tenant IDOR pattern exists across
campaign data, DNA/behavioral profiles, geo-infrastructure maps,
investigation graphs, threat-intel summaries, background jobs, and
generated forensic reports — i.e. most of the product. I did not fix these:
doing nine more of these correctly requires checking each one's actual
ownership chain (some join through `email_id`, campaigns likely have their
own `organization_id` or join through member emails, jobs may key off the
user who created them, etc.) and there's no running test suite here to
verify each fix. **This is the single highest-priority follow-up** — I'd
suggest tackling `reports.py` and `campaigns.py` first (they expose the
most sensitive derived data), applying the exact `_get_authorized_evidence`
pattern above as the template, then working through the rest.

## Other observations

- **No login screen exists yet.** The backend enforces bearer auth on every
  route except `/health`, `/auth/register`, `/auth/login` — real JWTs,
  no demo bypass (`DEMO_USER_ID` in config is only used for the
  `/health/detailed` display, not auth). The frontend has no
  `AuthContext`/login form calling `/auth/login` at all yet. Practically:
  today, every other view will 401 against a real deployment of this
  backend. The `UnauthorizedScreen`/`AuthContext` scaffold built in this
  session is the integration point for when that lands — it's not a
  substitute for it.
- **Unpinned dependency floor versions.** `backend/requirements.txt` uses
  `>=` everywhere (e.g. `fastapi>=0.115.0`) rather than exact pins or a
  lockfile. That means two installs on two different days can resolve to
  different actual versions — not exploitable by itself, but it undermines
  reproducible builds and makes "what version is actually running"
  unanswerable without checking the running environment. Worth moving to
  `pip-compile`/exact pins for anything deployed.
- **What looked solid, for the record (so it doesn't get re-litigated):**
  CORS is an explicit allow-list (never `*`, correctly reasoned about given
  `allow_credentials=True`); standard security headers + HSTS in production
  are set globally; error handlers deliberately return the same generic
  shape regardless of `DEBUG`, so a misconfigured deploy can't leak stack
  traces; `/docs`/`/redoc`/`/openapi.json` are disabled outside dev; upload
  filenames are sanitized and path-traversal characters are rejected before
  ever touching a storage key; passwords go through a strength check and
  bcrypt; login/register are rate-limited; failed-login and
  no-such-account responses are deliberately indistinguishable
  (`_INVALID_CREDENTIALS_DETAIL`); the `Settings.validate_production_safety()`
  fail-fast check refuses to boot in production with a default `SECRET_KEY`
  or default DB/MinIO credentials; and the one outbound-fetch-with-user-input
  path I checked closely (RDAP IP lookups in `infrastructure_intel.py`)
  validates the IP isn't private/loopback/link-local before ever making the
  request, with a fixed target host (no SSRF via a spoofed hostname). I
  didn't exhaustively re-audit every intelligence adapter
  (`virustotal.py`/`abuseipdb.py`/`urlhaus.py`/`domain_intel.py`) for the
  same pattern — they're worth a pass, but on a skim they follow the same
  fixed-host structure.

## Update — RBAC v2 (cross-org roles, audit logging, platform administration)

Since the review above was written, the codebase went through an RBAC v2
pass (see `docs/RBAC_MATRIX.md` for the authoritative permission contract
and `Tracker.md`'s "RBAC v2" entry for the full file list). Summarizing what
changed and its security implications, in the same spirit as the rest of
this document — real findings, not a changelog:

**What changed.** Two new roles were introduced on top of the existing
`USER` / `SECURITY_ANALYST` / `INSTITUTION_ADMIN` set:
`CYBER_CELL_INVESTIGATOR` (cross-organization read/investigate, no
administration) and `SYSTEM_ADMIN` (cross-organization, full
administration, can exist with no organization membership at all — a true
platform-level identity). `get_authorized_email` / `get_authorized_campaign`
/ `get_authorized_report` in `app/api/deps.py` now bypass the
organization-match check for these two roles specifically
(`CROSS_ORG_ROLES`), and every list/aggregate endpoint that matters
(`campaigns.py`, `emails.py`, `evidence.py`, `reports.py`, `jobs.py`,
`similarity.py`, `graph.py`, and `geo.py`'s `/global` overview) was updated
to default to all-organization visibility for those two roles with an
optional `organization_id` narrowing filter, while every org-scoped role's
existing behavior is unchanged and still enforced by the same code path. A
new `SYSTEM_ADMIN`-only router (`app/api/v1/endpoints/platform_admin.py`,
mounted at `/platform/*`) is the only place organizations can be created and
the only place `CYBER_CELL_INVESTIGATOR`/`SYSTEM_ADMIN` can be granted — the
pre-existing org-scoped `/users` router was tightened to explicitly reject
both of those role codes with `422`, closing the gap noted in Phase 0 of
`docs/RBAC_MATRIX.md` where it previously accepted
`CYBER_CELL_INVESTIGATOR`. Every mutation on the platform router
(org create, cross-org invite/role-change/deactivate) now writes an
`AuditLog` row via `app/core/audit.py`.

**Security implications worth flagging explicitly:**

- **Blast radius of the two new roles is real and intentional.** A
  `SYSTEM_ADMIN` account is a full cross-tenant identity by design — it can
  read every organization's emails, campaigns, evidence, and reports, and
  can grant that same power to anyone. There is exactly one router that can
  mint a `SYSTEM_ADMIN` (`POST /platform/users/invite` and
  `PATCH /platform/users/{id}/role`), both `require_roles("SYSTEM_ADMIN")`-
  gated, both audited. If this deployment ever needs a stronger control
  than "another `SYSTEM_ADMIN` decided to," that's the chokepoint to add
  it at (e.g. requiring a second approver, or moving `SYSTEM_ADMIN` grants
  out of the API entirely and into a manual/offline process) — the code
  doesn't currently do more than role-check + audit-log this action.
- **Audit logging is fail-open by design, correctly.** `record_audit()`
  writes on its own isolated DB session with its own try/except, separate
  from the primary action's transaction, specifically so a broken audit
  write can never roll back or 500 a successful invite/role-change/
  deactivate/org-create. The tradeoff is the inverse of a typical audit
  requirement: if the audit DB write itself fails, the action still
  succeeds and only a `logger.exception` is emitted — there's no queue or
  retry, so a failure here is silent unless someone is watching application
  logs. For a compliance-sensitive deployment, treat that log line as
  something that needs alerting on, not just a printf.
- **This correction updates a stale finding above.** The "Flagged, not
  fixed" table earlier in this document (from before the RBAC v2 pass)
  listed `campaigns.py`, `geo.py`, `graph.py`, `jobs.py`, `reports.py`, and
  `similarity.py` as having **zero** `organization_id` ownership checks.
  That's no longer accurate — RBAC v2 added the ownership/scoping pattern
  to all of them. `dna.py`, `intelligence.py`, and `scoring.py` still show
  zero direct `organization_id` references, but on inspection that's
  because every route in those three files resolves authorization by
  calling `get_authorized_email`/`get_authorized_campaign` first (which
  does the organization check internally) rather than filtering by
  `organization_id` in-file — same effective protection, different
  implementation shape. I did not re-verify every route in every one of
  these files line-by-line as part of this update; if a full re-audit of
  the original IDOR finding is still on your roadmap, that work is now
  substantially smaller than before RBAC v2, not eliminated.
- **Test coverage.** `backend/tests/test_platform_admin.py` and
  `backend/tests/test_rbac_scoping.py` cover role-gating on every
  `/platform/*` route, elevated-role grants, last-admin protections,
  self-deactivation blocking, audit-row assertions, the cross-org
  default-visibility/narrowing behavior for `geo.py`'s `/global` endpoint,
  and — as of this update — direct coverage of
  `get_authorized_email`/`get_authorized_campaign`/`get_authorized_report`
  for both sides of the boundary: an org-less `SYSTEM_ADMIN` can reach a
  resource in any organization, and `SECURITY_ANALYST`/`INSTITUTION_ADMIN`
  are still denied `404` for a resource in a different organization than
  their own. `286` backend tests pass in full as of this session.

## What I'd genuinely recommend before calling this "pentested"

1. Apply the `evidence.py` ownership-check pattern to the nine files listed
   above.
2. Build the login/AuthGate flow so 401 handling can be tested end-to-end.
3. Run `npm install` (to pick up `dompurify`) and `npm audit` /
   `pip-audit` for known-CVE dependency scanning — neither tool could reach
   the internet from this sandbox.
4. Once there's a staging deployment, get an actual dynamic scan/pentest
   (OWASP ZAP at minimum, ideally a third-party VAPT) — static review
   catches a real class of bugs (like the IDOR above) but can't find
   runtime-only issues, timing side-channels, or infra misconfiguration.
5. Decide whether minting a `SYSTEM_ADMIN` account should require anything
   beyond "an existing `SYSTEM_ADMIN` said so" — today that's the entire
   control, backed only by an audit log entry after the fact.
