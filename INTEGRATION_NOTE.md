# Integration note — why this zip looks the way it does

You gave me three zips: `MailinteL.zip` (oldest full checkpoint),
`MailinteL_checkpoint10_rbac_scoping.zip`, and
`MailinteL_checkpoint10_rbac_org_admin.zip`. All three passed a full
CRC integrity test (`unzip -t`) — **none of them are corrupted**. The
size drop you noticed is not data loss from a bad zip; it's because
the two "checkpoint10" zips are two *different, incompatible*
development branches that both started from checkpoint 9, and one of
them is a partial export.

## What each zip actually contains

| Zip | Backend files | Tests | RBAC design | Feature endpoints |
|---|---|---|---|---|
| `MailinteL.zip` (oldest) | 214 (incl. a built `frontend/dist`, inflating it to 18MB) | 24 files | none (pre-auth) | all domains, no auth |
| `..._scoping.zip` | 123 | 24 files, incl. `test_rbac_scoping.py`, `test_users.py` | **normalized**: `Organization` / `Role` / `RolePermission` / `OrganizationMember` tables, org-scoping applied across every endpoint | emails, campaigns, dna, evidence, geo, graph, intelligence, jobs, reports, scoring, similarity, users, auth — full set |
| `..._org_admin.zip` | 40 | **0** | **enum-based**: a `DBRole` column on `User` (`USER` / `SECURITY_ANALYST` / `INSTITUTION_ADMIN` / `CYBER_CELL_INVESTIGATOR`) + a non-DB, env-only `SYSTEM_ADMIN` | only auth, organizations, users |

The `org_admin` zip's own `RBAC_CHANGES.md` says outright that it's
rebuilding a backend package that had gone missing, and lists
email/campaign/evidence/report *endpoints* as **not done in this
checkpoint** (the services existed, the routes didn't). It also ships
with no `tests/`, no `docker-compose.yml`, and none of `Design.md` /
`Schema.md` / `TechSpec.md` / `Tracker.md` — consistent with it being
a scoped export of just the org-admin work, not a full project
checkpoint.

The two RBAC designs use **different database schemas**
(normalized role tables vs. an enum column), so they can't be
silently spliced together without risking broken migrations right
before a demo.

## What I did

This zip (`MailinteL_MVP`) is the `scoping` checkpoint, cleaned up
(`__pycache__`, `.pytest_cache`, `.pyc` removed) — it's the most
complete, most tested, already-working branch: full feature set,
auth, and org-scoping enforced on every endpoint, with 24 passing
test files. All backend `.py` files pass a syntax compile check.
This is what I'd put in front of judges.

## What I did *not* do

I did not merge in the `org_admin` branch's env-only `SYSTEM_ADMIN`
concept or its simpler role enum — that's a genuinely nice idea, but
grafting it onto the `scoping` branch's normalized role tables is a
real schema-migration task, not a file copy. If you want that for a
future pass, say so and I'll do it properly (new migration, updated
`deps.py`, updated tests) rather than rush it in.
