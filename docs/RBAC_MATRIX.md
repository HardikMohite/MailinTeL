# MailIntel RBAC v2 Permission Matrix

This document is the authoritative contract for role, visibility, and administration decisions.

| Role | Data visibility | Read scope | Write scope | Roles assignable | Assignment scope |
|---|---|---|---|---|---|
| `USER` | Personal | Emails, campaigns, reports, jobs, evidence derived from items personally uploaded | Normal upload and personal analysis workflow only; no user or organization administration | None | None |
| `SECURITY_ANALYST` | Organization | All emails, campaigns, reports, evidence, graph, correlation, intelligence, and jobs in own organization | Normal investigation workflow, report generation, evidence annotation, and campaign operations in own organization | None | None |
| `INSTITUTION_ADMIN` | Organization | All data in own organization | All normal investigation workflow plus invite, role-change, and deactivation in own organization | `SECURITY_ANALYST`, `USER`, `INSTITUTION_ADMIN` | Own organization only |
| `CYBER_CELL_INVESTIGATOR` | Cross-organization | All emails, campaigns, reports, evidence, graph, correlation, intelligence, and jobs across every organization; optional organization filter | Normal read/investigation workflow, report generation, and evidence annotation; no user/org administration | None | None |
| `SYSTEM_ADMIN` | Cross-organization | All data across every organization; optional organization filter; platform audit log | Everything, including organization lifecycle and any user management | All five roles, including `CYBER_CELL_INVESTIGATOR` and `SYSTEM_ADMIN` | Any organization; platform scope |

## Endpoint policy

Resource detail endpoints must return `404` for absent or out-of-scope resources. List endpoints use personal scope for `USER`, the caller's organization for organization roles, and all organizations by default for cross-organization roles. Cross-organization list views accept an optional `organization_id` narrowing filter.

The organization-scoped `/users` router is available to `INSTITUTION_ADMIN` (and remains reachable by `SYSTEM_ADMIN` only when they have an active organization membership) and can assign only `INSTITUTION_ADMIN`, `SECURITY_ANALYST`, and `USER`. The `/platform` router is `SYSTEM_ADMIN`-only and is the sole path for granting `CYBER_CELL_INVESTIGATOR` or `SYSTEM_ADMIN`, creating organizations, and managing users across organizations.

## Phase 0 gap list

The pre-RBAC-v2 implementation had only organization-wide `ANALYST_ROLES` and organization-scoped `ADMIN_ROLES`. `CYBER_CELL_INVESTIGATOR` was currently org-scoped because it was bucketed into `ANALYST_ROLES`. `SYSTEM_ADMIN` currently received **no cross-organization bypass** in `get_authorized_email`, `get_authorized_campaign`, or `get_authorized_report`; all three helpers hard-failed unless the resource organization matched `current_user.organization_id`. `get_current_user` also defaulted an account without an active membership to `USER`, which could lock out a pure platform administrator. The existing org-scoped user endpoint also incorrectly allowed `CYBER_CELL_INVESTIGATOR` to be assigned.

## Manual QA checklist

1. **USER:** sign in, confirm Dashboard/Analyze/History/own data navigation appears while graph and Team & Access are hidden; upload an email, verify only personally uploaded emails/campaigns/reports/jobs appear, and confirm another user's resource returns `404`.
2. **SECURITY_ANALYST:** sign in, confirm investigation and evidence/report navigation appears but Team & Access does not; verify all resources in the analyst's organization appear, cross-organization resources return `404`, and user-management attempts return `403`.
3. **INSTITUTION_ADMIN:** sign in, confirm Team & Access appears; verify all own-organization resources appear, invite/change/deactivate works only in the own organization, granting either cross-org role is rejected with `422`, and another organization's resource returns `404`.
4. **CYBER_CELL_INVESTIGATOR:** sign in, confirm cross-org investigation navigation and organization selector appear but Team & Access does not; verify all organizations appear by default, the selector narrows results, and every `/platform/*` operation returns `403`.
5. **SYSTEM_ADMIN:** sign in with or without an organization membership, confirm cross-org selector and platform administration are available; verify all organizations/data and audit log are visible, any role can be granted through `/platform`, organization creation works, and last-admin protections remain enforced.

## Verification deviations

The implementation preserves the existing normal investigation write workflow for `CYBER_CELL_INVESTIGATOR`, as explicitly decided in the plan. The frontend uses a platform-admin API path for cross-org administration while retaining the existing organization-scoped team path for institution administrators. Any endpoint that is not backed by an organization-bearing data model remains fail-closed rather than inventing ownership.
