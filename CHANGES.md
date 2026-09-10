# Changes in this pass

## 1. Error-handling UI layer (frontend)

New files:
- `src/hooks/useApiErrorHandler.ts` — `parseApiError(error)` / `useApiErrorHandler()`.
  Turns any axios error into `{ kind, title, message, retryAfterSeconds?, details? }`.
  This is the only place that should ever branch on HTTP status code.
- `src/services/apiEvents.ts` — tiny pub/sub so the axios interceptor (outside
  React) can notify the app of `unauthorized` / `network-error`.
- `src/services/authStorage.ts` — single source of truth for the bearer token.
- `src/context/AuthContext.tsx` — minimal `{ isAuthenticated, login, logout }`.
  **Note:** there is no login screen yet — see SECURITY_REVIEW.md.
- `src/components/errors/` — `ErrorBoundary`, `FullPageError`,
  `UnauthorizedScreen`, `ForbiddenScreen`, `NotFoundScreen`,
  `RateLimitedScreen` (live countdown), `ServerErrorScreen`, `OfflineScreen`
  (polls `checkHealth`, auto-dismisses), `ValidationErrorBanner` (inline, for
  forms). Import from `src/components/errors` (barrel export).

Wiring:
- `services/api.ts` — request interceptor attaches the bearer token; response
  interceptor emits `network-error` on no-response and `unauthorized` on 401
  (and clears the dead token). 403/404/413/422/429/5xx are left for call
  sites to catch and pass to `useApiErrorHandler`, since only the call site
  knows whether an inline banner or a full-page state is right.
- `App.tsx` — `<ErrorBoundary>` wraps the tab content inside `<main>` (sidebar/
  header stay usable); `OfflineScreen`/`UnauthorizedScreen` take over on the
  relevant global event; an unrecognized `activeTab` renders `NotFoundScreen`
  instead of a blank pane.
- `main.tsx` — wraps `<App />` in `<AuthProvider>`.

### Using it in a view (per-call-site pattern)

```tsx
import { useApiErrorHandler } from '../../hooks/useApiErrorHandler';
import { ValidationErrorBanner, ForbiddenScreen, NotFoundScreen, ServerErrorScreen, RateLimitedScreen } from '../errors';

const handleError = useApiErrorHandler();

try {
  await someApiCall();
} catch (err) {
  const parsed = handleError(err);
  switch (parsed.kind) {
    case 'validation':
      setFormError(parsed); // render <ValidationErrorBanner message={...} details={parsed.details} />
      break;
    case 'forbidden':
      setViewState('forbidden'); // render <ForbiddenScreen />
      break;
    case 'not_found':
      setViewState('not_found');
      break;
    case 'rate_limited':
      setViewState({ kind: 'rate_limited', retryAfterSeconds: parsed.retryAfterSeconds });
      break;
    case 'server_error':
      setViewState('server_error'); // render <ServerErrorScreen onRetry={retryFn} />
      break;
    // 'unauthorized' / 'network' are already handled globally — no need to branch on them here.
  }
}
```

A single failed fetch inside a view (e.g. loading one email in
`AnalysisWorkspace`) should set local view state and render inline/within
that view's own area — not blank the whole app.

## 2. Security fixes (see SECURITY_REVIEW.md for full detail)

- Fixed a cross-tenant IDOR in `backend/app/api/v1/endpoints/evidence.py`
  (any authenticated user from any org could read/download/verify another
  org's evidence by UUID).
- Fixed a stored-XSS in `frontend/src/components/workspace/AnalysisWorkspace.tsx`
  (unsanitized `dangerouslySetInnerHTML` of the analyzed email's own HTML
  body). Added `dompurify` to `package.json` — **run `npm install`**.
- **Read SECURITY_REVIEW.md** — the same IDOR pattern likely affects nine
  other endpoint files that weren't fixed in this pass (listed there with a
  suggested priority order).

## 3. QA follow-up pass (this checkpoint)

Addressed the open items from the prior status report:

- **`.env.example` / `docker-compose.yml`**: verified already correct in
  this checkpoint (`BACKEND_HOST=127.0.0.1`, pinned MinIO image + `mc ready`
  healthcheck). No changes needed here — if a different working copy still
  has the old values, that copy has diverged from this one and should be
  reconciled from this checkpoint.
- **`ADMIN_ROLES` dead code / missing invite endpoint**: new
  `backend/app/api/v1/endpoints/users.py` — `GET /api/v1/users` (roster,
  `ANALYST_ROLES`), `POST /api/v1/users/invite`, `PATCH
  /api/v1/users/{id}/role`, `DELETE /api/v1/users/{id}` (all three
  `ADMIN_ROLES`-gated, org-scoped, block removing/demoting the org's last
  admin). `ADMIN_ROLES` is now referenced by real routes. No DB migration
  needed (uses the existing `users`/`organization_members`/`roles` tables).
  MVP limitation, called out in the module docstring: there's no SMTP
  integration yet, so "invite" returns a one-time temporary password in the
  response instead of emailing it; the admin relays it out of band, and
  there's no forced-password-change-on-first-login flow yet either — track
  that as a fast-follow. `SYSTEM_ADMIN` is deliberately not grantable
  through this org-scoped endpoint (it's the cross-org platform role — see
  `alembic/versions/0002_seed_rbac_roles.py`). New `tests/test_users.py`
  (9 tests). Full suite: 213 passed.
- **Frontend**: new `frontend/src/components/settings/TeamView.tsx` (roster
  table, invite form with one-time-password banner, role-change/deactivate
  menu) plus matching API bindings in `services/api.ts`
  (`listOrgMembers`/`inviteOrgMember`/`updateOrgMemberRole`/`deactivateOrgMember`).
  Wired into `App.tsx`/`Sidebar.tsx` as a new "Team & Access" tab. Also
  fixed the sidebar footer, which still said "Authentication and RBAC
  arrive in Phase 9" even though both already ship.
- **Bug found while wiring this up, fixed in `backend/app/main.py`**: the
  global `RequestValidationError` handler crashed with an unrelated
  `TypeError` (`Object of type ValueError is not JSON serializable`)
  whenever a Pydantic `@field_validator` raised `ValueError` — because
  `exc.errors()` embeds the raw exception object in `ctx`. This affected
  the existing password-strength validator in `auth.register` too (just
  never had a test that hit it). Now stringifies `ctx` before serializing.
- **Not done, needs a browser / real infra** (unchanged from the prior
  report — see items 2 and 5 there): hostile-HTML rendering through the
  built frontend needs a real browser/CI run; evidence
  upload/download and full report-generation-with-storage flows need a
  real MinIO to exercise end to end. Neither is possible in this sandbox.


## 4. RBAC v2 — cross-organization investigator and platform administration

- Added `docs/RBAC_MATRIX.md` as the authoritative five-role permission contract and manual QA checklist.
- Added `CROSS_ORG_ROLES`, cross-org ownership bypasses, an org-less `SYSTEM_ADMIN` identity path, and migration `0004_platform_admin_flag.py`.
- Added the `SYSTEM_ADMIN`-only `/api/v1/platform` router for organizations, cross-org roster/invite/role/deactivation, and audit-log reads.
- Tightened org-scoped role assignment so `INSTITUTION_ADMIN` can grant only `INSTITUTION_ADMIN`, `SECURITY_ANALYST`, and `USER`.
- Applied optional organization filters and cross-org branches to email, campaign, report, job, graph, geo, evidence, similarity, and investigation route gates.
- Added resilient audit capture for cross-org reads and user administration actions.
- Added frontend RBAC helpers, shared role constants, and an investigator/system-admin organization selector.
- Verification: backend `224 passed`; frontend `npm run build` passed.
