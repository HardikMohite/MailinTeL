"""
Tests for app.api.v1.endpoints.platform_admin.

Covers:
- Each of the four mutating endpoints (create_organization, platform_invite_user,
  platform_update_role, platform_deactivate_user) writes an AuditLog row via
  app.core.audit.record_audit, scoped to the organization *acted upon* (not
  necessarily the SYSTEM_ADMIN actor's own organization_id, which may even be
  None for a pure platform account).
- record_audit is fail-safe: it opens its own session (see app.core.audit),
  so a failure writing the audit row must never surface as a non-2xx response
  from the parent request.
- GET /platform/audit-log accepts date_from/date_to and applies them as
  occurred_at range filters.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_current_user, CurrentUser
from app.db.session import get_db

client = TestClient(app)

# A pure platform account: SYSTEM_ADMIN with no organization membership of its
# own, so any audit row scoped to the *actor's* org would incorrectly be None
# -- these tests assert the audit row is scoped to the org actually acted upon.
PLATFORM_ADMIN = CurrentUser(
    id=uuid.uuid4(),
    email="platform.admin@mailintel.test",
    full_name="Platform Admin",
    organization_id=None,
    organization_name=None,
    role_code="SYSTEM_ADMIN",
)

TARGET_ORG_ID = uuid.uuid4()
OTHER_ORG_ID = uuid.uuid4()


def _install(current_user, db_mock):
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db] = lambda: db_mock


def _clear():
    app.dependency_overrides.clear()


def _make_result(*, scalar_one_or_none=None, scalar_one=None, first=None, all_=None):
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar_one_or_none
    result.scalar_one.return_value = scalar_one
    result.first.return_value = first
    result.all.return_value = all_ or []
    return result


class _FakeOrg:
    def __init__(self, org_id=TARGET_ORG_ID, name="Target Org"):
        self.id = org_id
        self.name = name
        self.organization_type = "ENTERPRISE"
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)


class _FakeUser:
    def __init__(self, email="new.user@mailintel.example"):
        self.id = uuid.uuid4()
        self.email = email
        self.full_name = "New User"
        self.status = "ACTIVE"
        self.last_login_at = None
        self.password_hash = None
        self.is_platform_admin = False


class _FakeRole:
    def __init__(self, code):
        self.id = uuid.uuid4()
        self.code = code
        self.name = code.title()


class _FakeMembership:
    def __init__(self, org_id, user_id, role_id):
        self.id = uuid.uuid4()
        self.organization_id = org_id
        self.user_id = user_id
        self.role_id = role_id
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Gap 1: each mutation writes an AuditLog row scoped to the org acted upon
# ---------------------------------------------------------------------------

def test_create_organization_writes_audit_row_for_new_org():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()) as mock_audit:
        resp = client.post(
            "/api/v1/platform/organizations",
            json={"name": "Brand New Org", "organization_type": "ENTERPRISE"},
        )
    _clear()

    assert resp.status_code == 201
    new_org_id = uuid.UUID(resp.json()["id"])

    mock_audit.assert_awaited_once()
    _, kwargs = mock_audit.call_args
    assert kwargs["action"] == "CREATE"
    assert kwargs["resource_type"] == "ORGANIZATION"
    assert kwargs["resource_id"] == new_org_id
    # Scoped to the org just created -- PLATFORM_ADMIN itself has no org.
    assert kwargs["organization_id"] == new_org_id
    assert kwargs["actor_user_id"] == PLATFORM_ADMIN.id


def test_platform_invite_user_writes_audit_row_for_target_org():
    org = _FakeOrg(org_id=TARGET_ORG_ID)
    role = _FakeRole("SECURITY_ANALYST")

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=org),    # organization lookup
        _make_result(scalar_one_or_none=None),   # no existing user with that email
        _make_result(scalar_one_or_none=role),   # role lookup in _get_or_create_role
    ])
    db.add_all = MagicMock()
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()) as mock_audit:
        resp = client.post(
            "/api/v1/platform/users/invite",
            json={
                "email": "new.analyst@mailintel.example",
                "organization_id": str(TARGET_ORG_ID),
                "role_code": "SECURITY_ANALYST",
            },
        )
    _clear()

    assert resp.status_code == 201
    new_user_id = uuid.UUID(resp.json()["user"]["id"])

    mock_audit.assert_awaited_once()
    _, kwargs = mock_audit.call_args
    assert kwargs["action"] == "CREATE"
    assert kwargs["resource_type"] == "USER"
    assert kwargs["resource_id"] == new_user_id
    # Scoped to the invited-into org, not PLATFORM_ADMIN's own (None) org.
    assert kwargs["organization_id"] == TARGET_ORG_ID
    assert kwargs["actor_user_id"] == PLATFORM_ADMIN.id


def test_platform_update_role_writes_audit_row_for_member_org():
    target_user = _FakeUser(email="member@mailintel.example")
    old_role = _FakeRole("SECURITY_ANALYST")
    new_role = _FakeRole("INSTITUTION_ADMIN")
    org = _FakeOrg(org_id=TARGET_ORG_ID)
    membership = _FakeMembership(TARGET_ORG_ID, target_user.id, old_role.id)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(first=(membership, target_user, old_role, org)),  # membership lookup
        _make_result(scalar_one_or_none=new_role),  # _get_or_create_role
    ])
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()) as mock_audit:
        resp = client.patch(
            f"/api/v1/platform/users/{target_user.id}/role",
            json={"role_code": "INSTITUTION_ADMIN"},
        )
    _clear()

    assert resp.status_code == 200
    mock_audit.assert_awaited_once()
    _, kwargs = mock_audit.call_args
    assert kwargs["action"] == "UPDATE"
    assert kwargs["resource_type"] == "USER"
    assert kwargs["resource_id"] == target_user.id
    assert kwargs["organization_id"] == TARGET_ORG_ID
    assert kwargs["metadata_json"] == {"role": "INSTITUTION_ADMIN"}
    assert kwargs["actor_user_id"] == PLATFORM_ADMIN.id


def test_platform_deactivate_user_writes_one_audit_row_per_membership():
    """A user with active memberships in two different orgs must produce
    two audit rows, each scoped to the correct membership's organization_id."""
    target_user_id = uuid.uuid4()
    role = _FakeRole("SECURITY_ANALYST")
    membership_a = _FakeMembership(TARGET_ORG_ID, target_user_id, role.id)
    membership_b = _FakeMembership(OTHER_ORG_ID, target_user_id, role.id)

    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(all_=[
        (membership_a, role),
        (membership_b, role),
    ]))
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()) as mock_audit:
        resp = client.delete(f"/api/v1/platform/users/{target_user_id}")
    _clear()

    assert resp.status_code == 204
    assert mock_audit.await_count == 2
    org_ids_audited = {call.kwargs["organization_id"] for call in mock_audit.call_args_list}
    assert org_ids_audited == {TARGET_ORG_ID, OTHER_ORG_ID}
    for call in mock_audit.call_args_list:
        assert call.kwargs["action"] == "DELETE"
        assert call.kwargs["resource_type"] == "USER"
        assert call.kwargs["resource_id"] == target_user_id
        assert call.kwargs["actor_user_id"] == PLATFORM_ADMIN.id


# ---------------------------------------------------------------------------
# Gap 2: an audit-write failure must never surface as a non-2xx response
# ---------------------------------------------------------------------------

def test_audit_write_failure_does_not_break_create_organization_request():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    # record_audit opens its OWN session via async_session_maker (see
    # app.core.audit) -- simulate that session blowing up entirely.
    with patch("app.core.audit.async_session_maker", side_effect=RuntimeError("db is on fire")):
        resp = client.post(
            "/api/v1/platform/organizations",
            json={"name": "Resilient Org", "organization_type": "ENTERPRISE"},
        )
    _clear()

    # The primary action (org creation) already committed before record_audit
    # ran, so the request must still succeed even though the audit write blew up.
    assert resp.status_code == 201
    assert resp.json()["name"] == "Resilient Org"


@pytest.mark.asyncio
async def test_record_audit_swallows_commit_failure():
    """Unit-level check directly on record_audit: a failure inside its own
    session's commit() must be caught and logged, never re-raised."""
    from app.core.audit import record_audit

    broken_session = AsyncMock()
    broken_session.add = MagicMock()
    broken_session.commit = AsyncMock(side_effect=RuntimeError("constraint violation"))
    broken_session.__aenter__ = AsyncMock(return_value=broken_session)
    broken_session.__aexit__ = AsyncMock(return_value=False)

    with patch("app.core.audit.async_session_maker", return_value=broken_session):
        # Should not raise.
        await record_audit(
            AsyncMock(),
            actor_user_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            action="CREATE",
            resource_type="ORGANIZATION",
        )
    broken_session.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Gap 3: GET /platform/audit-log respects date_from/date_to
# ---------------------------------------------------------------------------

def _compiled_where(stmt) -> str:
    return str(stmt.compile(compile_kwargs={"literal_binds": True}))


def test_audit_log_applies_date_range_filters():
    db = AsyncMock()
    captured = {}

    async def _execute(stmt, *args, **kwargs):
        captured["stmt"] = stmt
        return _make_result(all_=[])

    db.execute = AsyncMock(side_effect=_execute)
    _install(PLATFORM_ADMIN, db)

    date_from = "2026-01-01T00:00:00Z"
    date_to = "2026-02-01T00:00:00Z"
    resp = client.get(
        "/api/v1/platform/audit-log",
        params={"date_from": date_from, "date_to": date_to},
    )
    _clear()

    assert resp.status_code == 200
    sql = _compiled_where(captured["stmt"])
    assert "occurred_at >=" in sql
    assert "occurred_at <=" in sql
    assert "2026-01-01" in sql
    assert "2026-02-01" in sql


def test_audit_log_omits_date_filters_when_not_supplied():
    db = AsyncMock()
    captured = {}

    async def _execute(stmt, *args, **kwargs):
        captured["stmt"] = stmt
        return _make_result(all_=[])

    db.execute = AsyncMock(side_effect=_execute)
    _install(PLATFORM_ADMIN, db)

    resp = client.get("/api/v1/platform/audit-log")
    _clear()

    assert resp.status_code == 200
    sql = _compiled_where(captured["stmt"])
    assert "occurred_at >=" not in sql
    assert "occurred_at <=" not in sql


def test_audit_log_forbidden_for_non_system_admin():
    non_admin = CurrentUser(
        id=uuid.uuid4(), email="analyst@mailintel.test", full_name="Analyst",
        organization_id=uuid.uuid4(), organization_name="Some Org", role_code="SECURITY_ANALYST",
    )
    _install(non_admin, AsyncMock())
    resp = client.get("/api/v1/platform/audit-log")
    _clear()
    assert resp.status_code == 403


# ===========================================================================
# Additional coverage: RBAC matrix, role-grant scope, list filtering,
# last-admin protection, and self-deactivation on the platform-scoped path.
# ===========================================================================

# Every role except SYSTEM_ADMIN must be rejected from every /platform/* route.
# Explicitly includes INSTITUTION_ADMIN and CYBER_CELL_INVESTIGATOR, not just
# "some non-admin role" -- INSTITUTION_ADMIN is the highest org-scoped role and
# CYBER_CELL_INVESTIGATOR is a platform-flavored role that is still not
# SYSTEM_ADMIN, so both are the most likely candidates for an accidental
# permission leak.
NON_SYSTEM_ADMIN_ROLES = ("USER", "SECURITY_ANALYST", "INSTITUTION_ADMIN", "CYBER_CELL_INVESTIGATOR")

_RBAC_TARGET_USER_ID = uuid.uuid4()

# (method, path, json_body) -- bodies are valid so a 422 from payload
# validation can never masquerade as the 403 these tests are asserting.
PLATFORM_ROUTES = (
    ("post", "/api/v1/platform/organizations", {"name": "Some Org", "organization_type": "ENTERPRISE"}),
    ("get", "/api/v1/platform/organizations", None),
    ("get", "/api/v1/platform/users", None),
    ("post", "/api/v1/platform/users/invite", {
        "email": "invitee@mailintel.example",
        "organization_id": str(TARGET_ORG_ID),
        "role_code": "SECURITY_ANALYST",
    }),
    ("patch", f"/api/v1/platform/users/{_RBAC_TARGET_USER_ID}/role", {"role_code": "SECURITY_ANALYST"}),
    ("delete", f"/api/v1/platform/users/{_RBAC_TARGET_USER_ID}", None),
    ("get", "/api/v1/platform/audit-log", None),
)


def _role_user(role_code):
    return CurrentUser(
        id=uuid.uuid4(),
        email=f"{role_code.lower()}@mailintel.test",
        full_name=role_code.title(),
        organization_id=uuid.uuid4(),
        organization_name="Some Org",
        role_code=role_code,
    )


def _call(method, path, json_body):
    if method == "get":
        return client.get(path)
    if method == "delete":
        return client.delete(path)
    return getattr(client, method)(path, json=json_body)


@pytest.mark.parametrize("role_code", NON_SYSTEM_ADMIN_ROLES)
@pytest.mark.parametrize("method,path,json_body", PLATFORM_ROUTES)
def test_platform_routes_forbidden_for_non_system_admin(method, path, json_body, role_code):
    _install(_role_user(role_code), AsyncMock())
    resp = _call(method, path, json_body)
    _clear()
    assert resp.status_code == 403, f"{role_code} should be forbidden from {method.upper()} {path}"


# ---------------------------------------------------------------------------
# Item 2: SYSTEM_ADMIN can create an organization.
# ---------------------------------------------------------------------------

def test_system_admin_can_create_organization():
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()):
        resp = client.post(
            "/api/v1/platform/organizations",
            json={"name": "Freshly Created Org", "organization_type": "ENTERPRISE"},
        )
    _clear()

    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Freshly Created Org"
    assert data["status"] == "ACTIVE"


# ---------------------------------------------------------------------------
# Item 3: SYSTEM_ADMIN can grant CYBER_CELL_INVESTIGATOR and SYSTEM_ADMIN
# through the platform-scoped invite/role-change endpoints -- these are
# rejected by the org-scoped /users/invite and /users/{id}/role endpoints
# (see test_users.py), but must succeed here.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role_code", ("CYBER_CELL_INVESTIGATOR", "SYSTEM_ADMIN"))
def test_platform_invite_allows_elevated_roles(role_code):
    org = _FakeOrg(org_id=TARGET_ORG_ID)
    role = _FakeRole(role_code)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=org),   # organization lookup
        _make_result(scalar_one_or_none=None),  # no existing user with that email
        _make_result(scalar_one_or_none=role),  # role lookup in _get_or_create_role
    ])
    db.add_all = MagicMock()
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()):
        resp = client.post(
            "/api/v1/platform/users/invite",
            json={
                "email": f"elevated.{role_code.lower()}@mailintel.example",
                "organization_id": str(TARGET_ORG_ID),
                "role_code": role_code,
            },
        )
    _clear()

    assert resp.status_code == 201, resp.text
    assert resp.json()["user"]["role"] == role_code


@pytest.mark.parametrize("role_code", ("CYBER_CELL_INVESTIGATOR", "SYSTEM_ADMIN"))
def test_platform_update_role_allows_elevated_roles(role_code):
    target_user = _FakeUser(email="promote.me@mailintel.example")
    old_role = _FakeRole("SECURITY_ANALYST")
    new_role = _FakeRole(role_code)
    org = _FakeOrg(org_id=TARGET_ORG_ID)
    membership = _FakeMembership(TARGET_ORG_ID, target_user.id, old_role.id)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(first=(membership, target_user, old_role, org)),  # membership lookup
        _make_result(scalar_one_or_none=new_role),  # _get_or_create_role
    ])
    db.commit = AsyncMock()
    _install(PLATFORM_ADMIN, db)

    with patch("app.core.audit.record_audit", new=AsyncMock()):
        resp = client.patch(
            f"/api/v1/platform/users/{target_user.id}/role",
            json={"role_code": role_code},
        )
    _clear()

    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == role_code


# ---------------------------------------------------------------------------
# Item 4: GET /platform/users -- cross-org listing vs. single-org filter.
# ---------------------------------------------------------------------------

def test_list_platform_users_spans_multiple_orgs_without_filter():
    org_a = _FakeOrg(org_id=TARGET_ORG_ID, name="Org A")
    org_b = _FakeOrg(org_id=OTHER_ORG_ID, name="Org B")
    role = _FakeRole("SECURITY_ANALYST")
    user_a = _FakeUser(email="member.a@mailintel.example")
    user_b = _FakeUser(email="member.b@mailintel.example")
    membership_a = _FakeMembership(TARGET_ORG_ID, user_a.id, role.id)
    membership_b = _FakeMembership(OTHER_ORG_ID, user_b.id, role.id)

    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(all_=[
        (membership_a, user_a, role, org_a),
        (membership_b, user_b, role, org_b),
    ]))
    _install(PLATFORM_ADMIN, db)

    resp = client.get("/api/v1/platform/users")
    _clear()

    assert resp.status_code == 200
    data = resp.json()
    org_ids = {row["organization_id"] for row in data}
    assert org_ids == {str(TARGET_ORG_ID), str(OTHER_ORG_ID)}


def test_list_platform_users_filters_to_single_org_when_supplied():
    db = AsyncMock()
    captured = {}

    async def _execute(stmt, *args, **kwargs):
        captured["stmt"] = stmt
        return _make_result(all_=[])

    db.execute = AsyncMock(side_effect=_execute)
    _install(PLATFORM_ADMIN, db)

    resp = client.get("/api/v1/platform/users", params={"organization_id": str(TARGET_ORG_ID)})
    _clear()

    assert resp.status_code == 200
    sql = _compiled_where(captured["stmt"])
    assert "organization_members.organization_id" in sql or "organization_member.organization_id" in sql
    assert TARGET_ORG_ID.hex in sql.replace("-", "")


# ---------------------------------------------------------------------------
# Item 5: last-remaining-admin protection on the platform-scoped path.
# ---------------------------------------------------------------------------

def test_platform_update_role_blocks_demoting_last_admin():
    target_user = _FakeUser(email="last.admin@mailintel.example")
    admin_role = _FakeRole("INSTITUTION_ADMIN")
    org = _FakeOrg(org_id=TARGET_ORG_ID)
    membership = _FakeMembership(TARGET_ORG_ID, target_user.id, admin_role.id)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(first=(membership, target_user, admin_role, org)),  # membership lookup
        _make_result(scalar_one=1),  # only 1 active admin left
    ])
    _install(PLATFORM_ADMIN, db)

    resp = client.patch(
        f"/api/v1/platform/users/{target_user.id}/role",
        json={"role_code": "SECURITY_ANALYST"},
    )
    _clear()

    assert resp.status_code == 400
    assert "last remaining admin" in resp.json()["error"]


def test_platform_deactivate_user_blocks_deactivating_last_admin():
    target_user_id = uuid.uuid4()
    admin_role = _FakeRole("INSTITUTION_ADMIN")
    membership = _FakeMembership(TARGET_ORG_ID, target_user_id, admin_role.id)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(all_=[(membership, admin_role)]),  # active memberships lookup
        _make_result(scalar_one=1),  # only 1 active admin left
    ])
    _install(PLATFORM_ADMIN, db)

    resp = client.delete(f"/api/v1/platform/users/{target_user_id}")
    _clear()

    assert resp.status_code == 400
    assert "last remaining admin" in resp.json()["error"]


# ---------------------------------------------------------------------------
# Item 6: DELETE /platform/users/{id} rejects self-deactivation.
# ---------------------------------------------------------------------------

def test_platform_deactivate_user_blocks_self_removal():
    _install(PLATFORM_ADMIN, AsyncMock())
    resp = client.delete(f"/api/v1/platform/users/{PLATFORM_ADMIN.id}")
    _clear()
    assert resp.status_code == 400
