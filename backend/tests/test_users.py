import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_current_user, CurrentUser
from app.db.session import get_db
from tests.auth_helpers import TEST_USER, TEST_ORG_ID

client = TestClient(app)

ADMIN_USER = CurrentUser(
    id=uuid.uuid4(),
    email="org.admin@mailintel.example",
    full_name="Org Admin",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="INSTITUTION_ADMIN",
)


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


class _FakeUser:
    def __init__(self, email="new.analyst@mailintel.example", full_name="New Analyst"):
        self.id = uuid.uuid4()
        self.email = email
        self.full_name = full_name
        self.status = "ACTIVE"
        self.last_login_at = None
        self.password_hash = None


class _FakeRole:
    def __init__(self, code):
        self.id = uuid.uuid4()
        self.code = code
        self.name = code.title()


class _FakeOrg:
    def __init__(self, org_id):
        self.id = org_id
        self.name = "Test Org"
        self.status = "ACTIVE"


class _FakeMembership:
    def __init__(self, org_id, user_id, role_id):
        self.id = uuid.uuid4()
        self.organization_id = org_id
        self.user_id = user_id
        self.role_id = role_id
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc)


def test_list_members_forbidden_for_non_analyst_role():
    """A bare 'USER' role (below ANALYST_ROLES) cannot list the roster."""
    bare_user = CurrentUser(
        id=uuid.uuid4(), email="bare@mailintel.example", full_name=None,
        organization_id=TEST_ORG_ID, organization_name="Test Org", role_code="USER",
    )
    _install(bare_user, AsyncMock())
    response = client.get("/api/v1/users")
    _clear()
    assert response.status_code == 403


def test_list_members_success():
    user = _FakeUser()
    role = _FakeRole("SECURITY_ANALYST")
    membership = _FakeMembership(TEST_ORG_ID, user.id, role.id)

    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(all_=[(membership, user, role)]))
    _install(TEST_USER, db)

    response = client.get("/api/v1/users")
    _clear()

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["email"] == user.email
    assert data[0]["role"] == "SECURITY_ANALYST"


def test_invite_rejects_disallowed_role():
    """SYSTEM_ADMIN is a cross-org platform role and must not be grantable here."""
    _install(ADMIN_USER, AsyncMock())
    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new@mailintel.example", "role_code": "SYSTEM_ADMIN"},
    )
    _clear()
    assert response.status_code == 422


def test_invite_rejects_cyber_cell_investigator_role():
    """CYBER_CELL_INVESTIGATOR is a distinct, cross-org/platform-flavored role
    (see PLATFORM_ROLES in platform_admin.py) and must not be grantable via
    the org-scoped invite endpoint, same as SYSTEM_ADMIN above."""
    _install(ADMIN_USER, AsyncMock())
    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new@mailintel.example", "role_code": "CYBER_CELL_INVESTIGATOR"},
    )
    _clear()
    assert response.status_code == 422


def test_invite_rejects_institution_admin_role():
    """INSTITUTION_ADMIN can only be assigned by SYSTEM_ADMIN and must not be grantable
    through the org-scoped invite endpoint."""
    _install(ADMIN_USER, AsyncMock())
    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new.admin@mailintel.example", "role_code": "INSTITUTION_ADMIN"},
    )
    _clear()
    assert response.status_code == 422


def test_invite_forbidden_for_non_admin():
    _install(TEST_USER, AsyncMock())  # TEST_USER is SECURITY_ANALYST, not admin
    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new@mailintel.example", "role_code": "SECURITY_ANALYST"},
    )
    _clear()
    assert response.status_code == 403


def test_invite_forbidden_for_plain_user():
    plain_user = CurrentUser(
        id=uuid.uuid4(),
        email="plain.user@mailintel.example",
        full_name="Plain User",
        organization_id=TEST_ORG_ID,
        organization_name="Test Org",
        role_code="USER",
    )
    _install(plain_user, AsyncMock())
    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new@mailintel.example", "role_code": "USER"},
    )
    _clear()
    assert response.status_code == 403



def test_invite_success_returns_temporary_password():
    org = _FakeOrg(TEST_ORG_ID)
    role = _FakeRole("SECURITY_ANALYST")

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=None),   # no existing user with that email
        _make_result(scalar_one_or_none=org),     # active organization lookup
        _make_result(scalar_one_or_none=role),    # role lookup in _get_or_create_role
    ])
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    _install(ADMIN_USER, db)

    response = client.post(
        "/api/v1/users/invite",
        json={"email": "new.analyst@mailintel.example", "full_name": "New Analyst", "role_code": "SECURITY_ANALYST"},
    )
    _clear()

    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == "new.analyst@mailintel.example"
    assert data["user"]["role"] == "SECURITY_ANALYST"
    assert len(data["temporary_password"]) >= 16
    db.commit.assert_awaited_once()


def test_invite_rejects_existing_email():
    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(scalar_one_or_none=_FakeUser()))
    _install(ADMIN_USER, db)

    response = client.post(
        "/api/v1/users/invite",
        json={"email": "duplicate@mailintel.example", "role_code": "SECURITY_ANALYST"},
    )
    _clear()
    assert response.status_code == 400


def test_update_role_blocks_demoting_last_admin():
    target_user = _FakeUser(email="last.admin@mailintel.example")
    admin_role = _FakeRole("INSTITUTION_ADMIN")
    membership = _FakeMembership(TEST_ORG_ID, target_user.id, admin_role.id)

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(first=(membership, target_user, admin_role)),  # membership lookup
        _make_result(scalar_one=1),  # only 1 active admin left
    ])
    _install(ADMIN_USER, db)

    response = client.patch(
        f"/api/v1/users/{target_user.id}/role",
        json={"role_code": "SECURITY_ANALYST"},
    )
    _clear()
    assert response.status_code == 400
    assert "last remaining admin" in response.json()["error"]


def test_update_role_rejects_cyber_cell_investigator_role():
    """Same restriction as invite: CYBER_CELL_INVESTIGATOR must not be
    assignable through the org-scoped role-change endpoint."""
    target_user_id = uuid.uuid4()
    _install(ADMIN_USER, AsyncMock())
    response = client.patch(
        f"/api/v1/users/{target_user_id}/role",
        json={"role_code": "CYBER_CELL_INVESTIGATOR"},
    )
    _clear()
    assert response.status_code == 422


def test_update_role_rejects_institution_admin_role():
    """INSTITUTION_ADMIN can only be assigned by SYSTEM_ADMIN."""
    target_user_id = uuid.uuid4()
    _install(ADMIN_USER, AsyncMock())
    response = client.patch(
        f"/api/v1/users/{target_user_id}/role",
        json={"role_code": "INSTITUTION_ADMIN"},
    )
    _clear()
    assert response.status_code == 422


def test_deactivate_member_blocks_self_removal():
    _install(ADMIN_USER, AsyncMock())
    response = client.delete(f"/api/v1/users/{ADMIN_USER.id}")
    _clear()
    assert response.status_code == 400


def test_deactivate_member_success():
    target_user_id = uuid.uuid4()
    role = _FakeRole("SECURITY_ANALYST")
    membership = _FakeMembership(TEST_ORG_ID, target_user_id, role.id)

    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(first=(membership, role)))
    db.commit = AsyncMock()
    _install(ADMIN_USER, db)

    response = client.delete(f"/api/v1/users/{target_user_id}")
    _clear()

    assert response.status_code == 204
    assert membership.status == "INACTIVE"
    db.commit.assert_awaited_once()
