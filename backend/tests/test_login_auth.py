import uuid
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.security import hash_password
from app.db.session import get_db
from app.models.identity import User, Organization, OrganizationMember, Role

client = TestClient(app)


def _post(url: str, json_data: dict):
    """Issues POST request with unique isolated client IP to avoid global rate limiter conflicts."""
    ip = f"10.200.{uuid.uuid4().int % 200}.{uuid.uuid4().int % 200}"
    return client.post(url, json=json_data, headers={"X-Forwarded-For": ip})


def _make_result(*, scalar_one_or_none=None, first=None):
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar_one_or_none
    result.first.return_value = first
    return result


@pytest.fixture
def mock_user_with_username():
    user = User(
        id=uuid.uuid4(),
        email="analyst.smith@mailintel.org",
        username="asmith",
        full_name="Analyst Smith",
        password_hash=hash_password("SuperSecret123!@#"),
        auth_provider="LOCAL",
        status="ACTIVE",
        is_platform_admin=False,
    )
    org = Organization(
        id=uuid.uuid4(),
        name="Cyber Intel Agency",
        organization_type="ENTERPRISE",
        status="ACTIVE",
    )
    role = Role(id=uuid.uuid4(), code="USER", name="User")
    member = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=org.id,
        user_id=user.id,
        role_id=role.id,
        status="ACTIVE",
    )
    return user, org, role, member


@pytest.mark.asyncio
async def test_login_with_email_success(mock_user_with_username):
    user, org, role, member = mock_user_with_username

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=user),       # User query by email or username
        _make_result(first=(member, org, role)),      # OrganizationMember membership query
    ])
    db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db

    resp = _post(
        "/api/v1/auth/login",
        {
            "email": "analyst.smith@mailintel.org",
            "password": "SuperSecret123!@#",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "analyst.smith@mailintel.org"
    assert data["user"]["username"] == "asmith"
    assert data["user"]["role"] == "USER"


@pytest.mark.asyncio
async def test_login_with_username_success(mock_user_with_username):
    user, org, role, member = mock_user_with_username

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=user),       # User query by username
        _make_result(first=(member, org, role)),      # OrganizationMember membership query
    ])
    db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db

    # 1. Login with username in "email" field (standard form submission)
    resp1 = _post(
        "/api/v1/auth/login",
        {
            "email": "asmith",
            "password": "SuperSecret123!@#",
        },
    )

    # 2. Login with username explicitly in "username" field
    db.execute.side_effect = [
        _make_result(scalar_one_or_none=user),
        _make_result(first=(member, org, role)),
    ]
    resp2 = _post(
        "/api/v1/auth/login",
        {
            "username": "asmith",
            "password": "SuperSecret123!@#",
        },
    )

    # 3. Login with username in "identifier" field
    db.execute.side_effect = [
        _make_result(scalar_one_or_none=user),
        _make_result(first=(member, org, role)),
    ]
    resp3 = _post(
        "/api/v1/auth/login",
        {
            "identifier": "ASMITH",  # Case-insensitive
            "password": "SuperSecret123!@#",
        },
    )
    app.dependency_overrides.clear()

    assert resp1.status_code == 200, resp1.text
    assert resp1.json()["user"]["username"] == "asmith"

    assert resp2.status_code == 200, resp2.text
    assert resp2.json()["user"]["username"] == "asmith"

    assert resp3.status_code == 200, resp3.text
    assert resp3.json()["user"]["username"] == "asmith"


@pytest.mark.asyncio
async def test_login_invalid_password_rejected(mock_user_with_username):
    user, _, _, _ = mock_user_with_username

    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(scalar_one_or_none=user))

    app.dependency_overrides[get_db] = lambda: db

    resp = _post(
        "/api/v1/auth/login",
        {
            "email": "asmith",
            "password": "IncorrectPassword123!",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 401
    err_text = resp.json().get("error") or resp.json().get("detail", "")
    assert "Incorrect email, username, or password" in err_text


@pytest.mark.asyncio
async def test_login_unknown_user_rejected():
    db = AsyncMock()
    db.execute = AsyncMock(return_value=_make_result(scalar_one_or_none=None))

    app.dependency_overrides[get_db] = lambda: db

    unique_nonexistent = f"nonexistent_{uuid.uuid4().hex[:8]}"
    resp = _post(
        "/api/v1/auth/login",
        {
            "email": unique_nonexistent,
            "password": "AnyPassword123!",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 401
    err_text = resp.json().get("error") or resp.json().get("detail", "")
    assert "Incorrect email, username, or password" in err_text


@pytest.mark.asyncio
async def test_register_with_custom_username(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SELF_SIGNUP", True)
    user_role = Role(id=uuid.uuid4(), code="USER", name="User")

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=None),       # existing email lookup -> None
        _make_result(scalar_one_or_none=None),       # existing username lookup -> None
        _make_result(scalar_one_or_none=user_role),  # _get_or_create_role -> user_role
    ])
    db.add = MagicMock()
    db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db

    resp = _post(
        "/api/v1/auth/register",
        {
            "email": "hunter@soc.corp",
            "username": "threat_hunter_01",
            "password": "SecurePassword999!@#",
            "full_name": "Threat Hunter",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["user"]["email"] == "hunter@soc.corp"
    assert data["user"]["username"] == "threat_hunter_01"
