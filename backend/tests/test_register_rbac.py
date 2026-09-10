import uuid
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import get_db
from app.models.identity import Role

client = TestClient(app)



def _make_result(*, scalar_one_or_none=None):
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar_one_or_none
    return result


@pytest.mark.asyncio
async def test_self_registration_always_assigns_user_role(monkeypatch):
    """Verifies that self-registration strictly assigns standard USER role,
    even if an organization name is supplied."""
    monkeypatch.setattr(settings, "ALLOW_SELF_SIGNUP", True)
    user_role = Role(id=uuid.uuid4(), code="USER", name="User")

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=None),       # existing user lookup -> None
        _make_result(scalar_one_or_none=user_role),  # _get_or_create_role -> user_role
    ])
    db.add = MagicMock()
    db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db

    # 1. Register with a custom organization name
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "new.member@institute.ac.in",
            "password": "StrongPassword123!@#",
            "full_name": "New Institute Member",
            "organization_name": "Cyber Defense Institute",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 201, resp.text
    data = resp.json()
    # MUST strictly be USER, never INSTITUTION_ADMIN
    assert data["user"]["role"] == "USER"
    assert data["user"]["organization_name"] == "Cyber Defense Institute"


@pytest.mark.asyncio
async def test_self_registration_personal_workspace_assigns_user_role(monkeypatch):
    """Verifies that self-registration without organization name assigns USER role in Personal Workspace."""
    monkeypatch.setattr(settings, "ALLOW_SELF_SIGNUP", True)
    user_role = Role(id=uuid.uuid4(), code="USER", name="User")

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[
        _make_result(scalar_one_or_none=None),       # existing user lookup -> None
        _make_result(scalar_one_or_none=user_role),  # _get_or_create_role -> user_role
    ])
    db.add = MagicMock()
    db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db

    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "solo.user@example.com",
            "password": "StrongPassword123!@#",
            "full_name": "Solo Analyst",
        },
    )
    app.dependency_overrides.clear()

    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["user"]["role"] == "USER"
    assert data["user"]["organization_name"] == "Personal Workspace"

