import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.db.init_db import init_admin_account
from app.core.config import settings


@pytest.mark.asyncio
async def test_init_admin_account_disabled_when_empty():
    with patch.object(settings, "ADMIN_EMAIL", None), \
         patch.object(settings, "ADMIN_PASSWORD", None):
        result = await init_admin_account()
        assert result is False


@pytest.mark.asyncio
async def test_init_admin_account_provisions_new_user():
    mock_session = AsyncMock()

    # 1. Check existing user: None
    mock_user_res = MagicMock()
    mock_user_res.scalar_one_or_none.return_value = None

    # 2. Check role: None (triggers create)
    mock_role_res = MagicMock()
    mock_role_res.scalar_one_or_none.return_value = None

    # 3. Check org: None (triggers create)
    mock_org_res = MagicMock()
    mock_org_res.scalar_one_or_none.return_value = None

    mock_session.execute.side_effect = [mock_user_res, mock_role_res, mock_org_res]

    with patch.object(settings, "ADMIN_EMAIL", "admin@mailintel.local"), \
         patch.object(settings, "ADMIN_PASSWORD", "SuperSecurePassword123!"), \
         patch.object(settings, "ADMIN_FULL_NAME", "Lead Admin"), \
         patch.object(settings, "ADMIN_ORG_NAME", "SOC Team"):
        result = await init_admin_account(db=mock_session)
        assert result is True
        assert mock_session.add.call_count >= 3  # Role, Org, User, Membership
        assert mock_session.commit.called


@pytest.mark.asyncio
async def test_init_admin_account_skips_existing_user():
    mock_session = AsyncMock()

    # User already exists
    mock_user_res = MagicMock()
    mock_user_res.scalar_one_or_none.return_value = MagicMock()
    mock_session.execute.return_value = mock_user_res

    with patch.object(settings, "ADMIN_EMAIL", "admin@mailintel.local"), \
         patch.object(settings, "ADMIN_PASSWORD", "SuperSecurePassword123!"):
        result = await init_admin_account(db=mock_session)
        assert result is False
        assert not mock_session.commit.called
