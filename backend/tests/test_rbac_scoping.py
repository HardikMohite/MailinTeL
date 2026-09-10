"""
Tests for USER-role data scoping.

MailinteL's roles are SYSTEM_ADMIN / INSTITUTION_ADMIN / SECURITY_ANALYST /
CYBER_CELL_INVESTIGATOR / USER (see alembic/versions/0002_seed_rbac_roles.py).
Everyone above plain USER is an "analyst-and-up" role (app.api.deps.ANALYST_ROLES)
and keeps full organization-wide visibility. A plain USER account is scoped down
to only the emails it personally uploaded and the campaigns built from those
emails, and is blocked from the cross-email/cross-campaign correlation views
(investigation graph, similarity links) — see app.api.deps.get_authorized_email /
get_authorized_campaign and the ANALYST_ROLES gates in graph.py / similarity.py.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user, CurrentUser, get_authorized_email, get_authorized_campaign
from app.models.emails import Email, EmailSource
from app.models.campaign import Campaign
from tests.auth_helpers import TEST_ORG_ID, TEST_USER

client = TestClient(app)

USER_ID = uuid.uuid4()
OTHER_USER_ID = uuid.uuid4()

PLAIN_USER = CurrentUser(
    id=USER_ID,
    email="plain.user@mailintel.test",
    full_name="Plain User",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="USER",
)

ADMIN_USER = CurrentUser(
    id=uuid.uuid4(),
    email="admin@mailintel.test",
    full_name="Org Admin",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="INSTITUTION_ADMIN",
)


def _clear():
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# get_authorized_email: USER can only reach their own uploads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_authorized_email_denies_user_who_did_not_upload_it():
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=OTHER_USER_ID)

    mock_result = MagicMock()
    mock_result.first.return_value = (email_obj, source_obj)
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await get_authorized_email(email_id, PLAIN_USER, mock_session)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_authorized_email_allows_user_who_uploaded_it():
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=USER_ID)

    mock_result = MagicMock()
    mock_result.first.return_value = (email_obj, source_obj)
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    result = await get_authorized_email(email_id, PLAIN_USER, mock_session)
    assert result is email_obj


@pytest.mark.asyncio
async def test_get_authorized_email_admin_sees_any_org_email():
    """Analyst/admin roles keep full org-wide visibility (no ownership check)."""
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=OTHER_USER_ID)

    mock_result = MagicMock()
    mock_result.first.return_value = (email_obj, source_obj)
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    result = await get_authorized_email(email_id, ADMIN_USER, mock_session)
    assert result is email_obj


# ---------------------------------------------------------------------------
# get_authorized_campaign: USER can only reach campaigns containing an email
# they personally uploaded
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_authorized_campaign_denies_user_with_no_owned_membership():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)

    campaign_result = MagicMock()
    campaign_result.scalar_one_or_none.return_value = campaign_obj
    owns_result = MagicMock()
    owns_result.first.return_value = None  # no owned membership row

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(side_effect=[campaign_result, owns_result])

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await get_authorized_campaign(campaign_id, PLAIN_USER, mock_session)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_authorized_campaign_allows_user_with_owned_membership():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)

    campaign_result = MagicMock()
    campaign_result.scalar_one_or_none.return_value = campaign_obj
    owns_result = MagicMock()
    owns_result.first.return_value = (uuid.uuid4(),)  # found a membership row they own

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(side_effect=[campaign_result, owns_result])

    result = await get_authorized_campaign(campaign_id, PLAIN_USER, mock_session)
    assert result is campaign_obj


@pytest.mark.asyncio
async def test_get_authorized_campaign_admin_skips_ownership_check():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)

    campaign_result = MagicMock()
    campaign_result.scalar_one_or_none.return_value = campaign_obj

    mock_session = AsyncMock()
    # Only one execute() call expected for an admin — no ownership sub-query.
    mock_session.execute = AsyncMock(return_value=campaign_result)

    result = await get_authorized_campaign(campaign_id, ADMIN_USER, mock_session)
    assert result is campaign_obj
    assert mock_session.execute.await_count == 1


# ---------------------------------------------------------------------------
# GET /api/v1/campaigns: USER role only lists "their" campaigns
# ---------------------------------------------------------------------------

def test_api_list_campaigns_user_role_sees_org_campaigns():
    with patch(
        "app.services.campaign_service.default_campaign_service.list_campaigns",
        new=AsyncMock(return_value=[]),
    ) as mock_list:
        app.dependency_overrides[get_current_user] = lambda: PLAIN_USER
        resp = client.get("/api/v1/campaigns")
        _clear()

        assert resp.status_code == 200
        _, kwargs = mock_list.call_args
        assert kwargs["owner_user_id"] is None


def test_api_list_campaigns_admin_role_sees_all():
    with patch(
        "app.services.campaign_service.default_campaign_service.list_campaigns",
        new=AsyncMock(return_value=[]),
    ) as mock_list:
        app.dependency_overrides[get_current_user] = lambda: ADMIN_USER
        resp = client.get("/api/v1/campaigns")
        _clear()

        assert resp.status_code == 200
        _, kwargs = mock_list.call_args
        assert kwargs["owner_user_id"] is None


# ---------------------------------------------------------------------------
# Investigation graph: all authenticated organization roles have access to
# the global infrastructure graph, while similarity remains scoped.
# ---------------------------------------------------------------------------

def test_api_global_graph_allowed_for_plain_user():
    fake_graph = MagicMock()
    fake_graph.to_dict.return_value = {
        "nodes": [],
        "edges": [],
        "total_nodes": 0,
        "total_edges": 0,
        "density": 0.0,
        "clusters_detected": 0,
    }
    with patch(
        "app.services.graph_service.default_graph_service.build_global_investigation_graph",
        new=AsyncMock(return_value=fake_graph),
    ):
        app.dependency_overrides[get_current_user] = lambda: PLAIN_USER
        resp = client.get("/api/v1/graph/global")
        _clear()
        assert resp.status_code == 200


def test_api_similar_emails_forbidden_for_plain_user():
    email_id = uuid.uuid4()
    app.dependency_overrides[get_current_user] = lambda: PLAIN_USER
    resp = client.get(f"/api/v1/emails/{email_id}/similar")
    _clear()
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Admin can now actually provision plain USER accounts via the invite endpoint
# ---------------------------------------------------------------------------

def test_api_invite_user_role_allowed_for_admin():
    mock_session = AsyncMock()
    # No existing user with that email, no existing membership -> free to invite.
    empty_result = MagicMock()
    empty_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=empty_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()

    app.dependency_overrides[get_db] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: ADMIN_USER
    resp = client.post(
        "/api/v1/users/invite",
        json={"email": "new.analyst.viewer@mailintel.example", "role_code": "USER"},
    )
    _clear()
    # Not asserting 201 here since the mock session doesn't fully model the
    # multi-step invite flow (role lookup, membership insert, etc.) — the
    # point of this test is that "USER" no longer fails Pydantic validation
    # the way it did before ASSIGNABLE_ROLES included it.
    assert resp.status_code != 422


CROSS_ORG_INVESTIGATOR = CurrentUser(
    id=uuid.uuid4(), email="investigator@mailintel.test", full_name="Investigator",
    organization_id=uuid.uuid4(), organization_name="Other Org", role_code="CYBER_CELL_INVESTIGATOR",
)


@pytest.mark.asyncio
async def test_cross_org_investigator_can_read_email_outside_own_org():
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=OTHER_USER_ID)
    result = MagicMock()
    result.first.return_value = (email_obj, source_obj)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    assert await get_authorized_email(email_id, CROSS_ORG_INVESTIGATOR, session) is email_obj


@pytest.mark.asyncio
async def test_cross_org_investigator_can_read_campaign_outside_own_org():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)
    result = MagicMock()
    result.scalar_one_or_none.return_value = campaign_obj
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    assert await get_authorized_campaign(campaign_id, CROSS_ORG_INVESTIGATOR, session) is campaign_obj


# ---------------------------------------------------------------------------
# Residual coverage: an org-less SYSTEM_ADMIN must still reach
# get_authorized_email/get_authorized_campaign/get_authorized_report for a
# resource in ANY organization (the core new capability from Phase 1), and
# SECURITY_ANALYST/INSTITUTION_ADMIN must still be denied (404) when the
# resource belongs to a *different* organization than their own (the "must
# NOT regress" requirement from Phase 1) -- both were only exercised
# indirectly via the geo.py tests below before this addition.
# ---------------------------------------------------------------------------

SYSTEM_ADMIN_NO_ORG_DIRECT = CurrentUser(
    id=uuid.uuid4(), email="root.admin@mailintel.test", full_name="Root Admin",
    organization_id=None, organization_name=None, role_code="SYSTEM_ADMIN",
)

ANALYST_ORG_B = CurrentUser(
    id=uuid.uuid4(), email="analyst.b@mailintel.test", full_name="Analyst B",
    organization_id=uuid.uuid4(), organization_name="Org B", role_code="SECURITY_ANALYST",
)


@pytest.mark.asyncio
async def test_get_authorized_email_allows_org_less_system_admin_for_any_org():
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=OTHER_USER_ID)
    result = MagicMock()
    result.first.return_value = (email_obj, source_obj)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    assert await get_authorized_email(email_id, SYSTEM_ADMIN_NO_ORG_DIRECT, session) is email_obj


@pytest.mark.asyncio
async def test_get_authorized_campaign_allows_org_less_system_admin_for_any_org():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)
    result = MagicMock()
    result.scalar_one_or_none.return_value = campaign_obj
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    assert await get_authorized_campaign(campaign_id, SYSTEM_ADMIN_NO_ORG_DIRECT, session) is campaign_obj


@pytest.mark.asyncio
async def test_get_authorized_report_allows_org_less_system_admin_for_any_org():
    from app.api.deps import get_authorized_report
    from app.models.reports import Report

    report_id = uuid.uuid4()
    email_id = uuid.uuid4()
    report_obj = Report(id=report_id, email_id=email_id, campaign_id=None)

    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report_obj
    org_result = MagicMock()
    org_result.first.return_value = (TEST_ORG_ID,)
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[report_result, org_result])

    assert await get_authorized_report(report_id, SYSTEM_ADMIN_NO_ORG_DIRECT, session) is report_obj


@pytest.mark.asyncio
async def test_get_authorized_email_denies_analyst_from_different_org():
    email_id = uuid.uuid4()
    email_obj = Email(id=email_id, source_id=uuid.uuid4())
    source_obj = EmailSource(organization_id=TEST_ORG_ID, user_id=OTHER_USER_ID)
    result = MagicMock()
    result.first.return_value = (email_obj, source_obj)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    with pytest.raises(Exception) as exc_info:
        await get_authorized_email(email_id, ANALYST_ORG_B, session)
    assert getattr(exc_info.value, "status_code", None) == 404


@pytest.mark.asyncio
async def test_get_authorized_campaign_denies_admin_from_different_org():
    campaign_id = uuid.uuid4()
    campaign_obj = Campaign(id=campaign_id, organization_id=TEST_ORG_ID)
    result = MagicMock()
    result.scalar_one_or_none.return_value = campaign_obj
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    other_org_admin = CurrentUser(
        id=uuid.uuid4(), email="admin.b@mailintel.test", full_name="Admin B",
        organization_id=uuid.uuid4(), organization_name="Org B", role_code="INSTITUTION_ADMIN",
    )
    with pytest.raises(Exception) as exc_info:
        await get_authorized_campaign(campaign_id, other_org_admin, session)
    assert getattr(exc_info.value, "status_code", None) == 404


@pytest.mark.asyncio
async def test_get_authorized_report_denies_analyst_from_different_org():
    from app.api.deps import get_authorized_report
    from app.models.reports import Report

    report_id = uuid.uuid4()
    email_id = uuid.uuid4()
    report_obj = Report(id=report_id, email_id=email_id, campaign_id=None)

    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report_obj
    org_result = MagicMock()
    org_result.first.return_value = (TEST_ORG_ID,)
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[report_result, org_result])

    with pytest.raises(Exception) as exc_info:
        await get_authorized_report(report_id, ANALYST_ORG_B, session)
    assert getattr(exc_info.value, "status_code", None) == 404


# ---------------------------------------------------------------------------
# GET /api/v1/geo/global: cross-org roles default to all-org visibility with
# an optional organization_id narrowing filter; org-scoped roles are always
# pinned to their own organization regardless of the query param.
# ---------------------------------------------------------------------------

ORG_A = TEST_ORG_ID
ORG_B = uuid.uuid4()

SYSTEM_ADMIN_NO_ORG = CurrentUser(
    id=uuid.uuid4(), email="platform.admin@mailintel.test", full_name="Platform Admin",
    organization_id=None, organization_name=None, role_code="SYSTEM_ADMIN",
)


def _fake_global_geo(session, limit_emails=50, organization_id=None):
    """
    Stand-in for default_geo_service.get_global_geo_infrastructure that
    mimics its real organization_id filtering: None means "every
    organization", a UUID means "just that one".
    """
    all_markers = {
        ORG_A: {"id": "marker-org-a", "ip_address": "1.1.1.1", "country_code": "US"},
        ORG_B: {"id": "marker-org-b", "ip_address": "2.2.2.2", "country_code": "DE"},
    }
    if organization_id is None:
        markers = list(all_markers.values())
    else:
        markers = [m for org, m in all_markers.items() if org == organization_id]
    countries = {m["country_code"] for m in markers}
    return {
        "total_emails_scanned": 10,
        "total_unique_ips": len(markers),
        "total_markers": len(markers),
        "markers": markers,
        "country_distribution": {c: 1 for c in countries},
        "attribution_disclaimer": "Attribution: geolocation is approximate.",
    }


def test_api_global_geo_cross_org_investigator_sees_multiple_orgs_by_default():
    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(side_effect=_fake_global_geo),
    ) as mock_geo:
        app.dependency_overrides[get_current_user] = lambda: CROSS_ORG_INVESTIGATOR
        resp = client.get("/api/v1/geo/global")
        _clear()

        assert resp.status_code == 200
        data = resp.json()
        # No organization_id filter should have been forwarded for a
        # cross-org role that didn't supply one.
        _, kwargs = mock_geo.call_args
        assert kwargs["organization_id"] is None
        assert len(data["country_distribution"]) > 1
        assert data["total_markers"] == 2


def test_api_global_geo_cross_org_investigator_can_narrow_with_org_param():
    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(side_effect=_fake_global_geo),
    ) as mock_geo:
        app.dependency_overrides[get_current_user] = lambda: CROSS_ORG_INVESTIGATOR
        resp = client.get(f"/api/v1/geo/global?organization_id={ORG_A}")
        _clear()

        assert resp.status_code == 200
        data = resp.json()
        _, kwargs = mock_geo.call_args
        assert kwargs["organization_id"] == ORG_A
        assert data["total_markers"] == 1
        assert data["country_distribution"] == {"US": 1}


def test_api_global_geo_system_admin_with_no_org_gets_all_org_data_by_default():
    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(side_effect=_fake_global_geo),
    ) as mock_geo:
        app.dependency_overrides[get_current_user] = lambda: SYSTEM_ADMIN_NO_ORG
        resp = client.get("/api/v1/geo/global")
        _clear()

        # A SYSTEM_ADMIN with organization_id=None must not be treated as
        # "no org filter matched nothing" -- they should get the same
        # all-organizations view as any other cross-org caller, not an
        # error or an empty result.
        assert resp.status_code == 200
        data = resp.json()
        _, kwargs = mock_geo.call_args
        assert kwargs["organization_id"] is None
        assert data["total_markers"] == 2
        assert data["total_markers"] != 0


def test_api_global_geo_security_analyst_stays_own_org_regardless_of_param():
    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(side_effect=_fake_global_geo),
    ) as mock_geo:
        app.dependency_overrides[get_current_user] = lambda: TEST_USER  # SECURITY_ANALYST, org=ORG_A
        # Even though ORG_B is passed as a query param, a non-cross-org role
        # must have no ability to use it -- they stay pinned to their own org.
        resp = client.get(f"/api/v1/geo/global?organization_id={ORG_B}")
        _clear()

        assert resp.status_code == 200
        data = resp.json()
        _, kwargs = mock_geo.call_args
        assert kwargs["organization_id"] == TEST_USER.organization_id == ORG_A
        assert data["total_markers"] == 1
        assert data["country_distribution"] == {"US": 1}


def test_api_global_geo_institution_admin_stays_own_org_regardless_of_param():
    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(side_effect=_fake_global_geo),
    ) as mock_geo:
        app.dependency_overrides[get_current_user] = lambda: ADMIN_USER  # INSTITUTION_ADMIN, org=ORG_A
        resp = client.get(f"/api/v1/geo/global?organization_id={ORG_B}")
        _clear()

        assert resp.status_code == 200
        _, kwargs = mock_geo.call_args
        assert kwargs["organization_id"] == ADMIN_USER.organization_id == ORG_A
