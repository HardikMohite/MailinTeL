import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.emails import EmailSource, Email, RelayHop
from app.models.campaign import Campaign, CampaignMembership
from app.intelligence.geo_resolver import (
    AsyncGeoIPResolver,
    GeoIPResult,
    default_geoip_resolver,
    ATTRIBUTION_DISCLAIMER,
)
from app.services.geo_service import GeolocationService, default_geo_service
from tests.auth_helpers import (
    TEST_USER,
    make_authorized_email_db_mock,
    make_authorized_campaign_db_mock,
)

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for geo endpoint tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.delete = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.flush = AsyncMock()
    return mock_session


@pytest.mark.asyncio
async def test_geoip_resolver_private_ip():
    resolver = AsyncGeoIPResolver()
    res = await resolver.resolve_ip_geolocation("192.168.1.50")
    assert res.is_private is True
    assert res.country_code == "PRIVATE"
    assert res.latitude is None
    assert res.longitude is None
    assert "Private RFC 1918" in res.attribution_statement


@pytest.mark.asyncio
async def test_geoip_resolver_public_subnet():
    resolver = AsyncGeoIPResolver()
    res = await resolver.resolve_ip_geolocation("8.8.8.8")
    assert res.is_private is False
    assert res.country_code == "US"
    assert res.country_name == "United States"
    assert res.latitude is not None
    assert res.longitude is not None
    assert ATTRIBUTION_DISCLAIMER in res.attribution_statement


@pytest.mark.asyncio
async def test_geoip_resolver_european_ip():
    resolver = AsyncGeoIPResolver()
    res = await resolver.resolve_ip_geolocation("185.220.101.5")
    assert res.is_private is False
    assert res.country_code in ("NL", "DE")
    assert res.country_name in ("Netherlands", "Germany")


@pytest.mark.asyncio
async def test_geo_service_geolocate_ip():
    geo_service = GeolocationService()
    mock_session = AsyncMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    res = await geo_service.geolocate_ip(mock_session, "1.1.1.1")
    assert res["ip_address"] == "1.1.1.1"
    assert res["country_code"] == "AU"
    assert res["city_name"] == "Sydney"
    assert res["latitude"] is not None
    assert res["longitude"] is not None
    assert res["confidence"] >= 80.0
    assert ATTRIBUTION_DISCLAIMER in res["attribution_statement"]


@pytest.mark.asyncio
async def test_geo_service_email_infrastructure():
    geo_service = GeolocationService()
    email_id = uuid.uuid4()

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Phishing infrastructure test",
        sender_address="attacker@evil-domain.com",
    )

    hop1 = RelayHop(
        id=uuid.uuid4(),
        email_id=email_id,
        sequence_number=1,
        source_host="origin.badhost.nl",
        source_ip="185.10.10.10",
        destination_host="transit.relay.de",
        reliability="HIGH",
    )
    hop2 = RelayHop(
        id=uuid.uuid4(),
        email_id=email_id,
        sequence_number=2,
        source_host="transit.relay.de",
        source_ip="3.120.0.1",
        destination_host="mx.google.com",
        reliability="HIGH",
    )
    hop3 = RelayHop(
        id=uuid.uuid4(),
        email_id=email_id,
        sequence_number=3,
        source_host="mx.google.com",
        source_ip="8.8.8.8",
        destination_host="internal.corp",
        reliability="HIGH",
    )

    mock_session = AsyncMock()

    async def mock_execute(query, *args, **kwargs):
        q_str = str(query)
        mock_res = MagicMock()
        if "FROM emails" in q_str:
            mock_res.scalar_one_or_none.return_value = mock_email
        elif "FROM relay_hops" in q_str:
            mock_res.scalars.return_value.all.return_value = [hop1, hop2, hop3]
        elif "FROM ip_addresses" in q_str:
            mock_res.scalar_one_or_none.return_value = None
        elif "FROM geolocations" in q_str:
            mock_res.scalar_one_or_none.return_value = None
        elif "FROM entity_geolocations" in q_str:
            mock_res.scalar_one_or_none.return_value = None
        else:
            mock_res.scalar_one_or_none.return_value = None
            mock_res.scalars.return_value.all.return_value = []
        return mock_res

    mock_session.execute = AsyncMock(side_effect=mock_execute)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    res = await geo_service.geolocate_email_infrastructure(mock_session, email_id)
    assert res["email_id"] == str(email_id)
    assert res["total_hops"] == 3
    assert res["total_markers"] >= 2
    assert len(res["paths"]) >= 2
    assert any(c in res["country_distribution"] for c in ("NL", "DK", "DE"))
    assert ATTRIBUTION_DISCLAIMER in res["attribution_disclaimer"]


@pytest.mark.asyncio
async def test_geo_service_campaign_infrastructure():
    geo_service = GeolocationService()
    camp_id = uuid.uuid4()
    email1_id = uuid.uuid4()
    email2_id = uuid.uuid4()

    mock_camp = Campaign(
        id=camp_id,
        campaign_name="Operation GeoTrace",
        campaign_status="ACTIVE",
    )

    h1 = RelayHop(
        id=uuid.uuid4(),
        email_id=email1_id,
        sequence_number=1,
        source_ip="52.1.2.3",
    )
    h2 = RelayHop(
        id=uuid.uuid4(),
        email_id=email2_id,
        sequence_number=1,
        source_ip="195.10.10.10",
    )

    mock_session = AsyncMock()

    async def mock_execute(query, *args, **kwargs):
        q_str = str(query)
        mock_res = MagicMock()
        if "FROM campaigns" in q_str:
            mock_res.scalar_one_or_none.return_value = mock_camp
        elif "FROM campaign_memberships" in q_str:
            mock_res.scalars.return_value.all.return_value = [email1_id, email2_id]
        elif "FROM relay_hops" in q_str:
            mock_res.scalars.return_value.all.return_value = [h1, h2]
        else:
            mock_res.scalar_one_or_none.return_value = None
            mock_res.scalars.return_value.all.return_value = []
        return mock_res

    mock_session.execute = AsyncMock(side_effect=mock_execute)
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    res = await geo_service.geolocate_campaign_infrastructure(mock_session, camp_id)
    assert res["campaign_id"] == str(camp_id)
    assert res["total_emails"] == 2
    assert res["total_unique_ips"] == 2
    assert res["total_markers"] == 2
    assert "US" in res["country_distribution"]
    assert any(c in res["country_distribution"] for c in ("GB", "IT", "DE"))


def test_api_get_ip_geo_endpoint(mock_db_session):
    mock_data = {
        "ip_address": "8.8.8.8",
        "is_private": False,
        "country_code": "US",
        "country_name": "United States",
        "region_name": "California",
        "city_name": "Mountain View",
        "latitude": 37.4220,
        "longitude": -122.0841,
        "accuracy_radius_km": 15,
        "source": "SUBNET_REGISTRY",
        "confidence": 90.0,
        "attribution_statement": ATTRIBUTION_DISCLAIMER,
    }

    with patch(
        "app.services.geo_service.default_geo_service.geolocate_ip",
        new=AsyncMock(return_value=mock_data),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get("/api/v1/geo/ip/8.8.8.8")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip_address"] == "8.8.8.8"
        assert data["country_code"] == "US"
        assert ATTRIBUTION_DISCLAIMER in data["attribution_statement"]


def test_api_get_email_geo_endpoint():
    email_id = uuid.uuid4()
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="attacker@evil-domain.com",
    )
    mock_db_session = make_authorized_email_db_mock(mock_email)

    mock_data = {
        "email_id": str(email_id),
        "subject": "Test Geo Subject",
        "total_hops": 1,
        "total_markers": 1,
        "hops": [],
        "markers": [
            {
                "id": "marker-1",
                "entity_type": "RELAY_HOP",
                "sequence_number": 1,
                "ip_address": "8.8.8.8",
                "host": "dns.google",
                "latitude": 37.422,
                "longitude": -122.084,
                "country_code": "US",
                "country_name": "United States",
                "confidence": 90.0,
            }
        ],
        "paths": [],
        "country_distribution": {"US": 1},
        "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
    }

    with patch(
        "app.services.geo_service.default_geo_service.geolocate_email_infrastructure",
        new=AsyncMock(return_value=mock_data),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/geo/email/{email_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == str(email_id)
        assert data["total_markers"] == 1
        assert ATTRIBUTION_DISCLAIMER in data["attribution_disclaimer"]


def test_api_get_campaign_geo_endpoint():
    camp_id = uuid.uuid4()
    mock_camp = Campaign(
        id=camp_id,
        campaign_name="Campaign Geo Alpha",
        campaign_status="ACTIVE",
    )
    mock_db_session = make_authorized_campaign_db_mock(mock_camp)

    mock_data = {
        "campaign_id": str(camp_id),
        "campaign_name": "Campaign Geo Alpha",
        "campaign_status": "ACTIVE",
        "total_emails": 3,
        "total_unique_ips": 2,
        "total_markers": 2,
        "markers": [],
        "country_distribution": {"US": 2},
        "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
    }

    with patch(
        "app.services.geo_service.default_geo_service.geolocate_campaign_infrastructure",
        new=AsyncMock(return_value=mock_data),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/geo/campaign/{camp_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["campaign_id"] == str(camp_id)
        assert data["total_emails"] == 3


def test_api_get_global_geo_endpoint(mock_db_session):
    mock_data = {
        "total_emails_scanned": 10,
        "total_unique_ips": 5,
        "total_markers": 5,
        "markers": [],
        "country_distribution": {"US": 3, "DE": 2},
        "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
    }

    with patch(
        "app.services.geo_service.default_geo_service.get_global_geo_infrastructure",
        new=AsyncMock(return_value=mock_data),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get("/api/v1/geo/global")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_emails_scanned"] == 10
        assert ATTRIBUTION_DISCLAIMER in data["attribution_disclaimer"]


@pytest.mark.asyncio
async def test_geo_classification_tor_vpn_cloud_personal_mail():
    geo_service = GeolocationService()
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_session.add = MagicMock()

    # 1. Tor Node
    tor_res = await geo_service.geolocate_ip(mock_session, "185.220.101.5", host="tor-exit-01.relays.net")
    assert tor_res["is_tor"] is True
    assert tor_res["connection_type"] == "TOR"

    # 2. VPN Node
    vpn_res = await geo_service.geolocate_ip(mock_session, "194.26.29.1", host="nl-ams-wg-001.nordvpn.com")
    assert vpn_res["is_vpn"] is True
    assert vpn_res["connection_type"] == "VPN"

    # 3. Cloud Server (AWS)
    cloud_res = await geo_service.geolocate_ip(mock_session, "54.210.1.2", host="ec2-54-210-1-2.compute-1.amazonaws.com")
    assert cloud_res["is_cloud"] is True or cloud_res["is_datacenter"] is True
    assert cloud_res["connection_type"] == "CLOUD"

    # 4. Personal Mail (Gmail Webmail)
    mail_res = await geo_service.geolocate_ip(mock_session, "209.85.220.41", host="mail-sor-f41.google.com")
    assert mail_res["is_personal_mail"] is True
    assert mail_res["connection_type"] == "PERSONAL_MAIL"

