import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from httpx import Response
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.intelligence.infrastructure_intel import (
    AsyncReverseDNSResolver,
    AsyncASNResolver,
    InfrastructureClassifier,
    InfrastructureIntelligenceEngine,
    InfrastructureClassificationData,
    IPIntelBundle,
)
from app.services.infrastructure_service import (
    enrich_and_persist_ip_intelligence,
    enrich_email_infrastructure,
)
from app.models.emails import Email, RelayHop, EmailSource
from app.models.intelligence import (
    IPAddress,
    IPIntelligence,
    InfrastructureClassification,
)
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for infrastructure tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.delete = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.flush = AsyncMock()
    return mock_session


# ---------------------------------------------------------
# Unit Tests: AsyncReverseDNSResolver
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_reverse_dns_resolver_private_ip_skipped():
    resolver = AsyncReverseDNSResolver()
    res = await resolver.resolve_ptr("192.168.1.1")
    assert res is None

    res_loopback = await resolver.resolve_ptr("127.0.0.1")
    assert res_loopback is None


@pytest.mark.asyncio
async def test_reverse_dns_resolver_success():
    resolver = AsyncReverseDNSResolver()
    mock_target = MagicMock()
    mock_target.__str__.return_value = "mail-out.protection.outlook.com."

    mock_answer = [MagicMock(target=mock_target)]
    with patch.object(resolver.resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer
        ptr = await resolver.resolve_ptr("52.100.1.2")
        assert ptr == "mail-out.protection.outlook.com"


@pytest.mark.asyncio
async def test_reverse_dns_resolver_graceful_failure():
    resolver = AsyncReverseDNSResolver()
    with patch.object(resolver.resolver, "resolve", side_effect=Exception("Timeout")):
        ptr = await resolver.resolve_ptr("8.8.8.8")
        assert ptr is None


# ---------------------------------------------------------
# Unit Tests: AsyncASNResolver
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_asn_resolver_private_ip_returns_default():
    resolver = AsyncASNResolver()
    res = await resolver.query_ip_metadata("10.0.0.1")
    assert res["asn"] is None
    assert res["isp"] is None


@pytest.mark.asyncio
async def test_asn_resolver_rdap_success():
    resolver = AsyncASNResolver()
    mock_data = {
        "name": "AMAZON-AES",
        "country": "US",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Amazon.com, Inc."]],
                ],
            }
        ],
        "links": [{"href": "https://rdap.arin.net/registry/autnum/16509"}],
    }

    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
         patch("app.intelligence.infrastructure_intel.maxmind_client.lookup_asn", return_value=None):
        mock_get.return_value = mock_resp
        result = await resolver.query_ip_metadata("54.240.1.1")

        assert result["asn"] == "AS16509"
        assert result["isp"] == "Amazon.com, Inc."
        assert result["network_owner"] == "AMAZON-AES"
        assert result["country_code"] == "US"


# ---------------------------------------------------------
# Unit Tests: InfrastructureClassifier
# ---------------------------------------------------------

def test_classifier_private_ip():
    classifier = InfrastructureClassifier()
    classifications, risk_level, risk_tags = classifier.classify_ip(
        ip_str="192.168.1.100",
        reverse_dns=None,
        asn_metadata={},
    )
    assert len(classifications) == 1
    assert classifications[0].classification_type == "INTERNAL_PRIVATE_NETWORK"
    assert classifications[0].confidence == 1.0
    assert risk_level == "LOW"
    assert "INTERNAL_RFC1918_PRIVATE" in risk_tags


def test_classifier_tor_exit_node():
    classifier = InfrastructureClassifier(known_tor_exits={"185.220.101.5"})
    classifications, risk_level, risk_tags = classifier.classify_ip(
        ip_str="185.220.101.5",
        reverse_dns="tor-exit-01.relays.net",
        asn_metadata={},
    )
    tor_class = [c for c in classifications if c.classification_type == "TOR"]
    assert len(tor_class) == 1
    assert tor_class[0].confidence == 0.95
    assert risk_level == "HIGH"
    assert "TOR_EXIT_NODE" in risk_tags


def test_classifier_cloud_hosted_aws():
    classifier = InfrastructureClassifier()
    classifications, risk_level, risk_tags = classifier.classify_ip(
        ip_str="54.210.1.2",
        reverse_dns="ec2-54-210-1-2.compute-1.amazonaws.com",
        asn_metadata={"asn": "AS16509", "isp": "Amazon.com, Inc."},
    )
    cloud_class = [c for c in classifications if c.classification_type == "CLOUD_HOSTED"]
    assert len(cloud_class) >= 1
    assert cloud_class[0].confidence == 0.95
    assert risk_level == "MEDIUM"


def test_classifier_vpn_proxy():
    classifier = InfrastructureClassifier()
    classifications, risk_level, risk_tags = classifier.classify_ip(
        ip_str="194.26.29.1",
        reverse_dns="nl-ams-wg-001.nordvpn.com",
        asn_metadata={"isp": "NordVPN / Datacamp Limited"},
    )
    vpn_class = [c for c in classifications if c.classification_type == "VPN"]
    assert len(vpn_class) == 1
    assert vpn_class[0].confidence == 0.90
    assert risk_level == "HIGH"
    assert "VPN_OR_PROXY_PROVIDER" in risk_tags


def test_classifier_residential_isp():
    classifier = InfrastructureClassifier()
    classifications, risk_level, risk_tags = classifier.classify_ip(
        ip_str="73.150.20.1",
        reverse_dns="c-73-150-20-1.hsd1.va.comcast.net",
        asn_metadata={"asn": "AS7922", "isp": "Comcast Cable Communications, LLC"},
    )
    isp_class = [c for c in classifications if c.classification_type == "RESIDENTIAL_ISP"]
    assert len(isp_class) == 1
    assert risk_level == "LOW"
    assert "RESIDENTIAL_BROADBAND" in risk_tags


# ---------------------------------------------------------
# Unit Tests: InfrastructureIntelligenceEngine
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_analyze_ip():
    mock_ptr = AsyncMock(spec=AsyncReverseDNSResolver)
    mock_ptr.resolve_ptr.return_value = "mail-ej1-f49.google.com"

    mock_asn = AsyncMock(spec=AsyncASNResolver)
    mock_asn.query_ip_metadata.return_value = {
        "asn": "AS15169",
        "asn_org": "Google LLC",
        "isp": "Google LLC",
        "network_owner": "GOOGLE",
        "country_code": "US",
    }

    engine = InfrastructureIntelligenceEngine(ptr_resolver=mock_ptr, asn_resolver=mock_asn)
    bundle = await engine.analyze_ip("209.85.218.49")

    assert bundle.ip_address == "209.85.218.49"
    assert bundle.ip_type == "PUBLIC"
    assert bundle.is_private is False
    assert bundle.reverse_dns == "mail-ej1-f49.google.com"
    assert bundle.asn == "AS15169"
    assert bundle.country_code == "US"
    assert any(c.classification_type == "CLOUD_HOSTED" for c in bundle.classifications)


# ---------------------------------------------------------
# Integration Tests: DB Persistence & Service Layer
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_enrich_and_persist_ip_intelligence(mock_db_session):
    mock_ptr = AsyncMock(spec=AsyncReverseDNSResolver)
    mock_ptr.resolve_ptr.return_value = "outbound.protection.outlook.com"

    mock_asn = AsyncMock(spec=AsyncASNResolver)
    mock_asn.query_ip_metadata.return_value = {
        "asn": "AS8075",
        "isp": "Microsoft Corporation",
        "country_code": "US",
    }

    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_res

    engine = InfrastructureIntelligenceEngine(ptr_resolver=mock_ptr, asn_resolver=mock_asn)

    bundle = await enrich_and_persist_ip_intelligence(
        ip_str="40.92.1.2",
        db=mock_db_session,
        engine=engine,
    )

    assert bundle.ip_address == "40.92.1.2"
    assert bundle.asn == "AS8075"
    assert mock_db_session.add.called
    assert mock_db_session.commit.called


# ---------------------------------------------------------
# Integration Tests: REST API Endpoints
# ---------------------------------------------------------

def test_api_get_ip_intelligence(mock_db_session):
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.services.infrastructure_service.enrich_and_persist_ip_intelligence") as mock_enrich:
        mock_enrich.return_value = IPIntelBundle(
            ip_address="185.220.101.5",
            ip_type="PUBLIC",
            is_private=False,
            reverse_dns="tor-exit.relay.net",
            asn="AS208323",
            isp="Tor Network Operator",
            country_code="DE",
            classifications=[
                InfrastructureClassificationData(
                    classification_type="TOR",
                    confidence=0.95,
                    source="TOR_EXIT_LIST",
                )
            ],
            risk_level="HIGH",
            risk_tags=["TOR_EXIT_NODE"],
        )

        response = client.get("/api/v1/intelligence/ips/185.220.101.5")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["ip_address"] == "185.220.101.5"
        assert data["risk_level"] == "HIGH"
        assert data["country_code"] == "DE"
        assert len(data["classifications"]) == 1
        assert data["classifications"][0]["classification_type"] == "TOR"


def test_api_get_email_infrastructure_intelligence(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="alert@phish.net",
        analysis_status="EXTRACTED",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_res = MagicMock()
    mock_res.first.return_value = (email, EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id, source_type="FILE_UPLOAD"))
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.services.infrastructure_service.enrich_email_infrastructure") as mock_enrich_email:
        mock_enrich_email.return_value = [
            IPIntelBundle(
                ip_address="194.26.29.1",
                ip_type="PUBLIC",
                is_private=False,
                asn="AS9009",
                isp="M247 Europe",
                classifications=[
                    InfrastructureClassificationData(
                        classification_type="VPN",
                        confidence=0.90,
                        source="KEYWORD_MATCH",
                    )
                ],
                risk_level="HIGH",
                risk_tags=["VPN_OR_PROXY_PROVIDER"],
            )
        ]

        response = client.get(f"/api/v1/intelligence/emails/{email_id}/infrastructure")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["email_id"] == str(email_id)
        assert data["total_ips_analyzed"] == 1
        assert data["has_vpn_relay"] is True
        assert data["has_tor_relay"] is False
        assert data["ips"][0]["ip_address"] == "194.26.29.1"
