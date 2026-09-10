import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from httpx import Response
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.intelligence.adapters.base import ThreatIntelReport
from app.intelligence.adapters.virustotal import VirusTotalAdapter
from app.intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.intelligence.adapters.urlhaus import URLHausAdapter
from app.intelligence.adapters.internal_reputation import (
    InternalReputationAdapter,
    calculate_entropy,
)
from app.intelligence.threat_intel_engine import (
    ThreatIntelEngine,
    AggregatedThreatIntel,
)
from app.services.threat_intel_service import (
    enrich_and_persist_indicator,
    enrich_email_threat_intelligence,
)
from app.models.emails import Email, EmailSource, RelayHop
from app.models.intelligence import Domain, URL, EmailURL, IPAddress
from app.models.evidence import EvidenceObject
from app.models.indicators import ThreatIndicator, IndicatorSighting
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for threat intel tests."""
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
# Unit Tests: Adapters
# ---------------------------------------------------------

def test_entropy_calculation():
    # Low entropy for repetitive strings
    assert calculate_entropy("aaaaaaa") == 0.0
    # High entropy for random DGA string
    dga_entropy = calculate_entropy("xkcd983hfd8234")
    assert dga_entropy > 3.0


@pytest.mark.asyncio
async def test_internal_reputation_phishing_domain():
    adapter = InternalReputationAdapter()
    rep = await adapter.query_domain("secure-login-verify-account.top")
    assert rep is not None
    assert rep.verdict in ("MALICIOUS", "SUSPICIOUS")
    assert rep.threat_score >= 50.0
    assert "SUSPICIOUS_TLD_TOP" in rep.tags
    assert "MULTIPLE_PHISHING_KEYWORDS" in rep.tags


@pytest.mark.asyncio
async def test_internal_reputation_url_with_ip_and_payload():
    adapter = InternalReputationAdapter()
    rep = await adapter.query_url("http://198.51.100.22/update/invoice.exe")
    assert rep is not None
    assert rep.verdict == "MALICIOUS"
    assert rep.threat_score >= 70.0
    assert "IP_ADDRESS_IN_URL_HOST" in rep.tags
    assert "EXECUTABLE_PAYLOAD_DOWNLOAD" in rep.tags


@pytest.mark.asyncio
async def test_virustotal_adapter_disabled_without_key():
    adapter = VirusTotalAdapter(api_key="")
    assert adapter.is_enabled is False
    rep = await adapter.query_ip("1.2.3.4")
    assert rep is None


@pytest.mark.asyncio
async def test_virustotal_adapter_query_ip_success():
    adapter = VirusTotalAdapter(api_key="test-api-key")
    assert adapter.is_enabled is True

    mock_json = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 20,
                }
            }
        }
    }
    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        rep = await adapter.query_ip("198.51.100.5")

        assert rep is not None
        assert rep.provider == "VIRUSTOTAL"
        assert rep.verdict == "MALICIOUS"
        assert rep.malicious_votes == 12
        assert rep.threat_score >= 80.0


@pytest.mark.asyncio
async def test_abuseipdb_adapter_query_ip_success():
    adapter = AbuseIPDBAdapter(api_key="test-abuse-key")
    assert adapter.is_enabled is True

    mock_json = {
        "data": {
            "ipAddress": "185.220.101.5",
            "abuseConfidenceScore": 85,
            "totalReports": 34,
            "isWhitelisted": False,
        }
    }
    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        rep = await adapter.query_ip("185.220.101.5")

        assert rep is not None
        assert rep.provider == "ABUSEIPDB"
        assert rep.verdict == "MALICIOUS"
        assert rep.threat_score == 85.0
        assert "HIGH_ABUSE_REPORTS" in rep.tags


@pytest.mark.asyncio
async def test_urlhaus_adapter_query_url_malicious():
    adapter = URLHausAdapter()
    mock_json = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["Mozi", "elf"],
    }
    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        rep = await adapter.query_url("http://malware-drop.xyz/bin.sh")

        assert rep is not None
        assert rep.provider == "URLHAUS"
        assert rep.verdict == "MALICIOUS"
        assert rep.threat_score >= 90.0
        assert "URLHAUS_MALWARE_DOWNLOAD" in rep.tags


# ---------------------------------------------------------
# Unit Tests: ThreatIntelEngine Consensus
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_threat_intel_engine_consensus_multi_provider():
    mock_vt = AsyncMock()
    mock_vt.is_enabled = True
    mock_vt.query_url.return_value = ThreatIntelReport(
        indicator_type="URL",
        indicator_value="https://phish-secure.com",
        provider="VIRUSTOTAL",
        verdict="MALICIOUS",
        threat_score=85.0,
        confidence=0.90,
        tags=["VIRUSTOTAL_PHISH"],
        malicious_votes=8,
    )

    mock_urlhaus = AsyncMock()
    mock_urlhaus.is_enabled = True
    mock_urlhaus.query_url.return_value = ThreatIntelReport(
        indicator_type="URL",
        indicator_value="https://phish-secure.com",
        provider="URLHAUS",
        verdict="MALICIOUS",
        threat_score=95.0,
        confidence=0.95,
        tags=["URLHAUS_MALWARE"],
        malicious_votes=1,
    )

    engine = ThreatIntelEngine(adapters=[mock_vt, mock_urlhaus])
    agg = await engine.query_indicator("URL", "https://phish-secure.com")

    assert agg.consensus_verdict == "MALICIOUS"
    assert agg.consensus_threat_score >= 90.0
    assert agg.consensus_confidence >= 0.95
    assert "VIRUSTOTAL_PHISH" in agg.aggregated_tags
    assert "URLHAUS_MALWARE" in agg.aggregated_tags
    assert agg.provider_count == 2


# ---------------------------------------------------------
# Integration Tests: DB Persistence & Service Layer
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_enrich_and_persist_indicator(mock_db_session):
    mock_adapter = AsyncMock()
    mock_adapter.is_enabled = True
    mock_adapter.query_url.return_value = ThreatIntelReport(
        indicator_type="URL",
        indicator_value="http://evil-c2.net",
        provider="INTERNAL_REPUTATION",
        verdict="MALICIOUS",
        threat_score=90.0,
        confidence=0.88,
        tags=["C2_SERVER"],
    )

    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_res

    engine = ThreatIntelEngine(adapters=[mock_adapter])
    email_id = uuid.uuid4()

    agg = await enrich_and_persist_indicator(
        indicator_type="URL",
        indicator_value="http://evil-c2.net",
        db=mock_db_session,
        email_id=email_id,
        engine=engine,
    )

    assert agg.consensus_verdict == "MALICIOUS"
    assert agg.consensus_threat_score == 90.0
    assert mock_db_session.add.called
    assert mock_db_session.commit.called


# ---------------------------------------------------------
# Integration Tests: REST API Endpoints
# ---------------------------------------------------------

def test_api_lookup_threat_indicator(mock_db_session):
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.services.threat_intel_service.enrich_and_persist_indicator") as mock_enrich:
        mock_enrich.return_value = AggregatedThreatIntel(
            indicator_type="IP",
            indicator_value="185.220.101.5",
            consensus_verdict="MALICIOUS",
            consensus_threat_score=92.0,
            consensus_confidence=0.95,
            aggregated_tags=["TOR_EXIT_NODE", "HIGH_ABUSE_REPORTS"],
            provider_reports=[
                ThreatIntelReport(
                    indicator_type="IP",
                    indicator_value="185.220.101.5",
                    provider="ABUSEIPDB",
                    verdict="MALICIOUS",
                    threat_score=92.0,
                    confidence=0.95,
                    tags=["HIGH_ABUSE_REPORTS"],
                    malicious_votes=34,
                )
            ],
            provider_count=1,
        )

        response = client.get("/api/v1/intelligence/threat/lookup?indicator_type=IP&indicator_value=185.220.101.5")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["indicator_type"] == "IP"
        assert data["indicator_value"] == "185.220.101.5"
        assert data["consensus_verdict"] == "MALICIOUS"
        assert data["consensus_threat_score"] == 92.0
        assert "TOR_EXIT_NODE" in data["aggregated_tags"]
        assert len(data["provider_reports"]) == 1


def test_api_get_email_threat_intelligence(mock_db_session):
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
    mock_res.first.return_value = (
        email,
        EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
    )
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.services.threat_intel_service.enrich_email_threat_intelligence") as mock_enrich_email:
        mock_enrich_email.return_value = {
            "email_id": str(email_id),
            "total_iocs_analyzed": 2,
            "malicious_ioc_count": 1,
            "suspicious_ioc_count": 0,
            "overall_threat_level": "HIGH",
            "indicators": [
                {
                    "indicator_type": "URL",
                    "indicator_value": "http://evil-c2.net/login",
                    "consensus_verdict": "MALICIOUS",
                    "consensus_threat_score": 90.0,
                    "consensus_confidence": 0.92,
                    "aggregated_tags": ["PHISHING"],
                    "provider_reports": [],
                    "provider_count": 1,
                    "queried_at": now_utc.isoformat(),
                }
            ],
        }

        response = client.get(f"/api/v1/intelligence/emails/{email_id}/threat-intel")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["email_id"] == str(email_id)
        assert data["total_iocs_analyzed"] == 2
        assert data["malicious_ioc_count"] == 1
        assert data["overall_threat_level"] == "HIGH"
        assert len(data["indicators"]) == 1
        assert data["indicators"][0]["consensus_verdict"] == "MALICIOUS"
