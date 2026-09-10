import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone, timedelta
from httpx import Response
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.intelligence.domain_intel import (
    AsyncDNSResolver,
    AsyncRDAPClient,
    DomainRiskEvaluator,
    DomainIntelligenceEngine,
    DNSRecordData,
    RegistrationIntelData,
    DomainIntelBundle,
)
from app.services.domain_intel_service import (
    enrich_and_persist_domain_intelligence,
    enrich_email_domains,
)
from app.models.emails import Email, EmailSource
from app.models.intelligence import Domain, DomainDNSRecord, DomainRegistrationIntel, URL, EmailURL
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for domain intel tests."""
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
# Unit Tests: AsyncRDAPClient
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_rdap_payload_parsing():
    client_rdap = AsyncRDAPClient()
    now_utc = datetime.now(timezone.utc)
    reg_date = (now_utc - timedelta(days=20)).isoformat()
    exp_date = (now_utc + timedelta(days=345)).isoformat()

    mock_rdap_data = {
        "handle": "DOM-12345",
        "ldhName": "phishing-secure-login.xyz",
        "status": ["active", "clientTransferProhibited"],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "NameCheap, Inc."],
                    ],
                ],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": reg_date},
            {"eventAction": "expiration", "eventDate": exp_date},
            {"eventAction": "last changed", "eventDate": reg_date},
        ],
        "nameservers": [
            {"ldhName": "dns1.registrar-servers.com"},
            {"ldhName": "dns2.registrar-servers.com"},
        ],
    }

    parsed = client_rdap._parse_rdap_payload(mock_rdap_data)

    assert parsed.registrar == "NameCheap, Inc."
    assert parsed.registered_at is not None
    assert parsed.expires_at is not None
    assert parsed.domain_age_days == 20
    assert len(parsed.nameservers) == 2
    assert "dns1.registrar-servers.com" in parsed.nameservers


@pytest.mark.asyncio
async def test_rdap_query_domain_success():
    client_rdap = AsyncRDAPClient()
    now_utc = datetime.now(timezone.utc)
    reg_date = (now_utc - timedelta(days=45)).isoformat()

    mock_json = {
        "handle": "EXAMPLE-REG",
        "entities": [{"roles": ["registrar"], "handle": "GoDaddy.com, LLC"}],
        "events": [{"eventAction": "created", "eventDate": reg_date}],
        "nameservers": [{"ldhName": "ns1.godaddy.com"}],
    }

    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        result = await client_rdap.query_domain_registration("suspicious-target.com")

        assert result is not None
        assert result.registrar == "GoDaddy.com, LLC"
        assert result.domain_age_days == 45
        assert result.nameservers == ["ns1.godaddy.com"]


@pytest.mark.asyncio
async def test_rdap_query_graceful_failure():
    client_rdap = AsyncRDAPClient()

    mock_resp = MagicMock(spec=Response)
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        result = await client_rdap.query_domain_registration("nonexistent-domain-404.xyz")
        assert result is None


# ---------------------------------------------------------
# Unit Tests: DomainRiskEvaluator
# ---------------------------------------------------------

def test_evaluator_nrd_under_30_days():
    evaluator = DomainRiskEvaluator()
    dns_records = [
        DNSRecordData(record_type="A", record_value="192.0.2.1"),
        DNSRecordData(record_type="MX", record_value="mail.evil-domain.com", priority=10),
    ]
    reg_intel = RegistrationIntelData(
        registrar="Test Registrar",
        domain_age_days=12,
    )

    risk_tags, risk_level, is_nrd = evaluator.evaluate_domain(
        "evil-domain.com", dns_records, reg_intel
    )

    assert is_nrd is True
    assert "NEWLY_REGISTERED_DOMAIN_30D" in risk_tags
    assert risk_level == "HIGH"


def test_evaluator_nrd_under_90_days():
    evaluator = DomainRiskEvaluator()
    dns_records = [
        DNSRecordData(record_type="A", record_value="192.0.2.1"),
        DNSRecordData(record_type="MX", record_value="mail.medium-risk.com", priority=10),
    ]
    reg_intel = RegistrationIntelData(
        registrar="Test Registrar",
        domain_age_days=60,
    )

    risk_tags, risk_level, is_nrd = evaluator.evaluate_domain(
        "medium-risk.com", dns_records, reg_intel
    )

    assert is_nrd is True
    assert "NEWLY_REGISTERED_DOMAIN_90D" in risk_tags
    assert risk_level == "MEDIUM"


def test_evaluator_dynamic_dns_provider():
    evaluator = DomainRiskEvaluator()
    dns_records = [DNSRecordData(record_type="A", record_value="198.51.100.22")]
    reg_intel = RegistrationIntelData(domain_age_days=500)

    risk_tags, risk_level, is_nrd = evaluator.evaluate_domain(
        "attacker.duckdns.org", dns_records, reg_intel
    )

    assert "DYNAMIC_DNS_PROVIDER" in risk_tags
    assert "NO_MX_RECORDS" in risk_tags
    assert risk_level == "HIGH"


def test_evaluator_punycode_homoglyph():
    evaluator = DomainRiskEvaluator()
    dns_records = [DNSRecordData(record_type="A", record_value="192.0.2.1")]

    risk_tags, risk_level, is_nrd = evaluator.evaluate_domain(
        "xn--gogle-pua.com", dns_records, None
    )

    assert "PUNYCODE_HOMOGLYPH" in risk_tags
    assert risk_level == "MEDIUM"


def test_evaluator_established_benign_domain():
    evaluator = DomainRiskEvaluator()
    dns_records = [
        DNSRecordData(record_type="A", record_value="142.250.190.46"),
        DNSRecordData(record_type="MX", record_value="smtp.google.com", priority=5),
        DNSRecordData(record_type="TXT", record_value="v=spf1 include:_spf.google.com ~all"),
    ]
    reg_intel = RegistrationIntelData(domain_age_days=8500, registrar="MarkMonitor")

    risk_tags, risk_level, is_nrd = evaluator.evaluate_domain(
        "google.com", dns_records, reg_intel
    )

    assert is_nrd is False
    assert len(risk_tags) == 0
    assert risk_level == "LOW"


# ---------------------------------------------------------
# Unit Tests: DomainIntelligenceEngine
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_intelligence_engine_bundle():
    mock_dns = AsyncMock(spec=AsyncDNSResolver)
    mock_dns.query_domain_records.return_value = [
        DNSRecordData(record_type="A", record_value="93.184.216.34"),
        DNSRecordData(record_type="MX", record_value="mail.example.com", priority=10),
        DNSRecordData(record_type="TXT", record_value="v=spf1 -all"),
        DNSRecordData(record_type="NS", record_value="a.iana-servers.net"),
    ]

    mock_rdap = AsyncMock(spec=AsyncRDAPClient)
    mock_rdap.query_domain_registration.return_value = RegistrationIntelData(
        registrar="IANA Registrar",
        domain_age_days=4000,
        nameservers=["a.iana-servers.net"],
    )

    engine = DomainIntelligenceEngine(dns_resolver=mock_dns, rdap_client=mock_rdap)
    bundle = await engine.analyze_domain("example.com")

    assert bundle.domain == "example.com"
    assert bundle.root_domain == "example.com"
    assert len(bundle.dns_records) == 4
    assert "93.184.216.34" in bundle.a_records
    assert "mail.example.com" in bundle.mx_hosts
    assert bundle.registration_intel.registrar == "IANA Registrar"
    assert bundle.risk_level == "LOW"
    assert bundle.is_nrd is False


# ---------------------------------------------------------
# Integration Tests: DB Persistence & Service Layer
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_enrich_and_persist_domain_intelligence(mock_db_session):
    mock_dns = AsyncMock(spec=AsyncDNSResolver)
    mock_dns.query_domain_records.return_value = [
        DNSRecordData(record_type="A", record_value="104.18.2.1"),
        DNSRecordData(record_type="MX", record_value="mx.cloudflare.com", priority=1),
    ]

    mock_rdap = AsyncMock(spec=AsyncRDAPClient)
    mock_rdap.query_domain_registration.return_value = RegistrationIntelData(
        registrar="Cloudflare, Inc.",
        domain_age_days=15,
        nameservers=["ns1.cloudflare.com"],
    )

    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_res

    engine = DomainIntelligenceEngine(dns_resolver=mock_dns, rdap_client=mock_rdap)

    bundle = await enrich_and_persist_domain_intelligence(
        domain_name="nrd-test-sample.xyz",
        db=mock_db_session,
        engine=engine,
    )

    assert bundle.is_nrd is True
    assert bundle.risk_level == "HIGH"
    assert "NEWLY_REGISTERED_DOMAIN_30D" in bundle.risk_tags
    assert mock_db_session.add.called
    assert mock_db_session.commit.called


# ---------------------------------------------------------
# Integration Tests: REST API Endpoints
# ---------------------------------------------------------

def test_api_get_domain_intelligence(mock_db_session):
    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.api.v1.endpoints.intelligence.enrich_and_persist_domain_intelligence") as mock_enrich:
        mock_enrich.return_value = DomainIntelBundle(
            domain="corporate-login.com",
            root_domain="corporate-login.com",
            dns_records=[DNSRecordData(record_type="A", record_value="1.2.3.4")],
            registration_intel=RegistrationIntelData(registrar="MarkMonitor Inc.", domain_age_days=2500),
            a_records=["1.2.3.4"],
            risk_level="LOW",
            is_nrd=False,
        )

        response = client.get("/api/v1/intelligence/domains/corporate-login.com")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "corporate-login.com"
        assert data["risk_level"] == "LOW"
        assert data["is_nrd"] is False
        assert len(data["dns_records"]) == 1
        assert data["registration_intel"]["registrar"] == "MarkMonitor Inc."


def test_api_get_email_domains_intelligence(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="sender@evil-spoof.com",
        analysis_status="EXTRACTED",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_res = MagicMock()
    mock_res.first.return_value = (email, EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id, source_type="FILE_UPLOAD"))
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch("app.api.v1.endpoints.intelligence.enrich_email_domains") as mock_email_enrich:
        mock_email_enrich.return_value = [
            DomainIntelBundle(
                domain="evil-spoof.com",
                root_domain="evil-spoof.com",
                dns_records=[DNSRecordData(record_type="A", record_value="185.220.101.5")],
                registration_intel=RegistrationIntelData(registrar="Tucows", domain_age_days=8),
                is_nrd=True,
                risk_level="HIGH",
                risk_tags=["NEWLY_REGISTERED_DOMAIN_30D"],
            )
        ]

        response = client.get(f"/api/v1/intelligence/emails/{email_id}/domains")
        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["email_id"] == str(email_id)
        assert data["total_domains_analyzed"] == 1
        assert data["domains"][0]["domain"] == "evil-spoof.com"
        assert data["domains"][0]["is_nrd"] is True
        assert data["domains"][0]["risk_level"] == "HIGH"


def test_api_get_email_domains_not_found(mock_db_session):
    nonexistent_id = uuid.uuid4()
    mock_res = MagicMock()
    mock_res.first.return_value = None
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/intelligence/emails/{nonexistent_id}/domains")
    app.dependency_overrides.clear()

    assert response.status_code == 404
