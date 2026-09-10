import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.scoring.explainable_scorer import (
    ExplainableScoringEngine,
    ScoringResult,
    ForensicFindingData,
)
from app.services.scoring_service import execute_email_analysis_and_scoring
from app.models.emails import Email, EmailSource, RelayHop, EmailAuthenticationResult
from app.models.analysis import AnalysisRun, EmailAnalysis, AnalysisFinding
from app.models.evidence import EvidenceObject
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for scoring tests."""
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
# Unit Tests: ExplainableScoringEngine
# ---------------------------------------------------------

def test_scoring_benign_authenticated_email():
    engine = ExplainableScoringEngine()
    result = engine.evaluate_email(
        email_metadata={"sender_address": "support@google.com", "subject": "Monthly Statement"},
        auth_results={
            "spf_verdict": "PASS",
            "spf_domain": "google.com",
            "dkim_verdict": "PASS",
            "dmarc_verdict": "PASS",
            "from_domain_aligned": "PASS",
        },
        relay_hops=[{"hop_index": 1, "source_host": "mail.google.com", "delay_seconds": 1}],
        artifacts={"urls": [{"url": "https://google.com/help", "domain": "google.com"}], "attachments": []},
        domain_intel=[{"domain": "google.com", "risk_tags": []}],
        infrastructure_intel=[],
        threat_intel={"total_iocs_analyzed": 1, "indicators": []},
    )

    assert result.threat_classification == "BENIGN"
    assert result.threat_risk_score == 0.0
    assert result.evidence_confidence_score >= 80.0
    assert result.spoofed_domain_likelihood == "UNLIKELY"
    assert result.anonymized_infrastructure_likelihood == "UNLIKELY"
    assert result.malicious_environment_likelihood == "UNLIKELY"
    assert any(f.finding_type == "AUTH_AUTHENTICATION_PASSED" for f in result.findings)


def test_scoring_phishing_spoofed_email():
    engine = ExplainableScoringEngine()
    result = engine.evaluate_email(
        email_metadata={"sender_address": "security-alert@paypal.com", "subject": "Urgent: Account Locked"},
        auth_results={
            "spf_verdict": "FAIL",
            "spf_domain": "paypal.com",
            "dkim_verdict": "FAIL",
            "dmarc_verdict": "FAIL",
            "from_domain_aligned": "FAIL",
        },
        relay_hops=[{"hop_index": 1, "source_host": "evil-relay.net", "delay_seconds": 5}],
        artifacts={
            "urls": [{"url": "http://paypal-verification-account.top/login", "domain": "paypal-verification-account.top"}],
            "attachments": [],
        },
        domain_intel=[
            {
                "domain": "paypal-verification-account.top",
                "risk_tags": ["NEWLY_REGISTERED_DOMAIN_30D", "SUSPICIOUS_TLD_TOP"],
                "registration_intel": {"domain_age_days": 4, "registrar": "NameCheap"},
            }
        ],
        infrastructure_intel=[],
        threat_intel={
            "total_iocs_analyzed": 1,
            "indicators": [
                {
                    "indicator_type": "URL",
                    "indicator_value": "http://paypal-verification-account.top/login",
                    "consensus_verdict": "MALICIOUS",
                    "consensus_threat_score": 95.0,
                    "consensus_confidence": 0.96,
                    "aggregated_tags": ["PHISHING_CREDENTIAL_HARVESTER"],
                }
            ],
        },
    )

    assert result.threat_classification in ("MALICIOUS", "PHISHING", "SPOOFING")
    assert result.threat_risk_score >= 80.0
    assert result.spoofed_domain_likelihood == "HIGH"
    assert result.malicious_environment_likelihood in ("HIGH", "MEDIUM")
    assert any(f.finding_type == "AUTH_DMARC_ALIGNMENT_FAILURE" for f in result.findings)
    assert any(f.finding_type == "DOMAIN_NEWLY_REGISTERED_30D" for f in result.findings)
    assert any(f.finding_type == "THREAT_INTEL_MALICIOUS_URL" for f in result.findings)


def test_scoring_tor_relay_and_dangerous_attachment():
    engine = ExplainableScoringEngine()
    result = engine.evaluate_email(
        email_metadata={"sender_address": "anon@dark.org", "subject": "Invoice PDF"},
        auth_results={"spf_verdict": "NONE", "dkim_verdict": "NONE"},
        relay_hops=[{"hop_index": 1, "source_host": "tor-node", "delay_seconds": 450}],
        artifacts={
            "urls": [],
            "attachments": [
                {
                    "filename": "Invoice_2026.pdf.exe",
                    "sha256_hash": "a" * 64,
                    "size_bytes": 1048576,
                    "is_dangerous": True,
                    "extension": ".exe",
                }
            ],
        },
        domain_intel=[],
        infrastructure_intel=[
            {
                "ip_address": "185.220.101.5",
                "risk_tags": ["TOR_EXIT_NODE"],
                "classifications": [{"classification_type": "TOR", "confidence": 0.95}],
            }
        ],
        threat_intel={},
    )

    assert result.threat_classification == "MALICIOUS"
    assert result.threat_risk_score >= 80.0
    assert result.anonymized_infrastructure_likelihood == "HIGH"
    assert result.malicious_environment_likelihood == "HIGH"
    assert any(f.finding_type == "RELAY_TOR_EXIT_NODE" for f in result.findings)
    assert any(f.finding_type == "ATTACHMENT_DANGEROUS_EXECUTABLE" for f in result.findings)
    assert any(f.finding_type == "RELAY_SUSPICIOUS_TRANSIT_DELAY" for f in result.findings)


def test_scoring_compromised_account_detection():
    engine = ExplainableScoringEngine()
    result = engine.evaluate_email(
        email_metadata={"sender_address": "finance@legitimate-corporate.com", "subject": "Updated Wire Details"},
        auth_results={
            "spf_verdict": "PASS",
            "spf_domain": "legitimate-corporate.com",
            "dkim_verdict": "PASS",
            "dmarc_verdict": "PASS",
            "from_domain_aligned": "PASS",
        },
        relay_hops=[{"hop_index": 1, "source_host": "mail.corporate.com", "delay_seconds": 2}],
        artifacts={"urls": [{"url": "http://c2-malware-drop.xyz/payload.exe", "domain": "c2-malware-drop.xyz"}], "attachments": []},
        domain_intel=[],
        infrastructure_intel=[],
        threat_intel={
            "total_iocs_analyzed": 1,
            "indicators": [
                {
                    "indicator_type": "URL",
                    "indicator_value": "http://c2-malware-drop.xyz/payload.exe",
                    "consensus_verdict": "MALICIOUS",
                    "consensus_threat_score": 98.0,
                    "consensus_confidence": 0.99,
                    "aggregated_tags": ["MALWARE_C2"],
                }
            ],
        },
    )

    assert result.compromised_account_likelihood == "HIGH"
    assert result.threat_risk_score >= 40.0


# ---------------------------------------------------------
# Integration Tests: DB Persistence & Service Layer
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_email_analysis_and_scoring(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="sender@target.com",
        subject="Test Alert",
        analysis_status="PENDING",
        created_at=now_utc,
        updated_at=now_utc,
    )

    # Setup mock DB queries
    mock_res_email = MagicMock()
    mock_res_email.scalar_one_or_none.return_value = mock_email

    mock_res_empty = MagicMock()
    mock_res_empty.scalar_one_or_none.return_value = None
    mock_res_empty.scalars.return_value.all.return_value = []
    mock_res_empty.all.return_value = []

    mock_db_session.execute.side_effect = [
        mock_res_email,  # Email
        mock_res_empty,  # Auth
        mock_res_empty,  # Hops
        mock_res_empty,  # Evidence attachments
        mock_res_empty,  # URLs
    ]

    with patch("app.services.domain_intel_service.enrich_email_domains", new_callable=AsyncMock) as mock_dom, \
         patch("app.services.infrastructure_service.enrich_email_infrastructure", new_callable=AsyncMock) as mock_infra, \
         patch("app.services.threat_intel_service.enrich_email_threat_intelligence", new_callable=AsyncMock) as mock_threat:

        mock_dom.return_value = []
        mock_infra.return_value = []
        mock_threat.return_value = {"total_iocs_analyzed": 0, "indicators": []}

        result = await execute_email_analysis_and_scoring(
            email_id=email_id,
            db=mock_db_session,
        )

        assert result["email_id"] == str(email_id)
        assert result["threat_classification"] == "BENIGN"
        assert result["threat_risk_score"] == 0.0
        assert mock_db_session.add.called
        assert mock_db_session.commit.called
        assert mock_email.analysis_status == "COMPLETED"


# ---------------------------------------------------------
# Integration Tests: REST API Endpoints
# ---------------------------------------------------------

def test_api_get_email_analysis_success(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="sender@target.com",
        analysis_status="COMPLETED",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_run = AnalysisRun(id=uuid.uuid4(), email_id=email_id, status="COMPLETED")
    mock_analysis = EmailAnalysis(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=mock_run.id,
        threat_classification="SUSPICIOUS",
        threat_risk_score=45.0,
        evidence_confidence_score=85.0,
        summary="Suspicious indicators detected.",
        compromised_account_likelihood="LOW",
        spoofed_domain_likelihood="MEDIUM",
        anonymized_infrastructure_likelihood="UNLIKELY",
        malicious_environment_likelihood="LOW",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_res_email = MagicMock()
    mock_res_email.first.return_value = (
        mock_email,
        EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
    )

    mock_res_analysis = MagicMock()
    mock_res_analysis.first.return_value = (mock_analysis, mock_run)

    mock_res_findings = MagicMock()
    mock_res_findings.scalars.return_value.all.return_value = [
        AnalysisFinding(
            id=uuid.uuid4(),
            email_id=email_id,
            analysis_run_id=mock_run.id,
            finding_type="AUTH_SPF_SOFTFAIL",
            severity="MEDIUM",
            confidence=0.85,
            title="SPF Softfail",
            description="SPF softfail detected.",
            evidence={"spf": "softfail"},
            created_at=now_utc,
        )
    ]

    mock_db_session.execute.side_effect = [
        mock_res_email,
        mock_res_analysis,
        mock_res_findings,
    ]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/analysis")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["threat_classification"] == "SUSPICIOUS"
    assert data["threat_risk_score"] == 45.0
    assert data["evidence_confidence_score"] == 85.0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["finding_type"] == "AUTH_SPF_SOFTFAIL"


def test_api_get_email_findings_filter(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="sender@target.com",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_res_email = MagicMock()
    mock_res_email.first.return_value = (
        mock_email,
        EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
    )

    mock_res_findings = MagicMock()
    mock_res_findings.scalars.return_value.all.return_value = [
        AnalysisFinding(
            id=uuid.uuid4(),
            email_id=email_id,
            analysis_run_id=uuid.uuid4(),
            finding_type="RELAY_TOR_EXIT_NODE",
            severity="CRITICAL",
            confidence=0.98,
            title="Tor Exit Node",
            description="Tor relay detected.",
            evidence={},
            created_at=now_utc,
        )
    ]

    mock_db_session.execute.side_effect = [
        mock_res_email,
        mock_res_findings,
    ]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/findings?severity=CRITICAL")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 1
    assert data["findings"][0]["severity"] == "CRITICAL"


def test_api_get_email_analysis_not_found(mock_db_session):
    nonexistent_id = uuid.uuid4()
    mock_res = MagicMock()
    mock_res.first.return_value = None
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{nonexistent_id}/analysis")
    app.dependency_overrides.clear()

    assert response.status_code == 404
