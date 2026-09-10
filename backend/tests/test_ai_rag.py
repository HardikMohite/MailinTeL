import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.services.llm_provider import GroqLLMClient
from app.services.ai_rag_service import ForensicRAGService, _defang_text
from app.models.emails import Email, EmailHeader, RelayHop, EmailAuthenticationResult
from app.models.analysis import EmailAnalysis, AnalysisFinding, AnalysisRun
from tests.auth_helpers import TEST_USER, make_authorized_email_db_mock

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for AI RAG tests."""
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
# Unit Tests: Defanging & Groq Client
# ---------------------------------------------------------

def test_defang_text():
    assert _defang_text("https://malicious.com/phish") == "hxxps://malicious.com/phish"
    assert _defang_text("http://evil.com") == "hxxp://evil.com"
    assert _defang_text("192.168.1.100") == "192[.]168[.]1[.]100"
    assert _defang_text("") == ""


@pytest.mark.asyncio
async def test_groq_client_unconfigured_fallback():
    client_instance = GroqLLMClient()
    client_instance.api_key = ""
    assert client_instance.is_configured is False
    res = await client_instance.chat_completion([{"role": "user", "content": "hello"}])
    assert res is None


@pytest.mark.asyncio
async def test_groq_client_mock_completion():
    client_instance = GroqLLMClient()
    client_instance.api_key = "gsk_valid_mock_key_1234567890"
    assert client_instance.is_configured is True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"classification": "phishing"}'}}]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await client_instance.chat_completion([{"role": "user", "content": "test"}])
        assert res == '{"classification": "phishing"}'


# ---------------------------------------------------------
# Unit Tests: Forensic RAG Service
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_forensic_rag_context_retrieval(mock_db_session):
    email_id = uuid.uuid4()
    org_id = TEST_USER.organization_id

    email = Email(
        id=email_id,
        organization_id=org_id,
        source_id=uuid.uuid4(),
        subject="Urgent Payroll Notification",
        sender_address="payroll@spoofed-company.com",
    )

    auth = EmailAuthenticationResult(
        id=uuid.uuid4(),
        email_id=email_id,
        spf_result="FAIL",
        dkim_result="NONE",
        dmarc_result="FAIL",
        from_alignment_result="FAIL",
    )

    analysis = EmailAnalysis(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=uuid.uuid4(),
        threat_classification="SUSPICIOUS",
        threat_risk_score=65.0,
        evidence_confidence_score=90.0,
        summary="DMARC alignment failed",
    )

    run = AnalysisRun(id=analysis.analysis_run_id, email_id=email_id, status="COMPLETED")

    finding = AnalysisFinding(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=run.id,
        finding_type="AUTH_DMARC_FAIL",
        severity="HIGH",
        confidence=0.9,
        title="DMARC Alignment Failure",
        description="From header domain does not match authenticating SPF or DKIM domains.",
    )

    # Setup mock executes
    async def mock_execute(stmt):
        mock_res = MagicMock()
        stmt_str = str(stmt).lower()
        if "from emails" in stmt_str:
            mock_res.scalar_one_or_none.return_value = email
            mock_res.scalars.return_value.first.return_value = email
        elif "from email_headers" in stmt_str:
            h = EmailHeader(id=uuid.uuid4(), email_id=email_id, header_name="Subject", header_value="Urgent Payroll", header_order=1)
            mock_res.scalars.return_value.all.return_value = [h]
        elif "from email_authentication_results" in stmt_str:
            mock_res.scalar_one_or_none.return_value = auth
        elif "from email_analysis" in stmt_str:
            mock_res.first.return_value = (analysis, run)
        elif "from analysis_findings" in stmt_str:
            mock_res.scalars.return_value.all.return_value = [finding]
        else:
            mock_res.scalars.return_value.all.return_value = []
            mock_res.scalars.return_value.first.return_value = None
            mock_res.all.return_value = []
            mock_res.first.return_value = None
            mock_res.scalar_one_or_none.return_value = None
        return mock_res

    mock_db_session.execute.side_effect = mock_execute

    service = ForensicRAGService()
    ctx = await service.retrieve_case_forensic_context(mock_db_session, email_id)

    assert ctx["email_id"] == str(email_id)
    assert ctx["threat_score"] == 65.0
    assert ctx["threat_verdict"] == "SUSPICIOUS"
    assert ctx["authentication"]["dmarc_status"] == "FAIL"
    assert len(ctx["findings"]) == 1
    assert ctx["findings"][0]["type"] == "AUTH_DMARC_FAIL"


@pytest.mark.asyncio
async def test_explain_email_threat_strict_schema(mock_db_session):
    email_id = uuid.uuid4()
    service = ForensicRAGService()

    # Test fallback deterministic reasoning matches schema
    mock_ctx = {
        "email_id": str(email_id),
        "threat_score": 75.0,
        "threat_verdict": "PHISHING",
        "evidence_confidence": 95.0,
        "sender": "boss@external-lure.com",
        "reply_to": "attacker@gmail.com",
        "authentication": {"spf_status": "FAIL", "dkim_status": "NONE", "dmarc_status": "FAIL"},
        "findings": [
            {"title": "DMARC Alignment Failure", "description": "Spoofed sender domain", "confidence": 0.9},
            {"title": "Credential Harvesting URL Detected", "description": "Phishing portal linked", "confidence": 0.95},
        ],
        "extracted_urls": [{"url": "hxxps://fake-login[.]com", "context": "BUTTON_HREF"}],
        "infrastructure_ips": [],
        "campaign_memberships": [],
    }

    with patch.object(service, "retrieve_case_forensic_context", new_callable=AsyncMock) as mock_ret:
        mock_ret.return_value = mock_ctx
        result = await service.explain_email_threat(mock_db_session, email_id)

        assert result["classification"] == "phishing"
        assert len(result["reasoning"]) >= 2
        for r in result["reasoning"]:
            assert "finding" in r
            assert "evidence" in r
            assert "confidence" in r
            assert 0.0 <= r["confidence"] <= 1.0
        assert len(result["social_engineering_indicators"]) >= 1
        assert len(result["attack_intent"]) >= 1
        assert len(result["recommended_actions"]) >= 1
        assert 0.0 <= result["confidence"] <= 1.0


@pytest.mark.asyncio
async def test_investigate_case_assistant_grounding(mock_db_session):
    email_id = uuid.uuid4()
    service = ForensicRAGService()

    mock_ctx = {
        "email_id": str(email_id),
        "subject": "Wire Transfer Needed",
        "threat_score": 85.0,
        "threat_verdict": "MALICIOUS",
        "findings": [{"title": "Malicious IP 77.32.148.26", "description": "Known bulletproof host"}],
        "relay_chain": [{"hop": 1, "source_ip": "77.32.148.26", "country": "RU"}],
        "infrastructure_ips": [{"ip": "77.32.148.26", "asn": "AS12345"}],
        "pgvector_similar_emails": [{"related_email_id": "0000-1111", "similarity_score": 92.5}],
        "campaign_memberships": [{"campaign_name": "FIN7-Lure", "status": "ACTIVE", "confidence": 90.0}],
        "extracted_urls": [],
        "authentication": {"spf_status": "PASS", "dkim_status": "PASS", "dmarc_status": "PASS"},
    }

    with patch.object(service, "retrieve_case_forensic_context", new_callable=AsyncMock) as mock_ret:
        mock_ret.return_value = mock_ctx

        # Test Q1: Risk Question
        ans1 = await service.investigate_case_assistant(mock_db_session, email_id, "Why is this email high risk?")
        assert ans1["email_id"] == str(email_id)
        assert "85" in ans1["answer"]
        assert ans1["grounded_sources"]["findings_count"] == 1

        # Test Q2: Similar Emails
        ans2 = await service.investigate_case_assistant(mock_db_session, email_id, "Which emails are related to this?")
        assert "92.5" in ans2["answer"]

        # Test Q3: Campaign
        ans3 = await service.investigate_case_assistant(mock_db_session, email_id, "What campaign is this?")
        assert "FIN7-Lure" in ans3["answer"]


# ---------------------------------------------------------
# API Endpoint Integration Tests
# ---------------------------------------------------------

def test_ai_status_endpoint():
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    resp = client.get("/api/v1/ai/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "provider" in data
    assert "model" in data
    assert data["rag_pgvector_active"] is True
    app.dependency_overrides.clear()


def test_ai_explain_endpoint():
    email_id = uuid.uuid4()
    org_id = TEST_USER.organization_id

    email = Email(
        id=email_id,
        organization_id=org_id,
        source_id=uuid.uuid4(),
        subject="Invoice Confirmation",
        sender_address="billing@vendor.com",
    )

    mock_db = make_authorized_email_db_mock(email)

    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.services.ai_rag_service.default_forensic_rag_service.explain_email_threat", new_callable=AsyncMock) as mock_exp:
        mock_exp.return_value = {
            "classification": "suspicious",
            "reasoning": [
                {"finding": "Lookalike Domain", "evidence": "Typo in vendor domain", "confidence": 0.85}
            ],
            "social_engineering_indicators": ["Urgency marker in subject"],
            "attack_intent": ["Invoice Fraud"],
            "recommended_actions": ["Contact vendor via out-of-band channel"],
            "confidence": 0.88,
        }

        resp = client.post(f"/api/v1/ai/{email_id}/explain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "suspicious"
        assert len(data["reasoning"]) == 1
        assert data["reasoning"][0]["finding"] == "Lookalike Domain"
        assert data["confidence"] == 0.88

    app.dependency_overrides.clear()


def test_ai_investigate_endpoint():
    email_id = uuid.uuid4()
    org_id = TEST_USER.organization_id

    email = Email(
        id=email_id,
        organization_id=org_id,
        source_id=uuid.uuid4(),
        subject="Security Update",
        sender_address="admin@corporate.com",
    )

    mock_db = make_authorized_email_db_mock(email)

    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.services.ai_rag_service.default_forensic_rag_service.investigate_case_assistant", new_callable=AsyncMock) as mock_inv:
        mock_inv.return_value = {
            "email_id": str(email_id),
            "question": "What infrastructure is shared?",
            "answer": "Shares IP 77.32.148.26 with Campaign FIN7.",
            "grounded_sources": {"findings_count": 2},
        }

        resp = client.post(
            f"/api/v1/ai/{email_id}/investigate",
            json={"question": "What infrastructure is shared?"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == str(email_id)
        assert "Shares IP 77.32.148.26" in data["answer"]

    app.dependency_overrides.clear()


def test_ai_summarize_endpoint():
    email_id = uuid.uuid4()
    org_id = TEST_USER.organization_id

    email = Email(
        id=email_id,
        organization_id=org_id,
        source_id=uuid.uuid4(),
        subject="Reset Password",
        sender_address="support@helpdesk.com",
    )

    mock_db = make_authorized_email_db_mock(email)

    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.services.ai_rag_service.default_forensic_rag_service.summarize_case", new_callable=AsyncMock) as mock_sum:
        mock_sum.return_value = {
            "email_id": str(email_id),
            "summary": "High-risk credential phishing campaign targeting IT helpdesk.",
            "classification": "phishing",
            "threat_score": 90.0,
            "top_findings": ["Fake Login Page", "DMARC Failed"],
            "recommended_actions": ["Reset user credentials immediately"],
        }

        resp = client.post(f"/api/v1/ai/{email_id}/summarize")
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "phishing"
        assert data["threat_score"] == 90.0

    app.dependency_overrides.clear()
