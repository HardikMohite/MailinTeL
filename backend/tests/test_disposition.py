import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.disposition_service import default_disposition_service
from app.api.deps import get_current_user


class MockUser:
    id = uuid.uuid4()
    email = "analyst@mailintel.local"
    full_name = "Lead Forensic Analyst"
    is_active = True
    role = "SECURITY_ANALYST"
    organization_id = uuid.uuid4()


TEST_ANALYST = MockUser()


@pytest.fixture
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: TEST_ANALYST
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_triage_tier_calculation_tier1_auto():
    """Conclusive high score with no conflict produces TIER_1_AUTO."""
    res = default_disposition_service.calculate_triage_tier(
        threat_score=92.0,
        evidence_confidence=95.0,
        findings=[{"title": "Known Phishing Kit Detected", "severity": "CRITICAL"}],
        auth_summary={"spf_status": "FAIL", "dkim_status": "FAIL"},
        indicators=[{"reputation": "MALICIOUS"}],
    )
    assert res["triage_tier"] == "TIER_1_AUTO"
    assert res["is_gated"] is False


def test_triage_tier_calculation_tier2_human_gated():
    """Conflicting signals (SPF PASS + Malicious IP) force TIER_2_HUMAN_GATED."""
    res = default_disposition_service.calculate_triage_tier(
        threat_score=45.0,
        evidence_confidence=80.0,
        findings=[{"title": "Malicious Relay IP", "severity": "HIGH"}],
        auth_summary={"spf_status": "PASS", "dkim_status": "PASS"},
        indicators=[{"reputation": "MALICIOUS"}],
    )
    assert res["triage_tier"] == "TIER_2_HUMAN_GATED"
    assert res["is_gated"] is True
    assert len(res["conflict_reasons"]) > 0


def test_triage_tier_calculation_tier3_auto_cleared():
    """Low threat score and clean indicators produce TIER_3_AUTO_CLEARED."""
    res = default_disposition_service.calculate_triage_tier(
        threat_score=10.0,
        evidence_confidence=85.0,
        findings=[],
        auth_summary={"spf_status": "PASS", "dkim_status": "PASS"},
        indicators=[],
    )
    assert res["triage_tier"] == "TIER_3_AUTO_CLEARED"
    assert res["is_gated"] is False


@pytest.mark.asyncio
async def test_get_or_calculate_disposition_mock():
    mock_session = AsyncMock()
    mock_email_id = uuid.uuid4()

    # Mock no existing disposition
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_result.first.return_value = None
    mock_result.scalars.return_value.all.return_value = []
    mock_session.execute.return_value = mock_result

    data = await default_disposition_service.get_or_calculate_disposition(mock_session, mock_email_id)
    assert data["email_id"] == str(mock_email_id)
    assert data["is_resolved"] is False
    assert "triage_tier" in data


@pytest.mark.asyncio
async def test_submit_analyst_disposition_invalid_verdict():
    mock_session = AsyncMock()
    mock_email_id = uuid.uuid4()

    with pytest.raises(ValueError, match="Invalid verdict"):
        await default_disposition_service.submit_analyst_disposition(
            session=mock_session,
            email_id=mock_email_id,
            user=TEST_ANALYST,
            verdict="INVALID_VERDICT",
            notes="Should fail",
        )


def test_get_disposition_endpoint(override_auth):
    client = TestClient(app)
    mock_email_id = uuid.uuid4()

    with patch.object(
        default_disposition_service,
        "get_or_calculate_disposition",
        new=AsyncMock(return_value={
            "email_id": str(mock_email_id),
            "is_resolved": False,
            "triage_tier": "TIER_2_HUMAN_GATED",
            "tier_label": "Action Required: Gated Human Review",
            "verdict": None,
            "confidence": 0.65,
            "analyst_notes": None,
            "flagged_iocs": [],
            "remediation_actions": [],
            "reviewed_by_name": None,
            "reviewed_at": None,
            "conflict_reasons": ["Cryptographic SPF passed but relay IP flagged on threat intelligence."],
            "recommendation": "Review conflicting signals.",
            "precedents": [],
        }),
    ):
        resp = client.get(f"/api/v1/disposition/{mock_email_id}")
        assert resp.status_code == 200
        json_data = resp.json()
        assert json_data["triage_tier"] == "TIER_2_HUMAN_GATED"
        assert len(json_data["conflict_reasons"]) == 1


def test_submit_disposition_endpoint(override_auth):
    client = TestClient(app)
    mock_email_id = uuid.uuid4()

    with patch.object(
        default_disposition_service,
        "submit_analyst_disposition",
        new=AsyncMock(return_value={
            "email_id": str(mock_email_id),
            "verdict": "CONFIRMED_PHISHING",
            "triage_tier": "HUMAN_RESOLVED",
            "tier_label": "Resolved by Human Analyst",
            "reviewed_by_name": TEST_ANALYST.full_name,
            "reviewed_at": "2026-09-09T14:50:00Z",
            "analyst_notes": "Verified malicious Sendinblue relay.",
            "remediation_actions": ["BLOCK_SENDER", "BLACKLIST_IP"],
            "flagged_iocs": [],
            "learned_vector_indexed": True,
        }),
    ):
        payload = {
            "verdict": "CONFIRMED_PHISHING",
            "notes": "Verified malicious Sendinblue relay.",
            "actions": ["BLOCK_SENDER", "BLACKLIST_IP"],
            "flagged_iocs": [],
        }
        resp = client.post(f"/api/v1/disposition/{mock_email_id}", json=payload)
        assert resp.status_code == 200
        json_data = resp.json()
        assert json_data["verdict"] == "CONFIRMED_PHISHING"
        assert json_data["learned_vector_indexed"] is True


def test_get_precedents_endpoint(override_auth):
    client = TestClient(app)
    mock_email_id = uuid.uuid4()

    with patch.object(
        default_disposition_service,
        "find_analyst_precedents",
        new=AsyncMock(return_value=[
            {
                "precedent_email_id": str(uuid.uuid4()),
                "similarity_score": 94.5,
                "analyst_verdict": "CONFIRMED_PHISHING",
                "analyst_notes": "Abused Sendinblue relay with travel lure.",
                "reviewer_name": "Admin",
                "reviewed_at": "2026-09-09T12:00:00Z",
                "shared_indicators": ["Relay IP 77.32.148.26"],
            }
        ]),
    ):
        resp = client.get(f"/api/v1/disposition/{mock_email_id}/precedents")
        assert resp.status_code == 200
        json_data = resp.json()
        assert len(json_data) == 1
        assert json_data[0]["similarity_score"] == 94.5
