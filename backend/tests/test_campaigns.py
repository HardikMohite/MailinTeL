import uuid
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.campaigns.correlation_engine import CorrelationEngine, CorrelationSignal, default_correlation_engine
from app.services.campaign_service import CampaignCorrelationService
from app.models.campaign import Campaign, CampaignMembership, CampaignEvidence, CampaignEvent
from app.models.emails import Email
from tests.auth_helpers import TEST_USER, make_authorized_email_db_mock

client = TestClient(app)


def test_correlation_engine_shared_attachment_hash():
    engine = CorrelationEngine()
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    source = {
        "email_id": src_id,
        "attachments": [{"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
    }
    target = {
        "email_id": tgt_id,
        "attachments": [{"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
    }

    res = engine.correlate_email_pair(source, target)
    assert res.composite_correlation_score > 80.0
    assert any(s.signal_type == "SHARED_ATTACHMENT_HASH" for s in res.signals)
    assert res.is_actionable_correlation is True


def test_correlation_engine_shared_urls_and_domains():
    engine = CorrelationEngine()
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    source = {
        "email_id": src_id,
        "urls": [{"url_hash": "hash123", "normalized_url": "http://evil-login.com/secure"}],
        "domains": [{"root_domain": "evil-login.com"}],
    }
    target = {
        "email_id": tgt_id,
        "urls": [{"url_hash": "hash123", "normalized_url": "http://evil-login.com/secure"}],
        "domains": [{"root_domain": "evil-login.com"}],
    }

    res = engine.correlate_email_pair(source, target)
    assert res.composite_correlation_score >= 80.0
    signal_types = {s.signal_type for s in res.signals}
    assert "SHARED_URL" in signal_types
    assert "SHARED_DOMAIN" in signal_types


def test_correlation_engine_shared_ip_and_infrastructure():
    engine = CorrelationEngine()
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    source = {
        "email_id": src_id,
        "ips": [{"ip_address": "198.51.100.5", "asn": "AS45102", "is_private": False, "is_tor": True}],
    }
    target = {
        "email_id": tgt_id,
        "ips": [{"ip_address": "198.51.100.5", "asn": "AS45102", "is_private": False, "is_tor": True}],
    }

    res = engine.correlate_email_pair(source, target)
    assert res.composite_correlation_score >= 75.0
    signal_types = {s.signal_type for s in res.signals}
    assert "SHARED_IP" in signal_types
    assert "SHARED_INFRASTRUCTURE" in signal_types


def test_correlation_engine_dna_and_temporal():
    engine = CorrelationEngine()
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    now = datetime.now(timezone.utc)
    source = {
        "email_id": src_id,
        "sent_at": now.isoformat(),
        "dna_profile": {
            "technical_fingerprint": {
                "header_ordering_hash": "abc123hash",
                "dkim_selector": "s2026",
                "dkim_domain": "spoof-target.com",
            }
        },
    }
    target = {
        "email_id": tgt_id,
        "sent_at": (now + timedelta(minutes=45)).isoformat(),
        "dna_profile": {
            "technical_fingerprint": {
                "header_ordering_hash": "abc123hash",
                "dkim_selector": "s2026",
                "dkim_domain": "spoof-target.com",
            }
        },
    }

    res = engine.correlate_email_pair(source, target)
    signal_types = {s.signal_type for s in res.signals}
    assert "EMAIL_DNA_SIMILARITY" in signal_types
    assert "TEMPORAL_PATTERN" in signal_types


def test_correlation_engine_no_signals():
    engine = CorrelationEngine()
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    source = {"email_id": src_id, "urls": [], "domains": [], "ips": [], "attachments": []}
    target = {"email_id": tgt_id, "urls": [], "domains": [], "ips": [], "attachments": []}

    res = engine.correlate_email_pair(source, target)
    assert res.composite_correlation_score == 0.0
    assert res.is_actionable_correlation is False
    assert len(res.signals) == 0


@pytest.mark.asyncio
async def test_campaign_service_correlate_email():
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()

    service = CampaignCorrelationService()

    mock_src_bundle = {
        "email_id": src_id,
        "subject": "Wire Transfer Update",
        "sender_address": "finance@evilcorp.com",
        "urls": [{"url_hash": "abc", "normalized_url": "http://evilcorp.com"}],
        "domains": [],
        "ips": [],
        "attachments": [],
        "dna_profile": None,
    }
    mock_tgt_bundle = {
        "email_id": tgt_id,
        "subject": "Overdue Wire Notice",
        "sender_address": "accounting@evilcorp.com",
        "urls": [{"url_hash": "abc", "normalized_url": "http://evilcorp.com"}],
        "domains": [],
        "ips": [],
        "attachments": [],
        "dna_profile": None,
    }

    with patch.object(service, "_gather_email_forensic_bundle", side_effect=[mock_src_bundle, mock_tgt_bundle]):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()

        # Mock candidate email query
        mock_result = MagicMock()
        mock_result.all.return_value = [(tgt_id,)]
        mock_session.execute.side_effect = [mock_result, MagicMock(all=MagicMock(return_value=[]))]

        results = await service.correlate_email(mock_session, src_id, min_score=30.0)

        assert len(results) == 1
        assert results[0]["source_email_id"] == str(src_id)
        assert results[0]["target_email_id"] == str(tgt_id)
        assert results[0]["composite_correlation_score"] >= 80.0
        assert results[0]["target_subject"] == "Overdue Wire Notice"


@pytest.mark.asyncio
async def test_campaign_service_overlapping_memberships_and_bridge_entity():
    service = CampaignCorrelationService()
    email_id = uuid.uuid4()
    camp1_id = uuid.uuid4()
    camp2_id = uuid.uuid4()

    mock_session = AsyncMock()
    
    # Mock memberships returning 2 campaigns for the same email (Bridge Entity)
    mock_m1 = CampaignMembership(id=uuid.uuid4(), campaign_id=camp1_id, email_id=email_id, membership_confidence=90.0, membership_status="CONFIRMED")
    mock_m2 = CampaignMembership(id=uuid.uuid4(), campaign_id=camp2_id, email_id=email_id, membership_confidence=75.0, membership_status="CONFIRMED")

    mock_res = MagicMock()
    mock_res.all.return_value = [
        (mock_m1, "Campaign Alpha", "ACTIVE"),
        (mock_m2, "Campaign Beta", "INVESTIGATING"),
    ]
    mock_session.execute = AsyncMock(return_value=mock_res)

    result = await service.get_email_campaign_memberships(mock_session, email_id)
    assert result["email_id"] == str(email_id)
    assert result["is_bridge_entity"] is True
    assert result["total_campaigns"] == 2
    assert "bridge connecting multiple distinct campaign clusters" in result["investigation_note"]


@pytest.mark.asyncio
async def test_campaign_service_create_and_add_email():
    service = CampaignCorrelationService()
    camp_id = uuid.uuid4()
    email_id = uuid.uuid4()

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.flush = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()

    camp = await service.create_campaign(
        mock_session,
        campaign_name="Targeted Phishing Q3",
        threat_summary="Credential harvesting campaign targeting executive team.",
        campaign_confidence=85.0,
        initial_email_ids=[email_id],
    )

    assert mock_session.add.call_count >= 2  # Campaign, Membership, Event
    assert mock_session.commit.called


def test_api_create_campaign_endpoint():
    camp_id = uuid.uuid4()
    mock_details = {
        "id": str(camp_id),
        "campaign_name": "FIN7 Clone",
        "campaign_status": "ACTIVE",
        "campaign_confidence": 88.0,
        "threat_summary": "High risk financial phishing",
        "first_detected_at": datetime.now(timezone.utc).isoformat(),
        "last_activity_at": datetime.now(timezone.utc).isoformat(),
        "total_members": 1,
        "total_evidence_links": 0,
        "memberships": [],
        "evidence": [],
        "events": [],
    }

    with patch(
        "app.services.campaign_service.default_campaign_service.create_campaign",
        new=AsyncMock(return_value=MagicMock(id=camp_id)),
    ), patch(
        "app.services.campaign_service.default_campaign_service.get_campaign_details",
        new=AsyncMock(return_value=mock_details),
    ):
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.post(
            "/api/v1/campaigns",
            json={"campaign_name": "FIN7 Clone", "threat_summary": "High risk financial phishing", "campaign_confidence": 88.0},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 201
        data = resp.json()
        assert data["campaign_name"] == "FIN7 Clone"
        assert data["campaign_confidence"] == 88.0


def test_api_get_email_campaign_memberships_endpoint():
    email_id = uuid.uuid4()
    mock_resp = {
        "email_id": str(email_id),
        "is_bridge_entity": True,
        "total_campaigns": 2,
        "investigation_note": "Entity acts as an investigation bridge.",
        "memberships": [
            {
                "membership_id": str(uuid.uuid4()),
                "campaign_id": str(uuid.uuid4()),
                "campaign_name": "Phishing 1",
                "campaign_status": "ACTIVE",
                "membership_confidence": 85.0,
                "membership_status": "CONFIRMED",
                "evidence_summary": {},
            },
            {
                "membership_id": str(uuid.uuid4()),
                "campaign_id": str(uuid.uuid4()),
                "campaign_name": "Phishing 2",
                "campaign_status": "ACTIVE",
                "membership_confidence": 75.0,
                "membership_status": "CONFIRMED",
                "evidence_summary": {},
            },
        ],
    }

    mock_email = Email(id=email_id, source_id=uuid.uuid4())
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.campaign_service.default_campaign_service.get_email_campaign_memberships",
        new=AsyncMock(return_value=mock_resp),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/campaigns/emails/{email_id}/memberships")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_bridge_entity"] is True
        assert data["total_campaigns"] == 2


def test_api_auto_cluster_endpoint():
    mock_clusters = [
        {"campaign_id": str(uuid.uuid4()), "campaign_name": "Cluster: Shared URL", "members_count": 3}
    ]
    with patch(
        "app.services.campaign_service.default_campaign_service.auto_cluster_campaigns",
        new=AsyncMock(return_value=mock_clusters),
    ):
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.post("/api/v1/campaigns/auto-cluster?min_score=60.0")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_clusters_created"] == 1
        assert data["clusters"][0]["members_count"] == 3


def test_api_compute_email_correlations_endpoint():
    email_id = uuid.uuid4()
    target_id = uuid.uuid4()

    mock_correlations = [
        {
            "source_email_id": str(email_id),
            "target_email_id": str(target_id),
            "target_subject": "Suspicious Login",
            "target_sender": "admin@phish.net",
            "composite_correlation_score": 85.5,
            "primary_link_reason": "Shared normalized URL detected across emails",
            "evidence_count": 2,
            "is_actionable_correlation": True,
            "signals": [
                {
                    "signal_type": "SHARED_URL",
                    "confidence": 90.0,
                    "weight": 2.5,
                    "description": "Shared normalized URL",
                    "evidence": {"total_shared": 1},
                }
            ],
        }
    ]

    mock_email = Email(id=email_id, source_id=uuid.uuid4())
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.campaign_service.default_campaign_service.correlate_email",
        new=AsyncMock(return_value=mock_correlations),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.post(f"/api/v1/campaigns/correlate/{email_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == str(email_id)
        assert data["total_correlated_emails"] == 1
        assert data["correlations"][0]["composite_correlation_score"] == 85.5


def test_api_get_email_correlations_endpoint():
    email_id = uuid.uuid4()
    mock_email = Email(id=email_id, source_id=uuid.uuid4())
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.campaign_service.default_campaign_service.correlate_email",
        new=AsyncMock(return_value=[]),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/campaigns/correlations/{email_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == str(email_id)
        assert data["total_correlated_emails"] == 0


def test_api_update_campaign_endpoint():
    camp_id = uuid.uuid4()
    mock_campaign = Campaign(
        id=camp_id,
        campaign_name="Test Campaign",
        campaign_status="ACTIVE",
        campaign_confidence=80.0,
        organization_id=TEST_USER.organization_id,
    )
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_campaign
    mock_db.execute.return_value = mock_result
    mock_db.commit = AsyncMock()

    updated_details = {
        "id": str(camp_id),
        "campaign_name": "Updated Phish Net",
        "campaign_status": "MITIGATED",
        "campaign_confidence": 95.0,
        "threat_summary": "Mitigated across mail gateways",
        "total_members": 2,
        "total_evidence_links": 1,
        "memberships": [],
        "evidence": [],
        "events": [],
    }

    with patch(
        "app.services.campaign_service.default_campaign_service.get_campaign_details",
        new=AsyncMock(return_value=updated_details),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.patch(
            f"/api/v1/campaigns/{camp_id}",
            json={"campaign_name": "Updated Phish Net", "campaign_status": "MITIGATED"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["campaign_status"] == "MITIGATED"
        assert data["campaign_name"] == "Updated Phish Net"


def test_api_delete_campaign_endpoint():
    camp_id = uuid.uuid4()
    mock_campaign = Campaign(
        id=camp_id,
        campaign_name="Test Campaign",
        campaign_status="ACTIVE",
        campaign_confidence=80.0,
        organization_id=TEST_USER.organization_id,
    )
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_campaign
    mock_db.execute.return_value = mock_result
    mock_db.commit = AsyncMock()

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    resp = client.delete(f"/api/v1/campaigns/{camp_id}")
    app.dependency_overrides.clear()
    assert resp.status_code == 200
    assert "archived" in resp.json()["message"].lower()
    assert mock_campaign.campaign_status == "ARCHIVED"
