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


@pytest.mark.asyncio
async def test_get_campaign_details_includes_targeted_users():
    """Verify get_campaign_details aggregates targeted recipients across member emails."""
    service = CampaignCorrelationService()
    session = AsyncMock()

    camp_id = uuid.uuid4()
    email_id1 = uuid.uuid4()
    email_id2 = uuid.uuid4()

    mock_campaign = Campaign(
        id=camp_id,
        campaign_name="Targeted Phishing Cluster",
        campaign_status="ACTIVE",
        campaign_confidence=85.0,
        threat_summary="Attacker targeting finance users",
        first_detected_at=datetime.now(timezone.utc),
        last_activity_at=datetime.now(timezone.utc),
    )

    mem1 = CampaignMembership(id=uuid.uuid4(), campaign_id=camp_id, email_id=email_id1, membership_confidence=90.0)
    mem2 = CampaignMembership(id=uuid.uuid4(), campaign_id=camp_id, email_id=email_id2, membership_confidence=90.0)

    # Mock execute results
    # 1. select Campaign
    res_c = MagicMock()
    res_c.scalar_one_or_none.return_value = mock_campaign

    # 2. select CampaignMembership
    now = datetime.now(timezone.utc)
    u_id = uuid.uuid4()
    # 2. select CampaignMembership, Email.subject, sender, dates, qual, status, uploader
    res_m = MagicMock()
    res_m.all.return_value = [
        (mem1, "Urgent Payroll Update", "attacker@phish.test", now, now, now, "CRITICAL", "COMPLETED", u_id, "Asmodeus", "asmodeus.loh01@gmail.com"),
        (mem2, "Action Required: Tax Info", "attacker@phish.test", now, now, now, "HIGH", "COMPLETED", u_id, "Asmodeus", "asmodeus.loh01@gmail.com"),
    ]

    # 3. select EmailRecipient across emails (14 values)
    res_r = MagicMock()
    res_r.all.return_value = [
        ("cfo@victim.org", "Chief Financial Officer", email_id1, "Urgent Payroll Update", "attacker@phish.test", now, "CRITICAL", "COMPLETED", now, None, None, u_id, "Asmodeus", "asmodeus.loh01@gmail.com"),
        ("cfo@victim.org", "Chief Financial Officer", email_id2, "Action Required: Tax Info", "attacker@phish.test", now, "HIGH", "COMPLETED", now, None, None, u_id, "Asmodeus", "asmodeus.loh01@gmail.com"),
        ("accountant@victim.org", "Lead Accountant", email_id1, "Urgent Payroll Update", "attacker@phish.test", now, "CRITICAL", "COMPLETED", now, None, None, u_id, "Asmodeus", "asmodeus.loh01@gmail.com"),
    ]

    # 4. select CampaignEvidence
    res_ev = MagicMock()
    res_ev.scalars.return_value.all.return_value = []

    # 5. select CampaignEvent
    res_evt = MagicMock()
    res_evt.scalars.return_value.all.return_value = []

    session.execute.side_effect = [res_c, res_m, res_r, res_ev, res_evt]

    details = await service.get_campaign_details(session, camp_id)
    assert details is not None
    assert "targeted_users" in details
    assert len(details["targeted_users"]) == 2
    assert "reporting_users" in details
    assert len(details["reporting_users"]) == 1
    assert details["reporting_users"][0]["username"] == "Asmodeus"

    # cfo@victim.org received 2 emails
    cfo = next(u for u in details["targeted_users"] if u["recipient_address"] == "cfo@victim.org")
    assert cfo["emails_count"] == 2
    assert len(cfo["emails"]) == 2
    assert cfo["display_name"] == "Chief Financial Officer"
    assert cfo["emails"][0]["submitted_by_name"] == "Asmodeus"

    # accountant@victim.org received 1 email
    accountant = next(u for u in details["targeted_users"] if u["recipient_address"] == "accountant@victim.org")
    assert accountant["emails_count"] == 1


@pytest.mark.asyncio
async def test_detect_distributed_attack_campaigns():
    """Verify detect_distributed_attack_campaigns clusters emails targeting >= N distinct users."""
    service = CampaignCorrelationService()
    session = AsyncMock()

    eid1 = uuid.uuid4()
    eid2 = uuid.uuid4()
    eid3 = uuid.uuid4()
    org_id = uuid.uuid4()

    # Query returns 3 emails from same sender to 3 distinct victims with org_id
    mock_res = MagicMock()
    mock_res.all.return_value = [
        (eid1, "hacker@apt.test", "Invoice 1", datetime.now(timezone.utc), "alice@corp.test", "198.51.100.22", org_id),
        (eid2, "hacker@apt.test", "Invoice 2", datetime.now(timezone.utc), "bob@corp.test", "198.51.100.22", org_id),
        (eid3, "hacker@apt.test", "Invoice 3", datetime.now(timezone.utc), "charlie@corp.test", "198.51.100.22", org_id),
    ]

    # Mock existing check returning None (no prior campaign with this name)
    mock_existing = MagicMock()
    mock_existing.scalar_one_or_none.return_value = None

    session.execute.side_effect = [mock_res, mock_existing, mock_existing]

    mock_camp = Campaign(
        id=uuid.uuid4(),
        campaign_name="Targeted Campaign: hacker@apt.test (3 Users)",
        campaign_status="ACTIVE",
    )

    with patch.object(service, "create_campaign", new=AsyncMock(return_value=mock_camp)):
        clusters = await service.detect_distributed_attack_campaigns(session, min_targets=2)
        assert len(clusters) >= 1
        c = clusters[0]
        assert "hacker@apt.test" in c["campaign_name"]
        assert c["targeted_users_count"] == 3
        assert c["members_count"] == 3

