import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.dna.dna_builder import (
    EmailDNABuilder,
    EmailDNABundle,
    compute_stable_json_hash,
)
from app.services.dna_service import generate_and_persist_email_dna
from app.models.emails import Email, EmailSource
from app.models.dna import EmailDNAProfile
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for DNA tests."""
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
# Unit Tests: EmailDNABuilder & Hash Engine
# ---------------------------------------------------------

def test_compute_stable_json_hash():
    dict_a = {"z": 1, "a": {"b": 2, "c": 3}}
    dict_b = {"a": {"c": 3, "b": 2}, "z": 1}
    # Hashes must be completely deterministic regardless of dict insertion order
    hash_a = compute_stable_json_hash(dict_a)
    hash_b = compute_stable_json_hash(dict_b)
    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_dna_content_fingerprint_extraction():
    builder = EmailDNABuilder()
    email_metadata = {
        "subject": "Fwd: URGENT: Verify Your Account Security Now",
        "plain_text_body": "Please click the link below to verify your password immediately or account will be locked.",
        "html_body": "<html><body><div><p>Click <a href='http://phish.net'>here</a></p></div></body></html>",
    }
    artifacts = {
        "attachments": [
            {"filename": "document.pdf", "sha256_hash": "1111" * 16, "extension": ".pdf"}
        ]
    }

    fp = builder.extract_content_fingerprint(email_metadata, artifacts)

    assert fp["subject_normalized"] == "urgent: verify your account security now"
    assert fp["subject_hash"] is not None
    assert "urgent" in fp["subject_tokens"]
    assert "verify" in fp["subject_tokens"]
    assert fp["attachment_count"] == 1
    assert fp["attachment_extensions"] == [".pdf"]
    assert len(fp["dom_tag_sequence"]) >= 3
    assert len(fp["detected_urgency_markers"]) >= 1


def test_dna_technical_fingerprint_extraction():
    builder = EmailDNABuilder()
    headers = [
        {"header_name": "Return-Path", "header_value": "<bounces@evil.com>"},
        {"header_name": "DKIM-Signature", "header_value": "v=1; a=rsa-sha256; d=evil.com; s=s2026; ..."},
        {"header_name": "Message-ID", "header_value": "<12345.abc@evil.com>"},
        {"header_name": "X-Mailer", "header_value": "PHPMailer 6.0.0"},
    ]
    auth_results = {
        "spf_verdict": "FAIL",
        "dkim_verdict": "PASS",
        "dmarc_verdict": "FAIL",
    }
    structure = {
        "total_mime_parts": 2,
        "mime_parts": [{"content_type": "text/html"}, {"content_type": "application/pdf"}],
    }

    fp = builder.extract_technical_fingerprint(headers, auth_results, structure)

    assert fp["header_order_hash"] is not None
    assert fp["header_count"] == 4
    assert fp["x_mailer"] == "PHPMailer 6.0.0"
    assert fp["message_id_domain"] == "evil.com"
    assert fp["dkim_selector"] == "s2026"
    assert fp["dkim_signing_domain"] == "evil.com"
    assert fp["dkim_algorithm"] == "rsa-sha256"
    assert fp["total_mime_parts"] == 2
    assert fp["spf_verdict"] == "FAIL"


def test_dna_infrastructure_fingerprint_extraction():
    builder = EmailDNABuilder()
    relay_hops = [
        {"source_ip": "185.220.101.5", "source_host": "tor-exit-01.relay.net"},
        {"source_ip": "54.240.1.2", "source_host": "mail.amazon.com"},
    ]
    infrastructure_intel = [
        {
            "ip_address": "185.220.101.5",
            "asn": "AS208323",
            "country_code": "DE",
            "classifications": [{"classification_type": "TOR"}],
        },
        {
            "ip_address": "54.240.1.2",
            "asn": "AS16509",
            "country_code": "US",
            "classifications": [{"classification_type": "CLOUD_HOSTED"}],
        },
    ]
    domain_intel = [
        {"domain": "attacker.duckdns.org", "is_dynamic_dns": True, "is_nrd": True}
    ]

    fp = builder.extract_infrastructure_fingerprint(relay_hops, infrastructure_intel, domain_intel)

    assert fp["originating_ip"] == "185.220.101.5"
    assert fp["relay_hop_count"] == 2
    assert "AS208323" in fp["asn_chain"]
    assert "AS16509" in fp["asn_chain"]
    assert "DE" in fp["country_chain"]
    assert "US" in fp["country_chain"]
    assert "TOR" in fp["infrastructure_classifications"]
    assert "CLOUD_HOSTED" in fp["infrastructure_classifications"]
    assert fp["has_dynamic_dns"] is True
    assert fp["has_nrd"] is True


def test_dna_behavioral_fingerprint_brand_spoofing():
    builder = EmailDNABuilder()
    email_metadata = {
        "sender_address": "attacker@phish-portal.xyz",
        "sender_display_name": "Microsoft 365 Support Desk",
        "recipients": [
            {"address": "victim1@target.com"},
            {"address": "victim2@target.com"},
        ],
    }
    auth_results = {"from_domain_aligned": "FAIL"}
    artifacts = {
        "urls": [
            {"domain": "login-office365-verify.com"},
            {"domain": "phish-portal.xyz"},
        ]
    }

    fp = builder.extract_behavioral_fingerprint(email_metadata, auth_results, artifacts)

    assert fp["recipient_count"] == 2
    assert fp["recipient_domain_diversity"] == 1
    assert fp["url_count"] == 2
    assert fp["has_brand_display_mismatch"] is True
    assert fp["from_domain_alignment"] == "FAIL"


def test_dna_temporal_fingerprint_extraction():
    builder = EmailDNABuilder()
    email_metadata = {"sent_at": "2026-09-06T14:30:00Z"}
    headers = [{"header_name": "Date", "header_value": "Sun, 6 Sep 2026 14:30:00 +0000"}]
    relay_hops = [{"delay_seconds": 3}, {"delay_seconds": 15}]

    fp = builder.extract_temporal_fingerprint(email_metadata, headers, relay_hops)

    assert fp["hour_of_day_utc"] == 14
    assert fp["day_of_week"] == 6  # Sunday
    assert fp["timezone_offset_header"] == "+0000"
    assert fp["total_transit_delay_seconds"] == 18
    assert fp["max_hop_delay_seconds"] == 15


def test_build_dna_profile_bundle():
    builder = EmailDNABuilder()
    bundle = builder.build_dna_profile(
        email_id=str(uuid.uuid4()),
        email_metadata={"subject": "Important Invoice", "sender_address": "billing@corp.com"},
        headers=[{"header_name": "X-Mailer", "header_value": "Outlook"}],
    )

    assert bundle.dna_version == "1.0"
    assert bundle.overall_dna_hash is not None
    assert len(bundle.overall_dna_hash) == 64
    assert "subject_normalized" in bundle.content_fingerprint
    assert "x_mailer" in bundle.technical_fingerprint


# ---------------------------------------------------------
# Integration Tests: DB Persistence & Service Layer
# ---------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_and_persist_email_dna(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="admin@sample.org",
        subject="DNA Test Email",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_res_email = MagicMock()
    mock_res_email.scalar_one_or_none.return_value = mock_email

    mock_res_empty = MagicMock()
    mock_res_empty.scalar_one_or_none.return_value = None
    mock_res_empty.scalars.return_value.all.return_value = []
    mock_res_empty.all.return_value = []

    mock_db_session.execute.side_effect = [
        mock_res_email,  # Email
        mock_res_empty,  # Recipients
        mock_res_empty,  # Headers
        mock_res_empty,  # Auth
        mock_res_empty,  # Hops
        mock_res_empty,  # Evidence attachments
        mock_res_empty,  # URLs
        mock_res_empty,  # EmailDNAProfile check
    ]

    with patch("app.services.domain_intel_service.enrich_email_domains", new_callable=AsyncMock) as mock_dom, \
         patch("app.services.infrastructure_service.enrich_email_infrastructure", new_callable=AsyncMock) as mock_infra:

        mock_dom.return_value = []
        mock_infra.return_value = []

        bundle = await generate_and_persist_email_dna(
            email_id=email_id,
            db=mock_db_session,
        )

        assert bundle.email_id == str(email_id)
        assert len(bundle.overall_dna_hash) == 64
        assert mock_db_session.add.called
        assert mock_db_session.commit.called


# ---------------------------------------------------------
# Integration Tests: REST API Endpoints
# ---------------------------------------------------------

def test_api_get_email_dna_success(mock_db_session):
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="sender@target.com",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_dna_rec = EmailDNAProfile(
        id=uuid.uuid4(),
        email_id=email_id,
        content_fingerprint={"subject_hash": "abcd"},
        technical_fingerprint={"header_count": 5},
        infrastructure_fingerprint={"relay_hop_count": 2},
        behavioral_fingerprint={"recipient_count": 1},
        temporal_fingerprint={"hour_of_day_utc": 10},
        dna_version="1.0",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_source = EmailSource(
        id=uuid.uuid4(),
        organization_id=TEST_USER.organization_id,
        source_type="FILE_UPLOAD",
    )

    mock_res_email = MagicMock()
    mock_res_email.first.return_value = (mock_email, mock_source)

    mock_res_dna = MagicMock()
    mock_res_dna.scalar_one_or_none.return_value = mock_dna_rec

    mock_db_session.execute.side_effect = [
        mock_res_email,
        mock_res_dna,
    ]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/dna")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["dna_version"] == "1.0"
    assert len(data["overall_dna_hash"]) == 64
    assert data["content_fingerprint"]["subject_hash"] == "abcd"
    assert data["technical_fingerprint"]["header_count"] == 5


def test_api_get_email_dna_not_found(mock_db_session):
    nonexistent_id = uuid.uuid4()
    mock_res = MagicMock()
    mock_res.first.return_value = None
    mock_db_session.execute.return_value = mock_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{nonexistent_id}/dna")
    app.dependency_overrides.clear()

    assert response.status_code == 404
