import uuid
import email
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.storage import storage
from app.models.emails import Email, RelayHop, EmailAuthenticationResult
from app.models.evidence import EvidenceObject
from app.parser.header_analyzer import (
    ReceivedHeaderParser,
    AuthenticationResultsParser,
    extract_ip_from_text,
    extract_domain_from_email_or_host,
    get_organizational_domain,
    ParsedRelayHop,
    ParsedAuthenticationResult,
)
from app.services.header_analysis_service import analyze_and_persist_headers
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for header analysis tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    return mock_session


def test_extract_ip_from_text():
    """Verify IPv4 and IPv6 extraction from various Received header formats."""
    # IPv4 inside bracket
    assert extract_ip_from_text("from mail.example.com ([198.51.100.42])") == "198.51.100.42"
    # Bare IPv4
    assert extract_ip_from_text("from 203.0.113.15 by mx.google.com") == "203.0.113.15"
    # IPv6
    assert extract_ip_from_text("from [2001:db8:85a3::8a2e:370:7334]") == "2001:db8:85a3::8a2e:370:7334"
    # Non-IP
    assert extract_ip_from_text("from hostname.local without ip") is None


def test_domain_extraction_and_organizational_domain():
    """Verify domain extraction and multi-level TLD organizational domain heuristics."""
    assert extract_domain_from_email_or_host("user@mail.corp.company.com") == "mail.corp.company.com"
    assert extract_domain_from_email_or_host("<admin@victim.co.uk>") == "victim.co.uk"
    assert get_organizational_domain("mail.sub.corp.company.com") == "company.com"
    assert get_organizational_domain("mail.threat.co.uk") == "threat.co.uk"
    assert get_organizational_domain("google.com") == "google.com"


def test_parse_received_headers_chronological():
    """Verify Received headers are sorted chronologically and calculate transit delays."""
    raw_headers = [
        # Final hop (top of email)
        "from mail-relay.internal.net (10.0.0.5) by mx.internal.net with ESMTP; Sun, 06 Sep 2026 12:00:04 +0000",
        # Intermediate hop
        "from mail-out.sender.com (198.51.100.10) by mail-relay.internal.net with ESMTPS id xyz123; Sun, 06 Sep 2026 12:00:02 +0000",
        # Originating hop (bottom of email)
        "from client-workstation.lan (192.168.1.50) by mail-out.sender.com with SMTP; Sun, 06 Sep 2026 12:00:00 +0000",
    ]

    parser = ReceivedHeaderParser()
    hops = parser.parse_received_headers(raw_headers)

    assert len(hops) == 3
    # Hop 1 is the earliest originating hop
    assert hops[0].sequence_number == 1
    assert hops[0].source_ip == "192.168.1.50"
    assert hops[0].source_host == "client-workstation.lan"
    assert hops[0].destination_host == "mail-out.sender.com"
    assert hops[0].transit_delay_seconds is None  # First hop has no prior delay

    # Hop 2 is the gateway/edge hop
    assert hops[1].sequence_number == 2
    assert hops[1].source_ip == "198.51.100.10"
    assert hops[1].source_host == "mail-out.sender.com"
    assert hops[1].queue_id == "xyz123"
    assert hops[1].transit_delay_seconds == 2  # 12:00:00 -> 12:00:02 = 2s
    assert hops[1].reliability == "HIGH"

    # Hop 3 is the internal delivery hop
    assert hops[2].sequence_number == 3
    assert hops[2].source_ip == "10.0.0.5"
    assert hops[2].transit_delay_seconds == 2  # 12:00:02 -> 12:00:04 = 2s


def test_parse_authentication_results_and_alignment():
    """Verify Authentication-Results parsing for SPF, DKIM, DMARC, and domain alignment."""
    raw_eml = (
        b"From: Security Team <alert@notifications.paypal.com>\r\n"
        b"Return-Path: <bounces@notifications.paypal.com>\r\n"
        b"Authentication-Results: mx.google.com; "
        b"spf=pass (google.com: domain of bounces@notifications.paypal.com designates 198.51.100.1 as permitted sender) "
        b"smtp.mailfrom=bounces@notifications.paypal.com; "
        b"dkim=pass header.i=@notifications.paypal.com header.s=s2026 header.b=AbCdEfGh; "
        b"dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=notifications.paypal.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=notifications.paypal.com; "
        b"s=s2026; t=1757160000; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; "
        b"b=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789==;\r\n"
        b"Subject: Statement Ready\r\n"
        b"\r\n"
        b"Your statement is ready."
    )

    msg = email.message_from_bytes(raw_eml, policy=email.policy.default)
    auth_parser = AuthenticationResultsParser()
    auth_result = auth_parser.parse_authentication(msg)

    assert auth_result.spf_result == "PASS"
    assert auth_result.dkim_result == "PASS"
    assert auth_result.dmarc_result == "PASS"
    assert auth_result.from_alignment_result == "PASS"
    assert auth_result.from_domain == "notifications.paypal.com"
    assert auth_result.auth_serv_id == "mx.google.com"

    assert len(auth_result.dkim_signatures) == 1
    sig = auth_result.dkim_signatures[0]
    assert sig.domain == "notifications.paypal.com"
    assert sig.selector == "s2026"
    assert sig.algorithm == "rsa-sha256"


def test_from_domain_alignment_spoof_detection():
    """Verify From domain alignment fails when attacker spoofs domain with different SPF return-path."""
    raw_eml = (
        b"From: CEO <ceo@target-enterprise.com>\r\n"
        b"Return-Path: <attacker@malicious-vps.net>\r\n"
        b"Authentication-Results: mx.target-enterprise.com; "
        b"spf=pass smtp.mailfrom=attacker@malicious-vps.net; "
        b"dkim=fail;\r\n"
        b"Subject: Wire Transfer Request\r\n"
        b"\r\n"
        b"Please send 50,000 USD immediately."
    )

    msg = email.message_from_bytes(raw_eml, policy=email.policy.default)
    auth_parser = AuthenticationResultsParser()
    auth_result = auth_parser.parse_authentication(msg)

    assert auth_result.spf_result == "PASS"
    assert auth_result.dkim_result == "FAIL"
    # Even though SPF passed for malicious-vps.net, it does NOT align with target-enterprise.com!
    assert auth_result.from_alignment_result == "FAIL"


@pytest.mark.asyncio
async def test_header_analysis_service_persistence(mock_db_session):
    """Verify analyze_and_persist_headers persists RelayHop and EmailAuthenticationResult."""
    email_id = uuid.uuid4()
    raw_eml = (
        b"From: sender@domain.com\r\n"
        b"Received: from mx.sender.com (198.51.100.25) by mx.recipient.com; Sun, 06 Sep 2026 12:00:00 +0000\r\n"
        b"Authentication-Results: mx.recipient.com; spf=pass; dkim=pass\r\n"
        b"Subject: Test\r\n\r\nBody"
    )

    hops, auth = await analyze_and_persist_headers(
        email_id=email_id,
        raw_bytes=raw_eml,
        db=mock_db_session,
    )

    assert len(hops) == 1
    assert auth.spf_result == "PASS"
    assert auth.dkim_result == "PASS"

    # Verify add called for RelayHop and EmailAuthenticationResult
    assert mock_db_session.add.call_count >= 2
    assert mock_db_session.commit.called


def test_api_get_email_relay_hops(mock_db_session):
    """Verify GET /api/v1/emails/{email_id}/hops returns reconstructed relay hops."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_email = Email(id=email_id, source_id=uuid.uuid4(), created_at=now_utc, updated_at=now_utc)
    mock_hops = [
        RelayHop(
            id=uuid.uuid4(),
            email_id=email_id,
            sequence_number=1,
            source_host="mail.origin.net",
            source_ip="203.0.113.5",
            destination_host="mx.edge.com",
            observed_at=now_utc,
            reliability="HIGH",
            evidence={"transit_delay_seconds": 1, "protocol": "ESMTPS"},
            created_at=now_utc,
        )
    ]

    mock_email_res = MagicMock()
    mock_email_res.first.return_value = (mock_email, None, None)

    mock_hops_res = MagicMock()
    mock_hops_res.scalars.return_value.all.return_value = mock_hops

    mock_db_session.execute.side_effect = [mock_email_res, mock_hops_res]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/hops")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["total_hops"] == 1
    assert data["originating_ip"] == "203.0.113.5"
    assert data["hops"][0]["source_ip"] == "203.0.113.5"
    assert data["hops"][0]["reliability"] == "HIGH"


def test_api_get_email_auth_results(mock_db_session):
    """Verify GET /api/v1/emails/{email_id}/auth returns authentication details."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_email = Email(id=email_id, source_id=uuid.uuid4(), created_at=now_utc, updated_at=now_utc)
    mock_auth = EmailAuthenticationResult(
        id=uuid.uuid4(),
        email_id=email_id,
        spf_result="PASS",
        dkim_result="PASS",
        dmarc_result="PASS",
        from_alignment_result="PASS",
        return_path="bounces@verified.com",
        evidence={"auth_serv_id": "mx.google.com", "dkim_signatures": [{"domain": "verified.com"}]},
        created_at=now_utc,
    )

    mock_email_res = MagicMock()
    mock_email_res.first.return_value = (mock_email, None, None)

    mock_auth_res = MagicMock()
    mock_auth_res.scalar_one_or_none.return_value = mock_auth

    mock_db_session.execute.side_effect = [mock_email_res, mock_auth_res]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/auth")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["spf_result"] == "PASS"
    assert data["dkim_result"] == "PASS"
    assert data["dmarc_result"] == "PASS"
    assert data["from_alignment_result"] == "PASS"
    assert data["auth_serv_id"] == "mx.google.com"
