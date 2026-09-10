import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.storage import storage
from app.models.emails import Email, EmailHeader, EmailRecipient
from app.models.evidence import EvidenceObject
from tests.auth_helpers import TEST_USER
from app.parser.email_parser import (
    EmailStructureParser,
    sanitize_string,
    safe_decode_header_str,
    parse_rfc2822_date,
    extract_address_and_name,
    extract_address_list,
    MAX_MIME_RECURSION_DEPTH,
    MAX_HEADER_COUNT,
)
from app.services.parser_service import parse_and_persist_email

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for parser tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    return mock_session


def test_sanitize_string():
    """Verify null bytes are stripped and whitespace preserved."""
    assert sanitize_string("hello\x00world\x00") == "helloworld"
    assert sanitize_string(None) is None
    assert sanitize_string("   valid string   ") == "valid string"


def test_rfc2047_header_decoding():
    """Verify RFC 2047 encoded words are decoded cleanly."""
    # Base64 encoded UTF-8 "Urgent Security Alert"
    encoded_subj = "=?UTF-8?B?VXJnZW50IFNlY3VyaXR5IEFsZXJ0?="
    assert safe_decode_header_str(encoded_subj) == "Urgent Security Alert"

    # Plain ASCII
    assert safe_decode_header_str("Standard Subject") == "Standard Subject"
    assert safe_decode_header_str(None) is None


def test_rfc2822_date_parsing():
    """Verify standard and non-standard dates parse to UTC."""
    raw_date = "Sun, 06 Sep 2026 10:30:00 +0000"
    utc_dt, cleaned = parse_rfc2822_date(raw_date)
    assert utc_dt is not None
    assert utc_dt.year == 2026
    assert utc_dt.month == 9
    assert utc_dt.day == 6
    assert utc_dt.hour == 10
    assert utc_dt.tzinfo == timezone.utc

    # Malformed date fallback
    malformed = "Not-A-Valid-Date-String"
    dt_none, raw_out = parse_rfc2822_date(malformed)
    assert dt_none is None
    assert raw_out == malformed


def test_address_and_name_extraction():
    """Verify display names and addresses are separated."""
    raw = "Security Team <security@example.com>"
    name, addr = extract_address_and_name(raw)
    assert name == "Security Team"
    assert addr == "security@example.com"

    # Multi-address list
    multi = "Alice <alice@test.org>, Bob <bob@test.org>, carol@test.org"
    parsed_list = extract_address_list(multi)
    assert len(parsed_list) == 3
    assert parsed_list[0] == ("Alice", "alice@test.org")
    assert parsed_list[1] == ("Bob", "bob@test.org")
    assert parsed_list[2] == (None, "carol@test.org")


def test_parse_simple_plaintext_email():
    """Verify parsing a basic RFC822 plaintext message."""
    raw_eml = (
        b"From: John Doe <john.doe@company.com>\r\n"
        b"To: Jane Smith <jane.smith@target.com>\r\n"
        b"Cc: Audit <audit@target.com>\r\n"
        b"Subject: Q3 Threat Intelligence Report\r\n"
        b"Date: Sun, 06 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <msg-12345@company.com>\r\n"
        b"Return-Path: <bounce@company.com>\r\n"
        b"Reply-To: Helpdesk <support@company.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Dear Jane,\r\n"
        b"Please review the attached threat intelligence report.\r\n"
        b"Best regards,\r\n"
        b"John"
    )

    parser = EmailStructureParser()
    structure = parser.parse_bytes(raw_eml)

    assert structure.subject == "Q3 Threat Intelligence Report"
    assert structure.sender_display_name == "John Doe"
    assert structure.sender_address == "john.doe@company.com"
    assert structure.message_id == "<msg-12345@company.com>"
    assert structure.return_path == "bounce@company.com"
    assert structure.reply_to == "support@company.com"
    assert structure.reply_to_display_name == "Helpdesk"
    assert structure.sent_at is not None
    assert structure.sent_at.year == 2026

    # Recipients
    assert len(structure.recipients) == 2
    assert structure.recipients[0].recipient_type == "TO"
    assert structure.recipients[0].address == "jane.smith@target.com"
    assert structure.recipients[0].display_name == "Jane Smith"
    assert structure.recipients[1].recipient_type == "CC"
    assert structure.recipients[1].address == "audit@target.com"

    # Body
    assert structure.plain_text_body is not None
    assert "Please review the attached threat intelligence report" in structure.plain_text_body
    assert structure.is_multipart is False
    assert structure.has_attachments is False


def test_parse_multipart_mixed_with_attachment():
    """Verify parsing a multipart/mixed message with plain text, HTML, and a PDF attachment."""
    raw_eml = (
        b"From: attacker@malicious-domain.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: Urgent Invoice Payment Required\r\n"
        b"Date: Sun, 06 Sep 2026 14:00:00 +0000\r\n"
        b"Message-ID: <invoice-999@malicious-domain.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY_MIXED"\r\n'
        b"\r\n"
        b"--BOUNDARY_MIXED\r\n"
        b'Content-Type: multipart/alternative; boundary="BOUNDARY_ALT"\r\n'
        b"\r\n"
        b"--BOUNDARY_ALT\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please pay invoice 1042 immediately.\r\n"
        b"--BOUNDARY_ALT\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Please pay <b>invoice 1042</b> immediately.</p>\r\n"
        b"--BOUNDARY_ALT--\r\n"
        b"--BOUNDARY_MIXED\r\n"
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="invoice_1042.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAw\r\n"
        b"--BOUNDARY_MIXED--"
    )

    parser = EmailStructureParser()
    structure = parser.parse_bytes(raw_eml)

    assert structure.subject == "Urgent Invoice Payment Required"
    assert structure.sender_address == "attacker@malicious-domain.com"
    assert structure.is_multipart is True
    assert structure.has_attachments is True
    assert structure.attachment_count == 1
    assert structure.plain_text_body is not None
    assert "Please pay invoice 1042" in structure.plain_text_body
    assert structure.html_body is not None
    assert "<b>invoice 1042</b>" in structure.html_body


def test_security_null_byte_sanitization():
    """Security Test: Null bytes in headers/bodies must be stripped to prevent DB errors."""
    raw_eml = (
        b"From: malicious\x00user <attacker@domain\x00.com>\r\n"
        b"To: victim\x00@target.com\r\n"
        b"Subject: Malicious\x00 Subject with Null\x00 Bytes\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Body with \x00null bytes\x00."
    )

    parser = EmailStructureParser()
    structure = parser.parse_bytes(raw_eml)

    assert "\x00" not in structure.subject
    assert "\x00" not in structure.sender_display_name
    assert "\x00" not in structure.sender_address
    assert "\x00" not in structure.plain_text_body


def test_security_mime_recursion_depth():
    """Security Test: Deeply nested MIME structures must terminate at max_depth."""
    parser = EmailStructureParser(max_depth=5)

    # Construct nested multipart boundaries
    body = b"Leaf plain text content"
    for i in range(10):
        bnd = f"BND_{i}".encode("utf-8")
        body = (
            b'Content-Type: multipart/mixed; boundary="' + bnd + b'"\r\n\r\n'
            b"--" + bnd + b"\r\n" + body + b"\r\n--" + bnd + b"--"
        )

    raw_eml = b"From: test@domain.com\r\nSubject: Deep MIME\r\n" + body
    structure = parser.parse_bytes(raw_eml)

    assert structure is not None
    assert structure.total_mime_parts > 0


@pytest.mark.asyncio
async def test_parse_and_persist_service(mock_db_session):
    """Verify parse_and_persist_email updates the Email model and inserts headers & recipients."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        email_size_bytes=1024,
        analysis_status="PENDING",
        qualification_status="NORMAL",
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_email
    mock_db_session.execute.return_value = mock_result

    raw_eml = (
        b"From: Analyst <analyst@soc.gov>\r\n"
        b"To: Manager <manager@soc.gov>\r\n"
        b"Subject: Phishing Incident IOCs\r\n"
        b"Date: Sun, 06 Sep 2026 15:00:00 +0000\r\n"
        b"Message-ID: <ioc-123@soc.gov>\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Here are the confirmed malicious indicators."
    )

    structure = await parse_and_persist_email(
        email_id=email_id,
        raw_bytes=raw_eml,
        db=mock_db_session,
    )

    assert structure.subject == "Phishing Incident IOCs"
    assert mock_email.subject == "Phishing Incident IOCs"
    assert mock_email.sender_address == "analyst@soc.gov"
    assert mock_email.sender_display_name == "Analyst"
    assert mock_email.message_id_header == "<ioc-123@soc.gov>"

    # Verify headers and recipients added to session
    assert mock_db_session.add.call_count >= 2
    assert mock_db_session.commit.called


def test_api_get_email_headers(mock_db_session):
    """Verify GET /api/v1/emails/{email_id}/headers returns ordered RFC822 headers."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        created_at=now_utc,
        updated_at=now_utc,
    )

    mock_headers = [
        EmailHeader(
            id=uuid.uuid4(),
            email_id=email_id,
            header_name="From",
            header_value="admin@domain.com",
            normalized_value="admin@domain.com",
            header_order=1,
            created_at=now_utc,
        ),
        EmailHeader(
            id=uuid.uuid4(),
            email_id=email_id,
            header_name="Subject",
            header_value="Alert",
            normalized_value="Alert",
            header_order=2,
            created_at=now_utc,
        ),
    ]

    # Return mock email on first execute (via _get_authorized_email_and_evidence,
    # which expects a (Email, EvidenceObject, EmailSource) row from .first()) and
    # headers on second execute.
    mock_email_res = MagicMock()
    mock_email_res.first.return_value = (mock_email, None, None)

    mock_headers_res = MagicMock()
    mock_headers_res.scalars.return_value.all.return_value = mock_headers

    mock_db_session.execute.side_effect = [mock_email_res, mock_headers_res]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/emails/{email_id}/headers")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["total_headers"] == 2
    assert data["headers"][0]["header_name"] == "From"
    assert data["headers"][0]["header_order"] == 1
    assert data["headers"][1]["header_name"] == "Subject"
    assert data["headers"][1]["header_order"] == 2


def test_api_get_email_structure_endpoint(mock_db_session):
    """Verify GET /api/v1/emails/{email_id}/structure returns parsed structure & MIME tree."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    raw_eml = (
        b"From: Threat Actor <actor@apt.net>\r\n"
        b"To: Target User <target@corp.com>\r\n"
        b"Subject: Password Expiry Notification\r\n"
        b"Date: Sun, 06 Sep 2026 16:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Click here to reset your credentials."
    )

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Password Expiry Notification",
        sender_address="actor@apt.net",
        sender_display_name="Threat Actor",
        sent_at=now_utc,
        created_at=now_utc,
        updated_at=now_utc,
    )
    mock_evidence = EvidenceObject(
        id=uuid.uuid4(),
        email_id=email_id,
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/sample.eml",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        created_at=now_utc,
    )

    mock_row_res = MagicMock()
    mock_row_res.first.return_value = (mock_email, mock_evidence, None)

    mock_recipients_res = MagicMock()
    mock_recipients_res.scalars.return_value.all.return_value = [
        EmailRecipient(
            id=uuid.uuid4(),
            email_id=email_id,
            recipient_type="TO",
            address="target@corp.com",
            display_name="Target User",
            created_at=now_utc,
        )
    ]

    mock_db_session.execute.side_effect = [mock_row_res, mock_recipients_res]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    with patch.object(storage, "get_evidence_object", return_value=raw_eml):
        response = client.get(f"/api/v1/emails/{email_id}/structure")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["subject"] == "Password Expiry Notification"
    assert data["sender_address"] == "actor@apt.net"
    assert data["sender_display_name"] == "Threat Actor"
    assert len(data["recipients"]) == 1
    assert data["recipients"][0]["address"] == "target@corp.com"
    assert "Click here to reset your credentials" in data["plain_text_body"]
