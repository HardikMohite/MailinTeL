import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.storage import storage
from app.models.emails import Email
from app.models.intelligence import Domain, URL, EmailURL, IPAddress
from app.models.evidence import EvidenceObject
from app.parser.artifact_extractor import (
    EmailArtifactExtractor,
    refang_indicator,
    defang_indicator,
    normalize_url_string,
    DANGEROUS_EXTENSIONS,
)
from app.services.artifact_service import extract_and_persist_artifacts
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for artifact tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.delete = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    return mock_session


def test_refang_and_defang_indicators():
    """Verify refanging and defanging of URLs and indicators."""
    defanged = "hxxps://malicious[.]phish-portal[.]xyz/login?id=123"
    refanged = refang_indicator(defanged)
    assert refanged == "https://malicious.phish-portal.xyz/login?id=123"

    safe_display = defang_indicator("https://bank-login.com/auth")
    assert safe_display == "hxxps://bank-login[.]com/auth"


def test_normalize_url_string():
    """Verify URL normalization, scheme prepending, domain extraction, and SHA-256 generation."""
    raw_url = "www.target-portal.com/login?token=abc#section"
    norm_url, domain, url_hash = normalize_url_string(raw_url)

    assert norm_url == "http://www.target-portal.com/login?token=abc#section"
    assert domain == "www.target-portal.com"
    assert url_hash is not None
    assert len(url_hash) == 64


def test_extract_urls_from_html_and_text():
    """Verify extraction of URLs, anchor texts, and images from HTML and plain text bodies."""
    raw_eml = (
        b"From: Spoofed Support <support@legit-service.com>\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Action Required: Verify Account\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b'<html><body>'
        b'<p>Dear Customer, please verify your account at <a href="https://account-verify.phish.top/login">Verify Now</a>.</p>'
        b'<img src="https://tracking-pixel.phish.top/img.png" />'
        b'<p>Also visit hxxp://backup-portal[.]xyz for details.</p>'
        b'</body></html>'
    )

    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml)

    assert bundle.total_urls >= 3
    urls_dict = {u.normalized_url: u for u in bundle.urls}

    # Verify primary phishing link
    assert "https://account-verify.phish.top/login" in urls_dict
    assert urls_dict["https://account-verify.phish.top/login"].anchor_text == "Verify Now"
    assert urls_dict["https://account-verify.phish.top/login"].domain == "account-verify.phish.top"
    assert urls_dict["https://account-verify.phish.top/login"].root_domain == "phish.top"

    # Verify defanged URL extracted and refanged
    assert "http://backup-portal.xyz" in urls_dict


def test_extract_domains_and_suspicious_tlds():
    """Verify extracted domains are tagged with suspicious TLD and punycode flags."""
    raw_eml = (
        b"From: admin@xn--pypal-4ve.com\r\n"
        b"Subject: Test\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Visit http://stealth-malware.loan and https://clean-company.com"
    )

    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml)

    domains_dict = {d.domain: d for d in bundle.domains}

    assert "xn--pypal-4ve.com" in domains_dict
    assert domains_dict["xn--pypal-4ve.com"].is_punycode is True

    assert "stealth-malware.loan" in domains_dict
    assert domains_dict["stealth-malware.loan"].is_suspicious_tld is True

    assert "clean-company.com" in domains_dict
    assert domains_dict["clean-company.com"].is_suspicious_tld is False


def test_extract_ips_and_categories():
    """Verify IP addresses extracted and categorized from headers and bodies."""
    raw_eml = (
        b"From: test@domain.com\r\n"
        b"Received: from [198.51.100.75] by mx.google.com; Sun, 06 Sep 2026 12:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Internal C2 at 10.0.50.25 and external gateway at 203.0.113.88."
    )

    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml)

    ips_dict = {ip.ip_address: ip for ip in bundle.ip_addresses}

    assert "10.0.50.25" in ips_dict
    assert ips_dict["10.0.50.25"].category == "PRIVATE_RFC1918"

    assert "203.0.113.88" in ips_dict
    assert "198.51.100.75" in ips_dict


def test_extract_attachments_and_threat_scoring():
    """Verify attachment extraction, SHA-256/MD5 hashing, and dangerous extension flagging."""
    raw_eml = (
        b"From: attacker@malicious.org\r\n"
        b"Subject: Resume\r\n"
        b'Content-Type: multipart/mixed; boundary="ATTACH_BND"\r\n'
        b"\r\n"
        b"--ATTACH_BND\r\n"
        b"Content-Type: text/plain\r\n\r\nSee attached invoice.\r\n"
        b"--ATTACH_BND\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="invoice_scan.pdf.exe"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA\r\n"
        b"--ATTACH_BND--"
    )

    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml)

    assert bundle.total_attachments == 1
    att = bundle.attachments[0]
    assert att.filename == "invoice_scan.pdf.exe"
    assert att.is_dangerous is True
    assert att.has_double_extension is True
    assert len(att.sha256_hash) == 64
    assert len(att.md5_hash) == 32
    assert bundle.has_dangerous_attachments is True


@pytest.mark.asyncio
async def test_artifact_service_persistence(mock_db_session):
    """Verify extract_and_persist_artifacts saves Domain, URL, EmailURL, IPAddress, and EvidenceObject."""
    email_id = uuid.uuid4()
    raw_eml = (
        b"From: alert@phish-domain.com\r\n"
        b"Subject: Action Required\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Visit https://phish-domain.com/login and connect to 198.51.100.99"
    )

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalars.return_value.all.return_value = []
    mock_db_session.execute.return_value = mock_result

    with patch.object(storage, "upload_evidence_object", return_value={"version_id": "v1"}):
        bundle = await extract_and_persist_artifacts(
            email_id=email_id,
            raw_bytes=raw_eml,
            db=mock_db_session,
        )

    assert bundle.total_urls >= 1
    assert bundle.total_domains >= 1
    assert bundle.total_ips >= 1

    assert mock_db_session.add.called
    assert mock_db_session.commit.called


def test_api_get_email_artifacts_endpoint(mock_db_session):
    """Verify GET /api/v1/emails/{email_id}/artifacts returns normalized bundle."""
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    raw_eml = (
        b"From: alert@phish-domain.com\r\n"
        b"Subject: Urgent Action\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Click https://phish-domain.com/login"
    )

    mock_email = Email(id=email_id, source_id=uuid.uuid4(), created_at=now_utc, updated_at=now_utc)
    mock_evidence = EvidenceObject(
        id=uuid.uuid4(),
        email_id=email_id,
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/sample.eml",
        created_at=now_utc,
    )

    mock_row_res = MagicMock()
    # _get_authorized_email_and_evidence unpacks (Email, EvidenceObject, EmailSource);
    # no EmailSource is needed for this test's assertions, so the third element is None.
    mock_row_res.first.return_value = (mock_email, mock_evidence, None)
    mock_db_session.execute.return_value = mock_row_res

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    with patch.object(storage, "get_evidence_object", return_value=raw_eml):
        response = client.get(f"/api/v1/emails/{email_id}/artifacts")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["email_id"] == str(email_id)
    assert data["total_urls"] >= 1
    assert data["total_domains"] >= 1
    assert data["urls"][0]["domain"] == "phish-domain.com"
