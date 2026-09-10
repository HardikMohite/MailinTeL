import hashlib
import io
import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.storage import storage
from app.core.tasks import job_manager, JobStatus
from app.models.emails import Email, EmailSource
from app.models.evidence import EvidenceObject, CustodyEvent
from tests.auth_helpers import TEST_USER

client = TestClient(app)

SAMPLE_EML_CONTENT = b"""From: "Security Alert" <alert@account-verify-portal.com>
To: victim@target-corp.com
Subject: Urgent: Verify Account Access Immediately
Date: Sun, 06 Sep 2026 12:00:00 +0000
Message-ID: <threat-12345@account-verify-portal.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your account has been flagged for immediate verification.
Click here to confirm your credentials: https://account-verify-portal.com/login
"""


@pytest.fixture
def mock_db_session():
    """Mock async database session for upload tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    return mock_session


def test_upload_eml_success(mock_db_session):
    """Verify successful .eml upload returns 201 Created and valid receipt with SHA-256."""
    expected_sha256 = hashlib.sha256(SAMPLE_EML_CONTENT).hexdigest()

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch.object(storage, "upload_evidence_object", return_value={"version_id": "v1"}):
        response = client.post(
            "/api/v1/emails/upload",
            files={"file": ("phishing_test.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
        )

    app.dependency_overrides.clear()

    assert response.status_code == 201
    data = response.json()
    assert "email_id" in data
    assert "evidence_id" in data
    assert "job_id" in data
    assert data["filename"] == "phishing_test.eml"
    assert data["sha256_hash"] == expected_sha256
    assert data["size_bytes"] == len(SAMPLE_EML_CONTENT)
    assert data["analysis_status"] == "PENDING"
    assert data["qualification_status"] == "NORMAL"

    # Verify database objects were staged
    assert mock_db_session.add.call_count >= 4
    assert mock_db_session.commit.called


def test_upload_invalid_extension():
    """Verify uploading non-email extensions (.exe, .pdf) is rejected with 400."""
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.post(
        "/api/v1/emails/upload",
        files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")},
    )
    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert "invalid file extension" in response.json()["error"].lower()


def test_upload_empty_file():
    """Verify uploading an empty 0-byte file is rejected with 400."""
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.post(
        "/api/v1/emails/upload",
        files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")},
    )
    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert "empty" in response.json()["error"].lower()


def test_upload_oversized_file():
    """Verify uploading file exceeding 25MB is rejected with 413."""
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    with patch("app.api.v1.endpoints.emails.MAX_UPLOAD_SIZE_BYTES", 100):
        response = client.post(
            "/api/v1/emails/upload",
            files={"file": ("large.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")},
        )
        assert response.status_code == 413
        assert "exceeds the maximum permitted size" in response.json()["error"].lower()
    app.dependency_overrides.clear()


def test_get_email_details_success(mock_db_session):
    """Verify GET /api/v1/emails/{email_id} returns normalized email details."""
    test_id = uuid.uuid4()
    source_id = uuid.uuid4()

    mock_email = Email(
        id=test_id,
        source_id=source_id,
        subject="Suspicious Invoice Attached",
        sender_address="billing@evil-phish.net",
        sender_display_name="Accounting",
        email_size_bytes=1024,
        analysis_status="PENDING",
        qualification_status="NORMAL",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    mock_source = EmailSource(id=source_id, source_type="FILE_UPLOAD", source_reference="invoice.eml")
    mock_evidence = EvidenceObject(
        id=uuid.uuid4(),
        email_id=test_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="invoice.eml",
        content_type="message/rfc822",
        size_bytes=1024,
        sha256_hash="abc123def456",
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/test.eml",
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_email, mock_source, mock_evidence)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    response = client.get(f"/api/v1/emails/{test_id}")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_id)
    assert data["subject"] == "Suspicious Invoice Attached"
    assert data["sender_address"] == "billing@evil-phish.net"
    assert data["sha256_hash"] == "abc123def456"


def test_get_email_details_not_found(mock_db_session):
    """Verify GET /api/v1/emails/{non_existent} returns 404."""
    mock_result = MagicMock()
    mock_result.first.return_value = None
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    non_existent = uuid.uuid4()
    response = client.get(f"/api/v1/emails/{non_existent}")

    app.dependency_overrides.clear()

    assert response.status_code == 404
    assert "not found" in response.json()["error"].lower()


def test_list_emails_success(mock_db_session):
    """Verify GET /api/v1/emails returns paginated email list."""
    mock_email = Email(
        id=uuid.uuid4(),
        source_id=uuid.uuid4(),
        subject="Phishing Alert",
        sender_address="attacker@domain.com",
        analysis_status="PENDING",
        qualification_status="NORMAL",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    mock_source = EmailSource(source_type="FILE_UPLOAD")
    mock_evidence = EvidenceObject(
        evidence_type="ORIGINAL_EMAIL",
        original_filename="alert.eml",
        sha256_hash="11223344",
        bucket_name="mailintel-evidence",
        object_key="test.eml",
        size_bytes=500,
        content_type="message/rfc822",
    )

    mock_result = MagicMock()
    mock_result.all.return_value = [(mock_email, mock_source, mock_evidence)]
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    response = client.get("/api/v1/emails?limit=10&analysis_status=PENDING")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["subject"] == "Phishing Alert"
