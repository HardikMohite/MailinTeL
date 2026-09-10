import hashlib
import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.storage import storage
from app.models.evidence import EvidenceObject, CustodyEvent
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for evidence tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.execute = AsyncMock()
    return mock_session


def test_get_evidence_metadata_success(mock_db_session):
    """Verify GET /api/v1/evidence/{evidence_id} returns authoritative evidence metadata."""
    evidence_id = uuid.uuid4()
    email_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_evidence = EvidenceObject(
        id=evidence_id,
        email_id=email_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="threat_sample.eml",
        content_type="message/rfc822",
        size_bytes=2048,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/threat_sample.eml",
        immutable=True,
        retention_status="ACTIVE",
        acquired_at=now_utc,
        stored_at=now_utc,
        created_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_evidence, None)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    response = client.get(f"/api/v1/evidence/{evidence_id}")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(evidence_id)
    assert data["original_filename"] == "threat_sample.eml"
    assert data["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert data["immutable"] is True


def test_get_evidence_metadata_not_found(mock_db_session):
    """Verify GET /api/v1/evidence/{non_existent} returns 404."""
    mock_result = MagicMock()
    mock_result.first.return_value = None
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    non_existent = uuid.uuid4()
    response = client.get(f"/api/v1/evidence/{non_existent}")

    app.dependency_overrides.clear()

    assert response.status_code == 404
    assert "not found" in response.json()["error"].lower()


def test_get_evidence_download_url_and_custody_log(mock_db_session):
    """Verify generating presigned download URL and creating VIEWED custody event."""
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_evidence = EvidenceObject(
        id=evidence_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="sample.eml",
        content_type="message/rfc822",
        size_bytes=1024,
        sha256_hash="abc123hash",
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/sample.eml",
        immutable=True,
        retention_status="ACTIVE",
        acquired_at=now_utc,
        stored_at=now_utc,
        created_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_evidence, None)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch.object(
        storage,
        "generate_presigned_download_url",
        return_value="https://minio.local:9000/mailintel-evidence/sample.eml?token=123",
    ):
        response = client.get(f"/api/v1/evidence/{evidence_id}/download")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["evidence_id"] == str(evidence_id)
    assert data["download_url"] == "https://minio.local:9000/mailintel-evidence/sample.eml?token=123"
    assert data["expires_in_seconds"] == 3600

    # Verify custody event was recorded
    assert mock_db_session.add.called
    assert mock_db_session.commit.called


def test_get_evidence_custody_history(mock_db_session):
    """Verify GET /api/v1/evidence/{evidence_id}/custody returns ordered custody events."""
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_evidence = EvidenceObject(id=evidence_id)
    event1 = CustodyEvent(
        id=uuid.uuid4(),
        evidence_id=evidence_id,
        event_type="ACQUIRED",
        event_at=now_utc,
        event_metadata={"source": "upload"},
        created_at=now_utc,
    )
    event2 = CustodyEvent(
        id=uuid.uuid4(),
        evidence_id=evidence_id,
        event_type="VIEWED",
        event_at=now_utc,
        event_metadata={"action": "presigned_download"},
        created_at=now_utc,
    )

    # First query checks evidence existence, second query fetches events
    mock_res_check = MagicMock()
    mock_res_check.first.return_value = (mock_evidence, None)

    mock_res_events = MagicMock()
    mock_res_events.scalars.return_value.all.return_value = [event1, event2]

    mock_db_session.execute.side_effect = [mock_res_check, mock_res_events]

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    response = client.get(f"/api/v1/evidence/{evidence_id}/custody")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["event_type"] == "ACQUIRED"
    assert data[1]["event_type"] == "VIEWED"


def test_verify_evidence_integrity_success(mock_db_session):
    """Verify POST /api/v1/evidence/{evidence_id}/verify returns VERIFIED when SHA-256 matches."""
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    raw_bytes = b"Authenticated pristine RFC822 forensic content"
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()

    mock_evidence = EvidenceObject(
        id=evidence_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="sample.eml",
        content_type="message/rfc822",
        size_bytes=len(raw_bytes),
        sha256_hash=expected_hash,
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/sample.eml",
        immutable=True,
        retention_status="ACTIVE",
        acquired_at=now_utc,
        stored_at=now_utc,
        created_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_evidence, None)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch.object(storage, "get_evidence_object", return_value=raw_bytes):
        response = client.post(f"/api/v1/evidence/{evidence_id}/verify")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["evidence_id"] == str(evidence_id)
    assert data["is_valid"] is True
    assert data["status"] == "VERIFIED"
    assert data["stored_sha256"] == expected_hash
    assert data["computed_sha256"] == expected_hash

    # Verify VERIFIED custody event logged
    assert mock_db_session.add.called
    assert mock_db_session.commit.called


def test_verify_evidence_integrity_tampered(mock_db_session):
    """Verify POST /api/v1/evidence/{evidence_id}/verify detects hash mismatch as TAMPERED."""
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    tampered_bytes = b"TAMPERED / ALTERED payload that does not match original"
    stored_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    mock_evidence = EvidenceObject(
        id=evidence_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="tampered.eml",
        content_type="message/rfc822",
        size_bytes=100,
        sha256_hash=stored_hash,
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/tampered.eml",
        immutable=True,
        retention_status="ACTIVE",
        acquired_at=now_utc,
        stored_at=now_utc,
        created_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_evidence, None)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch.object(storage, "get_evidence_object", return_value=tampered_bytes):
        response = client.post(f"/api/v1/evidence/{evidence_id}/verify")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["evidence_id"] == str(evidence_id)
    assert data["is_valid"] is False
    assert data["status"] == "TAMPERED"
    assert data["stored_sha256"] == stored_hash
    assert data["computed_sha256"] != stored_hash
    assert "mismatch detected" in data["details"]["alert"].lower()


def test_verify_evidence_integrity_object_not_found(mock_db_session):
    """Verify POST /api/v1/evidence/{evidence_id}/verify returns OBJECT_NOT_FOUND if storage missing."""
    evidence_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    mock_evidence = EvidenceObject(
        id=evidence_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="missing.eml",
        content_type="message/rfc822",
        size_bytes=100,
        sha256_hash="abc123",
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/missing.eml",
        immutable=True,
        retention_status="ACTIVE",
        acquired_at=now_utc,
        stored_at=now_utc,
        created_at=now_utc,
    )

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_evidence, None)
    mock_db_session.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER

    with patch.object(storage, "get_evidence_object", return_value=None):
        response = client.post(f"/api/v1/evidence/{evidence_id}/verify")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert data["status"] == "OBJECT_NOT_FOUND"

