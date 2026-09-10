import io
import hashlib
from unittest.mock import MagicMock, patch
from minio.datatypes import Bucket
from app.core.storage import StorageManager, REQUIRED_BUCKETS
from app.core.config import settings


def test_storage_manager_initialization():
    with patch.object(settings, "STORAGE_PROVIDER", "minio"), \
         patch.object(settings, "SUPABASE_URL", None):
        mgr = StorageManager()
        assert mgr.client is not None
        assert mgr.client._base_url.host == settings.MINIO_ENDPOINT




def test_ensure_buckets_exist():
    mgr = StorageManager()
    mock_client = MagicMock()
    # First bucket exists, others do not
    mock_client.bucket_exists.side_effect = lambda b: b == REQUIRED_BUCKETS[0]
    
    with patch.object(mgr, "_client", mock_client):
        res = mgr.ensure_buckets_exist()
        assert len(res) == len(REQUIRED_BUCKETS)
        assert res[REQUIRED_BUCKETS[0]] is True
        assert res[REQUIRED_BUCKETS[1]] is True
        # make_bucket should be called for the other buckets
        assert mock_client.make_bucket.call_count == len(REQUIRED_BUCKETS) - 1


def test_check_connectivity_success():
    mgr = StorageManager()
    mock_client = MagicMock()
    mock_b1 = MagicMock(spec=Bucket)
    mock_b1.name = "mailintel-evidence"
    mock_client.list_buckets.return_value = [mock_b1]

    with patch.object(mgr, "_client", mock_client):
        res = mgr.check_connectivity(timeout_seconds=2.0)
        assert res["connected"] is True
        assert "mailintel-evidence" in res["available_buckets"]
        assert res["error"] is None
        assert isinstance(res["latency_ms"], float)


def test_check_connectivity_failure():
    mgr = StorageManager()
    mock_client = MagicMock()
    mock_client.list_buckets.side_effect = ConnectionRefusedError("MinIO connection refused")

    with patch.object(mgr, "_client", mock_client):
        res = mgr.check_connectivity(timeout_seconds=1.0)
        assert res["connected"] is False
        assert "MinIO connection refused" in res["error"]
        assert res["available_buckets"] == []


def test_upload_evidence_object():
    mgr = StorageManager()
    mock_client = MagicMock()
    test_data = b"From: attacker@malicious.domain\r\nSubject: Critical Security Alert\r\n\r\nPhishing payload"
    expected_hash = hashlib.sha256(test_data).hexdigest()

    with patch.object(mgr, "_client", mock_client):
        res = mgr.upload_evidence_object(
            bucket_name="mailintel-evidence",
            object_key="originals/2026/09/EV-001.eml",
            data=test_data,
            content_type="message/rfc822",
            metadata={"source": "upload_api"},
        )

        assert res["bucket_name"] == "mailintel-evidence"
        assert res["object_key"] == "originals/2026/09/EV-001.eml"
        assert res["size_bytes"] == len(test_data)
        assert res["sha256_hash"] == expected_hash
        assert mock_client.put_object.called


def test_get_evidence_object_and_integrity_verification():
    mgr = StorageManager()
    mock_client = MagicMock()
    test_data = b"Raw forensic .eml content data"
    correct_hash = hashlib.sha256(test_data).hexdigest()

    mock_response = MagicMock()
    mock_response.read.return_value = test_data

    mock_stat = MagicMock()
    mock_stat.size = len(test_data)
    mock_stat.content_type = "message/rfc822"
    mock_stat.last_modified = None
    mock_stat.etag = "etag-123"
    mock_stat.metadata = {"sha256": correct_hash}

    mock_client.get_object.return_value = mock_response
    mock_client.stat_object.return_value = mock_stat

    with patch.object(mgr, "_client", mock_client):
        # 1. Direct get_evidence_object
        data, meta = mgr.get_evidence_object("mailintel-evidence", "test.eml")
        assert data == test_data
        assert meta["size_bytes"] == len(test_data)

        # 2. verify_evidence_integrity matching
        is_valid, calc_hash = mgr.verify_evidence_integrity("mailintel-evidence", "test.eml", correct_hash)
        assert is_valid is True
        assert calc_hash == correct_hash

        # 3. verify_evidence_integrity mismatching
        is_valid, calc_hash = mgr.verify_evidence_integrity("mailintel-evidence", "test.eml", "bad_hash_value_12345")
        assert is_valid is False


def test_generate_presigned_download_url():
    mgr = StorageManager()
    mock_client = MagicMock()
    mock_client.presigned_get_object.return_value = "http://localhost:9000/mailintel-evidence/test.eml?token=xyz"

    with patch.object(mgr, "_client", mock_client):
        url = mgr.generate_presigned_download_url("mailintel-evidence", "test.eml", expires_seconds=1800)
        assert "token=xyz" in url
        mock_client.presigned_get_object.assert_called_once()


# =====================================================================
# Supabase Storage Driver Tests
# =====================================================================
from app.core.storage import SupabaseStorageDriver
import httpx


def test_supabase_storage_driver_properties():
    with patch.object(settings, "SUPABASE_URL", "https://xyzproject.supabase.co"), \
         patch.object(settings, "SUPABASE_SERVICE_KEY", "test-service-key-123"):
        driver = SupabaseStorageDriver()
        assert driver.base_url == "https://xyzproject.supabase.co/storage/v1/"
        assert driver.auth_headers["Authorization"] == "Bearer test-service-key-123"
        assert driver.auth_headers["apikey"] == "test-service-key-123"
        assert isinstance(driver.client, httpx.Client)


def test_supabase_check_connectivity_success():
    mock_http_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"name": "mailintel-evidence", "id": "mailintel-evidence"}]
    mock_http_client.get.return_value = mock_resp

    with patch.object(settings, "SUPABASE_URL", "https://xyzproject.supabase.co"):
        driver = SupabaseStorageDriver(client=mock_http_client)
        res = driver.check_connectivity(timeout_seconds=2.0)
        assert res["connected"] is True
        assert res["provider"] == "supabase"
        assert "mailintel-evidence" in res["available_buckets"]
        assert res["error"] is None
        assert isinstance(res["latency_ms"], float)


def test_supabase_check_connectivity_failure():
    mock_http_client = MagicMock()
    mock_http_client.get.side_effect = httpx.ConnectError("Supabase connection timed out")

    with patch.object(settings, "SUPABASE_URL", "https://xyzproject.supabase.co"):
        driver = SupabaseStorageDriver(client=mock_http_client)
        res = driver.check_connectivity(timeout_seconds=1.0)
        assert res["connected"] is False
        assert res["provider"] == "supabase"
        assert "Supabase connection timed out" in res["error"]
        assert res["available_buckets"] == []


def test_supabase_ensure_buckets_exist():
    mock_http_client = MagicMock()
    # Mock listing existing buckets: only evidence bucket exists
    mock_list_resp = MagicMock()
    mock_list_resp.status_code = 200
    mock_list_resp.json.return_value = [{"name": REQUIRED_BUCKETS[0], "id": REQUIRED_BUCKETS[0]}]
    mock_http_client.get.return_value = mock_list_resp

    # Mock bucket creation for others: success 201
    mock_create_resp = MagicMock()
    mock_create_resp.status_code = 201
    mock_http_client.post.return_value = mock_create_resp

    driver = SupabaseStorageDriver(client=mock_http_client)
    res = driver.ensure_buckets_exist()

    assert len(res) == len(REQUIRED_BUCKETS)
    assert res[REQUIRED_BUCKETS[0]] is True
    assert res[REQUIRED_BUCKETS[1]] is True
    # POST /bucket should be called for the other missing buckets with public=False
    assert mock_http_client.post.call_count == len(REQUIRED_BUCKETS) - 1
    call_args = mock_http_client.post.call_args[1]
    assert call_args["json"]["public"] is False


def test_supabase_upload_evidence_object():
    mock_http_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"Key": "mailintel-evidence/originals/2026/09/EV-001.eml"}
    mock_http_client.post.return_value = mock_resp

    test_data = b"From: phisher@bad.actor\r\nSubject: Password Expiring\r\n\r\nPhish"
    expected_hash = hashlib.sha256(test_data).hexdigest()

    driver = SupabaseStorageDriver(client=mock_http_client)
    res = driver.upload_evidence_object(
        bucket_name="mailintel-evidence",
        object_key="originals/2026/09/EV-001.eml",
        data=test_data,
        content_type="message/rfc822",
        metadata={"source": "pytest"},
    )

    assert res["bucket_name"] == "mailintel-evidence"
    assert res["object_key"] == "originals/2026/09/EV-001.eml"
    assert res["size_bytes"] == len(test_data)
    assert res["sha256_hash"] == expected_hash

    # Verify POST request parameters
    mock_http_client.post.assert_called_once()
    called_path = mock_http_client.post.call_args[0][0]
    called_headers = mock_http_client.post.call_args[1]["headers"]
    assert called_path == "object/mailintel-evidence/originals/2026/09/EV-001.eml"
    assert called_headers["Content-Type"] == "message/rfc822"
    assert called_headers["x-upsert"] == "true"
    assert called_headers["x-meta-sha256"] == expected_hash


def test_supabase_get_evidence_object_and_integrity():
    mock_http_client = MagicMock()
    test_data = b"Forensic raw evidence data from Supabase storage"
    expected_hash = hashlib.sha256(test_data).hexdigest()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = test_data
    mock_resp.headers = {
        "content-type": "message/rfc822",
        "content-length": str(len(test_data)),
        "etag": '"etag-supabase-123"',
        "last-modified": "Wed, 09 Sep 2026 00:00:00 GMT",
    }
    mock_http_client.get.return_value = mock_resp

    driver = SupabaseStorageDriver(client=mock_http_client)

    # 1. get_evidence_object
    data, meta = driver.get_evidence_object("mailintel-evidence", "originals/EV-001.eml")
    assert data == test_data
    assert meta["size_bytes"] == len(test_data)
    assert meta["content_type"] == "message/rfc822"
    assert meta["etag"] == "etag-supabase-123"

    # 2. verify_evidence_integrity match
    is_valid, calc_hash = driver.verify_evidence_integrity("mailintel-evidence", "originals/EV-001.eml", expected_hash)
    assert is_valid is True
    assert calc_hash == expected_hash

    # 3. verify_evidence_integrity mismatch
    is_valid, calc_hash = driver.verify_evidence_integrity("mailintel-evidence", "originals/EV-001.eml", "incorrect_hash")
    assert is_valid is False


def test_supabase_generate_presigned_download_url():
    mock_http_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "signedURL": "/storage/v1/object/sign/mailintel-evidence/test.eml?token=jwt.token.here"
    }
    mock_http_client.post.return_value = mock_resp

    with patch.object(settings, "SUPABASE_URL", "https://xyzproject.supabase.co"):
        driver = SupabaseStorageDriver(client=mock_http_client)
        url = driver.generate_presigned_download_url("mailintel-evidence", "test.eml", expires_seconds=1800)
        assert url.startswith("https://xyzproject.supabase.co/storage/v1/object/sign/mailintel-evidence/test.eml?token=")
        mock_http_client.post.assert_called_once_with(
            "object/sign/mailintel-evidence/test.eml",
            json={"expiresIn": 1800},
        )


def test_storage_manager_active_provider_dispatch():
    with patch.object(settings, "STORAGE_PROVIDER", "supabase"), \
         patch.object(settings, "SUPABASE_URL", "https://xyzproject.supabase.co"), \
         patch.object(settings, "SUPABASE_SERVICE_KEY", "secret-key"):
        mgr = StorageManager()
        assert mgr.provider == "supabase"
        assert isinstance(mgr.driver, SupabaseStorageDriver)
        assert isinstance(mgr.client, httpx.Client)


def test_validate_production_safety_supabase():
    import pytest
    from app.core.config import Settings

    # 1. Valid Supabase config in production: MinIO defaults should not trigger errors
    s_valid = Settings(
        SECRET_KEY="a-very-strong-production-secret-key-that-is-long-enough",
        DEBUG=False,
        POSTGRES_PASSWORD="secure_db_password_123",
        STORAGE_PROVIDER="supabase",
        SUPABASE_URL="https://projectref.supabase.co",
        SUPABASE_SERVICE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_service_key",
        MINIO_ACCESS_KEY="minioadmin",  # MinIO defaults present but should be ignored
        MINIO_SECRET_KEY="minioadmin",
        APP_ENV="production",
    )
    s_valid.validate_production_safety()

    # 2. Invalid Supabase URL in production: should trigger error
    s_bad_url = Settings(
        SECRET_KEY="a-very-strong-production-secret-key-that-is-long-enough",
        DEBUG=False,
        POSTGRES_PASSWORD="secure_db_password_123",
        STORAGE_PROVIDER="supabase",
        SUPABASE_URL="not-a-valid-url",
        SUPABASE_SERVICE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_service_key",
        APP_ENV="production",
    )
    with pytest.raises(RuntimeError) as exc_info:
        s_bad_url.validate_production_safety()
    assert "SUPABASE_URL must be configured" in str(exc_info.value)


