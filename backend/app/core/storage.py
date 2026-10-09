import io
import time
import hashlib
import logging
from datetime import timedelta
from typing import Dict, Any, Optional, Tuple, BinaryIO, List
import httpx
from minio import Minio
from minio.error import S3Error

from app.core.config import settings

logger = logging.getLogger("mailintel.storage")

REQUIRED_BUCKETS = [
    settings.evidence_bucket,
    settings.derived_bucket,
    settings.reports_bucket,
    settings.temp_bucket,
]


class MinioStorageDriver:
    """
    MinIO S3-compatible storage driver for MailIntel evidence preservation,
    derived artifact management, and report generation.
    """

    def __init__(self, client: Optional[Minio] = None):
        self._client = client

    @property
    def client(self) -> Minio:
        if self._client is None:
            self._client = Minio(
                endpoint=settings.MINIO_ENDPOINT,
                access_key=settings.MINIO_ACCESS_KEY,
                secret_key=settings.MINIO_SECRET_KEY,
                secure=settings.MINIO_SECURE,
            )
        return self._client

    def ensure_buckets_exist(self) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        for bucket in REQUIRED_BUCKETS:
            try:
                if not self.client.bucket_exists(bucket):
                    self.client.make_bucket(bucket)
                    logger.info("Created MinIO bucket: %s", bucket)
                results[bucket] = True
            except Exception as exc:
                logger.warning("Failed to verify/create MinIO bucket '%s': %s", bucket, exc)
                results[bucket] = False
        return results

    def check_connectivity(self, timeout_seconds: float = 3.0) -> Dict[str, Any]:
        start_time = time.perf_counter()
        try:
            buckets = [b.name for b in self.client.list_buckets()]
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "connected": True,
                "provider": "minio",
                "latency_ms": latency_ms,
                "endpoint": settings.MINIO_ENDPOINT,
                "available_buckets": buckets,
                "required_buckets": REQUIRED_BUCKETS,
                "error": None,
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning("MinIO connectivity check failed: %s", exc)
            return {
                "connected": False,
                "provider": "minio",
                "latency_ms": latency_ms,
                "endpoint": settings.MINIO_ENDPOINT,
                "available_buckets": [],
                "required_buckets": REQUIRED_BUCKETS,
                "error": str(exc),
            }

    def upload_evidence_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "message/rfc822",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        sha256_hash = hashlib.sha256(data).hexdigest()
        size_bytes = len(data)
        data_stream = io.BytesIO(data)

        user_metadata = metadata or {}
        user_metadata["sha256"] = sha256_hash

        self.client.put_object(
            bucket_name=bucket_name,
            object_name=object_key,
            data=data_stream,
            length=size_bytes,
            content_type=content_type,
            metadata=user_metadata,
        )

        logger.info(
            "Evidence preserved in MinIO: bucket=%s, key=%s, size=%d bytes, sha256=%s",
            bucket_name,
            object_key,
            size_bytes,
            sha256_hash,
        )

        return {
            "bucket_name": bucket_name,
            "object_key": object_key,
            "size_bytes": size_bytes,
            "sha256_hash": sha256_hash,
            "content_type": content_type,
        }

    def get_evidence_object(self, bucket_name: str, object_key: str) -> Tuple[bytes, Dict[str, Any]]:
        response = None
        try:
            response = self.client.get_object(bucket_name, object_key)
            data = response.read()
            stat = self.client.stat_object(bucket_name, object_key)
            meta = {
                "size_bytes": stat.size,
                "content_type": stat.content_type,
                "last_modified": stat.last_modified.isoformat() if stat.last_modified else None,
                "etag": stat.etag,
                "metadata": stat.metadata or {},
            }
            return data, meta
        finally:
            if response is not None:
                response.close()
                response.release_conn()

    def verify_evidence_integrity(
        self,
        bucket_name: str,
        object_key: str,
        expected_sha256: str,
    ) -> Tuple[bool, str]:
        data, _ = self.get_evidence_object(bucket_name, object_key)
        actual_sha256 = hashlib.sha256(data).hexdigest()
        is_valid = actual_sha256.lower() == expected_sha256.lower()
        return is_valid, actual_sha256

    def generate_presigned_download_url(
        self,
        bucket_name: str,
        object_key: str,
        expires_seconds: int = 3600,
    ) -> str:
        return self.client.presigned_get_object(
            bucket_name=bucket_name,
            object_name=object_key,
            expires=timedelta(seconds=expires_seconds),
        )

    def delete_evidence_object(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.client.remove_object(bucket_name=bucket_name, object_name=object_key)
            return True
        except Exception as exc:
            logger.warning("Failed to remove object '%s' from bucket '%s': %s", object_key, bucket_name, exc)
            return False


class SupabaseStorageDriver:
    """
    Supabase Storage REST API driver for MailIntel evidence preservation,
    derived artifact management, and report generation.

    Uses native HTTP REST endpoints via httpx:
      - /storage/v1/bucket (bucket management)
      - /storage/v1/object/... (object upload/download)
      - /storage/v1/object/sign/... (presigned/signed URL generation)
    """

    def __init__(self, client: Optional[httpx.Client] = None):
        self._client = client

    @property
    def base_url(self) -> str:
        url = (settings.SUPABASE_URL or "http://localhost:54321").rstrip("/")
        return f"{url}/storage/v1/"

    @property
    def auth_headers(self) -> Dict[str, str]:
        key = settings.effective_supabase_key or ""
        return {
            "Authorization": f"Bearer {key}",
            "apikey": key,
        }

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=self.auth_headers,
                timeout=httpx.Timeout(30.0, connect=5.0),
            )
        return self._client

    def ensure_buckets_exist(self) -> Dict[str, bool]:
        """
        Verifies that required MailIntel buckets exist in Supabase Storage,
        creating them as Private buckets if not already present.
        """
        results: Dict[str, bool] = {}
        existing_buckets = set()
        try:
            resp = self.client.get("bucket")
            if resp.status_code == 200:
                for b in resp.json():
                    existing_buckets.add(b.get("id") or b.get("name"))
        except Exception as exc:
            logger.warning("Failed to list Supabase buckets: %s", exc)

        for bucket in REQUIRED_BUCKETS:
            if bucket in existing_buckets:
                results[bucket] = True
                continue
            try:
                # Create private bucket
                resp = self.client.post(
                    "bucket",
                    json={"id": bucket, "name": bucket, "public": False},
                )
                if resp.status_code in (200, 201):
                    logger.info("Created Supabase Storage bucket: %s (private)", bucket)
                    results[bucket] = True
                elif resp.status_code == 400 and "already exists" in resp.text.lower():
                    results[bucket] = True
                else:
                    logger.warning("Failed to create Supabase bucket '%s': HTTP %d %s", bucket, resp.status_code, resp.text)
                    results[bucket] = False
            except Exception as exc:
                logger.warning("Exception creating Supabase bucket '%s': %s", bucket, exc)
                results[bucket] = False
        return results

    def check_connectivity(self, timeout_seconds: float = 3.0) -> Dict[str, Any]:
        """
        Checks Supabase Storage liveness by querying bucket endpoint and measuring latency.
        """
        start_time = time.perf_counter()
        try:
            resp = self.client.get("bucket", timeout=timeout_seconds)
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if resp.status_code == 200:
                buckets = [b.get("name") or b.get("id") for b in resp.json()]
                return {
                    "connected": True,
                    "provider": "supabase",
                    "latency_ms": latency_ms,
                    "endpoint": settings.SUPABASE_URL or "configured",
                    "available_buckets": buckets,
                    "required_buckets": REQUIRED_BUCKETS,
                    "error": None,
                }
            else:
                error_msg = f"HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning("Supabase Storage connectivity check failed: %s", error_msg)
                return {
                    "connected": False,
                    "provider": "supabase",
                    "latency_ms": latency_ms,
                    "endpoint": settings.SUPABASE_URL or "configured",
                    "available_buckets": [],
                    "required_buckets": REQUIRED_BUCKETS,
                    "error": error_msg,
                }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning("Supabase Storage connectivity check failed: %s", exc)
            return {
                "connected": False,
                "provider": "supabase",
                "latency_ms": latency_ms,
                "endpoint": settings.SUPABASE_URL or "configured",
                "available_buckets": [],
                "required_buckets": REQUIRED_BUCKETS,
                "error": str(exc),
            }

    def upload_evidence_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "message/rfc822",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Uploads raw evidence bytes to Supabase Storage and calculates SHA-256 hash.
        """
        sha256_hash = hashlib.sha256(data).hexdigest()
        size_bytes = len(data)
        clean_key = object_key.lstrip("/")
        target_path = f"object/{bucket_name}/{clean_key}"

        upload_headers = {
            "Content-Type": content_type,
            "x-upsert": "true",
        }
        if metadata:
            for k, v in metadata.items():
                upload_headers[f"x-meta-{k}"] = str(v)
        upload_headers["x-meta-sha256"] = sha256_hash

        resp = self.client.post(
            target_path,
            content=data,
            headers=upload_headers,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to upload object to Supabase Storage '{bucket_name}/{clean_key}': "
                f"HTTP {resp.status_code} {resp.text}"
            )

        logger.info(
            "Evidence preserved in Supabase Storage: bucket=%s, key=%s, size=%d bytes, sha256=%s",
            bucket_name,
            object_key,
            size_bytes,
            sha256_hash,
        )

        return {
            "bucket_name": bucket_name,
            "object_key": object_key,
            "size_bytes": size_bytes,
            "sha256_hash": sha256_hash,
            "content_type": content_type,
        }

    def get_evidence_object(self, bucket_name: str, object_key: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieves evidence bytes and metadata from Supabase Storage.
        """
        clean_key = object_key.lstrip("/")
        target_path = f"object/authenticated/{bucket_name}/{clean_key}"

        resp = self.client.get(target_path)
        if resp.status_code == 404:
            raise FileNotFoundError(f"Object '{object_key}' not found in Supabase bucket '{bucket_name}'")
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch object from Supabase Storage '{bucket_name}/{clean_key}': "
                f"HTTP {resp.status_code} {resp.text}"
            )

        data = resp.content
        calc_sha256 = hashlib.sha256(data).hexdigest()
        meta = {
            "size_bytes": len(data),
            "content_type": resp.headers.get("content-type", "application/octet-stream"),
            "last_modified": resp.headers.get("last-modified"),
            "etag": resp.headers.get("etag", "").strip('"'),
            "metadata": {"sha256": calc_sha256},
        }
        return data, meta

    def verify_evidence_integrity(
        self,
        bucket_name: str,
        object_key: str,
        expected_sha256: str,
    ) -> Tuple[bool, str]:
        """
        Re-reads stored evidence object from Supabase Storage, calculates live SHA-256 hash,
        and verifies it matches the expected hash.
        """
        data, _ = self.get_evidence_object(bucket_name, object_key)
        actual_sha256 = hashlib.sha256(data).hexdigest()
        is_valid = actual_sha256.lower() == expected_sha256.lower()
        return is_valid, actual_sha256

    def generate_presigned_download_url(
        self,
        bucket_name: str,
        object_key: str,
        expires_seconds: int = 3600,
    ) -> str:
        """
        Generates a time-limited signed download URL via Supabase Storage sign endpoint.
        """
        clean_key = object_key.lstrip("/")
        target_path = f"object/sign/{bucket_name}/{clean_key}"

        resp = self.client.post(
            target_path,
            json={"expiresIn": expires_seconds},
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Failed to generate signed URL for Supabase Storage '{bucket_name}/{clean_key}': "
                f"HTTP {resp.status_code} {resp.text}"
            )

        data = resp.json()
        signed_url_path = data.get("signedURL") or ""
        if signed_url_path.startswith("http://") or signed_url_path.startswith("https://"):
            return signed_url_path

        base = (settings.SUPABASE_URL or "").rstrip("/")
        if signed_url_path.startswith("/storage/v1"):
            return f"{base}{signed_url_path}"
        if signed_url_path.startswith("/object"):
            return f"{base}/storage/v1{signed_url_path}"
        return f"{base}/storage/v1/{signed_url_path.lstrip('/')}"

    def delete_evidence_object(self, bucket_name: str, object_key: str) -> bool:
        try:
            clean_key = object_key.lstrip("/")
            resp = self.client.delete(f"object/{bucket_name}", json={"prefixes": [clean_key]})
            return resp.status_code in (200, 204)
        except Exception as exc:
            logger.warning("Failed to remove object '%s' from Supabase bucket '%s': %s", object_key, bucket_name, exc)
            return False


class StorageManager:
    """
    Unified Object Storage Manager for MailIntel.
    Seamlessly dispatches to MinIO or Supabase Storage depending on configuration.
    """

    def __init__(self):
        self._client: Optional[Any] = None
        self._driver: Optional[Any] = None

    @property
    def provider(self) -> str:
        return settings.active_storage_provider

    def _sync_client(self) -> None:
        if self._client is not None:
            if hasattr(self._client, "list_buckets") or hasattr(self._client, "bucket_exists") or hasattr(self._client, "presigned_get_object"):
                if not isinstance(self._driver, MinioStorageDriver):
                    self._driver = MinioStorageDriver(client=self._client)
                else:
                    self._driver._client = self._client
            elif isinstance(self._client, httpx.Client):
                if not isinstance(self._driver, SupabaseStorageDriver):
                    self._driver = SupabaseStorageDriver(client=self._client)
                else:
                    self._driver._client = self._client

    @property
    def driver(self) -> Any:
        self._sync_client()
        if self._driver is None:
            if self.provider == "supabase":
                self._driver = SupabaseStorageDriver()
            else:
                self._driver = MinioStorageDriver(client=self._client)
        return self._driver

    @property
    def client(self) -> Any:
        if self._client is not None:
            return self._client
        return self.driver.client

    def ensure_buckets_exist(self) -> Dict[str, bool]:
        self._sync_client()
        return self.driver.ensure_buckets_exist()

    def check_connectivity(self, timeout_seconds: float = 3.0) -> Dict[str, Any]:
        self._sync_client()
        return self.driver.check_connectivity(timeout_seconds=timeout_seconds)

    def upload_evidence_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "message/rfc822",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        self._sync_client()
        return self.driver.upload_evidence_object(
            bucket_name=bucket_name,
            object_key=object_key,
            data=data,
            content_type=content_type,
            metadata=metadata,
        )

    def get_evidence_object(self, bucket_name: str, object_key: str) -> Tuple[bytes, Dict[str, Any]]:
        self._sync_client()
        return self.driver.get_evidence_object(bucket_name=bucket_name, object_key=object_key)

    def verify_evidence_integrity(
        self,
        bucket_name: str,
        object_key: str,
        expected_sha256: str,
    ) -> Tuple[bool, str]:
        self._sync_client()
        return self.driver.verify_evidence_integrity(
            bucket_name=bucket_name,
            object_key=object_key,
            expected_sha256=expected_sha256,
        )

    def generate_presigned_download_url(
        self,
        bucket_name: str,
        object_key: str,
        expires_seconds: int = 3600,
    ) -> str:
        self._sync_client()
        return self.driver.generate_presigned_download_url(
            bucket_name=bucket_name,
            object_key=object_key,
            expires_seconds=expires_seconds,
        )

    def delete_evidence_object(self, bucket_name: str, object_key: str) -> bool:
        self._sync_client()
        return self.driver.delete_evidence_object(bucket_name=bucket_name, object_key=object_key)


storage = StorageManager()
