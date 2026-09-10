#!/usr/bin/env python3
"""
MailinteL Supabase Storage Setup and Verification Utility

Usage:
    python -m scripts.setup_supabase_storage
    python -m scripts.setup_supabase_storage --url https://xyz.supabase.co --key eyJhbGci...
    python -m scripts.setup_supabase_storage --smoke-test
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

# Ensure backend directory is in sys.path when invoked directly
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.storage import SupabaseStorageDriver, REQUIRED_BUCKETS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("setup_supabase_storage")


def run_setup(url: Optional[str] = None, key: Optional[str] = None, run_test: bool = True) -> bool:
    if url:
        settings.SUPABASE_URL = url
    if key:
        settings.SUPABASE_SERVICE_KEY = key
    settings.STORAGE_PROVIDER = "supabase"

    effective_url = settings.SUPABASE_URL
    effective_key = settings.effective_supabase_key

    print("=" * 65)
    print("  MailinteL — Supabase Storage Provisioning & Smoke Test")
    print("=" * 65)
    print(f"Target URL:    {effective_url or '<Not configured>'}")
    print(f"Key configured: {'Yes (Length: %d)' % len(effective_key) if effective_key else 'No'}")
    print(f"Required Buckets (All Private):")
    for b in REQUIRED_BUCKETS:
        print(f"  - {b}")
    print("-" * 65)

    if not effective_url or not effective_key:
        print("\n[!] ERROR: Missing Supabase credentials.")
        print("Please configure in your .env file:")
        print("  STORAGE_PROVIDER=supabase")
        print("  SUPABASE_URL=https://<your-project-ref>.supabase.co")
        print("  SUPABASE_SERVICE_KEY=<your-service-role-key>")
        print("Or provide them as arguments: --url <URL> --key <KEY>")
        return False

    driver = SupabaseStorageDriver()

    # 1. Connectivity Check
    print("\n[Step 1/3] Probing Supabase Storage connectivity...")
    conn = driver.check_connectivity(timeout_seconds=5.0)
    if not conn["connected"]:
        print(f"[-] Connectivity Failed: {conn['error']}")
        print("Please verify that:")
        print("  1. Your SUPABASE_URL is correct.")
        print("  2. Your SUPABASE_SERVICE_KEY has service_role privileges.")
        print("  3. Your network can reach Supabase Storage.")
        return False

    print(f"[+] Connected successfully! Latency: {conn['latency_ms']}ms")
    print(f"    Existing buckets in project: {conn['available_buckets'] or 'None'}")

    # 2. Bucket Verification and Auto-Creation
    print("\n[Step 2/3] Verifying and provisioning required Private buckets...")
    bucket_results = driver.ensure_buckets_exist()
    all_buckets_ok = True
    for bucket_name, created_or_exists in bucket_results.items():
        if created_or_exists:
            print(f"    [+] Bucket '{bucket_name}' is ready (Private).")
        else:
            print(f"    [-] Bucket '{bucket_name}' could not be verified or created.")
            all_buckets_ok = False

    if not all_buckets_ok:
        print("\n[-] Some buckets could not be verified/created.")
        print("Please ensure your SUPABASE_SERVICE_KEY has storage administration permissions,")
        print("or manually create these buckets as PRIVATE in the Supabase Dashboard:")
        print("Storage -> New Bucket -> Name: <bucket> -> Set 'Public bucket' to OFF.")
        return False

    # 3. End-to-End Smoke Test
    if run_test:
        print("\n[Step 3/3] Running end-to-end evidence preservation smoke test...")
        test_bucket = settings.evidence_bucket
        test_key = "test/smoke_test_evidence.eml"
        test_payload = b"From: investigator@mailintel.local\r\nSubject: Supabase Storage Smoke Test\r\n\r\nEvidence Verification."

        try:
            print(f"    -> Uploading test evidence object to '{test_bucket}/{test_key}'...")
            upload_res = driver.upload_evidence_object(
                bucket_name=test_bucket,
                object_key=test_key,
                data=test_payload,
                content_type="message/rfc822",
                metadata={"test": "true", "purpose": "supabase_provisioning_smoke_test"},
            )
            print(f"       Preserved! Size: {upload_res['size_bytes']} bytes, SHA-256: {upload_res['sha256_hash'][:16]}...")

            print(f"    -> Verifying cryptographic integrity against Supabase Storage...")
            is_valid, calc_hash = driver.verify_evidence_integrity(
                bucket_name=test_bucket,
                object_key=test_key,
                expected_sha256=upload_res["sha256_hash"],
            )
            if not is_valid:
                print(f"       [-] Integrity mismatch! Expected: {upload_res['sha256_hash']}, Got: {calc_hash}")
                return False
            print(f"       [+] Cryptographic hash match confirmed: {calc_hash[:16]}...")

            print(f"    -> Generating time-limited presigned download URL...")
            presigned_url = driver.generate_presigned_download_url(
                bucket_name=test_bucket,
                object_key=test_key,
                expires_seconds=300,
            )
            print(f"       [+] Presigned URL generated successfully!")
            print(f"           Preview: {presigned_url[:80]}...")

            # Clean up test object
            try:
                driver.client.delete(f"object/{test_bucket}/{test_key}")
                print(f"    -> Cleaned up temporary test evidence object.")
            except Exception:
                pass

        except Exception as exc:
            print(f"[-] Smoke test failed: {exc}")
            return False

    print("\n" + "=" * 65)
    print("  [SUCCESS] Supabase Storage is configured and ready for MailinteL!")
    print("=" * 65)
    return True


def main():
    parser = argparse.ArgumentParser(description="MailinteL Supabase Storage Setup Utility")
    parser.add_argument("--url", help="Supabase project URL (e.g. https://xxx.supabase.co)")
    parser.add_argument("--key", help="Supabase service role secret key")
    parser.add_argument("--skip-test", action="store_true", help="Skip end-to-end smoke test")
    args = parser.parse_args()

    success = run_setup(url=args.url, key=args.key, run_test=not args.skip_test)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
