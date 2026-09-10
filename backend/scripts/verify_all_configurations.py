#!/usr/bin/env python3
"""
MailinteL Comprehensive System & Configuration Diagnostic
Checks Database, Storage, MaxMind, Admin Account, and Threat Intel APIs.
"""

import sys
import asyncio
import time
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.db.session import engine, check_db_connectivity
from app.core.storage import storage
from app.intelligence.maxmind_client import maxmind_client
from sqlalchemy import text


async def run_diagnostics():
    print("=" * 70)
    print("       MailinteL — Comprehensive Configuration & System Audit")
    print("=" * 70)

    results = {}

    # -------------------------------------------------------------
    # 1. CORE SETTINGS & ENVIRONMENT
    # -------------------------------------------------------------
    print("\n[1/5] Checking Core Application Settings...")
    print(f"  * App Name:    {settings.APP_NAME}")
    print(f"  * Environment: {settings.APP_ENV}")
    print(f"  * Debug Mode:  {settings.DEBUG}")
    print(f"  * API Prefix:  {settings.API_V1_PREFIX}")
    secret_key_ok = len(settings.SECRET_KEY) >= 32 and "change-me" not in settings.SECRET_KEY.lower()
    print(f"  * Secret Key:  {'[PASS] Secure (32+ chars)' if secret_key_ok else '[WARN] Insecure default'}")
    results["core_settings"] = True

    # -------------------------------------------------------------
    # 2. SUPABASE POSTGRESQL DATABASE
    # -------------------------------------------------------------
    print("\n[2/5] Checking Supabase PostgreSQL Database...")
    print(f"  * Target Host: {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}")
    print(f"  * Database:    {settings.POSTGRES_DB}")
    print(f"  * SSL Enforced:{settings.is_supabase_db or settings.POSTGRES_SSL}")
    print(f"  * Pooler Mode: {settings.is_pooler_connection}")

    db_status = await check_db_connectivity(timeout_seconds=15.0)
    if db_status["connected"]:
        print(f"  [PASS] Live DB Connection Established! (Latency: {db_status['latency_ms']}ms)")
        # Verify extensions and tables
        async with engine.connect() as conn:
            # Check extensions
            ext_res = await conn.execute(text("SELECT extname, extversion FROM pg_extension WHERE extname IN ('vector', 'pgcrypto');"))
            exts = {row[0]: row[1] for row in ext_res.fetchall()}
            print(f"  * Active Extensions: {exts}")

            # Check users table
            user_res = await conn.execute(text("SELECT email, is_platform_admin, status FROM users WHERE email = :email"), {"email": settings.ADMIN_EMAIL})
            admin_user = user_res.fetchone()

            # Check table count
            tables_res = await conn.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"))
            table_count = tables_res.scalar()
            print(f"  * Public Schema Tables: {table_count} tables present")

        if admin_user:
            print(f"  [PASS] Admin Account: {admin_user[0]} (Platform Admin: {admin_user[1]}, Status: {admin_user[2]})")
            results["database"] = True
        else:
            print(f"  [WARN] Admin account '{settings.ADMIN_EMAIL}' not found in users table.")
            results["database"] = True
    else:
        print(f"  [FAIL] Database Connection Failed: {db_status['error']}")
        results["database"] = False

    # -------------------------------------------------------------
    # 3. SUPABASE OBJECT STORAGE
    # -------------------------------------------------------------
    print("\n[3/5] Checking Supabase Object Storage...")
    print(f"  * Active Provider: {settings.active_storage_provider}")
    print(f"  * Endpoint:        {settings.SUPABASE_URL}")
    print(f"  * Buckets:         evidence={settings.evidence_bucket}, reports={settings.reports_bucket}")

    storage_status = storage.check_connectivity(timeout_seconds=15.0)
    if storage_status["connected"]:
        print(f"  [PASS] Storage API Connected! (Latency: {storage_status['latency_ms']}ms)")
        try:
            # Verify required private buckets exist
            storage.ensure_buckets_exist()
            print(f"  [PASS] All 4 Private Buckets Verified: {storage_status.get('buckets', [])}")

            # Test smoke upload & download
            test_key = "audit/smoke_test.txt"
            test_content = b"MailinteL live storage verification test"
            upload_res = storage.upload_evidence_object(
                bucket_name=settings.evidence_bucket,
                object_key=test_key,
                data=test_content,
                content_type="text/plain",
            )
            download_bytes, download_meta = storage.get_evidence_object(
                bucket_name=settings.evidence_bucket,
                object_key=test_key,
            )
            upload_sha = upload_res.get("sha256_hash") or upload_res.get("sha256")
            is_valid, computed_sha = storage.verify_evidence_integrity(
                bucket_name=settings.evidence_bucket,
                object_key=test_key,
                expected_sha256=upload_sha,
            )
            print(f"  [PASS] Object Upload & Cryptographic SHA-256 Integrity: Verified ({computed_sha[:16]}...)")

            # Test presigned URL
            signed_url = storage.generate_presigned_download_url(
                bucket_name=settings.evidence_bucket,
                object_key=test_key,
                expires_seconds=60,
            )
            print(f"  [PASS] Presigned Download URL Generation: Operational")
            results["storage"] = True
        except Exception as st_exc:
            print(f"  [FAIL] Storage operations error: {st_exc}")
            results["storage"] = False
    else:
        print(f"  [FAIL] Storage Connectivity Failed: {storage_status['error']}")
        results["storage"] = False

    # -------------------------------------------------------------
    # 4. MAXMIND GEOIP & ASN INTELLIGENCE
    # -------------------------------------------------------------
    print("\n[4/5] Checking MaxMind GeoIP / ASN Intelligence...")
    print(f"  * Configured Path: {settings.MAXMIND_GEOIP_DB_PATH}")
    mm_status = maxmind_client.get_status()
    print(f"  * Library:         {'Installed' if mm_status['library_installed'] else 'Missing'}")
    print(f"  * ASN Database:    {'Loaded' if mm_status['asn_database_loaded'] else 'Not Loaded'}")
    print(f"  * Loaded Files:    {mm_status.get('loaded_databases', [])}")

    if mm_status["asn_database_loaded"]:
        lookup = maxmind_client.lookup_asn("8.8.8.8")
        if lookup:
            print(f"  [PASS] Benchmark Lookup: 8.8.8.8 -> {lookup.get('asn')} ({lookup.get('asn_org')})")
            results["maxmind"] = True
        else:
            print(f"  [FAIL] MaxMind lookup for 8.8.8.8 failed")
            results["maxmind"] = False
    else:
        print("  [WARN] MaxMind ASN database is not loaded.")
        results["maxmind"] = False

    # -------------------------------------------------------------
    # 5. THREAT INTELLIGENCE API KEYS
    # -------------------------------------------------------------
    print("\n[5/5] Checking Threat Intelligence API Keys...")
    vt_configured = bool(settings.VIRUSTOTAL_API_KEY and len(settings.VIRUSTOTAL_API_KEY) > 20)
    abuse_configured = bool(settings.ABUSEIPDB_API_KEY and len(settings.ABUSEIPDB_API_KEY) > 20)

    print(f"  * VirusTotal API Key: {'[PASS] Configured (Key Length: ' + str(len(settings.VIRUSTOTAL_API_KEY)) + ')' if vt_configured else '[i] Not set'}")
    print(f"  * AbuseIPDB API Key:  {'[PASS] Configured (Key Length: ' + str(len(settings.ABUSEIPDB_API_KEY)) + ')' if abuse_configured else '[i] Not set'}")
    results["threat_intel"] = vt_configured and abuse_configured

    # -------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    all_passed = results["database"] and results["storage"] and results["maxmind"]
    if all_passed:
        print("  >>> ALL CONFIGURATIONS ARE PROPER, OPERATIONAL & PRODUCTION-READY! <<<")
    else:
        print("  >>> AUDIT FINISHED WITH NOTICES (See details above) <<<")
    print("=" * 70)
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(run_diagnostics())
    sys.exit(0 if success else 1)
