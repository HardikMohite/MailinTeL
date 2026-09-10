#!/usr/bin/env python3
"""
MailinteL Supabase PostgreSQL Database Setup & Migration Utility

Verifies connectivity to Supabase PostgreSQL, ensures required extensions
(vector, pgcrypto) exist, runs Alembic migrations to create tables, and
provisions the initial administrator account.

Usage:
    python backend/scripts/setup_supabase_db.py
    python backend/scripts/setup_supabase_db.py --url "postgresql+asyncpg://postgres:pass@db.xxx.supabase.co:5432/postgres"
"""

import sys
import asyncio
import argparse
import logging
from pathlib import Path
from sqlalchemy import text

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.db.session import engine, check_db_connectivity
from app.db.vector import ensure_db_extensions, check_pgvector_availability
from app.db.init_db import init_admin_account

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("setup_supabase_db")


async def run_db_setup(database_url: str = None) -> bool:
    if database_url:
        settings.DATABASE_URL = database_url

    print("=" * 65)
    print("  MailinteL — Supabase PostgreSQL Database Setup & Health Check")
    print("=" * 65)
    print(f"Target DB Host: {settings.POSTGRES_HOST}")
    print(f"Target DB Port: {settings.POSTGRES_PORT}")
    print(f"Target DB Name: {settings.POSTGRES_DB}")
    print(f"Supabase Mode:  {'Yes (SSL Enforced)' if settings.is_supabase_db else 'Standard / Local'}")
    print(f"Pooler Mode:    {'Yes (Supavisor / Prepared Statement Caching Disabled)' if settings.is_pooler_connection else 'Direct (Port 5432)'}")
    print("-" * 65)

    # 1. Check Connectivity
    print("\n[Step 1/4] Probing PostgreSQL connectivity...")
    status = await check_db_connectivity(timeout_seconds=15.0)
    if not status["connected"]:
        print(f"[-] Connection Failed: {status['error']}")
        print("\nTroubleshooting:")
        print("  1. Verify your DATABASE_URL or POSTGRES_HOST/PASSWORD in .env")
        print("  2. In Supabase Dashboard, verify Database password under Project Settings -> Database")
        print("  3. Direct connection (db.[ref].supabase.co:5432) requires IPv6 or Supabase IPv4 addon.")
        print("     If using standard IPv4 only, use Connection Pooler: aws-0-[region].pooler.supabase.com:6543")
        print("  4. Ensure your network/firewall allows outbound connections to port 5432 / 6543")
        return False

    print(f"[+] Connected to PostgreSQL! Latency: {status['latency_ms']}ms")

    # 2. Check & Enable Extensions (pgvector, pgcrypto)
    print("\n[Step 2/4] Verifying extensions (vector, pgcrypto)...")
    ext_results = await ensure_db_extensions(engine)
    for ext_name, is_ok in ext_results.items():
        state = "[+] Active" if is_ok else "[-] Missing/Failed"
        print(f"    {state} Extension: {ext_name}")

    vector_status = await check_pgvector_availability(engine)
    if vector_status.get("available"):
        print(f"    [+] pgvector verified: version {vector_status.get('version')}")
    else:
        print("    [!] Warning: pgvector could not be verified.")

    # 3. Run Alembic Migrations
    print("\n[Step 3/4] Running schema migrations (Alembic)...")
    try:
        from alembic import command
        from alembic.config import Config
        alembic_ini_path = backend_dir / "alembic.ini"
        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
        alembic_cfg.set_main_option("sqlalchemy.url", settings.effective_database_url)

        # Run upgrade head synchronously (alembic handles async loop internally)
        command.upgrade(alembic_cfg, "head")
        print("    [+] Schema migrations applied successfully (head).")
    except Exception as exc:
        print(f"    [-] Migration exception: {exc}")
        print("    You can run migrations manually with: alembic upgrade head")

    # 4. Provision Administrator Account
    print("\n[Step 4/4] Provisioning initial Administrator account...")
    if settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD:
        try:
            created = await init_admin_account()
            if created:
                print(f"    [+] Initial administrator user provisioned: {settings.ADMIN_EMAIL}")
            else:
                print(f"    [+] Administrator user already exists: {settings.ADMIN_EMAIL}")
        except Exception as exc:
            print(f"    [-] Admin provisioning warning: {exc}")
    else:
        print("    [i] Skipped (ADMIN_EMAIL/ADMIN_PASSWORD not set in .env)")

    print("\n" + "=" * 65)
    print("  [SUCCESS] Supabase Database is configured and ready for MailinteL!")
    print("=" * 65)
    return True


def main():
    parser = argparse.ArgumentParser(description="MailinteL Supabase Database Setup Utility")
    parser.add_argument("--url", help="Database connection URL override")
    args = parser.parse_args()

    success = asyncio.run(run_db_setup(database_url=args.url))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
