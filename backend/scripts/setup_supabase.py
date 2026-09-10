#!/usr/bin/env python3
"""
MailinteL — Complete Supabase Infrastructure Provisioning Utility

Sets up and verifies BOTH:
  1. Supabase PostgreSQL Database (pgvector, tables/migrations, admin user)
  2. Supabase Storage (4 Private buckets: evidence, derived, reports, temp, and smoke test)

Usage:
    python backend/scripts/setup_supabase.py
"""

import sys
import asyncio
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from scripts.setup_supabase_db import run_db_setup
from scripts.setup_supabase_storage import run_setup as run_storage_setup


async def main_async() -> int:
    print("\n" + "=" * 65)
    print("      MAILINTEL — COMPLETE SUPABASE INFRASTRUCTURE SETUP")
    print("=" * 65 + "\n")

    print("[SECTION 1: DATABASE PROVISIONING]")
    db_ok = await run_db_setup()

    print("\n[SECTION 2: STORAGE & BUCKET PROVISIONING]")
    storage_ok = run_storage_setup(run_test=True)

    print("\n" + "=" * 65)
    print("                      SUMMARY REPORT")
    print("=" * 65)
    print(f"  Supabase PostgreSQL Database: {'[READY]' if db_ok else '[FAILED]'}")
    print(f"  Supabase Object Storage:      {'[READY]' if storage_ok else '[FAILED]'}")
    print("=" * 65)

    return 0 if (db_ok and storage_ok) else 1


def main():
    exit_code = asyncio.run(main_async())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
