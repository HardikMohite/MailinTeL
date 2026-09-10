#!/usr/bin/env python3
"""
MailinteL MaxMind GeoIP & ASN Database Verification Utility

Verifies local MaxMind .mmdb database discovery, tests sub-millisecond
ASN lookups, and validates production readiness.

Usage:
    python backend/scripts/setup_maxmind.py
"""

import sys
import time
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.intelligence.maxmind_client import maxmind_client


def run_maxmind_check():
    print("=" * 65)
    print("  MailinteL — MaxMind GeoIP & ASN Intelligence Health Check")
    print("=" * 65)
    print(f"Configured Path:   {settings.MAXMIND_GEOIP_DB_PATH or '(Auto-discovery default)'}")

    status = maxmind_client.get_status()
    print(f"Library Installed: {'Yes (geoip2 / maxminddb)' if status['library_installed'] else 'No'}")
    print(f"ASN Database:      {'Active' if status['asn_database_loaded'] else 'Not Loaded'}")
    print(f"City Database:     {'Active' if status['city_database_loaded'] else 'Not Loaded'}")

    loaded_dbs = status.get("loaded_databases", [])
    if loaded_dbs:
        print(f"Loaded Files:      {', '.join(loaded_dbs)}")
    else:
        print("Loaded Files:      None found")
    print("-" * 65)

    if not status["asn_database_loaded"] and not status["city_database_loaded"]:
        print("\n[-] No MaxMind .mmdb databases found.")
        print("    Place 'GeoLite2-ASN.mmdb' or 'GeoLite2-City.mmdb' in the 'data/' folder,")
        print("    or set MAXMIND_GEOIP_DB_PATH in your .env file.")
        return False

    print("\n[Running Benchmark Lookups]")
    test_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14"]

    start = time.perf_counter()
    for ip in test_ips:
        asn_info = maxmind_client.lookup_asn(ip)
        city_info = maxmind_client.lookup_city(ip)

        parts = []
        if asn_info:
            parts.append(f"{asn_info.get('asn')} ({asn_info.get('asn_org')})")
        if city_info:
            parts.append(f"{city_info.get('city_name')}, {city_info.get('country_code')}")

        display = " | ".join(parts) if parts else "No record"
        print(f"  [+] {ip:15} -> {display}")

    elapsed_ms = (time.perf_counter() - start) * 1000
    avg_us = (elapsed_ms / len(test_ips)) * 1000
    print(f"\nBenchmark: {len(test_ips)} lookups completed in {elapsed_ms:.2f}ms (Avg: {avg_us:.1f}us / lookup)")

    print("\n" + "=" * 65)
    print("  [SUCCESS] MaxMind GeoIP/ASN configuration is operational!")
    print("=" * 65)
    return True


if __name__ == "__main__":
    success = run_maxmind_check()
    sys.exit(0 if success else 1)
