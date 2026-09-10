#!/usr/bin/env python3
"""
MailinteL MaxMind GeoIP & ASN Database Setup & Verification Utility

Verifies local MaxMind .mmdb database discovery, tests sub-millisecond
lookups for City/Country & ASN, and provides automated deployment downloads
for production (Render, Docker, CI/CD) and local development.

Usage:
    python backend/scripts/setup_maxmind.py
    python backend/scripts/setup_maxmind.py --download
"""

import os
import sys
import time
import shutil
import tarfile
import argparse
import urllib.request
from pathlib import Path

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import ROOT_DIR, BASE_DIR, settings


OFFICIAL_MAXMIND_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={license_key}&suffix=tar.gz"
)

MIRROR_URLS = {
    "GeoLite2-City": "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb",
    "GeoLite2-ASN": "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb",
}


def download_file_with_progress(url: str, dest_path: Path, desc: str) -> bool:
    """Downloads a file with streaming progress."""
    print(f"[*] Downloading {desc}...")
    temp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "MailinteL-Deployer/1.0 (Security Forensic Engine)"},
        )
        with urllib.request.urlopen(req, timeout=45) as response, open(temp_path, "wb") as out_file:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 1024 * 1024  # 1MB blocks

            while True:
                chunk = response.read(block_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    mb = downloaded / (1024 * 1024)
                    tot_mb = total_size / (1024 * 1024)
                    sys.stdout.write(f"\r    -> {mb:.1f}/{tot_mb:.1f} MB ({pct:.1f}%)")
                    sys.stdout.flush()

        print(f"\n    [+] Successfully downloaded {desc}")
        if temp_path.exists():
            if dest_path.exists():
                dest_path.unlink()
            temp_path.rename(dest_path)
        return True
    except Exception as exc:
        print(f"\n    [!] Failed to download {desc}: {exc}")
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        return False


def extract_mmdb_from_tar(tar_path: Path, edition: str, target_dir: Path) -> bool:
    """Extracts the .mmdb database from a MaxMind official tar.gz archive."""
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".mmdb") and edition in member.name:
                    extracted = tar.extractfile(member)
                    if extracted:
                        out_path = target_dir / f"{edition}.mmdb"
                        with open(out_path, "wb") as f_out:
                            shutil.copyfileobj(extracted, f_out)
                        print(f"    [+] Extracted {edition}.mmdb to {out_path}")
                        return True
        print(f"    [!] Could not locate {edition}.mmdb inside downloaded archive.")
        return False
    except Exception as exc:
        print(f"    [!] Error extracting archive for {edition}: {exc}")
        return False


def ensure_databases_present(target_dir: Path, force_download: bool = False) -> bool:
    """Ensures GeoLite2-City and GeoLite2-ASN databases are available in target_dir."""
    target_dir.mkdir(parents=True, exist_ok=True)
    license_key = getattr(settings, "MAXMIND_LICENSE_KEY", None) or os.environ.get("MAXMIND_LICENSE_KEY")
    if license_key:
        license_key = license_key.strip() or None

    all_success = True
    editions = ["GeoLite2-City", "GeoLite2-ASN"]

    for edition in editions:
        dest_file = target_dir / f"{edition}.mmdb"
        if dest_file.exists() and not force_download:
            continue

        print(f"\n[*] Deploying MaxMind database: {edition}")
        download_success = False

        # Attempt 1: Official MaxMind download if license key is configured
        if license_key:
            official_url = OFFICIAL_MAXMIND_URL.format(edition=edition, license_key=license_key)
            tar_temp = target_dir / f"{edition}.tar.gz"
            if download_file_with_progress(official_url, tar_temp, f"{edition} (Official MaxMind)"):
                if extract_mmdb_from_tar(tar_temp, edition, target_dir):
                    download_success = True
                if tar_temp.exists():
                    try:
                        tar_temp.unlink()
                    except Exception:
                        pass

        # Attempt 2: Fallback to community mirror
        if not download_success:
            mirror_url = MIRROR_URLS.get(edition)
            if mirror_url:
                download_success = download_file_with_progress(
                    mirror_url,
                    dest_file,
                    f"{edition} (High-Speed Mirror)",
                )

        if not download_success:
            all_success = False
            print(f"    [-] Could not deploy {edition}.mmdb.")

    return all_success


def run_maxmind_check(auto_download: bool = False) -> bool:
    data_dir = ROOT_DIR / "data"
    if not data_dir.exists():
        data_dir = BASE_DIR / "data"

    if auto_download:
        ensure_databases_present(data_dir)

    from app.intelligence.maxmind_client import maxmind_client

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
        print("    Run with '--download' to automatically download and deploy databases:")
        print("    python backend/scripts/setup_maxmind.py --download")
        return False

    print("\n[Running Benchmark Lookups]")
    test_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "49.36.0.1"]

    start = time.perf_counter()
    for ip in test_ips:
        asn_info = maxmind_client.lookup_asn(ip)
        city_info = maxmind_client.lookup_city(ip)

        parts = []
        if asn_info:
            parts.append(f"{asn_info.get('asn')} ({asn_info.get('asn_org')})")
        if city_info:
            loc_str = city_info.get('city_name') or city_info.get('region_name') or city_info.get('country_name')
            parts.append(f"{loc_str}, {city_info.get('country_code')}")

        display = " | ".join(parts) if parts else "No record"
        print(f"  [+] {ip:15} -> {display}")

    elapsed_ms = (time.perf_counter() - start) * 1000
    avg_us = (elapsed_ms / len(test_ips)) * 1000
    print(f"\nBenchmark: {len(test_ips)} lookups completed in {elapsed_ms:.2f}ms (Avg: {avg_us:.1f}us / lookup)")

    print("\n" + "=" * 65)
    print("  [SUCCESS] MaxMind GeoIP/ASN configuration is fully operational!")
    print("=" * 65)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MailinteL MaxMind GeoLite2 Deployer & Verifier")
    parser.add_argument(
        "--download",
        action="store_true",
        help="Automatically download missing GeoLite2 City and ASN databases",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download of databases even if they already exist",
    )
    args = parser.parse_args()

    if args.force:
        data_dir = ROOT_DIR / "data"
        ensure_databases_present(data_dir, force_download=True)

    success = run_maxmind_check(auto_download=args.download)
    sys.exit(0 if success else 1)
