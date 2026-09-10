#!/usr/bin/env python3
"""
MailinTeL - Standalone Forensic PDF Report Generation Script
Generates high-fidelity, strictly 2-page forensic email threat intelligence dossiers
branded with the official MailinTeL shield & DNA motif and light background watermark.

Usage:
    python scripts/generate_pdf_report.py --sample
    python scripts/generate_pdf_report.py --email-id <UUID> [--output <PATH>]
    python scripts/generate_pdf_report.py --json <PATH> [--output <PATH>]
"""

import sys
import os
import argparse
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add backend directory to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.pdf_report_service import PDFReportService


def load_sample_report_data() -> dict:
    """Returns realistic, comprehensive forensic report payload for testing/demo."""
    sample_json_path = BACKEND_DIR / "reports_output" / "sample_email_report.json"
    if sample_json_path.exists():
        with open(sample_json_path, "r", encoding="utf-8") as f:
            return json.load(f)

    # Fallback synthetic demo data
    return {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "report_version": "1.0",
        "email_id": str(uuid.uuid4()),
        "email_metadata": {
            "subject": "Urgent: Wire Transfer Verification Notice",
            "from_address": "phishverse@11929178.brevosend.com",
            "from_name": "Executive Finance Operations",
            "to_addresses": ["target.executive@enterprise-target.com"],
            "cc_addresses": [],
            "date_header": "2026-09-08T14:22:10+00:00",
            "message_id": "<202609081422.98283695014@smtp-relay.mailin.fr>",
            "reply_to": "bounces-493374490@gz.d.sender-sib.com",
            "return_path": "bounces-493374490@gz.d.sender-sib.com",
            "file_size_bytes": 12840,
            "sha256_hash": "69b0f389b99e323e130091bd5813d1c7f9ba9f4353c290392e602f557fb521f4",
            "attachment_count": 0,
        },
        "custody_and_integrity": {
            "integrity": {
                "verified": True,
                "original_sha256": "69b0f389b99e323e130091bd5813d1c7f9ba9f4353c290392e602f557fb521f4",
                "size_bytes": 12840,
                "bucket": "mailintel-evidence",
                "object_key": "originals/emails/2026/09/sample_forensic_evidence.eml",
                "stored_at": "2026-09-08T14:25:00Z",
                "immutable": True,
            },
            "custody_events": [
                {
                    "event_type": "ACQUIRED",
                    "timestamp": "2026-09-08T14:25:00Z",
                    "metadata": {"source": "api_upload", "hash_verified": True},
                }
            ],
        },
        "authentication_and_headers": {
            "spf_result": "PASS",
            "dkim_result": "PASS",
            "dmarc_result": "PASS",
            "from_domain_alignment": "PASS",
            "return_path": "bounces-493374490@gz.d.sender-sib.com",
            "reply_to": "bounces-493374490@gz.d.sender-sib.com",
            "raw_headers": {},
        },
        "explainable_scores": {
            "threat_classification": "SUSPICIOUS",
            "threat_risk_score": 48.5,
            "evidence_confidence_score": 95.0,
            "summary": "Email forensic analysis detected suspicious domain behavior with malicious relay transit hop 77.32.148.26 flagged in threat feeds.",
            "likelihoods": {
                "compromised_account": "HIGH",
                "spoofed_domain": "LOW",
                "anonymized_infrastructure": "UNLIKELY",
                "malicious_environment": "HIGH",
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "finding_type": "THREAT_INTEL_MALICIOUS_IP",
                    "confidence": 0.95,
                    "title": "Malicious Intermediate Relay IP: 77.32.148.26",
                    "description": "Indicator flagged as malicious in threat feeds with high confidence score 85.0.",
                },
                {
                    "severity": "INFO",
                    "finding_type": "AUTH_AUTHENTICATION_PASSED",
                    "confidence": 1.0,
                    "title": "Email Authentication Passed & Aligned",
                    "description": "SPF, DKIM, and DMARC verification succeeded for sending domain.",
                }
            ],
        },
        "email_dna": {
            "overall_dna_hash": "a4f81c9b20e1d8847b732d8a43290f11904e21a719d3bb824f1c98e219ba3802",
            "technical_fingerprint": {
                "header_order_hash": "3694578e6bc352dac677be51376003aac150ec14bc3f669c8d546b37fd119942",
                "x_mailer": "None / Stripped",
            },
            "infrastructure_fingerprint": {
                "originating_ip": "77.32.148.26",
                "asn_sequence": "AS12345 -> AS15169",
                "has_tor": False,
                "has_vpn": False,
                "has_cloud": True,
            },
        },
        "threat_intelligence": {
            "urls": [
                {"normalized_url": "https://phishpulse.onrender.com/api/track/c/travel_alibaug_getaway_v1-direct", "context": "BODY_LINK"},
                {"normalized_url": "https://bbjcjbhi.r.af.d.sendibt2.com/tr/cl/XBNuc6C-GTwMc2Ar", "context": "REDIRECT_URL"},
            ],
            "threat_indicators": [
                {"indicator_type": "IP", "value": "77.32.148.26", "source": "Threat Intel Engine", "verdict": "MALICIOUS", "threat_score": 85.0},
                {"indicator_type": "DOMAIN", "value": "11929178.brevosend.com", "source": "Threat Intel Engine", "verdict": "BENIGN", "threat_score": 10.0},
            ],
        },
        "similarity_and_clusters": {
            "campaigns": [
                {
                    "name": "PhishPulse: Alibaug Travel Getaway Lure",
                    "status": "ACTIVE",
                    "confidence_score": 90.0,
                    "is_bridge_entity": False,
                }
            ],
            "similar_emails": [],
        },
        "geo_intelligence": {
            "locations": [
                {
                    "ip_address": "77.32.148.26",
                    "role": "ORIGIN_RELAY",
                    "country": "Netherlands",
                    "country_code": "NL",
                    "city": "Amsterdam",
                    "region": "North Holland",
                    "asn": "AS12345",
                    "isp": "Transit Hosting B.V.",
                }
            ]
        },
        "domain_intelligence": {
            "domain": "11929178.brevosend.com",
            "root_domain": "brevosend.com",
            "registrar": "OVH sas",
            "registered_at": "2024-02-26T17:14:14+00:00",
            "expires_at": "2027-02-26T17:14:14+00:00",
            "domain_age_days": 926,
            "domain_age_str": "926 days (~2y 6m)",
            "mx_servers": ["dmarc.brevo.com"],
            "nameservers": ["josh.ns.cloudflare.com", "mary.ns.cloudflare.com"],
            "ip_addresses": ["172.67.185.98", "104.21.84.30"],
            "is_punycode": False,
            "is_dynamic_dns": False,
            "is_nrd": False,
            "domain_type": "Commercial ESP Relay",
            "safety_status": "CLEAN / SAFE",
        },
        "limitations_and_disclaimer": {
            "disclaimer": (
                "NOTICE & ATTRIBUTION DISCLAIMER: This forensic report is automatically synthesized from available "
                "RFC 822 email headers, cryptographic authentication assertions, DNS/RDAP records, and threat intelligence sources. "
                "Infrastructure observations (IP addresses, ASNs, geolocations) indicate intermediate transit, relay, or hosting facilities "
                "and do NOT establish the physical identity or geographical location of the human threat actor."
            ),
            "uncertainty_notes": [
                "Email header routing hops may be forged by prior relays before receipt by the first trusted MTA.",
                "Server hosting coordinates must never be conflated with the human perpetrator's physical whereabouts.",
            ]
        }
    }


async def generate_from_db(email_id: uuid.UUID) -> dict:
    """Fetches real forensic data for email_id from database."""
    from app.db.session import async_session_maker
    from app.services.report_service import ReportService
    
    async with async_session_maker() as session:
        return await ReportService.build_email_report_data(email_id=email_id, db=session)


def main():
    parser = argparse.ArgumentParser(
        description="MailinTeL - Automated 2-Page Forensic PDF Dossier Generator"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--email-id", type=str, help="Target Email UUID from database")
    group.add_argument("--json", type=str, help="Path to existing JSON report file")
    group.add_argument("--sample", action="store_true", help="Generate a sample demonstration dossier")

    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Target output PDF file path (default: reports_output/MailinTeL_Report_<id>.pdf)"
    )

    args = parser.parse_args()

    print("[*] MailinTeL Forensic PDF Generation Engine initialized.")

    report_data = None
    if args.sample:
        print("[+] Loading demonstration forensic report data...")
        report_data = load_sample_report_data()
    elif args.json:
        json_path = Path(args.json)
        if not json_path.exists():
            print(f"[!] Error: JSON file not found at {json_path}")
            sys.exit(1)
        print(f"[+] Loading report data from {json_path}...")
        with open(json_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    elif args.email_id:
        try:
            target_uuid = uuid.UUID(args.email_id)
        except ValueError:
            print(f"[!] Invalid email UUID: {args.email_id}")
            sys.exit(1)
        print(f"[+] Querying forensic database for email {target_uuid}...")
        try:
            report_data = asyncio.run(generate_from_db(target_uuid))
        except Exception as e:
            print(f"[!] Failed to fetch report data from DB: {e}")
            sys.exit(1)

    if not report_data:
        print("[!] No report data available.")
        sys.exit(1)

    # Determine output path
    rep_id = str(report_data.get("report_id", uuid.uuid4()))[:8]
    if args.output:
        out_path = Path(args.output)
    else:
        out_dir = BACKEND_DIR / "reports_output"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"MailinTeL_Forensic_Dossier_{rep_id}.pdf"

    print(f"[*] Rendering strictly 2-page PDF report with watermark and vector charts...")
    pdf_bytes = PDFReportService.render_pdf_report(report_data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(pdf_bytes)

    # Validate page count with PyMuPDF
    try:
        import pymupdf
        doc = pymupdf.open(str(out_path))
        print(f"[+] Output written to: {out_path} ({len(pdf_bytes):,} bytes)")
        print(f"[+] Validated Page Count: {doc.page_count} (Maximum constraint: 2)")
        if doc.page_count == 2:
            print("[+] PASS: Strictly 2-page constraint satisfied.")
        else:
            print(f"[!] WARNING: Page count is {doc.page_count} (expected exactly 2)!")
    except ImportError:
        print(f"[+] Output written to: {out_path} ({len(pdf_bytes):,} bytes)")

    print("[+] Complete.")


if __name__ == "__main__":
    main()
