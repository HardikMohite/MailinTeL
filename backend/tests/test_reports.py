import uuid
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_current_user
from app.models.emails import Email, EmailSource
from app.models.campaign import Campaign, CampaignMembership
from app.models.evidence import EvidenceObject
from app.models.analysis import EmailAnalysis, AnalysisFinding
from app.models.reports import Report
from app.services.report_service import ReportService, ATTRIBUTION_DISCLAIMER
from app.services.pdf_report_service import PDFReportService
import pymupdf
from tests.auth_helpers import TEST_USER

client = TestClient(app)


def test_render_markdown_report():
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "report_version": "1.0",
        "email_id": str(uuid.uuid4()),
        "email_metadata": {
            "subject": "Urgent: Wire Transfer Verification",
            "from_address": "cfo-exec@phish-corp.xyz",
            "from_name": "Executive Officer",
            "to_addresses": ["victim@target-corp.com"],
            "sha256_hash": "a" * 64,
            "file_size_bytes": 10240,
            "attachment_count": 1,
            "date_header": "2026-09-06T12:00:00Z",
        },
        "explainable_scores": {
            "threat_classification": "MALICIOUS",
            "threat_risk_score": 88.5,
            "evidence_confidence_score": 92.0,
            "summary": "Sophisticated display name spoofing with punycode domain.",
            "likelihoods": {
                "compromised_account": "UNLIKELY",
                "spoofed_domain": "HIGH",
                "anonymized_infrastructure": "MEDIUM",
                "malicious_environment": "HIGH",
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "finding_type": "AUTHENTICATION_FAILURE",
                    "title": "SPF and DMARC Failed",
                    "description": "Sending MTA is not permitted in SPF record.",
                }
            ],
        },
        "custody_and_integrity": {
            "integrity": {
                "bucket": "mailintel-evidence",
                "immutable": True,
                "stored_at": "2026-09-06T12:05:00Z",
            },
            "custody_events": [
                {
                    "event_type": "ACQUIRED",
                    "timestamp": "2026-09-06T12:05:00Z",
                    "metadata": {"source": "UPLOAD"},
                }
            ],
        },
        "authentication_and_headers": {
            "spf_result": "FAIL",
            "dkim_result": "NONE",
            "dmarc_result": "FAIL",
        },
        "threat_intelligence": {
            "urls": [{"normalized_url": "https://phish-corp.xyz/login", "context": "BODY"}],
            "threat_indicators": [
                {
                    "indicator_type": "DOMAIN",
                    "value": "phish-corp.xyz",
                    "source": "VirusTotal",
                    "verdict": "MALICIOUS",
                    "threat_score": 90.0,
                }
            ],
        },
        "geo_intelligence": {
            "locations": [
                {
                    "ip_address": "185.220.101.5",
                    "role": "ORIGIN_HOP",
                    "country": "Netherlands",
                    "country_code": "NL",
                    "city": "Amsterdam",
                    "asn": "AS12345",
                    "isp": "Tor Exit Relay",
                }
            ]
        },
        "limitations_and_disclaimer": {
            "disclaimer": ATTRIBUTION_DISCLAIMER,
            "uncertainty_notes": [
                "Infrastructure geolocation indicates server routing, NOT human attacker physical location.",
            ],
        },
    }

    md = ReportService.render_markdown_report(report_data)
    assert "# MailIntel Forensic Intelligence Report" in md
    assert "Urgent: Wire Transfer Verification" in md
    assert "MALICIOUS" in md
    assert "SPF and DMARC Failed" in md
    assert "Netherlands" in md
    assert ATTRIBUTION_DISCLAIMER in md


def test_render_html_report():
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "email_id": str(uuid.uuid4()),
        "email_metadata": {
            "subject": "Invoice Overdue",
            "from_address": "billing@malicious-fake.com",
            "to_addresses": ["accounting@target.com"],
            "sha256_hash": "b" * 64,
            "file_size_bytes": 5420,
        },
        "explainable_scores": {
            "threat_classification": "SUSPICIOUS",
            "threat_risk_score": 65.0,
            "evidence_confidence_score": 80.0,
            "summary": "Suspicious newly registered domain.",
            "findings": [],
        },
        "custody_and_integrity": {"integrity": {"bucket": "mailintel-evidence", "immutable": True}},
        "authentication_and_headers": {"spf_result": "SOFTFAIL"},
        "threat_intelligence": {"threat_indicators": []},
        "geo_intelligence": {"locations": []},
        "limitations_and_disclaimer": {
            "disclaimer": ATTRIBUTION_DISCLAIMER,
            "uncertainty_notes": [],
        },
    }

    html = ReportService.render_html_report(report_data)
    assert "<!DOCTYPE html>" in html
    assert "MAILINTEL" in html
    assert "Invoice Overdue" in html
    assert "SUSPICIOUS" in html
    assert ATTRIBUTION_DISCLAIMER in html


def test_render_json_report():
    data = {"report_id": "test-123", "score": 95}
    json_str = ReportService.render_json_report(data)
    parsed = json.loads(json_str)
    assert parsed["report_id"] == "test-123"
    assert parsed["score"] == 95


@pytest.mark.asyncio
async def test_build_email_report_data():
    email_id = uuid.uuid4()
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Credential Harvesting Lure",
        sender_address="phish@evil.com",
        email_size_bytes=2048,
    )
    mock_analysis = EmailAnalysis(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=uuid.uuid4(),
        threat_classification="MALICIOUS",
        threat_risk_score=95.0,
        evidence_confidence_score=90.0,
        summary="High risk credential phish",
        created_at=datetime.now(timezone.utc),
    )

    mock_session = AsyncMock()

    async def mock_execute(query, *args, **kwargs):
        q_str = str(query)
        mock_res = MagicMock()
        if "FROM emails" in q_str:
            mock_res.scalar_one_or_none.return_value = mock_email
        elif "FROM email_analysis" in q_str:
            mock_res.scalars.return_value.first.return_value = mock_analysis
        else:
            mock_res.scalar_one_or_none.return_value = None
            mock_res.scalars.return_value.all.return_value = []
            mock_res.all.return_value = []
        return mock_res

    mock_session.execute = AsyncMock(side_effect=mock_execute)

    res = await ReportService.build_email_report_data(email_id=email_id, db=mock_session)
    assert res["email_id"] == str(email_id)
    assert res["email_metadata"]["subject"] == "Credential Harvesting Lure"
    assert res["explainable_scores"]["threat_classification"] == "MALICIOUS"
    assert ATTRIBUTION_DISCLAIMER in res["limitations_and_disclaimer"]["disclaimer"]


@pytest.mark.asyncio
async def test_generate_and_save_email_report():
    email_id = uuid.uuid4()
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Report Save Test",
        sender_address="test@domain.com",
        email_size_bytes=1000,
    )

    mock_session = AsyncMock()

    async def mock_execute(query, *args, **kwargs):
        q_str = str(query)
        mock_res = MagicMock()
        if "FROM emails" in q_str:
            mock_res.scalar_one_or_none.return_value = mock_email
        else:
            mock_res.scalar_one_or_none.return_value = None
            mock_res.scalars.return_value.first.return_value = None
            mock_res.scalars.return_value.all.return_value = []
            mock_res.all.return_value = []
        return mock_res

    mock_session.execute = AsyncMock(side_effect=mock_execute)
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.add = MagicMock()

    with patch("app.core.storage.storage.upload_evidence_object", return_value={"bucket_name": "mailintel-reports"}):
        report_model, content, data = await ReportService.generate_and_save_email_report(
            email_id=email_id,
            format_type="markdown",
            db=mock_session,
        )
        assert report_model.report_type == "FORENSIC_SUMMARY"
        assert report_model.email_id == email_id
        assert "# MailIntel Forensic Intelligence Report" in content
        assert data["email_metadata"]["subject"] == "Report Save Test"


def test_api_generate_email_report_endpoint():
    email_id = uuid.uuid4()
    mock_report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "email_id": str(email_id),
        "email_metadata": {"subject": "Test Endpoint"},
        "explainable_scores": {"threat_classification": "SUSPICIOUS", "threat_risk_score": 70.0, "evidence_confidence_score": 80.0},
    }
    mock_report_model = Report(
        id=uuid.uuid4(),
        report_type="FORENSIC_SUMMARY",
        email_id=email_id,
        report_version="1.0",
        generated_at=datetime.now(timezone.utc),
        summary={"format": "html"},
    )

    with patch(
        "app.services.report_service.ReportService.generate_and_save_email_report",
        new=AsyncMock(return_value=(mock_report_model, "<html></html>", mock_report_data)),
    ), patch(
        "sqlalchemy.ext.asyncio.AsyncSession.execute"
    ) as mock_exec:
        mock_res = MagicMock()
        mock_res.first.return_value = (
            Email(id=email_id, source_id=uuid.uuid4(), subject="Test"),
            EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
        )
        mock_exec.return_value = mock_res

        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.post(f"/api/v1/reports/email/{email_id}?format=html")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_type"] == "FORENSIC_SUMMARY"
        assert data["email_id"] == str(email_id)


def test_api_export_email_report_markdown():
    email_id = uuid.uuid4()
    mock_report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "report_version": "1.0",
        "email_id": str(email_id),
        "email_metadata": {"subject": "Export Test", "sha256_hash": "e" * 64},
        "explainable_scores": {"threat_classification": "CLEAN", "threat_risk_score": 5.0, "evidence_confidence_score": 95.0},
        "custody_and_integrity": {"integrity": {}},
        "authentication_and_headers": {},
        "threat_intelligence": {},
        "geo_intelligence": {},
        "limitations_and_disclaimer": {"disclaimer": ATTRIBUTION_DISCLAIMER, "uncertainty_notes": []},
    }

    with patch(
        "app.services.report_service.ReportService.build_email_report_data",
        new=AsyncMock(return_value=mock_report_data),
    ), patch(
        "sqlalchemy.ext.asyncio.AsyncSession.execute"
    ) as mock_exec:
        mock_res = MagicMock()
        mock_res.first.return_value = (
            Email(id=email_id, source_id=uuid.uuid4(), subject="Export Test"),
            EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
        )
        mock_exec.return_value = mock_res

        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/reports/email/{email_id}/export?format=markdown")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/markdown")
        assert "MailIntel Forensic Intelligence Report" in resp.text


def test_render_pdf_report_strictly_two_pages():
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "email_id": str(uuid.uuid4()),
        "email_metadata": {
            "subject": "PDF Test: Invoice Verification",
            "from_address": "finance@test-domain.com",
            "to_addresses": ["accounting@target.com"],
            "sha256_hash": "c" * 64,
            "file_size_bytes": 14200,
        },
        "explainable_scores": {
            "threat_classification": "SUSPICIOUS",
            "threat_risk_score": 62.0,
            "evidence_confidence_score": 88.0,
            "summary": "Suspicious newly registered sending domain with SPF softfail.",
            "likelihoods": {
                "compromised_account": "LOW",
                "spoofed_domain": "HIGH",
                "anonymized_infrastructure": "UNLIKELY",
                "malicious_environment": "MEDIUM",
            },
            "findings": [
                {
                    "severity": "HIGH",
                    "finding_type": "DOMAIN_AGE",
                    "title": "Newly Registered Domain",
                    "description": "Domain registered 4 days ago.",
                }
            ],
        },
        "custody_and_integrity": {"integrity": {"bucket": "mailintel-evidence", "immutable": True}},
        "authentication_and_headers": {"spf_result": "SOFTFAIL", "dkim_result": "PASS", "dmarc_result": "FAIL"},
        "threat_intelligence": {"threat_indicators": [], "urls": []},
        "geo_intelligence": {"locations": []},
        "limitations_and_disclaimer": {
            "disclaimer": ATTRIBUTION_DISCLAIMER,
            "uncertainty_notes": ["Routing hops may be forged."],
        },
    }

    pdf_bytes = PDFReportService.render_pdf_report(report_data)
    assert len(pdf_bytes) > 1000
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    assert doc.page_count == 2, f"Expected strictly 2 pages, got {doc.page_count}"
    page1_text = doc[0].get_text()
    assert "SENDER DOMAIN & REGISTRATION INTELLIGENCE" in page1_text
    page2_text = doc[1].get_text()
    assert "DETAILED ANALYSIS FINDINGS & SECURITY CHECKS" in page2_text


def test_render_pdf_report_domain_intelligence_and_benign_wording():
    """Verify that BENIGN classification renders as CLEAN / SAFE and domain intel is rendered."""
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "email_id": str(uuid.uuid4()),
        "email_metadata": {
            "subject": "Benign Newsletter",
            "from_address": "support@brevosend.com",
            "from_name": "Brevo Support",
            "to_addresses": ["user@example.com"],
            "sha256_hash": "a" * 64,
        },
        "explainable_scores": {
            "threat_classification": "BENIGN",
            "threat_risk_score": 3.0,
            "evidence_confidence_score": 95.0,
            "summary": "All checks passed cleanly.",
            "likelihoods": {
                "compromised_account": "UNLIKELY",
                "spoofed_domain": "UNLIKELY",
                "anonymized_infrastructure": "UNLIKELY",
                "malicious_environment": "UNLIKELY",
            },
            "findings": [
                {
                    "severity": "INFO",
                    "finding_type": "AUTH_AUTHENTICATION_PASSED",
                    "title": "Authentication Passed",
                    "description": "SPF, DKIM, and DMARC aligned.",
                }
            ],
        },
        "domain_intelligence": {
            "domain": "brevosend.com",
            "root_domain": "brevosend.com",
            "registrar": "OVH sas",
            "registered_at": "2024-02-26T17:14:14+00:00",
            "expires_at": "2027-02-26T17:14:14+00:00",
            "domain_age_days": 926,
            "domain_age_str": "926 days (~2y 6m)",
            "mx_servers": ["dmarc.brevo.com"],
            "nameservers": ["josh.ns.cloudflare.com"],
            "domain_type": "Commercial ESP Relay",
            "is_punycode": False,
        },
        "custody_and_integrity": {"integrity": {"bucket": "mailintel-evidence"}},
        "authentication_and_headers": {"spf_result": "PASS", "dkim_result": "PASS", "dmarc_result": "PASS"},
        "threat_intelligence": {
            "urls": [{"normalized_url": "https://example.com/link", "context": "BODY"}],
            "threat_indicators": [
                {"indicator_type": "DOMAIN", "value": "brevosend.com", "source": "Threat Intelligence Engine", "verdict": "BENIGN"}
            ]
        },
        "geo_intelligence": {"locations": []},
        "limitations_and_disclaimer": {"disclaimer": ATTRIBUTION_DISCLAIMER, "uncertainty_notes": []},
    }

    pdf_bytes = PDFReportService.render_pdf_report(report_data)
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    assert doc.page_count == 2
    p1 = doc[0].get_text()
    assert "CLEAN / SAFE" in p1
    assert "brevosend.com" in p1
    assert "OVH sas" in p1
    p2 = doc[1].get_text()
    assert "SAFE / PASSED" in p2
    assert "Email Authentication" in p2
    assert "FOUND IN EMAIL" in p2


def test_export_pdf_report_endpoint():
    email_id = uuid.uuid4()
    mock_report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": "FORENSIC_SUMMARY",
        "email_id": str(email_id),
        "email_metadata": {"subject": "PDF Export Test", "sha256_hash": "d" * 64},
        "explainable_scores": {"threat_classification": "BENIGN", "threat_risk_score": 10.0, "evidence_confidence_score": 90.0},
        "custody_and_integrity": {"integrity": {}},
        "authentication_and_headers": {},
        "threat_intelligence": {},
        "geo_intelligence": {},
        "limitations_and_disclaimer": {"disclaimer": ATTRIBUTION_DISCLAIMER, "uncertainty_notes": []},
    }

    with patch(
        "app.services.report_service.ReportService.build_email_report_data",
        new=AsyncMock(return_value=mock_report_data),
    ), patch(
        "sqlalchemy.ext.asyncio.AsyncSession.execute"
    ) as mock_exec:
        mock_res = MagicMock()
        mock_res.first.return_value = (
            Email(id=email_id, source_id=uuid.uuid4(), subject="PDF Export Test"),
            EmailSource(id=uuid.uuid4(), organization_id=TEST_USER.organization_id),
        )
        mock_exec.return_value = mock_res

        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/reports/email/{email_id}/export?format=pdf")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert f"MailIntel_Forensic_Report_{str(email_id)[:8]}.pdf" in resp.headers["content-disposition"]

