import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select, inspect

from app.db.base import Base
import app.models as models


def test_all_models_registered_in_metadata():
    """Verify that all expected tables are registered with SQLAlchemy Base.metadata."""
    expected_tables = {
        "users",
        "organizations",
        "roles",
        "permissions",
        "role_permissions",
        "organization_members",
        "email_sources",
        "emails",
        "email_headers",
        "email_recipients",
        "email_authentication_results",
        "relay_hops",
        "evidence_objects",
        "custody_events",
        "domains",
        "domain_dns_records",
        "domain_registration_intel",
        "urls",
        "email_urls",
        "ip_addresses",
        "ip_intelligence",
        "infrastructure_classifications",
        "geolocations",
        "entity_geolocations",
        "analysis_runs",
        "email_analysis",
        "analysis_findings",
        "email_dna_profiles",
        "email_similarity_links",
        "email_embeddings",
        "campaigns",
        "campaign_memberships",
        "campaign_evidence",
        "campaign_events",
        "intel_entities",
        "intel_relationships",
        "cases",
        "case_emails",
        "case_campaigns",
        "investigation_actions",
        "reports",
        "audit_logs",
        "retention_policies",
        "retention_assignments",
        "data_classifications",
        "masking_rules",
        "threat_indicators",
        "indicator_sightings",
        "oauth_connections",
        "extension_events",
    }

    registered_tables = set(Base.metadata.tables.keys())
    missing_tables = expected_tables - registered_tables

    assert not missing_tables, f"Missing tables in Base.metadata: {missing_tables}"
    assert len(registered_tables) >= len(expected_tables)


def test_identity_model_instantiation():
    """Verify instantiation of User, Organization, Role, and Member models."""
    user = models.User(
        email="analyst@mailintel.local",
        full_name="Security Analyst 1",
        auth_provider="LOCAL",
        status="ACTIVE",
    )
    assert user.email == "analyst@mailintel.local"
    assert user.id is not None or user.status == "ACTIVE"

    org = models.Organization(
        name="State Cyber Cell",
        organization_type="LAW_ENFORCEMENT",
        status="ACTIVE",
    )
    assert org.name == "State Cyber Cell"

    role = models.Role(
        code="CYBER_CELL_INVESTIGATOR",
        name="Cyber Cell Investigator",
        description="Authorized forensic officer",
    )
    assert role.code == "CYBER_CELL_INVESTIGATOR"


def test_email_and_forensics_model_instantiation():
    """Verify Email, EmailSource, Header, Recipient, and Auth Result instantiation."""
    email_id = uuid.uuid4()
    source_id = uuid.uuid4()

    source = models.EmailSource(
        id=source_id,
        source_type="FILE_UPLOAD",
        source_provider="GENERIC",
        source_reference="phishing_sample.eml",
    )
    assert source.source_type == "FILE_UPLOAD"

    email = models.Email(
        id=email_id,
        source_id=source_id,
        message_id_header="<12345@evil-phish.net>",
        subject="Urgent: Verify Your Account Credentials",
        sender_address="admin@evil-phish.net",
        sender_display_name="Security Desk",
        analysis_status="PENDING",
        qualification_status="SUSPICIOUS",
    )
    assert email.subject == "Urgent: Verify Your Account Credentials"
    assert email.qualification_status == "SUSPICIOUS"

    header = models.EmailHeader(
        email_id=email_id,
        header_name="X-Originating-IP",
        header_value="[198.51.100.23]",
        header_order=1,
    )
    assert header.header_name == "X-Originating-IP"

    recipient = models.EmailRecipient(
        email_id=email_id,
        recipient_type="TO",
        address="victim@target-corp.com",
    )
    assert recipient.recipient_type == "TO"

    auth = models.EmailAuthenticationResult(
        email_id=email_id,
        spf_result="FAIL",
        dkim_result="FAIL",
        dmarc_result="FAIL",
        from_alignment_result="FAIL",
        return_path="bounce@spoofed-domain.com",
    )
    assert auth.spf_result == "FAIL"

    hop = models.RelayHop(
        email_id=email_id,
        sequence_number=1,
        source_host="mail.evil-phish.net",
        source_ip="198.51.100.23",
        destination_host="mx.target-corp.com",
        reliability="HIGH",
    )
    assert hop.reliability == "HIGH"


def test_evidence_and_custody_model_instantiation():
    """Verify EvidenceObject and CustodyEvent models with SHA-256 integrity metadata."""
    evidence_id = uuid.uuid4()
    test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    evidence = models.EvidenceObject(
        id=evidence_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename="sample_threat.eml",
        content_type="message/rfc822",
        size_bytes=1048576,
        sha256_hash=test_hash,
        bucket_name="mailintel-evidence",
        object_key="originals/emails/2026/09/sample_threat.eml",
        immutable=True,
        retention_status="ACTIVE",
    )
    assert evidence.sha256_hash == test_hash
    assert evidence.immutable is True

    event = models.CustodyEvent(
        evidence_id=evidence_id,
        event_type="ACQUIRED",
        event_metadata={"source": "upload_api", "sha256": test_hash},
    )
    assert event.event_type == "ACQUIRED"
    assert event.evidence_id == evidence_id


def test_intelligence_and_infrastructure_models():
    """Verify Domain, URL, IP, Infrastructure, and Geolocation models."""
    domain = models.Domain(
        normalized_domain="evil-phish.net",
        root_domain="evil-phish.net",
    )
    assert domain.normalized_domain == "evil-phish.net"

    dns = models.DomainDNSRecord(
        domain_id=uuid.uuid4(),
        record_type="MX",
        record_value="10 mail.evil-phish.net.",
        observed_at=datetime.now(timezone.utc),
    )
    assert dns.record_type == "MX"

    url = models.URL(
        normalized_url="https://evil-phish.net/login/credential-harvest",
        url_hash="abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
    )
    assert url.url_hash.startswith("abc123")

    ip = models.IPAddress(
        ip_address="198.51.100.23",
    )
    assert ip.ip_address == "198.51.100.23"

    infra = models.InfrastructureClassification(
        ip_id=uuid.uuid4(),
        classification_type="TOR",
        confidence=95.50,
        source="INTERNAL_EXIT_NODE_FEED",
    )
    assert infra.classification_type == "TOR"
    assert infra.confidence == 95.50

    geo = models.Geolocation(
        country_code="IN",
        country_name="India",
        region_name="Maharashtra",
        city_name="Mumbai",
        latitude=19.0760,
        longitude=72.8777,
        accuracy_radius_km=10,
    )
    assert geo.country_code == "IN"
    assert geo.city_name == "Mumbai"


def test_threat_analysis_and_findings_models():
    """Verify AnalysisRun, EmailAnalysis, and AnalysisFinding models with dual scores."""
    email_id = uuid.uuid4()
    run_id = uuid.uuid4()

    run = models.AnalysisRun(
        id=run_id,
        email_id=email_id,
        analysis_type="FULL_PIPELINE",
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    assert run.status == "COMPLETED"

    analysis = models.EmailAnalysis(
        email_id=email_id,
        analysis_run_id=run_id,
        threat_classification="MALICIOUS",
        threat_risk_score=94.50,
        evidence_confidence_score=98.00,
        summary="High-confidence phishing campaign targeting banking credentials.",
        spoofed_domain_likelihood="HIGH",
    )
    assert analysis.threat_classification == "MALICIOUS"
    assert analysis.threat_risk_score == 94.50
    assert analysis.evidence_confidence_score == 98.00

    finding = models.AnalysisFinding(
        email_id=email_id,
        analysis_run_id=run_id,
        finding_type="LOOKALIKE_DOMAIN",
        severity="CRITICAL",
        confidence=95.00,
        title="Punycode/Typosquatted Brand Domain Detected",
        description="Sender domain mimics official banking portal with character replacement.",
    )
    assert finding.severity == "CRITICAL"


def test_campaign_and_graph_models():
    """Verify Campaign, CampaignMembership, and IntelEntity models."""
    campaign_id = uuid.uuid4()
    email_id = uuid.uuid4()

    campaign = models.Campaign(
        id=campaign_id,
        campaign_name="Operation CredentialHarvester 2026",
        campaign_status="ACTIVE",
        campaign_confidence=92.50,
        threat_summary="Multi-stage credential harvesting campaign using compromised relays.",
        first_detected_at=datetime.now(timezone.utc),
        last_activity_at=datetime.now(timezone.utc),
    )
    assert campaign.campaign_name == "Operation CredentialHarvester 2026"

    membership = models.CampaignMembership(
        campaign_id=campaign_id,
        email_id=email_id,
        membership_confidence=90.00,
        membership_status="CONFIRMED",
    )
    assert membership.membership_status == "CONFIRMED"

    entity = models.IntelEntity(
        entity_type="DOMAIN",
        normalized_value="evil-phish.net",
        display_value="evil-phish.net",
    )
    assert entity.entity_type == "DOMAIN"
