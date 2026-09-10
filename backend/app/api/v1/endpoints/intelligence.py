import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    Query,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.api.deps import get_current_user, get_authorized_email, CurrentUser
from app.models.emails import Email
from app.models.intelligence import Domain, DomainDNSRecord, DomainRegistrationIntel
from app.intelligence.domain_intel import (
    DomainIntelligenceEngine,
    DomainIntelBundle,
)
from app.services.domain_intel_service import (
    enrich_and_persist_domain_intelligence,
    enrich_email_domains,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class DNSRecordSchema(BaseModel):
    record_type: str
    record_value: str
    priority: Optional[int] = None
    ttl: Optional[int] = None


class RegistrationIntelSchema(BaseModel):
    source: str = "RDAP"
    registrar: Optional[str] = None
    registered_at: Optional[str] = None
    expires_at: Optional[str] = None
    updated_at: Optional[str] = None
    domain_age_days: Optional[int] = None
    nameservers: List[str] = Field(default_factory=list)
    raw_summary: Dict[str, Any] = Field(default_factory=dict)


class DomainIntelResponse(BaseModel):
    domain: str
    root_domain: str
    is_nrd: bool
    is_dynamic_dns: bool
    is_punycode: bool
    risk_level: str
    risk_tags: List[str] = Field(default_factory=list)
    mx_hosts: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    dns_records: List[DNSRecordSchema] = Field(default_factory=list)
    registration_intel: Optional[RegistrationIntelSchema] = None
    resolved_at: str


class EmailDomainIntelResponse(BaseModel):
    email_id: str
    total_domains_analyzed: int
    domains: List[DomainIntelResponse]


@router.get(
    "/domains/{domain_name}",
    response_model=DomainIntelResponse,
    summary="Get Domain Threat Intelligence",
    description="Retrieve DNS records (A/MX/TXT/NS), RDAP registration age, and Newly Registered Domain (NRD) risk analysis.",
)
async def get_domain_intelligence(
    domain_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> DomainIntelResponse:
    """Analyze a domain name or return cached intelligence. Not tenant-owned data — any
    authenticated user may query any indicator, matching /ips/{ip_address} below."""
    clean_domain = domain_name.strip(".").strip().lower()
    if not clean_domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain name cannot be empty",
        )

    bundle = await enrich_and_persist_domain_intelligence(domain_name=clean_domain, db=db)

    return DomainIntelResponse(
        domain=bundle.domain,
        root_domain=bundle.root_domain,
        is_nrd=bundle.is_nrd,
        is_dynamic_dns=bundle.is_dynamic_dns,
        is_punycode=bundle.is_punycode,
        risk_level=bundle.risk_level,
        risk_tags=bundle.risk_tags,
        mx_hosts=bundle.mx_hosts,
        a_records=bundle.a_records,
        txt_records=bundle.txt_records,
        ns_records=bundle.ns_records,
        dns_records=[DNSRecordSchema(**r.to_dict()) for r in bundle.dns_records],
        registration_intel=RegistrationIntelSchema(**bundle.registration_intel.to_dict()) if bundle.registration_intel else None,
        resolved_at=bundle.resolved_at.isoformat(),
    )


@router.get(
    "/emails/{email_id}/domains",
    response_model=EmailDomainIntelResponse,
    summary="Get Email Domains Intelligence Summary",
    description="Enrich and retrieve domain threat intelligence for all domains extracted from an email.",
)
async def get_email_domains_intelligence(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailDomainIntelResponse:
    """Analyze all sender and extracted URL domains associated with an email."""
    await get_authorized_email(email_id, current_user, db)

    bundles = await enrich_email_domains(email_id=email_id, db=db)

    domain_responses = [
        DomainIntelResponse(
            domain=b.domain,
            root_domain=b.root_domain,
            is_nrd=b.is_nrd,
            is_dynamic_dns=b.is_dynamic_dns,
            is_punycode=b.is_punycode,
            risk_level=b.risk_level,
            risk_tags=b.risk_tags,
            mx_hosts=b.mx_hosts,
            a_records=b.a_records,
            txt_records=b.txt_records,
            ns_records=b.ns_records,
            dns_records=[DNSRecordSchema(**r.to_dict()) for r in b.dns_records],
            registration_intel=RegistrationIntelSchema(**b.registration_intel.to_dict()) if b.registration_intel else None,
            resolved_at=b.resolved_at.isoformat(),
        )
        for b in bundles
    ]

    return EmailDomainIntelResponse(
        email_id=str(email_id),
        total_domains_analyzed=len(domain_responses),
        domains=domain_responses,
    )


# ---------------------------------------------------------
# IP & Infrastructure Intelligence
# ---------------------------------------------------------

class InfrastructureClassificationSchema(BaseModel):
    classification_type: str
    confidence: float
    source: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class IPIntelResponse(BaseModel):
    ip_address: str
    ip_type: str
    is_private: bool
    reverse_dns: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    network_owner: Optional[str] = None
    hosting_provider: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region_name: Optional[str] = None
    city_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    classifications: List[InfrastructureClassificationSchema] = Field(default_factory=list)
    risk_level: str
    risk_tags: List[str] = Field(default_factory=list)
    resolved_at: str


class EmailInfrastructureResponse(BaseModel):
    email_id: str
    total_ips_analyzed: int
    has_tor_relay: bool
    has_vpn_relay: bool
    has_cloud_hosted_relay: bool
    ips: List[IPIntelResponse]


@router.get(
    "/ips/{ip_address}",
    response_model=IPIntelResponse,
    summary="Get IP Infrastructure Intelligence",
    description="Retrieve PTR reverse DNS, ASN/ISP registry records, and infrastructure classifications (TOR, VPN, Cloud, Residential).",
)
async def get_ip_intelligence(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> IPIntelResponse:
    """Analyze an IP address or return cached intelligence."""
    clean_ip = ip_address.strip()
    if not clean_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address cannot be empty",
        )

    from app.services.infrastructure_service import enrich_and_persist_ip_intelligence

    bundle = await enrich_and_persist_ip_intelligence(ip_str=clean_ip, db=db)

    return IPIntelResponse(
        ip_address=bundle.ip_address,
        ip_type=bundle.ip_type,
        is_private=bundle.is_private,
        reverse_dns=bundle.reverse_dns,
        asn=bundle.asn,
        asn_org=bundle.asn_org,
        isp=bundle.isp,
        network_owner=bundle.network_owner,
        hosting_provider=bundle.hosting_provider,
        country_code=bundle.country_code,
        country_name=bundle.country_name,
        region_name=bundle.region_name,
        city_name=bundle.city_name,
        latitude=bundle.latitude,
        longitude=bundle.longitude,
        classifications=[
            InfrastructureClassificationSchema(**c.to_dict()) for c in bundle.classifications
        ],
        risk_level=bundle.risk_level,
        risk_tags=bundle.risk_tags,
        resolved_at=bundle.resolved_at.isoformat(),
    )


@router.get(
    "/emails/{email_id}/infrastructure",
    response_model=EmailInfrastructureResponse,
    summary="Get Email Relay Infrastructure Intelligence",
    description="Analyze and classify all transmission relay IPs (TOR, VPN, Proxy, Cloud) involved in an email.",
)
async def get_email_infrastructure_intelligence(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailInfrastructureResponse:
    """Analyze all transmission relay hop IPs associated with an email."""
    await get_authorized_email(email_id, current_user, db)

    from app.services.infrastructure_service import enrich_email_infrastructure

    bundles = await enrich_email_infrastructure(email_id=email_id, db=db)

    ip_responses = [
        IPIntelResponse(
            ip_address=b.ip_address,
            ip_type=b.ip_type,
            is_private=b.is_private,
            reverse_dns=b.reverse_dns,
            asn=b.asn,
            asn_org=b.asn_org,
            isp=b.isp,
            network_owner=b.network_owner,
            hosting_provider=b.hosting_provider,
            country_code=b.country_code,
            country_name=b.country_name,
            region_name=b.region_name,
            city_name=b.city_name,
            latitude=b.latitude,
            longitude=b.longitude,
            classifications=[
                InfrastructureClassificationSchema(**c.to_dict()) for c in b.classifications
            ],
            risk_level=b.risk_level,
            risk_tags=b.risk_tags,
            resolved_at=b.resolved_at.isoformat(),
        )
        for b in bundles
    ]

    has_tor = any("TOR_EXIT_NODE" in b.risk_tags for b in bundles)
    has_vpn = any("VPN_OR_PROXY_PROVIDER" in b.risk_tags for b in bundles)
    has_cloud = any(
        any(c.classification_type == "CLOUD_HOSTED" for c in b.classifications)
        for b in bundles
    )

    return EmailInfrastructureResponse(
        email_id=str(email_id),
        total_ips_analyzed=len(ip_responses),
        has_tor_relay=has_tor,
        has_vpn_relay=has_vpn,
        has_cloud_hosted_relay=has_cloud,
        ips=ip_responses,
    )


# ---------------------------------------------------------
# Threat Intelligence Enrichment & Multi-Provider Consensus
# ---------------------------------------------------------

class ThreatIntelReportSchema(BaseModel):
    indicator_type: str
    indicator_value: str
    provider: str
    verdict: str
    threat_score: float
    confidence: float
    tags: List[str] = Field(default_factory=list)
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    total_votes: int = 0
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    queried_at: str
    is_fallback: bool = False
    details: Optional[str] = None


class AggregatedThreatIntelResponse(BaseModel):
    indicator_type: str
    indicator_value: str
    consensus_verdict: str
    consensus_threat_score: float
    consensus_confidence: float
    aggregated_tags: List[str] = Field(default_factory=list)
    provider_reports: List[ThreatIntelReportSchema] = Field(default_factory=list)
    provider_count: int
    queried_at: str


class EmailThreatIntelSummaryResponse(BaseModel):
    email_id: str
    total_iocs_analyzed: int
    malicious_ioc_count: int
    suspicious_ioc_count: int
    overall_threat_level: str
    indicators: List[AggregatedThreatIntelResponse]


@router.get(
    "/threat/lookup",
    response_model=AggregatedThreatIntelResponse,
    summary="Lookup Threat Intelligence Indicator",
    description="Query multi-provider threat intelligence (VirusTotal, AbuseIPDB, URLHaus, Internal Reputation) for an IP, domain, URL, or hash.",
)
async def lookup_threat_indicator(
    indicator_type: str = Query(..., description="Indicator type: IP, DOMAIN, URL, FILE_HASH, SHA256"),
    indicator_value: str = Query(..., description="Indicator value"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> AggregatedThreatIntelResponse:
    """Live query and consensus calculation for an indicator."""
    from app.services.threat_intel_service import enrich_and_persist_indicator

    aggregated = await enrich_and_persist_indicator(
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        db=db,
    )

    return AggregatedThreatIntelResponse(
        indicator_type=aggregated.indicator_type,
        indicator_value=aggregated.indicator_value,
        consensus_verdict=aggregated.consensus_verdict,
        consensus_threat_score=aggregated.consensus_threat_score,
        consensus_confidence=aggregated.consensus_confidence,
        aggregated_tags=aggregated.aggregated_tags,
        provider_reports=[
            ThreatIntelReportSchema(
                indicator_type=r.indicator_type,
                indicator_value=r.indicator_value,
                provider=r.provider,
                verdict=r.verdict,
                threat_score=r.threat_score,
                confidence=r.confidence,
                tags=r.tags,
                malicious_votes=r.malicious_votes,
                suspicious_votes=r.suspicious_votes,
                harmless_votes=r.harmless_votes,
                total_votes=r.total_votes,
                raw_data=r.raw_data,
                queried_at=r.queried_at.isoformat(),
                is_fallback=r.is_fallback,
                details=r.details,
            )
            for r in aggregated.provider_reports
        ],
        provider_count=aggregated.provider_count,
        queried_at=aggregated.queried_at.isoformat(),
    )


@router.get(
    "/emails/{email_id}/threat-intel",
    response_model=EmailThreatIntelSummaryResponse,
    summary="Get Email Threat Intelligence Summary",
    description="Retrieve consolidated threat intelligence for all IOCs extracted from an email.",
)
@router.post(
    "/emails/{email_id}/enrich",
    response_model=EmailThreatIntelSummaryResponse,
    summary="Trigger Email Threat Intelligence Enrichment",
    description="Trigger multi-provider threat intelligence enrichment for all IOCs extracted from an email.",
)
async def get_or_trigger_email_threat_intelligence(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailThreatIntelSummaryResponse:
    """Enrich all email IOCs with multi-provider threat intelligence."""
    await get_authorized_email(email_id, current_user, db)

    from app.services.threat_intel_service import enrich_email_threat_intelligence

    summary = await enrich_email_threat_intelligence(email_id=email_id, db=db)

    return EmailThreatIntelSummaryResponse(
        email_id=summary["email_id"],
        total_iocs_analyzed=summary["total_iocs_analyzed"],
        malicious_ioc_count=summary["malicious_ioc_count"],
        suspicious_ioc_count=summary["suspicious_ioc_count"],
        overall_threat_level=summary["overall_threat_level"],
        indicators=[
            AggregatedThreatIntelResponse(
                indicator_type=ind["indicator_type"],
                indicator_value=ind["indicator_value"],
                consensus_verdict=ind["consensus_verdict"],
                consensus_threat_score=ind["consensus_threat_score"],
                consensus_confidence=ind["consensus_confidence"],
                aggregated_tags=ind["aggregated_tags"],
                provider_reports=[
                    ThreatIntelReportSchema(**r) for r in ind["provider_reports"]
                ],
                provider_count=ind["provider_count"],
                queried_at=ind["queried_at"],
            )
            for ind in summary["indicators"]
        ],
    )


