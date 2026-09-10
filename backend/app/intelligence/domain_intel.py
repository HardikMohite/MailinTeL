import asyncio
import dns.asyncresolver
import dns.resolver
import httpx
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
import logging

from app.parser.header_analyzer import (
    extract_domain_from_email_or_host,
    get_organizational_domain,
)
from app.parser.email_parser import sanitize_string

logger = logging.getLogger(__name__)

# Constants for domain intelligence
DEFAULT_DNS_TIMEOUT_SECONDS = 1.0
DEFAULT_HTTP_TIMEOUT_SECONDS = 2.0
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain"

DYNAMIC_DNS_DOMAINS = {
    "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
    "dynu.net", "freedns.afraid.org", "ngrok.io", "localtunnel.me"
}


@dataclass
class DNSRecordData:
    record_type: str  # A, AAAA, MX, TXT, NS, CNAME
    record_value: str
    priority: Optional[int] = None
    ttl: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type,
            "record_value": self.record_value,
            "priority": self.priority,
            "ttl": self.ttl,
        }


@dataclass
class RegistrationIntelData:
    source: str = "RDAP"
    registrar: Optional[str] = None
    registered_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    nameservers: List[str] = field(default_factory=list)
    raw_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "registrar": self.registrar,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "domain_age_days": self.domain_age_days,
            "nameservers": self.nameservers,
            "raw_summary": self.raw_summary,
        }


@dataclass
class DomainIntelBundle:
    domain: str
    root_domain: str
    dns_records: List[DNSRecordData] = field(default_factory=list)
    registration_intel: Optional[RegistrationIntelData] = None
    mx_hosts: List[str] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    is_nrd: bool = False
    is_dynamic_dns: bool = False
    is_punycode: bool = False
    risk_tags: List[str] = field(default_factory=list)
    risk_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "root_domain": self.root_domain,
            "dns_records": [r.to_dict() for r in self.dns_records],
            "registration_intel": self.registration_intel.to_dict() if self.registration_intel else None,
            "mx_hosts": self.mx_hosts,
            "a_records": self.a_records,
            "txt_records": self.txt_records,
            "ns_records": self.ns_records,
            "is_nrd": self.is_nrd,
            "is_dynamic_dns": self.is_dynamic_dns,
            "is_punycode": self.is_punycode,
            "risk_tags": self.risk_tags,
            "risk_level": self.risk_level,
            "resolved_at": self.resolved_at.isoformat(),
        }


class AsyncDNSResolver:
    """
    Asynchronous DNS Resolver for domain intelligence.
    Performs concurrent lookups for A, AAAA, MX, TXT, NS, and CNAME records.
    """

    def __init__(self, timeout: float = DEFAULT_DNS_TIMEOUT_SECONDS):
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    async def query_domain_records(self, domain_name: str) -> List[DNSRecordData]:
        """Queries DNS records concurrently for a domain."""
        clean_domain = domain_name.strip(".").strip().lower()
        if not clean_domain:
            return []

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        tasks = [self._resolve_type(clean_domain, r_type) for r_type in record_types]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=1.2)
        except Exception:
            results = []

        all_records: List[DNSRecordData] = []
        for r_list in results:
            if isinstance(r_list, list):
                all_records.extend(r_list)

        return all_records

    async def _resolve_type(self, domain: str, record_type: str) -> List[DNSRecordData]:
        records: List[DNSRecordData] = []
        try:
            answers = await self.resolver.resolve(domain, record_type)
            for rdata in answers:
                priority = getattr(rdata, "preference", None)
                val_str = rdata.to_text().strip('"')
                records.append(
                    DNSRecordData(
                        record_type=record_type,
                        record_value=val_str,
                        priority=priority,
                        ttl=answers.ttl,
                    )
                )
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.exception.DNSException,
            Exception,
        ) as e:
            logger.debug(f"DNS {record_type} query for {domain} resulted in {type(e).__name__}")

        return records


class AsyncRDAPClient:
    """
    Asynchronous RDAP client for registrar intelligence and domain age calculations.
    Queries authoritative RDAP servers with graceful degradation.
    """

    def __init__(self, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS):
        self.timeout = timeout

    async def query_domain_registration(self, domain_name: str) -> Optional[RegistrationIntelData]:
        """Queries ICANN RDAP registry for domain registration metadata."""
        clean_domain = domain_name.strip(".").strip().lower()
        if not clean_domain:
            return None

        # Use root organizational domain for RDAP lookup if domain is a subdomain
        root_domain = get_organizational_domain(clean_domain) or clean_domain
        url = f"{RDAP_BOOTSTRAP_URL}/{root_domain}"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=1.0), follow_redirects=True) as client:
                resp = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_rdap_payload(data)
                logger.debug(f"RDAP lookup for {root_domain} returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"RDAP query failed for {root_domain}: {e}")

        return None

    def _parse_rdap_payload(self, data: Dict[str, Any]) -> RegistrationIntelData:
        registrar = None
        registered_at = None
        expires_at = None
        updated_at = None
        nameservers = []

        # 1. Parse Registrar
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if len(prop) > 3 and prop[0] == "fn":
                            registrar = sanitize_string(str(prop[3]))
                            break
                if not registrar and ent.get("handle"):
                    registrar = sanitize_string(str(ent.get("handle")))

        # 2. Parse Events (dates)
        events = data.get("events", [])
        now_utc = datetime.now(timezone.utc)
        for ev in events:
            action = ev.get("eventAction", "").lower()
            date_str = ev.get("eventDate", "")
            if date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    if "registration" in action or "created" in action:
                        registered_at = dt
                    elif "expiration" in action:
                        expires_at = dt
                    elif "last changed" in action or "last update" in action:
                        updated_at = dt
                except Exception:
                    pass

        # 3. Parse Nameservers
        ns_list = data.get("nameservers", [])
        for ns in ns_list:
            ldh = ns.get("ldhName")
            if ldh:
                nameservers.append(sanitize_string(str(ldh).lower()))

        # 4. Calculate domain age in days
        age_days = None
        if registered_at:
            delta = now_utc - registered_at
            age_days = max(0, int(delta.total_seconds() // 86400))

        raw_summary = {
            "handle": data.get("handle"),
            "ldhName": data.get("ldhName"),
            "status": data.get("status", []),
            "port43": data.get("port43"),
        }

        return RegistrationIntelData(
            source="RDAP",
            registrar=registrar,
            registered_at=registered_at,
            expires_at=expires_at,
            updated_at=updated_at,
            domain_age_days=age_days,
            nameservers=nameservers,
            raw_summary=raw_summary,
        )


class DomainRiskEvaluator:
    """
    Evaluates forensic threat score and risk indicators for domains based on DNS and RDAP intelligence.
    """

    def evaluate_domain(
        self,
        domain_name: str,
        dns_records: List[DNSRecordData],
        reg_intel: Optional[RegistrationIntelData],
    ) -> Tuple[List[str], str, bool]:
        """
        Evaluates risk tags, overall risk level, and NRD status for a domain.
        Returns (risk_tags, risk_level, is_nrd).
        """
        risk_tags: List[str] = []
        clean_domain = domain_name.strip(".").lower()
        root_domain = get_organizational_domain(clean_domain) or clean_domain

        # 1. Punycode / IDN Homoglyph check
        if clean_domain.startswith("xn--") or ".xn--" in clean_domain:
            risk_tags.append("PUNYCODE_HOMOGLYPH")

        # 2. Dynamic DNS Check
        if root_domain in DYNAMIC_DNS_DOMAINS:
            risk_tags.append("DYNAMIC_DNS_PROVIDER")

        # 3. Newly Registered Domain (NRD) Evaluation
        is_nrd = False
        if reg_intel and reg_intel.domain_age_days is not None:
            age = reg_intel.domain_age_days
            if age < 30:
                is_nrd = True
                risk_tags.append("NEWLY_REGISTERED_DOMAIN_30D")
            elif age < 90:
                is_nrd = True
                risk_tags.append("NEWLY_REGISTERED_DOMAIN_90D")
            elif age < 365:
                risk_tags.append("EMERGING_DOMAIN_UNDER_1YR")

        # 4. DNS Record Health Checks
        mx_records = [r for r in dns_records if r.record_type == "MX"]
        a_records = [r for r in dns_records if r.record_type == "A"]

        if not dns_records:
            risk_tags.append("NO_DNS_RECORDS_RESOLVED")
        elif not mx_records:
            risk_tags.append("NO_MX_RECORDS")

        # Determine overall Risk Level
        if "NEWLY_REGISTERED_DOMAIN_30D" in risk_tags or "DYNAMIC_DNS_PROVIDER" in risk_tags:
            risk_level = "HIGH"
        elif "NEWLY_REGISTERED_DOMAIN_90D" in risk_tags or "PUNYCODE_HOMOGLYPH" in risk_tags:
            risk_level = "MEDIUM"
        elif dns_records:
            risk_level = "LOW"
        else:
            risk_level = "UNKNOWN"

        return risk_tags, risk_level, is_nrd


class DomainIntelligenceEngine:
    """
    Unified Domain Intelligence Engine coordinating DNS resolution, RDAP querying,
    and forensic risk evaluation.
    """

    def __init__(
        self,
        dns_resolver: Optional[AsyncDNSResolver] = None,
        rdap_client: Optional[AsyncRDAPClient] = None,
    ):
        self.dns_resolver = dns_resolver or AsyncDNSResolver()
        self.rdap_client = rdap_client or AsyncRDAPClient()
        self.risk_evaluator = DomainRiskEvaluator()

    async def analyze_domain(self, domain_name: str) -> DomainIntelBundle:
        """Performs full DNS resolution, RDAP analysis, and risk scoring for a domain."""
        clean_domain = domain_name.strip(".").strip().lower()
        root_domain = get_organizational_domain(clean_domain) or clean_domain

        # Run DNS and RDAP queries concurrently with strict 2.0s bounded timeout
        dns_task = self.dns_resolver.query_domain_records(clean_domain)
        rdap_task = self.rdap_client.query_domain_registration(clean_domain)

        try:
            dns_records, reg_intel = await asyncio.wait_for(
                asyncio.gather(dns_task, rdap_task),
                timeout=2.0,
            )
        except Exception as e:
            logger.debug(f"Domain analysis timeout/degrade for {clean_domain}: {e}")
            dns_records, reg_intel = [], None

        # Categorize DNS records
        mx_hosts = [r.record_value for r in dns_records if r.record_type == "MX"]
        a_records = [r.record_value for r in dns_records if r.record_type == "A"]
        txt_records = [r.record_value for r in dns_records if r.record_type == "TXT"]
        ns_records = [r.record_value for r in dns_records if r.record_type == "NS"]

        # Evaluate risk
        risk_tags, risk_level, is_nrd = self.risk_evaluator.evaluate_domain(
            clean_domain, dns_records, reg_intel
        )

        is_dynamic_dns = root_domain in DYNAMIC_DNS_DOMAINS
        is_punycode = clean_domain.startswith("xn--") or ".xn--" in clean_domain

        return DomainIntelBundle(
            domain=clean_domain,
            root_domain=root_domain,
            dns_records=dns_records,
            registration_intel=reg_intel,
            mx_hosts=mx_hosts,
            a_records=a_records,
            txt_records=txt_records,
            ns_records=ns_records,
            is_nrd=is_nrd,
            is_dynamic_dns=is_dynamic_dns,
            is_punycode=is_punycode,
            risk_tags=risk_tags,
            risk_level=risk_level,
        )
