import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
import dns.asyncresolver
import dns.reversename
import dns.resolver
import httpx

from app.core.config import settings
from app.parser.email_parser import sanitize_string
from app.intelligence.maxmind_client import maxmind_client

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 1.0
DEFAULT_HTTP_TIMEOUT = 2.0

# ---------------------------------------------------------
# Known Threat & Infrastructure Signatures
# ---------------------------------------------------------

CLOUD_PROVIDERS_ASN = {
    "16509": ("Amazon AWS", "CLOUD_HOSTED"),
    "14618": ("Amazon AWS", "CLOUD_HOSTED"),
    "8075": ("Microsoft Azure", "CLOUD_HOSTED"),
    "15169": ("Google Cloud Platform", "CLOUD_HOSTED"),
    "396982": ("Google Cloud Platform", "CLOUD_HOSTED"),
    "31898": ("Oracle Cloud", "CLOUD_HOSTED"),
    "13335": ("Cloudflare", "CLOUD_HOSTED"),
    "14061": ("DigitalOcean", "CLOUD_HOSTED"),
    "63949": ("Linode / Akamai", "CLOUD_HOSTED"),
    "24940": ("Hetzner Online", "CLOUD_HOSTED"),
    "16276": ("OVH SAS", "CLOUD_HOSTED"),
    "20473": ("Vultr / Choopa", "CLOUD_HOSTED"),
    "132203": ("Tencent Cloud", "CLOUD_HOSTED"),
    "45102": ("Alibaba Cloud", "CLOUD_HOSTED"),
    "37963": ("Alibaba Cloud", "CLOUD_HOSTED"),
}

CLOUD_PTR_PATTERNS = [
    ("amazonaws.com", "Amazon AWS", "CLOUD_HOSTED"),
    ("cloudfront.net", "Amazon AWS", "CLOUD_HOSTED"),
    ("azure.com", "Microsoft Azure", "CLOUD_HOSTED"),
    ("cloudapp.net", "Microsoft Azure", "CLOUD_HOSTED"),
    ("googleusercontent.com", "Google Cloud Platform", "CLOUD_HOSTED"),
    ("digitalocean.com", "DigitalOcean", "CLOUD_HOSTED"),
    ("linode.com", "Linode / Akamai", "CLOUD_HOSTED"),
    ("linodeusercontent.com", "Linode / Akamai", "CLOUD_HOSTED"),
    ("your-server.de", "Hetzner Online", "CLOUD_HOSTED"),
    ("hetzner.com", "Hetzner Online", "CLOUD_HOSTED"),
    ("ovh.net", "OVH SAS", "CLOUD_HOSTED"),
    ("vultrusercontent.com", "Vultr", "CLOUD_HOSTED"),
    ("vultr.com", "Vultr", "CLOUD_HOSTED"),
    ("oraclecloud.com", "Oracle Cloud", "CLOUD_HOSTED"),
]

VPN_PROXY_KEYWORDS = {
    "nordvpn", "protonvpn", "expressvpn", "surfshark", "mullvad",
    "privateinternetaccess", "pia-vpn", "windscribe", "cyberghost",
    "torguard", "hidemyass", "ipvanish", "airvpn", "purevpn",
    "astrill", "tunnelbear", "mullvad.net", "brightdata", "luminati",
    "oxylabs", "smartproxy", "webshare", "proxyrack", "wireguard",
    "openvpn", "datacamp", "privatelayer", "m247", "ovh-vpn",
    "perfect-privacy", "ivpn", "ipredator", "fastestvpn", "hotspotshield",
}

TOR_PATTERNS = [
    "tor-exit", "tor-relay", "exit-node", "torproject.org", "torservers.net",
    "tor.eff.org", "nos-oignons.net", "onionoo", "calyxinstitute.org", "appliedprivacy.net",
]

PERSONAL_MAIL_PATTERNS = [
    ("google.com", "Google Workspace / Gmail", "PERSONAL_MAIL"),
    ("gmail.com", "Google Gmail", "PERSONAL_MAIL"),
    ("googlemail.com", "Google Gmail", "PERSONAL_MAIL"),
    ("outlook.com", "Microsoft 365 / Outlook", "PERSONAL_MAIL"),
    ("hotmail.com", "Microsoft Hotmail", "PERSONAL_MAIL"),
    ("live.com", "Microsoft Live Mail", "PERSONAL_MAIL"),
    ("yahoo.com", "Yahoo! Mail", "PERSONAL_MAIL"),
    ("yahoodns.net", "Yahoo! Mail Relay", "PERSONAL_MAIL"),
    ("protonmail.com", "Proton Mail", "PERSONAL_MAIL"),
    ("proton.me", "Proton Mail", "PERSONAL_MAIL"),
    ("protonmail.ch", "Proton Mail", "PERSONAL_MAIL"),
    ("icloud.com", "Apple iCloud Mail", "PERSONAL_MAIL"),
    ("apple.com", "Apple Mail Relay", "PERSONAL_MAIL"),
    ("me.com", "Apple iCloud Mail", "PERSONAL_MAIL"),
    ("zoho.com", "Zoho Mail", "PERSONAL_MAIL"),
    ("fastmail.com", "Fastmail", "PERSONAL_MAIL"),
    ("messagingengine.com", "Fastmail", "PERSONAL_MAIL"),
    ("gmx.com", "GMX Mail", "PERSONAL_MAIL"),
    ("gmx.net", "GMX Mail", "PERSONAL_MAIL"),
    ("mail.com", "Mail.com", "PERSONAL_MAIL"),
    ("aol.com", "AOL Mail", "PERSONAL_MAIL"),
    ("yandex.com", "Yandex Mail", "PERSONAL_MAIL"),
    ("yandex.ru", "Yandex Mail", "PERSONAL_MAIL"),
]

RESIDENTIAL_ISP_KEYWORDS = {
    "comcast", "verizon", "att", "charter", "spectrum",
    "centurylink", "deutsche telekom", "british telecommunications",
    "virgin media", "orange", "vodafone", "reliance jio",
    "bharti airtel", "telstra", "bell canada", "rogers", "shaw",
}


@dataclass
class InfrastructureClassificationData:
    classification_type: str  # TOR, VPN, PROXY, CLOUD_HOSTED, HOSTING_PROVIDER, RESIDENTIAL_ISP, INTERNAL_PRIVATE_NETWORK, OPEN_RELAY
    confidence: float  # 0.0 - 1.0
    source: str = "INTERNAL_HEURISTIC"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification_type": self.classification_type,
            "confidence": round(self.confidence, 2),
            "source": self.source,
            "evidence": self.evidence,
        }


@dataclass
class IPIntelBundle:
    ip_address: str
    ip_type: str  # PUBLIC, PRIVATE_RFC1918, LOOPBACK, LINK_LOCAL, RESERVED, MULTICAST
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
    classifications: List[InfrastructureClassificationData] = field(default_factory=list)
    risk_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    risk_tags: List[str] = field(default_factory=list)
    resolved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "ip_type": self.ip_type,
            "is_private": self.is_private,
            "reverse_dns": self.reverse_dns,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
            "network_owner": self.network_owner,
            "hosting_provider": self.hosting_provider,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "region_name": self.region_name,
            "city_name": self.city_name,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "classifications": [c.to_dict() for c in self.classifications],
            "risk_level": self.risk_level,
            "risk_tags": self.risk_tags,
            "resolved_at": self.resolved_at.isoformat(),
        }


# ---------------------------------------------------------
# Async Reverse DNS (PTR) Resolver
# ---------------------------------------------------------

class AsyncReverseDNSResolver:
    """Resolves PTR records for IPv4 and IPv6 addresses."""

    def __init__(self, timeout: float = DEFAULT_DNS_TIMEOUT):
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    async def resolve_ptr(self, ip_str: str) -> Optional[str]:
        """Performs async PTR reverse DNS lookup for an IP."""
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return None
            rev_name = dns.reversename.from_address(clean_ip)
            answers = await self.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                ptr_val = str(rdata.target).rstrip(".").lower()
                return sanitize_string(ptr_val)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.exception.DNSException,
            ValueError,
            Exception,
        ) as e:
            logger.debug(f"Reverse DNS PTR resolution for {clean_ip} failed or not found: {e}")
        return None


# ---------------------------------------------------------
# Async ASN & Geolocation Resolver
# ---------------------------------------------------------

class AsyncASNResolver:
    """
    Resolves ASN, Organization, ISP, and Geolocation metadata using RDAP / IP registries.
    """

    def __init__(self, timeout: float = DEFAULT_HTTP_TIMEOUT):
        self.timeout = timeout

    async def query_ip_metadata(self, ip_str: str) -> Dict[str, Any]:
        """Queries authoritative registry for ASN and Network details."""
        clean_ip = ip_str.strip()
        result = {
            "asn": None,
            "asn_org": None,
            "isp": None,
            "network_owner": None,
            "hosting_provider": None,
            "country_code": None,
            "country_name": None,
            "region_name": None,
            "city_name": None,
            "latitude": None,
            "longitude": None,
            "raw": {},
        }

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return result
        except ValueError:
            return result

        # 1. High-speed local MaxMind ASN & City lookup (< 0.05ms)
        try:
            mm_asn = maxmind_client.lookup_asn(clean_ip)
            if mm_asn:
                result["asn"] = mm_asn.get("asn")
                result["asn_org"] = mm_asn.get("asn_org")
                result["isp"] = mm_asn.get("asn_org")
                result["network_owner"] = mm_asn.get("asn_org")
                result["raw"] = {"maxmind_asn": mm_asn}

            mm_city = maxmind_client.lookup_city(clean_ip)
            if mm_city:
                result["country_code"] = mm_city.get("country_code")
                result["country_name"] = mm_city.get("country_name")
                result["region_name"] = mm_city.get("region_name")
                result["city_name"] = mm_city.get("city_name")
                result["latitude"] = mm_city.get("latitude")
                result["longitude"] = mm_city.get("longitude")

            # If ASN was resolved locally via MaxMind, skip slow HTTP RDAP query
            if result["asn"]:
                return result
        except Exception as mm_exc:
            logger.debug(f"MaxMind lookup error for {clean_ip}: {mm_exc}")

        # 2. Fallback to RDAP for IP network if not found in MaxMind
        rdap_url = f"https://rdap.arin.net/registry/ip/{clean_ip}"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=1.0), follow_redirects=True) as client:
                resp = await client.get(rdap_url, headers={"Accept": "application/rdap+json, application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    result["raw"] = data
                    # Extract network name and entities
                    net_name = data.get("name")
                    if net_name:
                        result["network_owner"] = sanitize_string(net_name)

                    entities = data.get("entities", [])
                    for ent in entities:
                        roles = ent.get("roles", [])
                        handle = ent.get("handle")
                        vcard = ent.get("vcardArray", [])
                        ent_name = None
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    ent_name = sanitize_string(str(prop[3]))
                                    break
                        if ent_name:
                            if "registrant" in roles or "administrative" in roles:
                                result["isp"] = result["isp"] or ent_name
                                result["network_owner"] = result["network_owner"] or ent_name
                            if "noc" in roles or "abuse" in roles:
                                result["asn_org"] = result["asn_org"] or ent_name

                    country = data.get("country")
                    if country:
                        result["country_code"] = sanitize_string(str(country).upper())

                    # Check for autnums / ASN references in links or entities
                    for link in data.get("links", []):
                        href = link.get("href", "")
                        if "/autnum/" in href:
                            asn_part = href.split("/autnum/")[-1].strip("/")
                            result["asn"] = f"AS{asn_part}"
        except Exception as e:
            logger.debug(f"RDAP IP query for {clean_ip} resulted in {type(e).__name__}: {e}")

        return result


# ---------------------------------------------------------
# Infrastructure Classifier
# ---------------------------------------------------------

class InfrastructureClassifier:
    """
    Classifies IP infrastructure into TOR, VPN, PROXY, CLOUD_HOSTED,
    HOSTING_PROVIDER, RESIDENTIAL_ISP, or INTERNAL_PRIVATE_NETWORK.
    """

    def __init__(self, known_tor_exits: Optional[Set[str]] = None):
        self.known_tor_exits = known_tor_exits or set()

    def classify_ip(
        self,
        ip_str: str,
        reverse_dns: Optional[str],
        asn_metadata: Dict[str, Any],
        host: Optional[str] = None,
    ) -> Tuple[List[InfrastructureClassificationData], str, List[str]]:
        """
        Evaluates classifications, overall risk level, and risk tags.
        Returns (classifications, risk_level, risk_tags).
        """
        classifications: List[InfrastructureClassificationData] = []
        risk_tags: List[str] = []
        clean_ip = ip_str.strip()

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return classifications, "UNKNOWN", ["INVALID_IP_FORMAT"]

        # 1. Private / RFC1918 / Loopback classification
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            ip_type_tag = "RFC1918_PRIVATE" if ip_obj.is_private else "LOOPBACK" if ip_obj.is_loopback else "LINK_LOCAL"
            classifications.append(
                InfrastructureClassificationData(
                    classification_type="INTERNAL_PRIVATE_NETWORK",
                    confidence=1.0,
                    source="RFC_SPEC",
                    evidence={"ip_type": ip_type_tag},
                )
            )
            return classifications, "LOW", [f"INTERNAL_{ip_type_tag}"]

        asn_num = (asn_metadata.get("asn") or "").replace("AS", "").strip()
        asn_org = (asn_metadata.get("asn_org") or "").lower()
        isp = (asn_metadata.get("isp") or "").lower()
        net_owner = (asn_metadata.get("network_owner") or "").lower()
        ptr = (reverse_dns or "").lower()
        host_lower = (host or "").lower()

        # 2. Tor Exit Node Check
        is_tor_match = (
            clean_ip in self.known_tor_exits
            or any(tp in ptr for tp in TOR_PATTERNS)
            or any(tp in host_lower for tp in TOR_PATTERNS)
            or any(tp in isp for tp in TOR_PATTERNS)
            or any(tp in asn_org for tp in TOR_PATTERNS)
        )
        if is_tor_match:
            classifications.append(
                InfrastructureClassificationData(
                    classification_type="TOR",
                    confidence=0.95,
                    source="TOR_EXIT_LIST",
                    evidence={"ip": clean_ip, "ptr": reverse_dns, "host": host},
                )
            )
            risk_tags.append("TOR_EXIT_NODE")

        # 3. VPN / Commercial Proxy Check
        for kw in VPN_PROXY_KEYWORDS:
            if (
                kw in ptr
                or (host_lower and kw in host_lower)
                or kw in isp
                or kw in net_owner
                or kw in asn_org
            ):
                classifications.append(
                    InfrastructureClassificationData(
                        classification_type="VPN",
                        confidence=0.90,
                        source="KEYWORD_MATCH",
                        evidence={"keyword": kw, "ptr": ptr, "host": host, "isp": isp},
                    )
                )
                risk_tags.append("VPN_OR_PROXY_PROVIDER")
                break

        # 4. Personal Mail / Webmail Check
        for pattern, provider_name, c_type in PERSONAL_MAIL_PATTERNS:
            if (
                pattern in ptr
                or (host_lower and pattern in host_lower)
                or pattern in isp
                or pattern in net_owner
                or pattern in asn_org
            ):
                classifications.append(
                    InfrastructureClassificationData(
                        classification_type=c_type,
                        confidence=0.92,
                        source="MAIL_PROVIDER_MATCH",
                        evidence={"pattern": pattern, "provider": provider_name, "ptr": ptr, "host": host},
                    )
                )
                risk_tags.append(f"PERSONAL_MAIL_{provider_name.replace(' ', '_').upper()}")
                break

        # 5. Cloud Provider Classification (by ASN & PTR)
        cloud_matched = False
        if asn_num in CLOUD_PROVIDERS_ASN:
            provider_name, c_type = CLOUD_PROVIDERS_ASN[asn_num]
            classifications.append(
                InfrastructureClassificationData(
                    classification_type=c_type,
                    confidence=0.95,
                    source="ASN_MATCH",
                    evidence={"asn": f"AS{asn_num}", "provider": provider_name},
                )
            )
            risk_tags.append(f"CLOUD_HOSTED_{provider_name.replace(' ', '_').upper()}")
            cloud_matched = True
        else:
            for pattern, provider_name, c_type in CLOUD_PTR_PATTERNS:
                if (
                    pattern in ptr
                    or (host_lower and pattern in host_lower)
                    or pattern in isp
                    or pattern in net_owner
                    or pattern in asn_org
                ):
                    classifications.append(
                        InfrastructureClassificationData(
                            classification_type=c_type,
                            confidence=0.90,
                            source="PTR_MATCH",
                            evidence={"pattern": pattern, "provider": provider_name, "ptr": ptr, "host": host},
                        )
                    )
                    risk_tags.append(f"CLOUD_HOSTED_{provider_name.replace(' ', '_').upper()}")
                    cloud_matched = True
                    break

        # 6. Residential ISP Check
        for r_kw in RESIDENTIAL_ISP_KEYWORDS:
            if r_kw in isp or r_kw in net_owner or r_kw in asn_org:
                classifications.append(
                    InfrastructureClassificationData(
                        classification_type="RESIDENTIAL_ISP",
                        confidence=0.85,
                        source="ISP_MATCH",
                        evidence={"isp_name": r_kw},
                    )
                )
                risk_tags.append("RESIDENTIAL_BROADBAND")
                break

        # 7. Generic Hosting / Datacenter fallback if not residential and not matched
        if not classifications and (ptr or isp or net_owner):
            classifications.append(
                InfrastructureClassificationData(
                    classification_type="HOSTING_PROVIDER",
                    confidence=0.60,
                    source="HEURISTIC",
                    evidence={"isp": isp or net_owner, "ptr": ptr},
                )
            )

        # Determine overall Risk Level
        if "TOR_EXIT_NODE" in risk_tags or "VPN_OR_PROXY_PROVIDER" in risk_tags:
            risk_level = "HIGH"
        elif "CLOUD_HOSTED" in [c.classification_type for c in classifications]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return classifications, risk_level, risk_tags

    def classify_node_summary(
        self,
        ip_str: str,
        reverse_dns: Optional[str] = None,
        asn_metadata: Optional[Dict[str, Any]] = None,
        host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Produces a consolidated infrastructure classification summary:
        Returns connection_type, provider, is_tor, is_vpn, is_datacenter, is_cloud,
        is_personal_mail, and classification_badges.
        """
        meta = asn_metadata or {}
        classifications, risk_level, risk_tags = self.classify_ip(
            ip_str=ip_str,
            reverse_dns=reverse_dns,
            asn_metadata=meta,
            host=host,
        )
        types = [c.classification_type for c in classifications]
        is_tor = "TOR" in types
        is_vpn = "VPN" in types
        is_cloud = "CLOUD_HOSTED" in types
        is_personal = "PERSONAL_MAIL" in types or "RESIDENTIAL_ISP" in types

        # Determine primary connection type
        if is_tor:
            connection_type = "TOR"
            provider = "Tor Exit Relay"
        elif is_vpn:
            connection_type = "VPN"
            vpn_ev = next((c.evidence for c in classifications if c.classification_type == "VPN"), {})
            provider = f"{vpn_ev.get('keyword', 'Commercial VPN').title()} Tunnel"
        elif is_personal:
            connection_type = "PERSONAL_MAIL"
            mail_ev = next((c.evidence for c in classifications if c.classification_type == "PERSONAL_MAIL"), None)
            if mail_ev:
                provider = mail_ev.get("provider", "Personal Webmail Provider")
            else:
                res_ev = next((c.evidence for c in classifications if c.classification_type == "RESIDENTIAL_ISP"), {})
                provider = f"{res_ev.get('isp_name', 'Consumer Residential').title()} ISP"
        elif is_cloud:
            connection_type = "CLOUD"
            cloud_ev = next((c.evidence for c in classifications if c.classification_type == "CLOUD_HOSTED"), {})
            provider = cloud_ev.get("provider", "Cloud VPS / Datacenter")
        elif any(c.classification_type == "INTERNAL_PRIVATE_NETWORK" for c in classifications):
            connection_type = "INTERNAL"
            provider = "Internal Private Network (RFC 1918)"
        else:
            connection_type = "RELAY"
            provider = meta.get("isp") or meta.get("asn_org") or "Standard MTA Relay"

        badges: List[str] = []
        if is_tor:
            badges.append("TOR_EXIT")
        if is_vpn:
            badges.append("VPN_TUNNEL")
        if is_cloud:
            badges.append("CLOUD_INFRASTRUCTURE")
        if is_personal:
            badges.append("PERSONAL_WEBMAIL")

        return {
            "connection_type": connection_type,
            "provider": provider,
            "is_tor": is_tor,
            "is_vpn": is_vpn,
            "is_datacenter": is_cloud,
            "is_cloud": is_cloud,
            "is_personal_mail": is_personal,
            "asn": meta.get("asn"),
            "asn_org": meta.get("asn_org"),
            "reverse_dns": reverse_dns,
            "classification_badges": badges,
            "risk_level": risk_level,
            "risk_tags": risk_tags,
        }


# ---------------------------------------------------------
# Unified Infrastructure Intelligence Engine
# ---------------------------------------------------------

class InfrastructureIntelligenceEngine:
    """
    Unified Infrastructure Intelligence Engine coordinating PTR resolution,
    ASN querying, and threat categorization.
    """

    def __init__(
        self,
        ptr_resolver: Optional[AsyncReverseDNSResolver] = None,
        asn_resolver: Optional[AsyncASNResolver] = None,
        classifier: Optional[InfrastructureClassifier] = None,
    ):
        self.ptr_resolver = ptr_resolver or AsyncReverseDNSResolver()
        self.asn_resolver = asn_resolver or AsyncASNResolver()
        self.classifier = classifier or InfrastructureClassifier()

    async def analyze_ip(self, ip_str: str) -> IPIntelBundle:
        """Performs reverse DNS, ASN/ISP lookup, and infrastructure classification for an IP."""
        clean_ip = ip_str.strip()

        # Classify IP type
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            if ip_obj.is_loopback:
                ip_type = "LOOPBACK"
            elif ip_obj.is_link_local:
                ip_type = "LINK_LOCAL"
            elif ip_obj.is_multicast:
                ip_type = "MULTICAST"
            elif ip_obj.is_reserved:
                ip_type = "RESERVED"
            elif ip_obj.is_private:
                ip_type = "PRIVATE_RFC1918"
            else:
                ip_type = "PUBLIC"
        except ValueError:
            return IPIntelBundle(
                ip_address=clean_ip,
                ip_type="INVALID",
                is_private=False,
                risk_level="UNKNOWN",
                risk_tags=["INVALID_IP_SYNTAX"],
            )

        # Run PTR and ASN queries concurrently with bounded 2.0s timeout
        ptr_task = self.ptr_resolver.resolve_ptr(clean_ip)
        asn_task = self.asn_resolver.query_ip_metadata(clean_ip)
        try:
            ptr_result, asn_metadata = await asyncio.wait_for(
                asyncio.gather(ptr_task, asn_task),
                timeout=2.0,
            )
        except Exception as e:
            logger.debug(f"IP analysis timeout/degrade for {clean_ip}: {e}")
            ptr_result, asn_metadata = None, {}

        # Classify infrastructure
        classifications, risk_level, risk_tags = self.classifier.classify_ip(
            ip_str=clean_ip,
            reverse_dns=ptr_result,
            asn_metadata=asn_metadata,
        )

        return IPIntelBundle(
            ip_address=clean_ip,
            ip_type=ip_type,
            is_private=is_priv,
            reverse_dns=ptr_result,
            asn=asn_metadata.get("asn"),
            asn_org=asn_metadata.get("asn_org"),
            isp=asn_metadata.get("isp"),
            network_owner=asn_metadata.get("network_owner"),
            hosting_provider=asn_metadata.get("hosting_provider"),
            country_code=asn_metadata.get("country_code"),
            country_name=asn_metadata.get("country_name"),
            region_name=asn_metadata.get("region_name"),
            city_name=asn_metadata.get("city_name"),
            latitude=asn_metadata.get("latitude"),
            longitude=asn_metadata.get("longitude"),
            classifications=classifications,
            risk_level=risk_level,
            risk_tags=risk_tags,
        )
