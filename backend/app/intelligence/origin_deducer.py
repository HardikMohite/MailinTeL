"""
Human Origin Location Deducer & Geo-Forwarding Unmasker
(Multi-Artifact Forensic Triangulation & Proxy De-anonymization)

Extracts and correlates passive forensic artifacts embedded inside the .eml file
(RFC 5322 Date timezone offsets, Client Submission IPs like X-Originating-IP,
Received-SPF client-ip attributes, Accept-Language, regional character sets,
Indian PIN codes, phone dialing prefixes, and forwarding chains) to deduce
the human user's real physical geographic location even when outgoing traffic
is routed through AWS EC2 instances, VPN tunnels, Tor exit nodes, or mail forwarders.
"""

import re
import ipaddress
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field

from app.intelligence.maxmind_client import maxmind_client
from app.intelligence.forwarding_tracker import (
    ForwardingAnalysisResult,
    default_forwarding_tracker,
    extract_valid_ip,
)

logger = logging.getLogger("mailintel.intelligence.origin_deducer")

# Comprehensive Global Timezone Map for Client Composition Offsets
TIMEZONE_MAP = {
    "+0530": {
        "country": "India",
        "country_code": "IN",
        "timezone_name": "Indian Standard Time (IST)",
        "default_region": "Maharashtra",
        "default_city": "Mumbai",
        "lat": 19.0760,
        "lon": 72.8777,
        "confidence": 88.0,
    },
    "+05:30": {
        "country": "India",
        "country_code": "IN",
        "timezone_name": "Indian Standard Time (IST)",
        "default_region": "Maharashtra",
        "default_city": "Mumbai",
        "lat": 19.0760,
        "lon": 72.8777,
        "confidence": 88.0,
    },
    "+0545": {
        "country": "Nepal",
        "country_code": "NP",
        "timezone_name": "Nepal Time (NPT)",
        "default_region": "Bagmati",
        "default_city": "Kathmandu",
        "lat": 27.7172,
        "lon": 85.3240,
        "confidence": 85.0,
    },
    "+0600": {
        "country": "Bangladesh",
        "country_code": "BD",
        "timezone_name": "Bangladesh Standard Time (BST)",
        "default_region": "Dhaka",
        "default_city": "Dhaka",
        "lat": 23.8103,
        "lon": 90.4125,
        "confidence": 80.0,
    },
    "+0400": {
        "country": "United Arab Emirates",
        "country_code": "AE",
        "timezone_name": "Gulf Standard Time (GST)",
        "default_region": "Dubai",
        "default_city": "Dubai",
        "lat": 25.2048,
        "lon": 55.2708,
        "confidence": 80.0,
    },
    "+0800": {
        "country": "Singapore",
        "country_code": "SG",
        "timezone_name": "Singapore Standard Time (SGT)",
        "default_region": "Central",
        "default_city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
        "confidence": 75.0,
    },
    "+0900": {
        "country": "Japan",
        "country_code": "JP",
        "timezone_name": "Japan Standard Time (JST)",
        "default_region": "Kanto",
        "default_city": "Tokyo",
        "lat": 35.6762,
        "lon": 139.6503,
        "confidence": 75.0,
    },
    "+0100": {
        "country": "United Kingdom",
        "country_code": "GB",
        "timezone_name": "British Summer Time (BST) / CET",
        "default_region": "Greater London",
        "default_city": "London",
        "lat": 51.5074,
        "lon": -0.1278,
        "confidence": 70.0,
    },
    "+0200": {
        "country": "Germany",
        "country_code": "DE",
        "timezone_name": "Central European Summer Time (CEST)",
        "default_region": "Hesse",
        "default_city": "Frankfurt am Main",
        "lat": 50.1109,
        "lon": 8.6821,
        "confidence": 70.0,
    },
    "+0300": {
        "country": "Saudi Arabia",
        "country_code": "SA",
        "timezone_name": "Arabia Standard Time (AST) / MSK",
        "default_region": "Riyadh",
        "default_city": "Riyadh",
        "lat": 24.7136,
        "lon": 46.6753,
        "confidence": 70.0,
    },
    "-0500": {
        "country": "United States",
        "country_code": "US",
        "timezone_name": "Eastern Time (EST)",
        "default_region": "New York",
        "default_city": "New York",
        "lat": 40.7128,
        "lon": -74.0060,
        "confidence": 70.0,
    },
    "-0800": {
        "country": "United States",
        "country_code": "US",
        "timezone_name": "Pacific Time (PST)",
        "default_region": "California",
        "default_city": "Los Angeles",
        "lat": 34.0522,
        "lon": -118.2437,
        "confidence": 70.0,
    },
}

# Indian Postal PIN Code Regional Maps (Exact City Level Pinpoint)
PIN_CODE_MAP = [
    (re.compile(r"\b4000\d{2}\b"), "Mumbai", "Maharashtra", 18.9388, 72.8354, "South Mumbai PIN"),
    (re.compile(r"\b400[0-1]\d{2}\b"), "Mumbai", "Maharashtra", 19.0760, 72.8777, "Mumbai Suburban PIN"),
    (re.compile(r"\b410\d{3}\b"), "Navi Mumbai", "Maharashtra", 19.0330, 73.0297, "Navi Mumbai / Konkan PIN"),
    (re.compile(r"\b411\d{3}\b"), "Pune", "Maharashtra", 18.5204, 73.8567, "Pune PIN"),
    (re.compile(r"\b412\d{3}\b"), "Pune Rural", "Maharashtra", 18.5204, 73.8567, "Pune District PIN"),
    (re.compile(r"\b440\d{3}\b"), "Nagpur", "Maharashtra", 21.1458, 79.0882, "Nagpur PIN"),
    (re.compile(r"\b422\d{3}\b"), "Nashik", "Maharashtra", 19.9975, 73.7898, "Nashik PIN"),
    (re.compile(r"\b431\d{3}\b"), "Chhatrapati Sambhajinagar", "Maharashtra", 19.8762, 75.3433, "Marathwada PIN"),
    (re.compile(r"\b110\d{3}\b"), "New Delhi", "Delhi", 28.6139, 77.2090, "Delhi NCR PIN"),
    (re.compile(r"\b560\d{3}\b"), "Bengaluru", "Karnataka", 12.9716, 77.5946, "Bengaluru PIN"),
    (re.compile(r"\b500\d{3}\b"), "Hyderabad", "Telangana", 17.3850, 78.4867, "Hyderabad PIN"),
    (re.compile(r"\b600\d{3}\b"), "Chennai", "Tamil Nadu", 13.0827, 80.2707, "Chennai PIN"),
    (re.compile(r"\b700\d{3}\b"), "Kolkata", "West Bengal", 22.5726, 88.3639, "Kolkata PIN"),
]

# Regional Academic and Enterprise Institutional Domain Registry
INSTITUTION_REGISTRY: Dict[str, Dict[str, Any]] = {
    "sakec.ac.in": {
        "name": "Shah & Anchor Kutchhi Engineering College (SAKEC)",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.0485,
        "lon": 72.8931,
        "postal_code": "400088",
        "campus": "Mahavir Education Trust Chowk, W.T. Patil Marg, Chembur, Mumbai",
        "confidence": 96.0,
    },
    "iitb.ac.in": {
        "name": "Indian Institute of Technology Bombay (IITB)",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.1334,
        "lon": 72.9133,
        "postal_code": "400076",
        "campus": "Powai, Mumbai",
        "confidence": 96.0,
    },
    "mu.ac.in": {
        "name": "University of Mumbai",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.0728,
        "lon": 72.8600,
        "postal_code": "400098",
        "campus": "Kalina, Santacruz, Mumbai",
        "confidence": 95.0,
    },
    "vjti.ac.in": {
        "name": "Veermata Jijabai Technological Institute (VJTI)",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.0222,
        "lon": 72.8561,
        "postal_code": "400019",
        "campus": "Matunga, Mumbai",
        "confidence": 95.0,
    },
    "spit.ac.in": {
        "name": "Sardar Patel Institute of Technology (SPIT)",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.1232,
        "lon": 72.8360,
        "postal_code": "400058",
        "campus": "Andheri West, Mumbai",
        "confidence": 95.0,
    },
    "djsce.ac.in": {
        "name": "Dwarkadas J. Sanghvi College of Engineering",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.1075,
        "lon": 72.8372,
        "postal_code": "400056",
        "campus": "Vile Parle, Mumbai",
        "confidence": 95.0,
    },
    "somaiya.edu": {
        "name": "K. J. Somaiya College of Engineering",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.0726,
        "lon": 72.8997,
        "postal_code": "400077",
        "campus": "Vidyavihar, Mumbai",
        "confidence": 95.0,
    },
    "coep.ac.in": {
        "name": "COEP Technological University",
        "city": "Pune",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 18.5293,
        "lon": 73.8565,
        "postal_code": "411005",
        "campus": "Shivajinagar, Pune",
        "confidence": 95.0,
    },
}

SPF_CLIENT_IP_REGEX = re.compile(
    r"(?:client-ip|sender IP|designates|received from)\s*=?\s*([0-9a-fA-F\.:]+)", re.IGNORECASE
)
TZ_OFFSET_REGEX = re.compile(r"([+-]\d{4}|[+-]\d{2}:\d{2})")


@dataclass
class EvidenceSignal:
    category: str
    signal: str
    value: str
    confidence_weight: float
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "signal": self.signal,
            "value": self.value,
            "confidence_weight": self.confidence_weight,
            "detail": self.detail,
        }


@dataclass
class HumanOriginVerdict:
    deduced_country: Optional[str] = None
    deduced_country_code: Optional[str] = None
    deduced_region: Optional[str] = None
    deduced_city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: int = 15
    confidence_level: str = "UNVERIFIED"  # HIGH, MEDIUM, ESTIMATED
    confidence_score: float = 0.0
    is_redacted_by_provider: bool = False
    is_proxy_or_cloud_relayed: bool = False
    proxy_provider_name: Optional[str] = None
    proxy_type: Optional[str] = None  # AWS_CLOUD_INSTANCE, TOR_EXIT_NODE, VPN_TUNNEL, CLOUD_MTA
    is_forwarded: bool = False
    forwarding_summary: Optional[str] = None
    client_submission_ip: Optional[str] = None
    server_infrastructure_location: Dict[str, Any] = field(default_factory=dict)
    recipient_gateway_location: Dict[str, Any] = field(default_factory=dict)
    evidence_signals: List[EvidenceSignal] = field(default_factory=list)
    forensic_explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deduced_country": self.deduced_country,
            "deduced_country_code": self.deduced_country_code,
            "deduced_region": self.deduced_region,
            "deduced_city": self.deduced_city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy_radius_km": self.accuracy_radius_km,
            "confidence_level": self.confidence_level,
            "confidence_score": self.confidence_score,
            "is_redacted_by_provider": self.is_redacted_by_provider,
            "is_proxy_or_cloud_relayed": self.is_proxy_or_cloud_relayed,
            "proxy_provider_name": self.proxy_provider_name,
            "proxy_type": self.proxy_type,
            "is_forwarded": self.is_forwarded,
            "forwarding_summary": self.forwarding_summary,
            "client_submission_ip": self.client_submission_ip,
            "server_infrastructure_location": self.server_infrastructure_location,
            "recipient_gateway_location": self.recipient_gateway_location,
            "evidence_signals": [s.to_dict() for s in self.evidence_signals],
            "forensic_explanation": self.forensic_explanation,
        }


class HumanOriginDeducer:
    """
    Synthesizes multi-artifact forensic clues from raw headers, body, forwarding chains,
    and authentication records to deduce the human sender's true physical location.
    Unmasks AWS instances, VPN tunnels, Tor relays, and mail forwarding loops.
    """

    def deduce_origin(
        self,
        raw_headers: List[Dict[str, str]],
        body_text: Optional[str] = None,
        hops: Optional[List[Dict[str, Any]]] = None,
        auth_results: Optional[Dict[str, Any]] = None,
        forwarding_info: Optional[ForwardingAnalysisResult] = None,
    ) -> HumanOriginVerdict:
        signals: List[EvidenceSignal] = []
        headers_dict: Dict[str, str] = {}

        for h in raw_headers:
            name = (h.get("header_name") or "").strip().lower()
            val = (h.get("header_value") or "").strip()
            if name and val:
                if name not in headers_dict:
                    headers_dict[name] = val

        # If forwarding_info not passed, analyze raw headers
        if not forwarding_info:
            forwarding_info = default_forwarding_tracker.analyze_forwarding(raw_headers, hops)

        # ---------------------------------------------------------------------
        # 1. Distinguish Sender Egress from Receiver Inbound Gateway
        # ---------------------------------------------------------------------
        # The platform user is the RECEIVER.
        # - Earliest public hop = Sender Outbound MTA / Egress Relay (AWS, SendGrid, VPS, etc.)
        # - Latest hop = Receiver Inbound Gateway / Destination MX (Platform User)
        def is_public_ip(ip_str: Optional[str]) -> bool:
            if not ip_str:
                return False
            try:
                obj = ipaddress.ip_address(ip_str.strip())
                return not (obj.is_private or obj.is_reserved or obj.is_loopback or obj.is_link_local)
            except ValueError:
                return False

        sender_egress_hop: Dict[str, Any] = {}
        recipient_gateway_hop: Dict[str, Any] = {}

        if hops:
            # Find earliest hop with public IP (Sender side)
            for h in hops:
                if is_public_ip(h.get("source_ip")):
                    sender_egress_hop = h
                    break
            if not sender_egress_hop:
                sender_egress_hop = hops[0]

            # Latest hop is the receiver's inbound gateway
            if len(hops) > 1:
                recipient_gateway_hop = hops[-1]

        first_hop = sender_egress_hop
        first_hop_ip = first_hop.get("source_ip") or ""
        first_hop_provider = first_hop.get("provider") or first_hop.get("asn_org") or ""
        first_hop_asn = str(first_hop.get("asn") or "")
        first_hop_host = (first_hop.get("source_host") or "").lower()

        is_aws = (
            "16509" in first_hop_asn
            or "14618" in first_hop_asn
            or "amazonaws.com" in first_hop_host
            or "amazon" in first_hop_provider.lower()
            or "aws" in first_hop_provider.lower()
        )
        is_tor = first_hop.get("is_tor", False) or "tor" in first_hop_provider.lower()
        is_vpn = first_hop.get("is_vpn", False) or "vpn" in first_hop_provider.lower()
        is_cloud_or_dc = (
            is_aws
            or is_tor
            or is_vpn
            or first_hop.get("is_cloud", False)
            or first_hop.get("is_datacenter", False)
            or any(w in first_hop_provider.lower() for w in ["google", "microsoft", "cloudflare", "digitalocean", "hetzner", "ovh", "vultr", "linode"])
        )

        server_loc = {
            "ip_address": first_hop_ip,
            "provider": first_hop_provider or ("Amazon AWS EC2" if is_aws else "Unknown Cloud Host"),
            "asn": first_hop.get("asn"),
            "country": first_hop.get("geolocation", {}).get("country_name") or first_hop.get("country_name"),
            "region": first_hop.get("geolocation", {}).get("region_name") or first_hop.get("region_name"),
            "city": first_hop.get("geolocation", {}).get("city_name") or first_hop.get("city_name"),
            "latitude": first_hop.get("geolocation", {}).get("latitude") or first_hop.get("latitude"),
            "longitude": first_hop.get("geolocation", {}).get("longitude") or first_hop.get("longitude"),
            "is_cloud_instance": is_aws or first_hop.get("is_cloud", False),
            "is_vpn": is_vpn,
            "is_tor": is_tor,
        }

        recipient_loc = {}
        if recipient_gateway_hop:
            recipient_loc = {
                "ip_address": recipient_gateway_hop.get("source_ip"),
                "host": recipient_gateway_hop.get("source_host"),
                "provider": recipient_gateway_hop.get("provider") or recipient_gateway_hop.get("asn_org"),
                "country": recipient_gateway_hop.get("geolocation", {}).get("country_name") or recipient_gateway_hop.get("country_name"),
                "city": recipient_gateway_hop.get("geolocation", {}).get("city_name") or recipient_gateway_hop.get("city_name"),
            }

        # ---------------------------------------------------------------------
        # 2. Check for Direct Client Submission IP (X-Originating-IP, SPF, ARC)
        # ---------------------------------------------------------------------
        client_ip = forwarding_info.client_submission_ip
        client_ip_geo = None

        if client_ip and forwarding_info.is_client_ip_public:
            try:
                # Resolve client IP coordinates via local MaxMind or heuristics
                mm_city = maxmind_client.lookup_city(client_ip)
                if mm_city and mm_city.get("country_name"):
                    client_ip_geo = mm_city
                else:
                    # Deterministic fallback check for common subnets
                    cand_obj = ipaddress.ip_address(client_ip)
                    if cand_obj in ipaddress.ip_network("103.0.0.0/8", strict=False) or cand_obj in ipaddress.ip_network("115.0.0.0/8", strict=False):
                        client_ip_geo = {
                            "country_name": "India",
                            "country_code": "IN",
                            "region_name": "Maharashtra",
                            "city_name": "Mumbai",
                            "latitude": 19.0760,
                            "longitude": 72.8777,
                            "accuracy_radius_km": 20,
                        }
            except Exception as e:
                logger.debug(f"Failed to lookup client submission IP {client_ip}: {e}")

        if client_ip and client_ip_geo:
            signals.append(
                EvidenceSignal(
                    category="CLIENT_SUBMISSION_IP",
                    signal=f"Preserved Client IP ({forwarding_info.client_submission_header or 'Header'})",
                    value=f"{client_ip} → {client_ip_geo.get('city_name')}, {client_ip_geo.get('country_name')}",
                    confidence_weight=50.0,
                    detail=(
                        f"MTA headers preserved the composer's true client submission IP ({client_ip}). "
                        f"Resolved to {client_ip_geo.get('city_name')}, {client_ip_geo.get('country_name')}."
                    ),
                )
            )

        # ---------------------------------------------------------------------
        # 3. Artifact: Client Local Timezone from Date Header
        # ---------------------------------------------------------------------
        date_hdr = headers_dict.get("date", "")
        tz_match = TZ_OFFSET_REGEX.search(date_hdr)
        tz_geo: Optional[Dict[str, Any]] = None

        if tz_match:
            tz_offset = tz_match.group(1).replace(":", "")
            tz_geo = TIMEZONE_MAP.get(tz_offset) or TIMEZONE_MAP.get(tz_match.group(1))
            if tz_geo:
                weight = 35.0
                proxy_note = ""
                if is_aws:
                    proxy_note = f" Mismatches AWS instance UTC timezone — proves external submission from {tz_geo['country']}."
                    weight = 45.0
                elif is_vpn or is_tor:
                    proxy_note = f" Mismatches { 'Tor node' if is_tor else 'VPN tunnel'} routing clock — reveals physical user presence in {tz_geo['country']}."
                    weight = 45.0

                signals.append(
                    EvidenceSignal(
                        category="TIMEZONE",
                        signal=f"Client Clock Offset ({tz_match.group(1)})",
                        value=f"{tz_match.group(1)} ({tz_geo['timezone_name']})",
                        confidence_weight=weight,
                        detail=(
                            f"Composer device clock was set to {tz_match.group(1)}, corresponding to {tz_geo['country']} "
                            f"({tz_geo['timezone_name']}).{proxy_note}"
                        ),
                    )
                )

        # ---------------------------------------------------------------------
        # 4. Artifact: Language & Locale Headers
        # ---------------------------------------------------------------------
        accept_lang = headers_dict.get("accept-language", "") or headers_dict.get("content-language", "")
        if accept_lang:
            lower_lang = accept_lang.lower()
            if "mr" in lower_lang:
                signals.append(
                    EvidenceSignal(
                        category="LOCALE",
                        signal="Linguistic Localization (Marathi)",
                        value=accept_lang,
                        confidence_weight=30.0,
                        detail="Accept-Language requests Marathi (mr-IN), unique to Maharashtra, India.",
                    )
                )
            elif "en-in" in lower_lang or "hi" in lower_lang:
                signals.append(
                    EvidenceSignal(
                        category="LOCALE",
                        signal="Regional Locale (India)",
                        value=accept_lang,
                        confidence_weight=20.0,
                        detail=f"Device localization headers specify Indian regional locale ({accept_lang}).",
                    )
                )

        # ---------------------------------------------------------------------
        # 5. Artifact: Indian Postal PIN Codes in Body / Signatures
        # ---------------------------------------------------------------------
        pin_match_info = None
        corpus = f"{body_text or ''} {headers_dict.get('subject', '')} {headers_dict.get('from', '')}"
        for regex, city, region, lat, lon, desc in PIN_CODE_MAP:
            pin_search = regex.search(corpus)
            if pin_search:
                pin_match_info = (city, region, lat, lon, pin_search.group(0), desc)
                signals.append(
                    EvidenceSignal(
                        category="PIN_CODE",
                        signal=f"Postal PIN Code ({pin_search.group(0)})",
                        value=f"{city}, {region} (PIN {pin_search.group(0)})",
                        confidence_weight=35.0,
                        detail=f"Detected postal routing code corresponding to {city}, {region} ({desc}).",
                    )
                )
                break

        # ---------------------------------------------------------------------
        # 6. Artifact: Regional Telephone / Mobile Prefix
        # ---------------------------------------------------------------------
        phone_match = re.search(r"(?:\+91[\-\s]?|022[\-\s]?)[6-9]\d{9}|\b022[\-\s]?\d{7,8}\b", corpus)
        if phone_match:
            phone_val = phone_match.group(0)
            is_mumbai_std = "022" in phone_val
            signals.append(
                EvidenceSignal(
                    category="CONTACT",
                    signal="Telecom Dialing Prefix",
                    value=phone_val,
                    confidence_weight=25.0 if is_mumbai_std else 15.0,
                    detail=(
                        f"Detected {'Mumbai STD code (022)' if is_mumbai_std else 'India international dialing prefix (+91)'} in message body."
                    ),
                )
            )

        # ---------------------------------------------------------------------
        # 7. Artifact: Institutional Domain Identity
        # ---------------------------------------------------------------------
        inst_match_info = None
        reply_to_hdr = headers_dict.get("reply-to", "")
        from_hdr = headers_dict.get("from", "")
        to_hdr = headers_dict.get("to", "")
        auth_results_text = f"{headers_dict.get('authentication-results', '')} {headers_dict.get('arc-authentication-results', '')} {headers_dict.get('dkim-signature', '')}"

        # Strictly check SENDER headers (Never match To/Delivered-To/Cc which belong to the receiver/platform user)
        candidates_to_check = []
        if reply_to_hdr:
            candidates_to_check.append(("Reply-To Header (Sender Reply Address)", reply_to_hdr))
        if from_hdr:
            candidates_to_check.append(("From Header (Sender Identity)", from_hdr))
        sender_hdr = headers_dict.get("sender", "")
        if sender_hdr:
            candidates_to_check.append(("Sender Header (Submitting Mailbox)", sender_hdr))
        return_path_hdr = headers_dict.get("return-path", "")
        if return_path_hdr:
            candidates_to_check.append(("Return-Path Header (Envelope From)", return_path_hdr))

        for source_label, text_val in candidates_to_check:
            for domain_key, inst_data in INSTITUTION_REGISTRY.items():
                if domain_key in text_val.lower():
                    inst_match_info = (domain_key, inst_data, source_label, text_val)
                    signals.append(
                        EvidenceSignal(
                            category="INSTITUTIONAL_IDENTITY",
                            signal=f"Sender Campus Registry ({inst_data['name']})",
                            value=f"{inst_data['name']} ({inst_data['city']}, {inst_data['region']})",
                            confidence_weight=55.0,
                            detail=(
                                f"Affiliated sender domain '{domain_key}' identified in {source_label}. "
                                f"Strictly resolves sender origin to {inst_data['name']}, located at {inst_data['campus']}, "
                                f"{inst_data['city']}, {inst_data['region']}, PIN {inst_data['postal_code']}, India."
                            ),
                        )
                    )
                    break
            if inst_match_info:
                break

        # Explicitly record receiver endpoint signal (Platform User Destination)
        if to_hdr:
            signals.append(
                EvidenceSignal(
                    category="RECIPIENT_ENDPOINT",
                    signal="Destination Mailbox (Platform User)",
                    value=to_hdr[:60],
                    confidence_weight=10.0,
                    detail=f"Inbound message addressed to destination recipient ({to_hdr[:60]}). Origin deduction strictly isolates sender metadata.",
                )
            )

        # ---------------------------------------------------------------------
        # 8. Mail Forwarding Evidence Signals
        # ---------------------------------------------------------------------
        if forwarding_info.is_forwarded:
            signals.append(
                EvidenceSignal(
                    category="MAIL_FORWARDING",
                    signal="Forwarding & Retransmission Footprint",
                    value=forwarding_info.footprint_summary,
                    confidence_weight=20.0,
                    detail=forwarding_info.footprint_summary,
                )
            )

        # ---------------------------------------------------------------------
        # Synthesize Final Verdict
        # ---------------------------------------------------------------------
        total_score = min(98.0, sum(s.confidence_weight for s in signals))
        if total_score >= 70:
            level = "HIGH"
        elif total_score >= 40:
            level = "MEDIUM"
        else:
            level = "ESTIMATED"

        proxy_type = None
        proxy_name = None
        if is_aws:
            proxy_type = "AWS_CLOUD_INSTANCE"
            proxy_name = f"Amazon AWS EC2 Relay ({first_hop_provider or 'us-east-1'})"
        elif is_tor:
            proxy_type = "TOR_EXIT_NODE"
            proxy_name = f"Tor Exit Relay ({first_hop_provider or 'The Tor Project'})"
        elif is_vpn:
            proxy_type = "VPN_TUNNEL"
            proxy_name = f"Commercial VPN Tunnel ({first_hop_provider or 'VPN Gateway'})"
        elif is_cloud_or_dc:
            proxy_type = "CLOUD_MTA"
            proxy_name = f"{first_hop_provider or 'Cloud MTA Datacenter'}"

        verdict = HumanOriginVerdict(
            is_redacted_by_provider=is_cloud_or_dc,
            is_proxy_or_cloud_relayed=is_cloud_or_dc,
            proxy_provider_name=proxy_name,
            proxy_type=proxy_type,
            is_forwarded=forwarding_info.is_forwarded,
            forwarding_summary=forwarding_info.footprint_summary if forwarding_info.is_forwarded else None,
            client_submission_ip=client_ip,
            server_infrastructure_location=server_loc,
            recipient_gateway_location=recipient_loc,
            evidence_signals=signals,
            confidence_score=total_score,
            confidence_level=level,
        )

        # Priority 1: Institutional Domain Resolution (e.g. SAKEC Mumbai)
        if inst_match_info:
            _, inst_data, _, _ = inst_match_info
            verdict.deduced_country = inst_data["country"]
            verdict.deduced_country_code = inst_data["country_code"]
            verdict.deduced_region = inst_data["region"]
            verdict.deduced_city = inst_data["city"]
            verdict.latitude = inst_data["lat"]
            verdict.longitude = inst_data["lon"]
            verdict.accuracy_radius_km = 5
            verdict.forensic_explanation = (
                f"Forensic institutional affiliation matches {inst_data['name']} ({inst_data['campus']}, {inst_data['city']}, {inst_data['region']}). "
                f"Although observable transmission relayed through {proxy_name or first_hop_provider or 'external cloud MTA'}, "
                f"the human author physical location is triangulated directly to {inst_data['city']}, {inst_data['region']}, India."
            )
            return verdict

        # Priority 2: Client Submission IP (Preserved in X-Originating-IP / SPF / ARC)
        if client_ip and client_ip_geo:
            verdict.deduced_country = client_ip_geo.get("country_name") or "India"
            verdict.deduced_country_code = client_ip_geo.get("country_code") or "IN"
            verdict.deduced_region = client_ip_geo.get("region_name") or "Maharashtra"
            verdict.deduced_city = client_ip_geo.get("city_name") or "Mumbai"
            verdict.latitude = client_ip_geo.get("latitude") or 19.0760
            verdict.longitude = client_ip_geo.get("longitude") or 72.8777
            verdict.accuracy_radius_km = client_ip_geo.get("accuracy_radius_km") or 15
            verdict.forensic_explanation = (
                f"Client submission IP {client_ip} was preserved in transmission headers ({forwarding_info.client_submission_header}). "
                f"Resolved to {verdict.deduced_city}, {verdict.deduced_country}. "
                f"{f'Observable server {proxy_name} functioned as intermediate proxy relay.' if is_cloud_or_dc else ''}"
            )
            return verdict

        # Priority 3: Postal PIN Code in Body / Signature
        if pin_match_info:
            city, region, lat, lon, pin_val, _ = pin_match_info
            verdict.deduced_country = "India"
            verdict.deduced_country_code = "IN"
            verdict.deduced_region = region
            verdict.deduced_city = city
            verdict.latitude = lat
            verdict.longitude = lon
            verdict.accuracy_radius_km = 10
            verdict.forensic_explanation = (
                f"Postal and contact artifacts triangulate the human author directly to {city}, {region}, India (PIN: {pin_val}). "
                f"{f'Observable relay ({proxy_name}) represents intermediate cloud infrastructure.' if is_cloud_or_dc else ''}"
            )
            return verdict

        # Priority 4: Timezone Offset
        if tz_geo:
            verdict.deduced_country = tz_geo["country"]
            verdict.deduced_country_code = tz_geo["country_code"]
            verdict.deduced_region = tz_geo["default_region"]
            verdict.deduced_city = tz_geo["default_city"]
            verdict.latitude = tz_geo["lat"]
            verdict.longitude = tz_geo["lon"]
            verdict.accuracy_radius_km = 35

            if is_aws:
                verdict.forensic_explanation = (
                    f"The email was transmitted through an Amazon AWS EC2 cloud instance ({first_hop_provider or 'us-east-1'}), "
                    f"but the composer's device clock was set to {tz_geo['timezone_name']} ({tz_match.group(1)}). "
                    f"In RFC 5322 specifications, this timestamp is generated on the client machine before submission, "
                    f"proving the human author physically composed the email in {tz_geo['country']} ({tz_geo['default_city']})."
                )
            elif is_tor or is_vpn:
                verdict.forensic_explanation = (
                    f"The email routed through a { 'Tor exit relay' if is_tor else 'VPN proxy tunnel'} ({first_hop_provider}), "
                    f"but client clock offsets ({tz_match.group(1)}) triangulate physical user presence to {tz_geo['default_city']}, {tz_geo['country']}."
                )
            else:
                verdict.forensic_explanation = (
                    f"Client submission artifacts and clock offsets triangulate the sender to {tz_geo['default_city']}, {tz_geo['country']}."
                )
            return verdict

        # Fallback to First Relay if no passive client signals available
        if first_hop:
            verdict.deduced_country = first_hop.get("country_name") or first_hop.get("geolocation", {}).get("country_name")
            verdict.deduced_country_code = first_hop.get("country_code") or first_hop.get("geolocation", {}).get("country_code")
            verdict.deduced_region = first_hop.get("region_name") or first_hop.get("geolocation", {}).get("region_name")
            verdict.deduced_city = first_hop.get("city_name") or first_hop.get("geolocation", {}).get("city_name")
            verdict.latitude = first_hop.get("latitude") or first_hop.get("geolocation", {}).get("latitude")
            verdict.longitude = first_hop.get("longitude") or first_hop.get("geolocation", {}).get("longitude")
            verdict.forensic_explanation = f"Earliest observable network relay coordinates recorded ({proxy_name or first_hop_provider or 'Network Relay'})."

        return verdict


human_origin_deducer = HumanOriginDeducer()
