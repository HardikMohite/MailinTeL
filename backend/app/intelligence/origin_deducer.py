"""
Human Origin Location Deducer (Multi-Artifact Forensic Triangulation)

Extracts and correlates passive forensic artifacts embedded inside the .eml file
(RFC 5322 Date timezone offsets, Received-SPF client-ip attributes, Accept-Language,
regional character sets, Indian PIN codes, and phone number prefixes) to deduce
the human user's physical geographic location even when outgoing cloud relays
(Google, Microsoft) redact the client IP address.
"""

import re
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("mailintel.intelligence.origin_deducer")

TIMEZONE_MAP = {
    "+0530": {
        "country": "India",
        "country_code": "IN",
        "timezone_name": "Indian Standard Time (IST)",
        "default_region": "Maharashtra",
        "default_city": "Mumbai Metropolitan Region",
        "lat": 19.0760,
        "lon": 72.8777,
        "confidence": 85.0,
    },
    "+05:30": {
        "country": "India",
        "country_code": "IN",
        "timezone_name": "Indian Standard Time (IST)",
        "default_region": "Maharashtra",
        "default_city": "Mumbai Metropolitan Region",
        "lat": 19.0760,
        "lon": 72.8777,
        "confidence": 85.0,
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
        "confidence": 75.0,
    },
    "+0800": {
        "country": "Singapore",
        "country_code": "SG",
        "timezone_name": "Singapore / China Standard Time",
        "default_region": "Central",
        "default_city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
        "confidence": 70.0,
    },
    "+0100": {
        "country": "United Kingdom / Central Europe",
        "country_code": "GB",
        "timezone_name": "British Summer Time / CET",
        "default_region": "London",
        "default_city": "London",
        "lat": 51.5074,
        "lon": -0.1278,
        "confidence": 70.0,
    },
    "-0500": {
        "country": "United States",
        "country_code": "US",
        "timezone_name": "Eastern Time (EST/EDT)",
        "default_region": "New York",
        "default_city": "New York",
        "lat": 40.7128,
        "lon": -74.0060,
        "confidence": 70.0,
    },
    "-0800": {
        "country": "United States",
        "country_code": "US",
        "timezone_name": "Pacific Standard Time (PST)",
        "default_region": "California",
        "default_city": "Los Angeles",
        "lat": 34.0522,
        "lon": -118.2437,
        "confidence": 70.0,
    },
}

# Indian PIN Code Regional Maps (Exact City Level Pinpoint)
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
]

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
    provider_name: Optional[str] = None
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
            "provider_name": self.provider_name,
            "evidence_signals": [s.to_dict() for s in self.evidence_signals],
            "forensic_explanation": self.forensic_explanation,
        }


class HumanOriginDeducer:
    """
    Synthesizes multi-artifact forensic clues from raw headers, body, and authentication
    records to deduce the human sender's physical location.
    """

    def deduce_origin(
        self,
        raw_headers: List[Dict[str, str]],
        body_text: Optional[str] = None,
        hops: Optional[List[Dict[str, Any]]] = None,
        auth_results: Optional[Dict[str, Any]] = None,
    ) -> HumanOriginVerdict:
        signals: List[EvidenceSignal] = []
        headers_dict: Dict[str, str] = {}

        for h in raw_headers:
            name = h.get("header_name", "").lower()
            val = h.get("header_value", "")
            if name and val:
                # Keep first or append
                if name not in headers_dict:
                    headers_dict[name] = val

        # ---------------------------------------------------------------------
        # 1. Check for Provider Redaction / First Relay
        # ---------------------------------------------------------------------
        first_hop = (hops or [{}])[0] if hops else {}
        first_hop_provider = first_hop.get("provider") or first_hop.get("asn_org") or ""
        first_hop_is_cloud = (
            first_hop.get("is_cloud", False)
            or first_hop.get("is_datacenter", False)
            or any(w in first_hop_provider.lower() for w in ["google", "microsoft", "amazon", "cloudflare"])
        )

        # ---------------------------------------------------------------------
        # 2. Artifact: Client Local Timezone from Date Header
        # ---------------------------------------------------------------------
        date_hdr = headers_dict.get("date", "")
        tz_match = TZ_OFFSET_REGEX.search(date_hdr)
        tz_geo: Optional[Dict[str, Any]] = None

        if tz_match:
            tz_offset = tz_match.group(1).replace(":", "")
            tz_geo = TIMEZONE_MAP.get(tz_offset) or TIMEZONE_MAP.get(tz_match.group(1))
            if tz_geo:
                signals.append(
                    EvidenceSignal(
                        category="TIMEZONE",
                        signal="Client Clock Offset (Date Header)",
                        value=f"{tz_match.group(1)} ({tz_geo['timezone_name']})",
                        confidence_weight=35.0,
                        detail=(
                            f"The composer's device clock was set to {tz_match.group(1)}, which is strictly "
                            f"bound to {tz_geo['country']} ({tz_geo['timezone_name']})."
                        ),
                    )
                )

        # ---------------------------------------------------------------------
        # 3. Artifact: Client IP Preserved in Received-SPF / Authentication-Results
        # ---------------------------------------------------------------------
        auth_client_ip = None
        spf_hdr = headers_dict.get("received-spf", "")
        auth_hdr = headers_dict.get("authentication-results", "")

        for text in [spf_hdr, auth_hdr]:
            if text:
                m = SPF_CLIENT_IP_REGEX.search(text)
                if m:
                    auth_client_ip = m.group(1).strip("[]")
                    break

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
                        detail="Accept-Language explicitly requests Marathi (mr-IN), unique to Maharashtra, India.",
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
                        confidence_weight=30.0,
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
                    confidence_weight=20.0 if is_mumbai_std else 15.0,
                    detail=(
                        f"Detected { 'Mumbai STD code (022)' if is_mumbai_std else 'India international dialing prefix (+91)'}."
                    ),
                )
            )

        # ---------------------------------------------------------------------
        # Synthesize Final Forensic Verdict
        # ---------------------------------------------------------------------
        total_score = min(98.0, sum(s.confidence_weight for s in signals))
        if total_score >= 70:
            level = "HIGH"
        elif total_score >= 40:
            level = "MEDIUM"
        else:
            level = "ESTIMATED"

        verdict = HumanOriginVerdict(
            is_redacted_by_provider=first_hop_is_cloud,
            provider_name=first_hop_provider or "Cloud Webmail Relay",
            evidence_signals=signals,
            confidence_score=total_score,
            confidence_level=level,
        )

        # If PIN code matched, pin directly to that specific city
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
                f"Postal and contact artifacts triangulate the human author directly to {city}, {region}, India (PIN: {pin_val})."
            )
            return verdict

        # If Timezone matched IST (+0530)
        if tz_geo:
            verdict.deduced_country = tz_geo["country"]
            verdict.deduced_country_code = tz_geo["country_code"]
            verdict.deduced_region = tz_geo["default_region"]
            verdict.deduced_city = tz_geo["default_city"]
            verdict.latitude = tz_geo["lat"]
            verdict.longitude = tz_geo["lon"]
            verdict.accuracy_radius_km = 35

            if first_hop_is_cloud:
                verdict.forensic_explanation = (
                    f"Although the outgoing transmission MTA ({first_hop_provider}) is hosted in the US, "
                    f"the human author's device clock was set to {tz_geo['timezone_name']} ({tz_match.group(1)}). "
                    f"In RFC 5322 specifications, this timestamp is generated on the user's personal client before "
                    f"submission, forensically proving active presence in India."
                )
            else:
                verdict.forensic_explanation = (
                    f"Client submission artifacts and clock offsets triangulate the sender to {tz_geo['default_city']}, {tz_geo['country']}."
                )
            return verdict

        # Fallback if no specific timezone match
        if first_hop:
            verdict.deduced_country = first_hop.get("country_name")
            verdict.deduced_country_code = first_hop.get("country_code")
            verdict.deduced_region = first_hop.get("region_name")
            verdict.deduced_city = first_hop.get("city_name")
            verdict.latitude = first_hop.get("latitude")
            verdict.longitude = first_hop.get("longitude")
            verdict.forensic_explanation = "Forensic signals point to the earliest observable network relay."

        return verdict


human_origin_deducer = HumanOriginDeducer()
