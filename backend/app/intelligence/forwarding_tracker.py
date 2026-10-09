"""
Forwarding & Proxy Footprint Tracker
Detects mail forwarding, re-mailing chains, auto-forwarding loops,
and client submission IP addresses from SMTP headers.
"""

import re
import ipaddress
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("mailintel.intelligence.forwarding")

IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_REGEX = re.compile(r"(?:[0-9a-fA-F]{1,4}:){1,7}(?:[0-9a-fA-F]{1,4}|:)|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}|::1")

CLIENT_IP_HEADER_KEYS = [
    "x-originating-ip",
    "x-client-ip",
    "x-sender-ip",
    "x-real-ip",
    "x-forwarded-for",
    "x-source-ip",
    "client-ip",
]


def extract_valid_ip(text: Optional[str]) -> Optional[str]:
    """Extract and validate first IPv4 or IPv6 address from text."""
    if not text:
        return None
    # Strip brackets if present
    bracket_m = re.search(r"\[([0-9a-fA-F\.:]+)\]", text)
    if bracket_m:
        candidate = bracket_m.group(1).strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

    for match in IPV4_REGEX.finditer(text):
        cand = match.group(0)
        try:
            ip_obj = ipaddress.IPv4Address(cand)
            if not ip_obj.is_loopback and not ip_obj.is_link_local:
                return cand
        except ValueError:
            pass

    for match in IPV6_REGEX.finditer(text):
        cand = match.group(0)
        try:
            ip_obj = ipaddress.IPv6Address(cand)
            if not ip_obj.is_loopback and not ip_obj.is_link_local:
                return cand
        except ValueError:
            pass

    return None


@dataclass
class ForwardingHop:
    sequence: int
    header_name: str
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    relay_ip: Optional[str] = None
    timestamp: Optional[str] = None
    mechanism: str = "FORWARDING_HEADER"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "header_name": self.header_name,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "relay_ip": self.relay_ip,
            "timestamp": self.timestamp,
            "mechanism": self.mechanism,
        }


@dataclass
class ForwardingAnalysisResult:
    is_forwarded: bool = False
    forwarding_type: str = "DIRECT"  # DIRECT, RESENT_FORWARD, ARC_FORWARD, ALIAS_REDIRECT, HEADER_INJECTED
    forwarder_addresses: List[str] = field(default_factory=list)
    original_recipient: Optional[str] = None
    final_recipient: Optional[str] = None
    client_submission_ip: Optional[str] = None
    client_submission_header: Optional[str] = None
    is_client_ip_public: bool = False
    arc_chain_count: int = 0
    arc_original_spf_pass: bool = False
    forwarding_hops: List[ForwardingHop] = field(default_factory=list)
    footprint_summary: str = "Direct end-to-end SMTP dispatch."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_forwarded": self.is_forwarded,
            "forwarding_type": self.forwarding_type,
            "forwarder_addresses": self.forwarder_addresses,
            "original_recipient": self.original_recipient,
            "final_recipient": self.final_recipient,
            "client_submission_ip": self.client_submission_ip,
            "client_submission_header": self.client_submission_header,
            "is_client_ip_public": self.is_client_ip_public,
            "arc_chain_count": self.arc_chain_count,
            "arc_original_spf_pass": self.arc_original_spf_pass,
            "forwarding_hops": [h.to_dict() for h in self.forwarding_hops],
            "footprint_summary": self.footprint_summary,
        }


class ForwardingTracker:
    """
    Analyzes raw email headers to track email forwarding, detect geo-forwarding proxies,
    and uncover hidden client submission IPs.
    """

    def analyze_forwarding(
        self,
        raw_headers: List[Dict[str, str]],
        hops: Optional[List[Dict[str, Any]]] = None,
    ) -> ForwardingAnalysisResult:
        result = ForwardingAnalysisResult()
        headers_by_name: Dict[str, List[str]] = {}

        for h in raw_headers:
            name = (h.get("header_name") or "").strip().lower()
            val = (h.get("header_value") or "").strip()
            if name and val:
                headers_by_name.setdefault(name, []).append(val)

        # -------------------------------------------------------------
        # 1. Look for Client Originating / Submission IP Headers
        # -------------------------------------------------------------
        for key in CLIENT_IP_HEADER_KEYS:
            values = headers_by_name.get(key, [])
            for val in values:
                cand_ip = extract_valid_ip(val)
                if cand_ip:
                    try:
                        ip_obj = ipaddress.ip_address(cand_ip)
                        result.client_submission_ip = cand_ip
                        result.client_submission_header = key
                        result.is_client_ip_public = not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback)
                        break
                    except ValueError:
                        pass
            if result.client_submission_ip:
                break

        # Check Received-SPF for client-ip attribute if not found yet
        if not result.client_submission_ip:
            spf_headers = headers_by_name.get("received-spf", [])
            for spf_val in spf_headers:
                m = re.search(r"client-ip\s*=\s*([0-9a-fA-F\.:]+)", spf_val, re.IGNORECASE)
                if m:
                    cand_ip = extract_valid_ip(m.group(1))
                    if cand_ip:
                        try:
                            ip_obj = ipaddress.ip_address(cand_ip)
                            result.client_submission_ip = cand_ip
                            result.client_submission_header = "received-spf (client-ip)"
                            result.is_client_ip_public = not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback)
                            break
                        except ValueError:
                            pass

        # -------------------------------------------------------------
        # 2. Check for Explicit Resent-* Headers (RFC 5322 section 3.6.6)
        # -------------------------------------------------------------
        resent_from = headers_by_name.get("resent-from", [])
        resent_to = headers_by_name.get("resent-to", [])
        resent_date = headers_by_name.get("resent-date", [])

        if resent_from:
            result.is_forwarded = True
            result.forwarding_type = "RESENT_FORWARD"
            result.forwarder_addresses.extend(resent_from)
            if resent_to:
                result.final_recipient = resent_to[0]
            result.forwarding_hops.append(
                ForwardingHop(
                    sequence=1,
                    header_name="Resent-From",
                    from_address=", ".join(resent_from),
                    to_address=", ".join(resent_to) if resent_to else None,
                    timestamp=resent_date[0] if resent_date else None,
                    mechanism="RFC 5322 Resent Specification",
                )
            )

        # -------------------------------------------------------------
        # 3. Check for X-Forwarded-* & X-Auto-Response Headers
        # -------------------------------------------------------------
        x_forwarded_to = headers_by_name.get("x-forwarded-to", [])
        x_forwarded_for = headers_by_name.get("x-forwarded-for", [])
        x_forwarded_by = headers_by_name.get("x-forwarded-by", [])

        if x_forwarded_to or x_forwarded_for or x_forwarded_by:
            result.is_forwarded = True
            if result.forwarding_type == "DIRECT":
                result.forwarding_type = "HEADER_INJECTED"
            for fwd in x_forwarded_by or x_forwarded_to:
                if fwd not in result.forwarder_addresses:
                    result.forwarder_addresses.append(fwd)
            result.forwarding_hops.append(
                ForwardingHop(
                    sequence=len(result.forwarding_hops) + 1,
                    header_name="X-Forwarded-*",
                    from_address=", ".join(x_forwarded_by) if x_forwarded_by else None,
                    to_address=", ".join(x_forwarded_to) if x_forwarded_to else None,
                    relay_ip=extract_valid_ip(", ".join(x_forwarded_for)) if x_forwarded_for else None,
                    mechanism="MTA Forwarding Proxy Header",
                )
            )

        # -------------------------------------------------------------
        # 4. Check for ARC (Authenticated Received Chain) Headers (RFC 8617)
        # -------------------------------------------------------------
        arc_seals = headers_by_name.get("arc-seal", [])
        arc_results = headers_by_name.get("arc-authentication-results", [])

        if arc_seals:
            result.arc_chain_count = len(arc_seals)
            result.is_forwarded = True
            if result.forwarding_type == "DIRECT":
                result.forwarding_type = "ARC_PRESERVED_FORWARD"

            # Check if ARC verified original passing authentication
            for arc_auth in arc_results:
                if "spf=pass" in arc_auth.lower():
                    result.arc_original_spf_pass = True
                    # Extract original client IP recorded in ARC
                    arc_ip_m = re.search(r"ip\s*=\s*([0-9a-fA-F\.:]+)", arc_auth, re.IGNORECASE)
                    if arc_ip_m and not result.client_submission_ip:
                        cand_ip = extract_valid_ip(arc_ip_m.group(1))
                        if cand_ip:
                            result.client_submission_ip = cand_ip
                            result.client_submission_header = "arc-authentication-results"
                            result.is_client_ip_public = True

            result.forwarding_hops.append(
                ForwardingHop(
                    sequence=len(result.forwarding_hops) + 1,
                    header_name="ARC-Chain",
                    from_address=f"{len(arc_seals)} Intermediate Sealing MTA(s)",
                    mechanism="RFC 8617 Authenticated Received Chain (Forwarding Preserved)",
                )
            )

        # -------------------------------------------------------------
        # 5. Check for Multiple Delivered-To Headers (Alias Stacking)
        # -------------------------------------------------------------
        delivered_to = headers_by_name.get("delivered-to", [])
        if len(delivered_to) > 1:
            result.is_forwarded = True
            if result.forwarding_type == "DIRECT":
                result.forwarding_type = "ALIAS_REDIRECT"
            for d in delivered_to[1:]:
                if d not in result.forwarder_addresses:
                    result.forwarder_addresses.append(d)
            result.original_recipient = delivered_to[-1]
            result.final_recipient = delivered_to[0]

        # -------------------------------------------------------------
        # 6. Check for X-Original-To vs Envelope-To Discrepancy
        # -------------------------------------------------------------
        x_orig_to = headers_by_name.get("x-original-to", [])
        envelope_to = headers_by_name.get("envelope-to", [])
        if x_orig_to and envelope_to and x_orig_to[0].strip().lower() != envelope_to[0].strip().lower():
            result.is_forwarded = True
            if result.forwarding_type == "DIRECT":
                result.forwarding_type = "ALIAS_REDIRECT"
            result.original_recipient = x_orig_to[0]
            result.final_recipient = envelope_to[0]

        # -------------------------------------------------------------
        # 7. Synthesize Footprint Summary
        # -------------------------------------------------------------
        if result.is_forwarded:
            fwd_count = len(result.forwarder_addresses)
            fwd_list = ", ".join(result.forwarder_addresses[:2])
            client_note = f" (Client Submission IP: {result.client_submission_ip})" if result.client_submission_ip else ""
            result.footprint_summary = (
                f"Mail forwarding detected via {result.forwarding_type}. "
                f"Relayed across {fwd_count} forwarder(s) [{fwd_list}]{client_note}."
            )
        else:
            client_note = f" (Client IP: {result.client_submission_ip})" if result.client_submission_ip else ""
            result.footprint_summary = f"Direct end-to-end transmission with no forwarding artifacts identified{client_note}."

        return result


default_forwarding_tracker = ForwardingTracker()
