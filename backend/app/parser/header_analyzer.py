import re
import email
import email.policy
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
import ipaddress
import logging

from app.parser.email_parser import (
    sanitize_string,
    safe_decode_header_str,
    parse_rfc2822_date,
    extract_address_and_name,
)

logger = logging.getLogger(__name__)

# Regular expressions for IP addresses
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_REGEX = re.compile(r"(?:[0-9a-fA-F]{1,4}:){1,7}(?:[0-9a-fA-F]{1,4}|:)|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}|::1")

# Regular expressions for Received header components
FROM_HOST_REGEX = re.compile(r"\bfrom\s+([^\s\(\)\[\];]+)", re.IGNORECASE)
BY_HOST_REGEX = re.compile(r"\bby\s+([^\s\(\)\[\];]+)", re.IGNORECASE)
WITH_PROTO_REGEX = re.compile(r"\bwith\s+([^\s;]+)", re.IGNORECASE)
ID_REGEX = re.compile(r"\bid\s+([^\s;]+)", re.IGNORECASE)
FOR_ADDR_REGEX = re.compile(r"\bfor\s+<([^>]+)>|\bfor\s+([^\s;]+)", re.IGNORECASE)
TLS_REGEX = re.compile(r"(version=TLS[^\s;\)]*|cipher=[^\s;\)]*|using\s+TLS[^\s;\)]*)", re.IGNORECASE)

# Regular expressions for Authentication-Results
AUTH_SPF_REGEX = re.compile(r"\bspf=([a-z]+)\b(?:\s+\((?:[^)]*)\))?", re.IGNORECASE)
AUTH_DKIM_REGEX = re.compile(r"\bdkim=([a-z]+)\b(?:\s+\((?:[^)]*)\))?", re.IGNORECASE)
AUTH_DMARC_REGEX = re.compile(r"\bdmarc=([a-z]+)\b(?:\s+\((?:[^)]*)\))?", re.IGNORECASE)

# Regular expressions for DKIM-Signature tags
DKIM_DOMAIN_REGEX = re.compile(r"\bd=([^;\s]+)", re.IGNORECASE)
DKIM_SELECTOR_REGEX = re.compile(r"\bs=([^;\s]+)", re.IGNORECASE)
DKIM_ALGO_REGEX = re.compile(r"\ba=([^;\s]+)", re.IGNORECASE)
DKIM_BH_REGEX = re.compile(r"\bbh=([^;\s]+)", re.IGNORECASE)
DKIM_SIG_REGEX = re.compile(r"\bb=([^;\s]+)", re.IGNORECASE)


def extract_ip_from_text(text: str) -> Optional[str]:
    """Extract and validate the first IPv4 or IPv6 address found in a string."""
    if not text:
        return None

    # Check for IP inside brackets first [1.2.3.4] or [2001:db8::1]
    bracket_match = re.search(r"\[([0-9a-fA-F\.:]+)\]", text)
    if bracket_match:
        candidate = bracket_match.group(1).strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

    # Check IPv4
    ipv4_match = IPV4_REGEX.search(text)
    if ipv4_match:
        ip_str = ipv4_match.group(0)
        try:
            ipaddress.IPv4Address(ip_str)
            return ip_str
        except ValueError:
            pass

    # Check IPv6
    ipv6_match = IPV6_REGEX.search(text)
    if ipv6_match:
        ip_str = ipv6_match.group(0)
        try:
            ipaddress.IPv6Address(ip_str)
            return ip_str
        except ValueError:
            pass

    return None


def extract_domain_from_email_or_host(identifier: Optional[str]) -> Optional[str]:
    """Extract domain part from an email address or fully qualified hostname."""
    if not identifier:
        return None
    cleaned = sanitize_string(identifier).lower()
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]
    # Remove surrounding brackets or quotes
    cleaned = cleaned.strip("<>\"'[]").strip()
    return cleaned if cleaned else None


def get_organizational_domain(domain: Optional[str]) -> Optional[str]:
    """Extract base organizational domain for relaxed DMARC/SPF alignment (e.g. mail.corp.com -> corp.com)."""
    if not domain:
        return None
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Generic two-level TLD heuristic (e.g. .co.uk, .gov.uk, .com.au)
    two_level_tlds = {"co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "co.jp", "co.in"}
    last_two = ".".join(parts[-2:])
    if last_two in two_level_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@dataclass
class ParsedRelayHop:
    sequence_number: int  # 1 = originating hop (earliest in time / bottom-most Received header)
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    destination_host: Optional[str] = None
    protocol: Optional[str] = None
    queue_id: Optional[str] = None
    envelope_to: Optional[str] = None
    tls_info: Optional[str] = None
    observed_at: Optional[datetime] = None
    raw_date_str: Optional[str] = None
    transit_delay_seconds: Optional[int] = None
    reliability: str = "UNVERIFIED"  # HIGH, MEDIUM, LOW, UNVERIFIED
    raw_header: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence_number": self.sequence_number,
            "source_host": self.source_host,
            "source_ip": self.source_ip,
            "destination_host": self.destination_host,
            "protocol": self.protocol,
            "queue_id": self.queue_id,
            "envelope_to": self.envelope_to,
            "tls_info": self.tls_info,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "raw_date_str": self.raw_date_str,
            "transit_delay_seconds": self.transit_delay_seconds,
            "reliability": self.reliability,
            "raw_header": self.raw_header,
        }


@dataclass
class ParsedDkimSignature:
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    body_hash: Optional[str] = None
    signature_preview: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "body_hash": self.body_hash,
            "signature_preview": self.signature_preview,
        }


@dataclass
class ParsedAuthenticationResult:
    spf_result: str = "NONE"  # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, PERMERROR
    dkim_result: str = "NONE"  # PASS, FAIL, NONE, TEMPERROR, PERMERROR
    dmarc_result: str = "NONE"  # PASS, FAIL, NONE, TEMPERROR, PERMERROR
    from_alignment_result: str = "NONE"  # PASS, FAIL, NONE
    from_domain: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    auth_serv_id: Optional[str] = None
    dkim_signatures: List[ParsedDkimSignature] = field(default_factory=list)
    raw_auth_results: List[str] = field(default_factory=list)
    raw_received_spf: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
            "from_alignment_result": self.from_alignment_result,
            "from_domain": self.from_domain,
            "return_path": self.return_path,
            "reply_to": self.reply_to,
            "auth_serv_id": self.auth_serv_id,
            "dkim_signatures": [s.to_dict() for s in self.dkim_signatures],
            "raw_auth_results": self.raw_auth_results,
            "raw_received_spf": self.raw_received_spf,
            "evidence": self.evidence,
        }


class ReceivedHeaderParser:
    """
    Parses SMTP 'Received:' headers, reconstructs the end-to-end routing hop chain
    in chronological sequence, and computes inter-hop transit delays and reliability scores.
    """

    def parse_received_headers(self, received_headers: List[str]) -> List[ParsedRelayHop]:
        """
        Parses a list of Received headers.
        In RFC822, MTAs prepend new Received headers at the top.
        Reversing the list reconstructs the chronological progression (Hop 1 = origin).
        """
        if not received_headers:
            return []

        chronological_headers = list(reversed(received_headers))
        hops: List[ParsedRelayHop] = []
        prev_hop_time: Optional[datetime] = None

        for idx, raw_header in enumerate(chronological_headers, start=1):
            hop = self._parse_single_received_header(raw_header, sequence_number=idx)

            # Compute inter-hop transit delay
            if hop.observed_at and prev_hop_time:
                delta = (hop.observed_at - prev_hop_time).total_seconds()
                hop.transit_delay_seconds = max(0, int(delta))
            if hop.observed_at:
                prev_hop_time = hop.observed_at

            # Classify reliability
            hop.reliability = self._classify_hop_reliability(hop)
            hops.append(hop)

        return hops

    def _parse_single_received_header(self, raw_header: str, sequence_number: int) -> ParsedRelayHop:
        cleaned_header = " ".join(raw_header.split())
        source_host = None
        source_ip = None
        dest_host = None
        protocol = None
        queue_id = None
        envelope_to = None
        tls_info = None
        observed_at = None
        raw_date_str = None

        # Extract date after semicolon if present
        if ";" in cleaned_header:
            header_body, date_part = cleaned_header.rsplit(";", 1)
            observed_at, raw_date_str = parse_rfc2822_date(date_part.strip())
        else:
            header_body = cleaned_header

        # Extract From Host & IP
        from_match = FROM_HOST_REGEX.search(header_body)
        if from_match:
            source_host = sanitize_string(from_match.group(1))

        # Check for IP in entire from clause or header body
        source_ip = extract_ip_from_text(header_body)

        # Extract By Host
        by_match = BY_HOST_REGEX.search(header_body)
        if by_match:
            dest_host = sanitize_string(by_match.group(1))

        # Extract Protocol (with ESMTP, ESMTPS, etc.)
        proto_match = WITH_PROTO_REGEX.search(header_body)
        if proto_match:
            protocol = sanitize_string(proto_match.group(1))

        # Extract Queue ID
        id_match = ID_REGEX.search(header_body)
        if id_match:
            queue_id = sanitize_string(id_match.group(1))

        # Extract Envelope To
        for_match = FOR_ADDR_REGEX.search(header_body)
        if for_match:
            envelope_to = sanitize_string(for_match.group(1) or for_match.group(2))

        # Extract TLS details
        tls_match = TLS_REGEX.search(header_body)
        if tls_match:
            tls_info = sanitize_string(tls_match.group(0))

        return ParsedRelayHop(
            sequence_number=sequence_number,
            source_host=source_host,
            source_ip=source_ip,
            destination_host=dest_host,
            protocol=protocol,
            queue_id=queue_id,
            envelope_to=envelope_to,
            tls_info=tls_info,
            observed_at=observed_at,
            raw_date_str=raw_date_str,
            raw_header=cleaned_header,
        )

    def _classify_hop_reliability(self, hop: ParsedRelayHop) -> str:
        """Classifies relay hop reliability based on IP characteristics and protocol clarity."""
        if not hop.source_ip and not hop.source_host:
            return "UNVERIFIED"

        if hop.source_ip:
            try:
                ip_obj = ipaddress.ip_address(hop.source_ip)
                # Check for RFC1918 internal enterprise / LAN address
                is_internal = False
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    is_internal = (
                        ip_obj in ipaddress.IPv4Network("10.0.0.0/8")
                        or ip_obj in ipaddress.IPv4Network("172.16.0.0/12")
                        or ip_obj in ipaddress.IPv4Network("192.168.0.0/16")
                        or ip_obj.is_loopback
                        or ip_obj.is_link_local
                    )
                else:
                    is_internal = ip_obj.is_loopback or ip_obj.is_link_local

                if is_internal:
                    return "MEDIUM"

                # Public / external internet relay with valid timestamp
                if hop.observed_at is not None:
                    return "HIGH"
            except ValueError:
                pass

        if hop.destination_host and hop.source_host and hop.observed_at:
            return "HIGH"

        return "MEDIUM"


class AuthenticationResultsParser:
    """
    Analyzes SPF, DKIM, DMARC verdicts and calculates From-header domain alignment.
    """

    def parse_authentication(
        self,
        msg: email.message.Message,
        from_address: Optional[str] = None,
        return_path: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> ParsedAuthenticationResult:
        result = ParsedAuthenticationResult()

        from_addr = from_address
        if not from_addr:
            _, from_addr = extract_address_and_name(msg.get("From"))
        result.from_domain = extract_domain_from_email_or_host(from_addr)

        if return_path:
            result.return_path = return_path
        else:
            _, rp = extract_address_and_name(msg.get("Return-Path"))
            result.return_path = rp

        if reply_to:
            result.reply_to = reply_to
        else:
            _, rt = extract_address_and_name(msg.get("Reply-To"))
            result.reply_to = rt

        # 1. Parse Authentication-Results headers (RFC 8601)
        auth_results_headers = msg.get_all("Authentication-Results", [])
        result.raw_auth_results = [sanitize_string(h) for h in auth_results_headers if h]

        for auth_hdr in auth_results_headers:
            if not auth_hdr:
                continue
            # Extract Authserv-id (first token before semicolon)
            if ";" in auth_hdr and not result.auth_serv_id:
                result.auth_serv_id = sanitize_string(auth_hdr.split(";")[0].strip())

            # Parse SPF verdict
            spf_match = AUTH_SPF_REGEX.search(auth_hdr)
            if spf_match and result.spf_result == "NONE":
                result.spf_result = spf_match.group(1).upper()

            # Parse DKIM verdict
            dkim_match = AUTH_DKIM_REGEX.search(auth_hdr)
            if dkim_match and result.dkim_result == "NONE":
                result.dkim_result = dkim_match.group(1).upper()

            # Parse DMARC verdict
            dmarc_match = AUTH_DMARC_REGEX.search(auth_hdr)
            if dmarc_match and result.dmarc_result == "NONE":
                result.dmarc_result = dmarc_match.group(1).upper()

        # 2. Parse Received-SPF fallback if SPF is still NONE
        received_spf_headers = msg.get_all("Received-SPF", [])
        if received_spf_headers:
            result.raw_received_spf = sanitize_string(received_spf_headers[0])
            if result.spf_result == "NONE":
                first_token = result.raw_received_spf.split()[0].upper().rstrip(":")
                if first_token in {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR"}:
                    result.spf_result = first_token

        # 3. Parse DKIM-Signature headers
        dkim_sig_headers = msg.get_all("DKIM-Signature", [])
        for sig_hdr in dkim_sig_headers:
            if not sig_hdr:
                continue
            d_match = DKIM_DOMAIN_REGEX.search(sig_hdr)
            s_match = DKIM_SELECTOR_REGEX.search(sig_hdr)
            a_match = DKIM_ALGO_REGEX.search(sig_hdr)
            bh_match = DKIM_BH_REGEX.search(sig_hdr)
            b_match = DKIM_SIG_REGEX.search(sig_hdr)

            sig = ParsedDkimSignature(
                domain=sanitize_string(d_match.group(1)) if d_match else None,
                selector=sanitize_string(s_match.group(1)) if s_match else None,
                algorithm=sanitize_string(a_match.group(1)) if a_match else None,
                body_hash=sanitize_string(bh_match.group(1)) if bh_match else None,
                signature_preview=sanitize_string(b_match.group(1)[:24] + "...") if b_match else None,
            )
            result.dkim_signatures.append(sig)

        # If DKIM signatures exist and result was NONE, flag presence
        if result.dkim_signatures and result.dkim_result == "NONE":
            result.dkim_result = "UNVERIFIED"

        # 4. Evaluate From-Header Domain Alignment
        result.from_alignment_result = self._calculate_from_alignment(result)

        # 5. Populate structured evidence
        result.evidence = {
            "from_domain": result.from_domain,
            "return_path_domain": extract_domain_from_email_or_host(result.return_path),
            "dkim_domains": [s.domain for s in result.dkim_signatures if s.domain],
            "auth_serv_id": result.auth_serv_id,
            "signatures_found": len(result.dkim_signatures),
            "raw_auth_headers_count": len(result.raw_auth_results),
        }

        return result

    def _calculate_from_alignment(self, auth: ParsedAuthenticationResult) -> str:
        """
        Calculates From-domain alignment:
        - Strict alignment: Exactly identical domain.
        - Relaxed alignment: Matches base organizational domain.
        Returns PASS if aligned with SPF or DKIM passing domain, FAIL if domains mismatch, NONE if no auth data.
        """
        if not auth.from_domain:
            return "NONE"

        from_org = get_organizational_domain(auth.from_domain)
        aligned = False

        # Check SPF domain alignment (against Return-Path)
        if auth.return_path and auth.spf_result == "PASS":
            rp_domain = extract_domain_from_email_or_host(auth.return_path)
            if rp_domain:
                rp_org = get_organizational_domain(rp_domain)
                if rp_org == from_org:
                    aligned = True

        # Check DKIM domain alignment (against signing domains `d=`)
        if auth.dkim_result == "PASS":
            for sig in auth.dkim_signatures:
                if sig.domain:
                    dkim_org = get_organizational_domain(sig.domain)
                    if dkim_org == from_org:
                        aligned = True
                        break

        if aligned:
            return "PASS"
        if auth.spf_result in ("PASS", "FAIL", "SOFTFAIL") or auth.dkim_result in ("PASS", "FAIL"):
            return "FAIL"

        return "NONE"
