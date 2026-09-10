import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

from app.parser.email_parser import sanitize_string
from app.parser.header_analyzer import extract_domain_from_email_or_host, get_organizational_domain

logger = logging.getLogger(__name__)

DNA_VERSION = "1.0"


def compute_stable_json_hash(data: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash of a dictionary."""
    normalized_json = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()


@dataclass
class EmailDNABundle:
    """
    Structured multi-dimensional fingerprint representing the complete DNA of an email.
    """
    email_id: str
    content_fingerprint: Dict[str, Any]
    technical_fingerprint: Dict[str, Any]
    infrastructure_fingerprint: Dict[str, Any]
    behavioral_fingerprint: Dict[str, Any]
    temporal_fingerprint: Dict[str, Any]
    dna_version: str = DNA_VERSION
    overall_dna_hash: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if not self.overall_dna_hash:
            composite_data = {
                "content": self.content_fingerprint,
                "technical": self.technical_fingerprint,
                "infrastructure": self.infrastructure_fingerprint,
                "behavioral": self.behavioral_fingerprint,
                "temporal": self.temporal_fingerprint,
            }
            self.overall_dna_hash = compute_stable_json_hash(composite_data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email_id": self.email_id,
            "dna_version": self.dna_version,
            "overall_dna_hash": self.overall_dna_hash,
            "content_fingerprint": self.content_fingerprint,
            "technical_fingerprint": self.technical_fingerprint,
            "infrastructure_fingerprint": self.infrastructure_fingerprint,
            "behavioral_fingerprint": self.behavioral_fingerprint,
            "temporal_fingerprint": self.temporal_fingerprint,
            "generated_at": self.generated_at.isoformat(),
        }


class EmailDNABuilder:
    """
    Extracts and compiles multi-layer forensic fingerprints across content,
    technical headers, transmission infrastructure, targeting behavior, and temporal metrics.
    """

    def extract_content_fingerprint(
        self,
        email_metadata: Dict[str, Any],
        artifacts: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extracts content, attachment, DOM, and lexical signatures."""
        subject = email_metadata.get("subject") or ""
        body_text = email_metadata.get("plain_text_body") or ""
        html_body = email_metadata.get("html_body") or ""

        # Subject normalization & tokenization
        clean_subj = re.sub(r"(?i)^(?:re|fwd|fw|aw|antw):\s*", "", subject).strip().lower()
        subj_tokens = sorted(list(set(re.findall(r"\b[a-z0-9]{3,}\b", clean_subj))))
        subj_hash = hashlib.sha256(clean_subj.encode("utf-8")).hexdigest() if clean_subj else None

        # Lexical & body length metrics
        body_length = len(body_text)
        word_count = len(body_text.split())

        # HTML tag sequence pattern (DOM signature)
        dom_tags: List[str] = []
        if html_body:
            tags = re.findall(r"<([a-zA-Z0-9]+)[\s>]", html_body)
            dom_tags = [t.lower() for t in tags[:50]]  # Top 50 elements

        # Attachments summary
        attachments = artifacts.get("attachments", [])
        att_extensions = sorted([a.get("extension", "").lower() for a in attachments if a.get("extension")])
        att_hashes = sorted([a.get("sha256_hash") for a in attachments if a.get("sha256_hash")])

        # Urgency / Phishing keywords detection
        urgency_regex = re.compile(
            r"(?i)\b(urgent|immediate|action required|suspended|locked|verify|password reset|invoice overdue|security alert)\b"
        )
        detected_urgency = sorted(list(set(urgency_regex.findall(f"{subject} {body_text}"))))

        return {
            "subject_normalized": clean_subj,
            "subject_hash": subj_hash,
            "subject_tokens": subj_tokens,
            "body_length_bytes": body_length,
            "word_count": word_count,
            "dom_tag_sequence": dom_tags[:20],
            "attachment_count": len(attachments),
            "attachment_extensions": att_extensions,
            "attachment_sha256_hashes": att_hashes,
            "detected_urgency_markers": detected_urgency,
        }

    def extract_technical_fingerprint(
        self,
        headers: List[Dict[str, Any]],
        auth_results: Dict[str, Any],
        structure: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extracts technical header ordering, mail client, MIME boundaries, and DKIM parameters."""
        header_names = [h.get("header_name", "").lower() for h in headers if h.get("header_name")]
        header_order_hash = hashlib.sha256("-".join(header_names).encode("utf-8")).hexdigest() if header_names else None

        # Mailer signatures
        x_mailer = None
        user_agent = None
        for h in headers:
            h_name = (h.get("header_name") or "").lower()
            h_val = h.get("header_value") or ""
            if h_name == "x-mailer":
                x_mailer = sanitize_string(h_val)
            elif h_name == "user-agent":
                user_agent = sanitize_string(h_val)

        # Message-ID signature
        msg_id = None
        for h in headers:
            if (h.get("header_name") or "").lower() == "message-id":
                msg_id = sanitize_string(h.get("header_value") or "")
                break

        msg_id_domain = msg_id.split("@")[-1].rstrip(">").strip().lower() if msg_id and "@" in msg_id else None

        # DKIM parameters
        dkim_sig = None
        for h in headers:
            if (h.get("header_name") or "").lower() == "dkim-signature":
                dkim_sig = h.get("header_value")
                break

        dkim_selector = None
        dkim_domain = None
        dkim_algo = None
        if dkim_sig:
            s_match = re.search(r"s=([^;\s]+)", dkim_sig)
            d_match = re.search(r"d=([^;\s]+)", dkim_sig)
            a_match = re.search(r"a=([^;\s]+)", dkim_sig)
            if s_match:
                dkim_selector = s_match.group(1).lower()
            if d_match:
                dkim_domain = d_match.group(1).lower()
            if a_match:
                dkim_algo = a_match.group(1).lower()

        # MIME structure topology
        total_parts = structure.get("total_mime_parts", 1)
        mime_types = []
        for part in structure.get("mime_parts", []):
            if isinstance(part, dict) and part.get("content_type"):
                mime_types.append(part.get("content_type").lower())

        return {
            "header_order_hash": header_order_hash,
            "header_count": len(header_names),
            "x_mailer": x_mailer,
            "user_agent": user_agent,
            "message_id_domain": msg_id_domain,
            "dkim_selector": dkim_selector,
            "dkim_signing_domain": dkim_domain,
            "dkim_algorithm": dkim_algo,
            "total_mime_parts": total_parts,
            "mime_part_types": mime_types,
            "spf_verdict": auth_results.get("spf_verdict"),
            "dkim_verdict": auth_results.get("dkim_verdict"),
            "dmarc_verdict": auth_results.get("dmarc_verdict"),
        }

    def extract_infrastructure_fingerprint(
        self,
        relay_hops: List[Dict[str, Any]],
        infrastructure_intel: List[Dict[str, Any]],
        domain_intel: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Extracts transmission infrastructure, ASN sequences, Tor/VPN/Cloud indicators."""
        relay_ips = [h.get("source_ip") for h in relay_hops if h.get("source_ip")]
        relay_hosts = [h.get("source_host") for h in relay_hops if h.get("source_host")]

        # ASN Sequence
        asn_sequence = []
        country_sequence = []
        classifications_all: Set[str] = set()

        for ip_intel in infrastructure_intel:
            if ip_intel.get("asn"):
                asn_sequence.append(ip_intel.get("asn"))
            if ip_intel.get("country_code"):
                country_sequence.append(ip_intel.get("country_code"))
            for c in ip_intel.get("classifications", []):
                if isinstance(c, dict) and c.get("classification_type"):
                    classifications_all.add(c.get("classification_type"))

        # Domain TLDs & DynDNS flags
        domain_tlds = []
        has_dynamic_dns = False
        has_nrd = False
        for d in domain_intel:
            d_name = d.get("domain", "")
            if "." in d_name:
                domain_tlds.append("." + d_name.split(".")[-1].lower())
            if d.get("is_dynamic_dns"):
                has_dynamic_dns = True
            if d.get("is_nrd"):
                has_nrd = True

        return {
            "originating_ip": relay_ips[0] if relay_ips else None,
            "relay_hop_count": len(relay_hops),
            "relay_ip_chain": relay_ips,
            "relay_host_chain": [sanitize_string(h) for h in relay_hosts[:5]],
            "asn_chain": asn_sequence,
            "country_chain": country_sequence,
            "infrastructure_classifications": sorted(list(classifications_all)),
            "has_dynamic_dns": has_dynamic_dns,
            "has_nrd": has_nrd,
            "associated_tlds": sorted(list(set(domain_tlds))),
        }

    def extract_behavioral_fingerprint(
        self,
        email_metadata: Dict[str, Any],
        auth_results: Dict[str, Any],
        artifacts: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extracts targeting profile, URL distribution, recipient counts, and header alignment."""
        sender = email_metadata.get("sender_address") or ""
        sender_display = email_metadata.get("sender_display_name") or ""
        sender_dom = sender.split("@")[-1].lower() if "@" in sender else ""
        root_sender_dom = get_organizational_domain(sender_dom) or sender_dom

        recipients = email_metadata.get("recipients", [])
        recipient_count = len(recipients)
        recipient_domains = sorted(list(set(r.get("address", "").split("@")[-1].lower() for r in recipients if "@" in r.get("address", ""))))

        urls = artifacts.get("urls", [])
        url_domains = sorted(list(set(u.get("domain", "").lower() for u in urls if u.get("domain"))))

        # Check display name spoofing indicator (e.g. "Microsoft Support" in display name but domain is xyz.com)
        has_brand_in_display = bool(
            re.search(r"(?i)\b(microsoft|google|paypal|apple|amazon|netflix|bank|chase|wells fargo)\b", sender_display)
        )
        is_brand_mismatched = has_brand_in_display and not any(
            brand in sender_dom for brand in ["microsoft", "google", "paypal", "apple", "amazon", "netflix", "chase", "wellsfargo"]
        )

        return {
            "recipient_count": recipient_count,
            "recipient_domain_diversity": len(recipient_domains),
            "recipient_domains": recipient_domains[:5],
            "url_count": len(urls),
            "unique_url_domains_count": len(url_domains),
            "url_domains": url_domains[:10],
            "from_domain_alignment": auth_results.get("from_domain_aligned") or "NONE",
            "sender_root_domain": root_sender_dom,
            "has_brand_display_mismatch": is_brand_mismatched,
        }

    def extract_temporal_fingerprint(
        self,
        email_metadata: Dict[str, Any],
        headers: List[Dict[str, Any]],
        relay_hops: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Extracts sending time-of-day, day of week, timezone offset, and transit latency."""
        sent_at_str = email_metadata.get("sent_at")
        hour_of_day_utc = None
        day_of_week = None  # 0=Monday, 6=Sunday
        tz_offset_str = None

        if sent_at_str:
            try:
                dt = datetime.fromisoformat(sent_at_str.replace("Z", "+00:00"))
                hour_of_day_utc = dt.hour
                day_of_week = dt.weekday()
            except Exception:
                pass

        # Extract timezone offset from raw Date header if available
        for h in headers:
            if (h.get("header_name") or "").lower() == "date":
                raw_date = h.get("header_value") or ""
                tz_match = re.search(r"([+-]\d{4}|[A-Z]{3,4})\s*$", raw_date.strip())
                if tz_match:
                    tz_offset_str = tz_match.group(1)
                break

        # Transit delays
        delays = [h.get("delay_seconds") for h in relay_hops if h.get("delay_seconds") is not None]
        total_transit_seconds = sum(delays) if delays else 0
        max_hop_delay_seconds = max(delays) if delays else 0

        return {
            "hour_of_day_utc": hour_of_day_utc,
            "day_of_week": day_of_week,
            "timezone_offset_header": tz_offset_str,
            "total_transit_delay_seconds": total_transit_seconds,
            "max_hop_delay_seconds": max_hop_delay_seconds,
        }

    def build_dna_profile(
        self,
        email_id: str,
        email_metadata: Dict[str, Any],
        headers: Optional[List[Dict[str, Any]]] = None,
        structure: Optional[Dict[str, Any]] = None,
        auth_results: Optional[Dict[str, Any]] = None,
        relay_hops: Optional[List[Dict[str, Any]]] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        domain_intel: Optional[List[Dict[str, Any]]] = None,
        infrastructure_intel: Optional[List[Dict[str, Any]]] = None,
    ) -> EmailDNABundle:
        """Compiles all forensic dimensions into a unified EmailDNABundle."""
        headers = headers or []
        structure = structure or {}
        auth_results = auth_results or {}
        relay_hops = relay_hops or []
        artifacts = artifacts or {}
        domain_intel = domain_intel or []
        infrastructure_intel = infrastructure_intel or []

        content_fp = self.extract_content_fingerprint(email_metadata, artifacts)
        technical_fp = self.extract_technical_fingerprint(headers, auth_results, structure)
        infra_fp = self.extract_infrastructure_fingerprint(relay_hops, infrastructure_intel, domain_intel)
        behavioral_fp = self.extract_behavioral_fingerprint(email_metadata, auth_results, artifacts)
        temporal_fp = self.extract_temporal_fingerprint(email_metadata, headers, relay_hops)

        return EmailDNABundle(
            email_id=email_id,
            content_fingerprint=content_fp,
            technical_fingerprint=technical_fp,
            infrastructure_fingerprint=infra_fp,
            behavioral_fingerprint=behavioral_fp,
            temporal_fingerprint=temporal_fp,
        )
