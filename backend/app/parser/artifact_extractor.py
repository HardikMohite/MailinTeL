import re
import hashlib
import email
import email.policy
from urllib.parse import urlparse, unquote
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
import ipaddress
import html
import logging

from app.parser.email_parser import (
    EmailStructureParser,
    sanitize_string,
    safe_decode_header_str,
)
from app.parser.header_analyzer import (
    extract_ip_from_text,
    extract_domain_from_email_or_host,
    get_organizational_domain,
    IPV4_REGEX,
    IPV6_REGEX,
)

logger = logging.getLogger(__name__)

# URL Extraction Regex (supporting standard and defanged URLs like hxxp://site[.]xyz)
URL_REGEX = re.compile(
    r"""(?i)\b(?:https?|hxxps?|ftp|hxxp)://[^\s<>"'{}|\\^`]+|\bwww\.[^\s<>"'{}|\\^`]+""",
    re.IGNORECASE,
)
HTML_HREF_REGEX = re.compile(r"""(?i)<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.DOTALL)
HTML_SRC_REGEX = re.compile(r"""(?i)<(?:img|iframe|script)\s+[^>]*src=["']([^"']+)["'][^>]*>""", re.IGNORECASE)

# Dangerous executable / script / container extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".hta", ".iso", ".img", ".lnk",
    ".bat", ".cmd", ".ps1", ".vbe", ".jse", ".wsf", ".wsh", ".msc",
    ".jar", ".cpl", ".dll", ".sys", ".docm", ".xlsm", ".pptm",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab"}


def refang_indicator(text: str) -> str:
    """
    Refangs defanged security indicators:
    - hxxp:// -> http://
    - hxxps:// -> https://
    - [.] -> .
    - [:] -> :
    - [at] / [@] -> @
    """
    if not text:
        return ""
    refanged = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    refanged = refanged.replace("[.]", ".").replace("[:]", ":")
    refanged = refanged.replace("[at]", "@").replace("[@]", "@")
    return refanged.strip()


def defang_indicator(text: str) -> str:
    """
    Defangs URL / IP / Domain for safe investigative display:
    - https:// -> hxxps://
    - http:// -> hxxp://
    - . -> [.]
    """
    if not text:
        return ""
    defanged = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def normalize_url_string(raw_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Normalizes a raw or defanged URL.
    Returns (normalized_url, url_domain, sha256_hash).
    """
    if not raw_url:
        return None, None, None

    refanged = refang_indicator(raw_url.strip())
    # Prepend http:// if starts with www.
    if refanged.lower().startswith("www."):
        refanged = "http://" + refanged

    # Unescape HTML entities (e.g. &amp; -> &)
    refanged = html.unescape(refanged)

    try:
        parsed = urlparse(refanged)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc.lower() if parsed.netloc else ""
        if not netloc and parsed.path:
            # Handle schemes like mailto or raw path
            parts = parsed.path.split("/", 1)
            netloc = parts[0].lower()
            path = "/" + parts[1] if len(parts) > 1 else ""
        else:
            path = parsed.path or ""

        # Normalize port
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        # Remove redundant default paths
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"

        # Calculate SHA-256
        url_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        domain = extract_domain_from_email_or_host(netloc)

        return sanitize_string(normalized), domain, url_hash
    except Exception as e:
        logger.debug(f"URL normalization error for '{raw_url[:40]}': {e}")
        return None, None, None


@dataclass
class ExtractedURL:
    url: str
    normalized_url: str
    url_hash: str
    domain: Optional[str] = None
    root_domain: Optional[str] = None
    context: str = "BODY_LINK"  # BODY_LINK, BUTTON_HREF, IMAGE_SRC, HEADER
    anchor_text: Optional[str] = None
    is_defanged: bool = False
    defanged_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "url_hash": self.url_hash,
            "domain": self.domain,
            "root_domain": self.root_domain,
            "context": self.context,
            "anchor_text": self.anchor_text,
            "is_defanged": self.is_defanged,
            "defanged_url": self.defanged_url,
        }


@dataclass
class ExtractedDomain:
    domain: str
    root_domain: str
    source_contexts: Set[str] = field(default_factory=set)
    is_suspicious_tld: bool = False
    is_punycode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "root_domain": self.root_domain,
            "source_contexts": list(self.source_contexts),
            "is_suspicious_tld": self.is_suspicious_tld,
            "is_punycode": self.is_punycode,
        }


@dataclass
class ExtractedIP:
    ip_address: str
    ip_version: int  # 4 or 6
    category: str  # PUBLIC, PRIVATE_RFC1918, LOOPBACK, LINK_LOCAL, RESERVED
    source_contexts: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "ip_version": self.ip_version,
            "category": self.category,
            "source_contexts": list(self.source_contexts),
        }


@dataclass
class ExtractedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    extension: str
    is_dangerous: bool = False
    is_archive: bool = False
    has_double_extension: bool = False
    raw_payload_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
            "extension": self.extension,
            "is_dangerous": self.is_dangerous,
            "is_archive": self.is_archive,
            "has_double_extension": self.has_double_extension,
        }


@dataclass
class EmailArtifactBundle:
    urls: List[ExtractedURL] = field(default_factory=list)
    domains: List[ExtractedDomain] = field(default_factory=list)
    ip_addresses: List[ExtractedIP] = field(default_factory=list)
    attachments: List[ExtractedAttachment] = field(default_factory=list)
    total_urls: int = 0
    total_domains: int = 0
    total_ips: int = 0
    total_attachments: int = 0
    has_dangerous_attachments: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "urls": [u.to_dict() for u in self.urls],
            "domains": [d.to_dict() for d in self.domains],
            "ip_addresses": [i.to_dict() for i in self.ip_addresses],
            "attachments": [a.to_dict() for a in self.attachments],
            "total_urls": self.total_urls,
            "total_domains": self.total_domains,
            "total_ips": self.total_ips,
            "total_attachments": self.total_attachments,
            "has_dangerous_attachments": self.has_dangerous_attachments,
        }


class EmailArtifactExtractor:
    """
    Forensic Artifact Extraction Engine for emails.
    Extracts, defangs, and normalizes URLs, Domains, IP addresses, and Attachments
    with cryptographic hashes and threat categorization.
    """

    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "loan", "club", "click", "link",
        "tokyo", "download", "men", "racing", "review", "country", "stream"
    }

    def extract_artifacts(self, raw_eml_bytes: bytes) -> EmailArtifactBundle:
        """
        Extracts all forensic artifacts from raw RFC822 email bytes.
        """
        if not raw_eml_bytes:
            return EmailArtifactBundle()

        try:
            msg = email.message_from_bytes(raw_eml_bytes, policy=email.policy.default)
        except Exception:
            msg = email.message_from_bytes(raw_eml_bytes, policy=email.policy.compat32)

        bundle = EmailArtifactBundle()
        seen_urls: Set[str] = set()
        domains_map: Dict[str, ExtractedDomain] = {}
        ips_map: Dict[str, ExtractedIP] = {}

        # 1. Parse Email Structure to get decoded bodies & headers
        parser = EmailStructureParser()
        structure = parser.parse_bytes(raw_eml_bytes)

        # 2. Extract URLs and Domains from HTML and Plain Text Bodies
        if structure.html_body:
            self._extract_urls_from_html(structure.html_body, bundle.urls, seen_urls, domains_map)
        if structure.plain_text_body:
            self._extract_urls_from_text(structure.plain_text_body, bundle.urls, seen_urls, domains_map)

        # Extract IPs from plain text and HTML bodies
        for body_text in (structure.plain_text_body, structure.html_body):
            if body_text:
                for match in IPV4_REGEX.finditer(body_text):
                    self._add_ip(match.group(0), "BODY_TEXT", ips_map)
                for match in IPV6_REGEX.finditer(body_text):
                    self._add_ip(match.group(0), "BODY_TEXT", ips_map)

        # 3. Extract Domains and IPs from Email Headers
        for header in structure.headers:
            h_name = header.header_name.lower()
            h_val = header.header_value or ""

            # Check for domains in From, To, Cc, Reply-To, Return-Path
            if h_name in ("from", "to", "cc", "bcc", "reply-to", "return-path"):
                d = extract_domain_from_email_or_host(h_val)
                if d:
                    self._add_domain(d, f"HEADER_{h_name.upper()}", domains_map)

            # Check for IPs in Received headers
            if h_name == "received":
                ip_found = extract_ip_from_text(h_val)
                if ip_found:
                    self._add_ip(ip_found, "HEADER_RECEIVED", ips_map)

            # Extract URLs that might appear in header fields (e.g. List-Unsubscribe)
            if "http" in h_val.lower() or "hxxp" in h_val.lower():
                self._extract_urls_from_text(h_val, bundle.urls, seen_urls, domains_map, context="HEADER")

        # 4. Extract Attachments from MIME parts
        self._extract_attachments(msg, bundle.attachments)

        # 5. Consolidate results
        bundle.domains = list(domains_map.values())
        bundle.ip_addresses = list(ips_map.values())
        bundle.total_urls = len(bundle.urls)
        bundle.total_domains = len(bundle.domains)
        bundle.total_ips = len(bundle.ip_addresses)
        bundle.total_attachments = len(bundle.attachments)
        bundle.has_dangerous_attachments = any(a.is_dangerous for a in bundle.attachments)

        return bundle

    def _extract_urls_from_html(
        self,
        html_content: str,
        urls_list: List[ExtractedURL],
        seen_urls: Set[str],
        domains_map: Dict[str, ExtractedDomain],
    ) -> None:
        """Extract URLs from HTML <a href="...">, <img src="...">, and plain occurrences."""
        # 1. Anchor hrefs
        for match in HTML_HREF_REGEX.finditer(html_content):
            raw_href = match.group(1).strip()
            anchor = sanitize_string(html.unescape(match.group(2).strip()))
            self._process_single_url(raw_href, "BUTTON_HREF" if "button" in match.group(0).lower() else "BODY_LINK", anchor, urls_list, seen_urls, domains_map)

        # 2. Img/iframe src
        for match in HTML_SRC_REGEX.finditer(html_content):
            raw_src = match.group(1).strip()
            self._process_single_url(raw_src, "IMAGE_SRC", None, urls_list, seen_urls, domains_map)

        # 3. Text regex fallback
        self._extract_urls_from_text(html_content, urls_list, seen_urls, domains_map, context="BODY_LINK")

    def _extract_urls_from_text(
        self,
        text_content: str,
        urls_list: List[ExtractedURL],
        seen_urls: Set[str],
        domains_map: Dict[str, ExtractedDomain],
        context: str = "BODY_LINK",
    ) -> None:
        """Extract URLs from plain text using regex."""
        for match in URL_REGEX.finditer(text_content):
            raw_url = match.group(0).rstrip(".,;)>'\"")
            self._process_single_url(raw_url, context, None, urls_list, seen_urls, domains_map)

    def _process_single_url(
        self,
        raw_url: str,
        context: str,
        anchor_text: Optional[str],
        urls_list: List[ExtractedURL],
        seen_urls: Set[str],
        domains_map: Dict[str, ExtractedDomain],
    ) -> None:
        if not raw_url or raw_url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return

        normalized, domain, url_hash = normalize_url_string(raw_url)
        if not normalized or not url_hash or url_hash in seen_urls:
            return

        seen_urls.add(url_hash)
        root_domain = get_organizational_domain(domain) if domain else None
        is_defanged = "hxxp" in raw_url.lower() or "[.]" in raw_url

        if domain:
            self._add_domain(domain, f"URL_{context}", domains_map)

        urls_list.append(
            ExtractedURL(
                url=raw_url,
                normalized_url=normalized,
                url_hash=url_hash,
                domain=domain,
                root_domain=root_domain,
                context=context,
                anchor_text=anchor_text,
                is_defanged=is_defanged,
                defanged_url=defang_indicator(normalized),
            )
        )

    def _add_domain(self, domain_name: str, context: str, domains_map: Dict[str, ExtractedDomain]) -> None:
        clean = domain_name.lower().strip(".").strip()
        if not clean or "." not in clean or len(clean) > 255:
            return

        root_d = get_organizational_domain(clean) or clean
        tld = clean.split(".")[-1]
        is_suspicious_tld = tld in self.SUSPICIOUS_TLDS
        is_punycode = clean.startswith("xn--") or ".xn--" in clean

        if clean not in domains_map:
            domains_map[clean] = ExtractedDomain(
                domain=clean,
                root_domain=root_d,
                source_contexts={context},
                is_suspicious_tld=is_suspicious_tld,
                is_punycode=is_punycode,
            )
        else:
            domains_map[clean].source_contexts.add(context)

    def _add_ip(self, ip_str: str, context: str, ips_map: Dict[str, ExtractedIP]) -> None:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            clean_ip = str(ip_obj)

            if ip_obj.is_private:
                cat = "PRIVATE_RFC1918"
            elif ip_obj.is_loopback:
                cat = "LOOPBACK"
            elif ip_obj.is_link_local:
                cat = "LINK_LOCAL"
            elif ip_obj.is_reserved:
                cat = "RESERVED"
            else:
                cat = "PUBLIC"

            if clean_ip not in ips_map:
                ips_map[clean_ip] = ExtractedIP(
                    ip_address=clean_ip,
                    ip_version=ip_obj.version,
                    category=cat,
                    source_contexts={context},
                )
            else:
                ips_map[clean_ip].source_contexts.add(context)
        except ValueError:
            pass

    def _extract_attachments(self, msg: email.message.Message, attachments_list: List[ExtractedAttachment]) -> None:
        """Walks MIME parts to extract binary attachments and calculate hashes."""
        for part in msg.walk():
            if part.is_multipart():
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()

            # Attachment determination
            if not filename and disposition != "attachment":
                continue

            clean_filename = safe_decode_header_str(filename) if filename else "unnamed_attachment"
            content_type = part.get_content_type() or "application/octet-stream"

            payload = part.get_payload(decode=True)
            if payload is None:
                payload = b""

            sha256_hash = hashlib.sha256(payload).hexdigest()
            md5_hash = hashlib.md5(payload).hexdigest()
            size_bytes = len(payload)

            # Extension analysis
            lower_name = clean_filename.lower()
            dot_idx = lower_name.rfind(".")
            ext = lower_name[dot_idx:] if dot_idx != -1 else ""

            # Double extension detection (e.g. invoice.pdf.exe)
            has_double_ext = False
            parts = lower_name.split(".")
            if len(parts) >= 3:
                has_double_ext = True

            is_dangerous = ext in DANGEROUS_EXTENSIONS or (has_double_ext and ext in DANGEROUS_EXTENSIONS)
            is_archive = ext in ARCHIVE_EXTENSIONS

            attachments_list.append(
                ExtractedAttachment(
                    filename=clean_filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    sha256_hash=sha256_hash,
                    md5_hash=md5_hash,
                    extension=ext,
                    is_dangerous=is_dangerous,
                    is_archive=is_archive,
                    has_double_extension=has_double_ext,
                    raw_payload_bytes=payload,
                )
            )
