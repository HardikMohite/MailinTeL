import email
import email.policy
import email.utils
from email.header import decode_header
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# Security and forensic limits
MAX_MIME_RECURSION_DEPTH = 32
MAX_BODY_TEXT_LENGTH = 1_000_000  # 1 MB max text extraction for memory protection
MAX_HEADER_COUNT = 500  # Protection against header bomb DOS attacks


def sanitize_string(val: Optional[str]) -> Optional[str]:
    """
    Security sanitization:
    - Strips null bytes (\x00) which cause PostgreSQL string termination errors.
    - Preserves standard whitespace and forensic integrity.
    """
    if val is None:
        return None
    # Remove null bytes
    val = val.replace("\x00", "")
    return val.strip()


def safe_decode_header_str(raw_header: Optional[str]) -> Optional[str]:
    """
    Safely decodes RFC 2047 encoded header strings (e.g. =?UTF-8?B?...?=).
    Gracefully falls back to Latin-1 or UTF-8 replace if malformed.
    """
    if not raw_header:
        return None
    try:
        decoded_chunks = decode_header(raw_header)
        result_parts = []
        for content, encoding in decoded_chunks:
            if isinstance(content, bytes):
                enc = encoding or "utf-8"
                try:
                    result_parts.append(content.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    result_parts.append(content.decode("latin-1", errors="replace"))
            else:
                result_parts.append(str(content))
        decoded_text = "".join(result_parts)
        return sanitize_string(decoded_text)
    except Exception as e:
        logger.debug(f"Header decoding fallback for '{str(raw_header)[:30]}...': {e}")
        return sanitize_string(str(raw_header))


def parse_rfc2822_date(raw_date: Optional[str]) -> Tuple[Optional[datetime], Optional[str]]:
    """
    Parses RFC 2822 / RFC 822 date header into timezone-aware UTC datetime.
    Returns (utc_datetime, raw_date_string).
    """
    if not raw_date:
        return None, None

    cleaned_raw = sanitize_string(raw_date)
    try:
        parsed_tuple = email.utils.parsedate_to_datetime(cleaned_raw)
        if parsed_tuple:
            # Convert to UTC
            if parsed_tuple.tzinfo is None:
                utc_dt = parsed_tuple.replace(tzinfo=timezone.utc)
            else:
                utc_dt = parsed_tuple.astimezone(timezone.utc)
            return utc_dt, cleaned_raw
    except Exception as e:
        logger.debug(f"Standard date parsing failed for '{cleaned_raw}': {e}")

    # Fallback with parsedate
    try:
        time_tuple = email.utils.parsedate(cleaned_raw)
        if time_tuple:
            dt = datetime(*time_tuple[:6], tzinfo=timezone.utc)
            return dt, cleaned_raw
    except Exception:
        pass

    return None, cleaned_raw


def extract_address_and_name(raw_header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts (display_name, email_address) from an address header like:
    'John Doe <john.doe@example.com>' or '=?UTF-8?B?...?= <admin@domain.com>'
    """
    if not raw_header:
        return None, None

    try:
        display_name, address = email.utils.parseaddr(raw_header)
        display_name = safe_decode_header_str(display_name)
        address = sanitize_string(address.lower() if address else None)
        # Empty string normalization
        if address == "":
            address = None
        if display_name == "":
            display_name = None
        return display_name, address
    except Exception as e:
        logger.warning(f"Error parsing address '{raw_header}': {e}")
        return None, sanitize_string(raw_header)


def extract_address_list(raw_header: Optional[str]) -> List[Tuple[Optional[str], str]]:
    """
    Extracts a list of (display_name, email_address) tuples from multi-address headers (To, Cc, Bcc).
    """
    if not raw_header:
        return []

    results: List[Tuple[Optional[str], str]] = []
    try:
        addresses = email.utils.getaddresses([raw_header])
        for name, addr in addresses:
            clean_name = safe_decode_header_str(name)
            clean_addr = sanitize_string(addr.lower() if addr else None)
            if clean_addr:
                results.append((clean_name if clean_name else None, clean_addr))
    except Exception as e:
        logger.warning(f"Error parsing address list '{str(raw_header)[:40]}...': {e}")

    return results


@dataclass
class ParsedRecipient:
    recipient_type: str  # TO, CC, BCC
    address: str
    display_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipient_type": self.recipient_type,
            "address": self.address,
            "display_name": self.display_name,
        }


@dataclass
class ParsedHeader:
    header_name: str
    header_value: str
    normalized_value: Optional[str] = None
    header_order: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header_name": self.header_name,
            "header_value": self.header_value,
            "normalized_value": self.normalized_value,
            "header_order": self.header_order,
        }


@dataclass
class ParsedMimePart:
    part_index: int
    content_type: str
    content_disposition: Optional[str] = None
    filename: Optional[str] = None
    charset: Optional[str] = None
    transfer_encoding: Optional[str] = None
    size_bytes: int = 0
    is_attachment: bool = False
    content_id: Optional[str] = None
    sub_parts: List["ParsedMimePart"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "part_index": self.part_index,
            "content_type": self.content_type,
            "content_disposition": self.content_disposition,
            "filename": self.filename,
            "charset": self.charset,
            "transfer_encoding": self.transfer_encoding,
            "size_bytes": self.size_bytes,
            "is_attachment": self.is_attachment,
            "content_id": self.content_id,
            "sub_parts": [p.to_dict() for p in self.sub_parts],
        }


@dataclass
class ParsedEmailStructure:
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    sender_display_name: Optional[str] = None
    sent_at: Optional[datetime] = None
    raw_date_str: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_display_name: Optional[str] = None
    recipients: List[ParsedRecipient] = field(default_factory=list)
    headers: List[ParsedHeader] = field(default_factory=list)
    mime_parts: List[ParsedMimePart] = field(default_factory=list)
    plain_text_body: Optional[str] = None
    html_body: Optional[str] = None
    has_attachments: bool = False
    attachment_count: int = 0
    total_mime_parts: int = 0
    is_multipart: bool = False
    root_content_type: str = "text/plain"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "sender_address": self.sender_address,
            "sender_display_name": self.sender_display_name,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "raw_date_str": self.raw_date_str,
            "message_id": self.message_id,
            "return_path": self.return_path,
            "reply_to": self.reply_to,
            "reply_to_display_name": self.reply_to_display_name,
            "recipients": [r.to_dict() for r in self.recipients],
            "headers": [h.to_dict() for h in self.headers],
            "mime_parts": [p.to_dict() for p in self.mime_parts],
            "plain_text_body": self.plain_text_body,
            "html_body": self.html_body,
            "has_attachments": self.has_attachments,
            "attachment_count": self.attachment_count,
            "total_mime_parts": self.total_mime_parts,
            "is_multipart": self.is_multipart,
            "root_content_type": self.root_content_type,
        }


class EmailStructureParser:
    """
    High-assurance RFC822 / MIME Email Structural Parser for Forensic Intelligence.
    Extracts envelope headers, MIME tree hierarchy, plain text and HTML bodies,
    preserving exact header sequence with security boundaries.
    """

    def __init__(
        self,
        max_depth: int = MAX_MIME_RECURSION_DEPTH,
        max_body_length: int = MAX_BODY_TEXT_LENGTH,
    ):
        self.max_depth = max_depth
        self.max_body_length = max_body_length

    def parse_bytes(self, raw_eml_bytes: bytes) -> ParsedEmailStructure:
        """
        Parses raw RFC822 email bytes into a structured forensic representation.
        """
        if not raw_eml_bytes:
            return ParsedEmailStructure()

        try:
            msg = email.message_from_bytes(raw_eml_bytes, policy=email.policy.default)
        except Exception as e:
            logger.warning(f"Default policy parsing failed, falling back to compat32: {e}")
            msg = email.message_from_bytes(raw_eml_bytes, policy=email.policy.compat32)

        structure = ParsedEmailStructure()

        # 1. Extract Core Headers
        structure.subject = safe_decode_header_str(msg.get("Subject"))
        from_header = msg.get("From")
        from_name, from_addr = extract_address_and_name(from_header)
        structure.sender_display_name = from_name
        structure.sender_address = from_addr

        # Date parsing
        date_header = msg.get("Date")
        utc_dt, raw_date_str = parse_rfc2822_date(date_header)
        structure.sent_at = utc_dt
        structure.raw_date_str = raw_date_str

        # Message-ID & Envelope
        raw_msg_id = msg.get("Message-ID") or msg.get("Message-Id") or msg.get("Resent-Message-ID")
        structure.message_id = sanitize_string(raw_msg_id)

        return_path_header = msg.get("Return-Path")
        _, return_path_addr = extract_address_and_name(return_path_header)
        structure.return_path = return_path_addr

        reply_to_header = msg.get("Reply-To")
        reply_name, reply_addr = extract_address_and_name(reply_to_header)
        structure.reply_to_display_name = reply_name
        structure.reply_to = reply_addr

        # 2. Extract Recipients (To, Cc, Bcc)
        recipients_list: List[ParsedRecipient] = []
        for r_type, header_key in [("TO", "To"), ("CC", "Cc"), ("BCC", "Bcc"), ("TO", "Resent-To"), ("CC", "Resent-Cc")]:
            header_vals = msg.get_all(header_key, [])
            for val in header_vals:
                parsed_addrs = extract_address_list(val)
                for d_name, addr in parsed_addrs:
                    recipients_list.append(
                        ParsedRecipient(
                            recipient_type=r_type,
                            address=addr,
                            display_name=d_name,
                        )
                    )
        structure.recipients = recipients_list

        # 3. Extract All Raw Headers preserving order
        headers_list: List[ParsedHeader] = []
        raw_headers = msg.items()
        for idx, (name, val) in enumerate(raw_headers[:MAX_HEADER_COUNT], start=1):
            decoded_val = safe_decode_header_str(val)
            headers_list.append(
                ParsedHeader(
                    header_name=name,
                    header_value=sanitize_string(val) or "",
                    normalized_value=decoded_val,
                    header_order=idx,
                )
            )
        structure.headers = headers_list

        # 4. MIME Structure and Body Extraction
        structure.is_multipart = msg.is_multipart()
        structure.root_content_type = msg.get_content_type()

        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        mime_parts_tree: List[ParsedMimePart] = []
        total_parts = [0]
        attachments_count = [0]

        self._walk_mime_tree(
            part=msg,
            depth=0,
            part_index=1,
            tree_output=mime_parts_tree,
            plain_text_parts=plain_text_parts,
            html_parts=html_parts,
            total_parts_counter=total_parts,
            attachments_counter=attachments_count,
        )

        structure.mime_parts = mime_parts_tree
        structure.total_mime_parts = total_parts[0]
        structure.attachment_count = attachments_count[0]
        structure.has_attachments = attachments_count[0] > 0

        # Consolidate primary plain text & HTML bodies safely
        if plain_text_parts:
            combined_text = "\n\n".join(plain_text_parts)
            structure.plain_text_body = sanitize_string(combined_text[: self.max_body_length])
        if html_parts:
            combined_html = "\n\n".join(html_parts)
            structure.html_body = sanitize_string(combined_html[: self.max_body_length])

        return structure

    def _walk_mime_tree(
        self,
        part: Any,
        depth: int,
        part_index: int,
        tree_output: List[ParsedMimePart],
        plain_text_parts: List[str],
        html_parts: List[str],
        total_parts_counter: List[int],
        attachments_counter: List[int],
    ) -> None:
        """
        Recursively walks MIME parts with recursion depth protection and size bounds.
        """
        if depth > self.max_depth:
            logger.warning(f"Exceeded max MIME recursion depth of {self.max_depth}")
            return

        total_parts_counter[0] += 1
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if filename:
            filename = safe_decode_header_str(filename)
        charset = part.get_content_charset() or "utf-8"
        transfer_encoding = part.get("Content-Transfer-Encoding", None)
        content_id = part.get("Content-ID", None)
        if content_id:
            content_id = sanitize_string(str(content_id).strip("<>"))

        # Calculate payload size
        payload = part.get_payload(decode=True)
        if payload is not None and isinstance(payload, (bytes, bytearray)):
            size_bytes = len(payload)
        else:
            raw_payload = part.get_payload()
            if isinstance(raw_payload, str):
                size_bytes = len(raw_payload.encode("utf-8", errors="replace"))
            else:
                size_bytes = 0

        # Attachment determination
        is_attachment = False
        if disposition in ("attachment", "inline") and filename:
            is_attachment = True
        elif filename is not None:
            is_attachment = True
        elif disposition == "attachment":
            is_attachment = True

        if is_attachment:
            attachments_counter[0] += 1

        mime_node = ParsedMimePart(
            part_index=total_parts_counter[0],
            content_type=content_type,
            content_disposition=disposition,
            filename=filename,
            charset=charset,
            transfer_encoding=transfer_encoding,
            size_bytes=size_bytes,
            is_attachment=is_attachment,
            content_id=content_id,
            sub_parts=[],
        )
        tree_output.append(mime_node)

        # Body text extraction if not an attachment
        if not is_attachment:
            if content_type == "text/plain":
                try:
                    if payload is not None and isinstance(payload, (bytes, bytearray)):
                        text_content = payload.decode(charset, errors="replace")
                    else:
                        text_content = str(part.get_payload() or "")
                    if text_content:
                        plain_text_parts.append(text_content)
                except Exception as e:
                    logger.debug(f"Error extracting plain text: {e}")
            elif content_type == "text/html":
                try:
                    if payload is not None and isinstance(payload, (bytes, bytearray)):
                        html_content = payload.decode(charset, errors="replace")
                    else:
                        html_content = str(part.get_payload() or "")
                    if html_content:
                        html_parts.append(html_content)
                except Exception as e:
                    logger.debug(f"Error extracting HTML: {e}")

        # Recurse if multipart
        if part.is_multipart():
            sub_parts = part.get_payload()
            if isinstance(sub_parts, list):
                for sub in sub_parts:
                    self._walk_mime_tree(
                        part=sub,
                        depth=depth + 1,
                        part_index=part_index + 1,
                        tree_output=mime_node.sub_parts,
                        plain_text_parts=plain_text_parts,
                        html_parts=html_parts,
                        total_parts_counter=total_parts_counter,
                        attachments_counter=attachments_counter,
                    )
