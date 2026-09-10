import uuid
import email
import email.policy
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.emails import Email, RelayHop, EmailAuthenticationResult
from app.parser.header_analyzer import (
    ReceivedHeaderParser,
    AuthenticationResultsParser,
    ParsedRelayHop,
    ParsedAuthenticationResult,
)

logger = logging.getLogger(__name__)


async def analyze_and_persist_headers(
    email_id: uuid.UUID,
    raw_bytes: bytes,
    db: AsyncSession,
) -> Tuple[List[ParsedRelayHop], ParsedAuthenticationResult]:
    """
    Parses transmission Received headers and authentication results from raw RFC822 bytes,
    and persists reconstructed RelayHop and EmailAuthenticationResult records into PostgreSQL.
    """
    if not raw_bytes:
        return [], ParsedAuthenticationResult()

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    # 1. Parse Received headers into chronological hops
    received_headers = msg.get_all("Received", [])
    hop_parser = ReceivedHeaderParser()
    parsed_hops = hop_parser.parse_received_headers(received_headers)

    # 2. Parse Authentication Results & Signatures
    auth_parser = AuthenticationResultsParser()
    parsed_auth = auth_parser.parse_authentication(msg)

    now_utc = datetime.now(timezone.utc)

    # 3. Clear previous relay hops and authentication results for idempotent re-analysis
    await db.execute(delete(RelayHop).where(RelayHop.email_id == email_id))
    await db.execute(delete(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id))

    # 4. Insert RelayHop records
    for hop in parsed_hops:
        hop_record = RelayHop(
            id=uuid.uuid4(),
            email_id=email_id,
            sequence_number=hop.sequence_number,
            source_host=hop.source_host,
            source_ip=hop.source_ip,
            destination_host=hop.destination_host,
            observed_at=hop.observed_at,
            reliability=hop.reliability,
            evidence={
                "protocol": hop.protocol,
                "queue_id": hop.queue_id,
                "envelope_to": hop.envelope_to,
                "tls_info": hop.tls_info,
                "raw_date_str": hop.raw_date_str,
                "transit_delay_seconds": hop.transit_delay_seconds,
                "raw_header": hop.raw_header,
            },
            created_at=now_utc,
        )
        db.add(hop_record)

    # 5. Insert EmailAuthenticationResult record
    auth_record = EmailAuthenticationResult(
        id=uuid.uuid4(),
        email_id=email_id,
        spf_result=parsed_auth.spf_result,
        dkim_result=parsed_auth.dkim_result,
        dmarc_result=parsed_auth.dmarc_result,
        from_alignment_result=parsed_auth.from_alignment_result,
        return_path=parsed_auth.return_path,
        reply_to=parsed_auth.reply_to,
        evidence=parsed_auth.to_dict(),
        created_at=now_utc,
    )
    db.add(auth_record)

    await db.commit()

    logger.info(
        f"Header analysis completed for email {email_id}: Hops={len(parsed_hops)}, "
        f"SPF={parsed_auth.spf_result}, DKIM={parsed_auth.dkim_result}, "
        f"DMARC={parsed_auth.dmarc_result}, Alignment={parsed_auth.from_alignment_result}"
    )

    return parsed_hops, parsed_auth
