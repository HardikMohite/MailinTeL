import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.emails import Email, EmailHeader, EmailRecipient
from app.parser.email_parser import EmailStructureParser, ParsedEmailStructure

logger = logging.getLogger(__name__)

_structure_cache: Dict[str, ParsedEmailStructure] = {}


def get_cached_structure(email_id: str) -> Optional[ParsedEmailStructure]:
    return _structure_cache.get(email_id)


def cache_structure(email_id: str, structure: ParsedEmailStructure) -> None:
    _structure_cache[email_id] = structure


async def parse_and_persist_email(
    email_id: uuid.UUID,
    raw_bytes: bytes,
    db: AsyncSession,
) -> ParsedEmailStructure:
    """
    Parses raw RFC822 bytes and persists extracted structural metadata,
    headers, and recipients into PostgreSQL.
    """
    parser = EmailStructureParser()
    structure = parser.parse_bytes(raw_bytes)
    cache_structure(str(email_id), structure)

    # 1. Fetch existing Email record
    stmt = select(Email).where(Email.id == email_id)
    result = await db.execute(stmt)
    email_record = result.scalar_one_or_none()

    now_utc = datetime.now(timezone.utc)

    if email_record:
        # Update email model attributes
        email_record.subject = structure.subject
        email_record.sender_address = structure.sender_address
        email_record.sender_display_name = structure.sender_display_name
        email_record.sent_at = structure.sent_at
        email_record.message_id_header = structure.message_id
        if structure.message_id and not email_record.external_message_id:
            email_record.external_message_id = structure.message_id
        email_record.updated_at = now_utc

        # 2. Clear previous headers and recipients for idempotent re-parsing
        await db.execute(delete(EmailHeader).where(EmailHeader.email_id == email_id))
        await db.execute(delete(EmailRecipient).where(EmailRecipient.email_id == email_id))

        # 3. Insert extracted headers
        for h in structure.headers:
            header_record = EmailHeader(
                id=uuid.uuid4(),
                email_id=email_id,
                header_name=h.header_name,
                header_value=h.header_value,
                normalized_value=h.normalized_value,
                header_order=h.header_order,
                created_at=now_utc,
            )
            db.add(header_record)

        # 4. Insert extracted recipients
        for r in structure.recipients:
            recipient_record = EmailRecipient(
                id=uuid.uuid4(),
                email_id=email_id,
                recipient_type=r.recipient_type,
                address=r.address,
                display_name=r.display_name,
                created_at=now_utc,
            )
            db.add(recipient_record)

        await db.commit()
        await db.refresh(email_record)

        logger.info(
            f"Successfully parsed email {email_id}: Subject='{structure.subject}', "
            f"Headers={len(structure.headers)}, Recipients={len(structure.recipients)}, "
            f"Parts={structure.total_mime_parts}"
        )

    return structure
