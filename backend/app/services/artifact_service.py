import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.core.config import settings
from app.core.storage import storage
from app.models.intelligence import Domain, URL, EmailURL, IPAddress
from app.models.evidence import EvidenceObject, CustodyEvent
from app.parser.artifact_extractor import (
    EmailArtifactExtractor,
    EmailArtifactBundle,
)

logger = logging.getLogger(__name__)


async def extract_and_persist_artifacts(
    email_id: uuid.UUID,
    raw_bytes: bytes,
    db: AsyncSession,
) -> EmailArtifactBundle:
    """
    Extracts URLs, Domains, IPs, and Attachments from raw RFC822 bytes,
    persists intelligence records in PostgreSQL, stores attachment evidence in MinIO,
    and returns the structured artifact bundle.
    """
    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml_bytes=raw_bytes)
    now_utc = datetime.now(timezone.utc)

    # 1. Persist Domains (Upsert / Find Existing)
    domain_id_map: Dict[str, uuid.UUID] = {}
    for d in bundle.domains:
        domain_stmt = select(Domain).where(Domain.normalized_domain == d.domain)
        res = await db.execute(domain_stmt)
        existing_domain = res.scalar_one_or_none()

        if existing_domain:
            domain_id_map[d.domain] = existing_domain.id
        else:
            new_domain = Domain(
                id=uuid.uuid4(),
                normalized_domain=d.domain,
                root_domain=d.root_domain,
                first_seen_at=now_utc,
                created_at=now_utc,
                updated_at=now_utc,
            )
            db.add(new_domain)
            domain_id_map[d.domain] = new_domain.id

    # 2. Persist URLs & EmailURL Associations
    # Clear previous email_urls for idempotent re-analysis
    await db.execute(delete(EmailURL).where(EmailURL.email_id == email_id))

    for u in bundle.urls:
        url_stmt = select(URL).where(URL.url_hash == u.url_hash)
        res = await db.execute(url_stmt)
        existing_url = res.scalar_one_or_none()

        if existing_url:
            url_id = existing_url.id
        else:
            d_id = domain_id_map.get(u.domain) if u.domain else None
            new_url = URL(
                id=uuid.uuid4(),
                normalized_url=u.normalized_url,
                url_hash=u.url_hash,
                domain_id=d_id,
                first_seen_at=now_utc,
                created_at=now_utc,
            )
            db.add(new_url)
            url_id = new_url.id

        # Add association
        email_url_link = EmailURL(
            email_id=email_id,
            url_id=url_id,
            context=u.context,
            created_at=now_utc,
        )
        db.add(email_url_link)

    # 3. Persist IP Addresses
    for ip in bundle.ip_addresses:
        ip_stmt = select(IPAddress).where(IPAddress.ip_address == ip.ip_address)
        res = await db.execute(ip_stmt)
        existing_ip = res.scalar_one_or_none()

        if not existing_ip:
            new_ip = IPAddress(
                id=uuid.uuid4(),
                ip_address=ip.ip_address,
                first_seen_at=now_utc,
                created_at=now_utc,
            )
            db.add(new_ip)

    # 4. Persist Attachments as Evidence Objects
    # Clear previous attachments for this email
    prev_att_stmt = select(EvidenceObject).where(
        EvidenceObject.email_id == email_id,
        EvidenceObject.evidence_type == "ATTACHMENT",
    )
    prev_att_res = await db.execute(prev_att_stmt)
    prev_attachments = prev_att_res.scalars().all()
    for pa in prev_attachments:
        await db.delete(pa)

    # Find parent evidence object ID
    parent_evidence_stmt = select(EvidenceObject).where(
        EvidenceObject.email_id == email_id,
        EvidenceObject.evidence_type == "ORIGINAL_EMAIL",
    )
    parent_res = await db.execute(parent_evidence_stmt)
    parent_evidence = parent_res.scalar_one_or_none()
    parent_id = parent_evidence.id if parent_evidence else None

    for att in bundle.attachments:
        att_id = uuid.uuid4()
        object_key = f"derived/attachments/{now_utc.year}/{now_utc.month:02d}/{att_id}_{att.filename}"

        # Upload binary attachment to MinIO
        try:
            if storage.client is not None and att.raw_payload_bytes:
                storage.upload_evidence_object(
                    bucket_name=settings.MINIO_DERIVED_BUCKET,
                    object_key=object_key,
                    data=att.raw_payload_bytes,
                    content_type=att.content_type,
                    metadata={
                        "email_id": str(email_id),
                        "filename": att.filename,
                        "sha256": att.sha256_hash,
                        "md5": att.md5_hash,
                        "size_bytes": str(att.size_bytes),
                    },
                )
        except Exception as e:
            logger.warning(f"Could not upload attachment {att.filename} to MinIO: {e}")

        # Store EvidenceObject
        att_evidence = EvidenceObject(
            id=att_id,
            email_id=email_id,
            parent_evidence_id=parent_id,
            evidence_type="ATTACHMENT",
            original_filename=att.filename,
            content_type=att.content_type,
            size_bytes=att.size_bytes,
            sha256_hash=att.sha256_hash,
            bucket_name=settings.MINIO_DERIVED_BUCKET,
            object_key=object_key,
            source_type="EXTRACTED_ATTACHMENT",
            acquired_at=now_utc,
            stored_at=now_utc,
            immutable=True,
            retention_status="ACTIVE",
            created_at=now_utc,
        )
        db.add(att_evidence)

        # Custody event
        custody = CustodyEvent(
            evidence_id=att_id,
            event_type="ACQUIRED",
            event_at=now_utc,
            event_metadata={
                "action": "ATTACHMENT_EXTRACTION",
                "sha256": att.sha256_hash,
                "md5": att.md5_hash,
                "size_bytes": att.size_bytes,
                "filename": att.filename,
                "is_dangerous": att.is_dangerous,
            },
            created_at=now_utc,
        )
        db.add(custody)

    await db.commit()

    logger.info(
        f"Artifact extraction completed for email {email_id}: URLs={bundle.total_urls}, "
        f"Domains={bundle.total_domains}, IPs={bundle.total_ips}, Attachments={bundle.total_attachments}"
    )

    return bundle
