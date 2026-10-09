import uuid
import logging
import asyncio
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
    persists intelligence records in PostgreSQL in high-performance batches,
    stores attachment evidence concurrently in MinIO, and returns the structured bundle.
    """
    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_eml_bytes=raw_bytes)
    now_utc = datetime.now(timezone.utc)

    # 1. Batch Persist Domains (Upsert / Find Existing)
    domain_id_map: Dict[str, uuid.UUID] = {}
    if bundle.domains:
        domain_names = [d.domain for d in bundle.domains]
        domain_stmt = select(Domain).where(Domain.normalized_domain.in_(domain_names))
        res = await db.execute(domain_stmt)
        for dom in res.scalars().all():
            domain_id_map[dom.normalized_domain] = dom.id

        new_domains = []
        for d in bundle.domains:
            if d.domain not in domain_id_map:
                nid = uuid.uuid4()
                new_domains.append(Domain(
                    id=nid,
                    normalized_domain=d.domain,
                    root_domain=d.root_domain,
                    first_seen_at=now_utc,
                    created_at=now_utc,
                    updated_at=now_utc,
                ))
                domain_id_map[d.domain] = nid
        if new_domains:
            db.add_all(new_domains)

    # 2. Batch Persist URLs & EmailURL Associations
    await db.execute(delete(EmailURL).where(EmailURL.email_id == email_id))

    if bundle.urls:
        url_hashes = [u.url_hash for u in bundle.urls]
        existing_urls_stmt = select(URL).where(URL.url_hash.in_(url_hashes))
        url_res = await db.execute(existing_urls_stmt)
        url_id_map: Dict[str, uuid.UUID] = {u.url_hash: u.id for u in url_res.scalars().all()}

        new_urls = []
        email_url_links = []
        for u in bundle.urls:
            if u.url_hash in url_id_map:
                url_id = url_id_map[u.url_hash]
            else:
                d_id = domain_id_map.get(u.domain) if u.domain else None
                url_id = uuid.uuid4()
                new_urls.append(URL(
                    id=url_id,
                    normalized_url=u.normalized_url,
                    url_hash=u.url_hash,
                    domain_id=d_id,
                    first_seen_at=now_utc,
                    created_at=now_utc,
                ))
                url_id_map[u.url_hash] = url_id

            email_url_links.append(EmailURL(
                email_id=email_id,
                url_id=url_id,
                context=u.context,
                created_at=now_utc,
            ))
        if new_urls:
            db.add_all(new_urls)
        if email_url_links:
            db.add_all(email_url_links)

    # 3. Batch Persist IP Addresses
    if bundle.ip_addresses:
        ip_strs = [ip.ip_address for ip in bundle.ip_addresses]
        existing_ips_stmt = select(IPAddress.ip_address).where(IPAddress.ip_address.in_(ip_strs))
        ip_res = await db.execute(existing_ips_stmt)
        existing_ip_set = set(ip_res.scalars().all())

        new_ips = []
        for ip in bundle.ip_addresses:
            if ip.ip_address not in existing_ip_set:
                new_ips.append(IPAddress(
                    id=uuid.uuid4(),
                    ip_address=ip.ip_address,
                    first_seen_at=now_utc,
                    created_at=now_utc,
                ))
                existing_ip_set.add(ip.ip_address)
        if new_ips:
            db.add_all(new_ips)

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

    # Parallel MinIO uploads for all attachments
    async def _upload_attachment_async(att_obj, obj_key):
        if storage.client is not None and att_obj.raw_payload_bytes:
            try:
                await asyncio.to_thread(
                    storage.upload_evidence_object,
                    bucket_name=settings.MINIO_DERIVED_BUCKET,
                    object_key=obj_key,
                    data=att_obj.raw_payload_bytes,
                    content_type=att_obj.content_type,
                    metadata={
                        "email_id": str(email_id),
                        "filename": att_obj.filename,
                        "sha256": att_obj.sha256_hash,
                        "md5": att_obj.md5_hash,
                        "size_bytes": str(att_obj.size_bytes),
                    },
                )
            except Exception as e:
                logger.warning(f"Could not upload attachment {att_obj.filename} to MinIO: {e}")

    upload_tasks = []
    att_evidence_list = []
    custody_events_list = []

    for att in bundle.attachments:
        att_id = uuid.uuid4()
        object_key = f"derived/attachments/{now_utc.year}/{now_utc.month:02d}/{att_id}_{att.filename}"
        upload_tasks.append(_upload_attachment_async(att, object_key))

        att_evidence_list.append(EvidenceObject(
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
        ))

        custody_events_list.append(CustodyEvent(
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
        ))

    # Execute all MinIO attachment uploads concurrently in thread pool
    if upload_tasks:
        await asyncio.gather(*upload_tasks)

    if att_evidence_list:
        db.add_all(att_evidence_list)
    if custody_events_list:
        db.add_all(custody_events_list)

    await db.commit()

    logger.info(
        f"Artifact extraction completed for email {email_id}: URLs={bundle.total_urls}, "
        f"Domains={bundle.total_domains}, IPs={bundle.total_ips}, Attachments={bundle.total_attachments}"
    )

    return bundle
