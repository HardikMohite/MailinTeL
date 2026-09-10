import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.emails import Email, EmailHeader, EmailRecipient, EmailAuthenticationResult, RelayHop
from app.models.dna import EmailDNAProfile
from app.models.intelligence import Domain, URL, EmailURL
from app.models.evidence import EvidenceObject
from app.dna.dna_builder import EmailDNABuilder, EmailDNABundle

logger = logging.getLogger(__name__)


async def generate_and_persist_email_dna(
    email_id: uuid.UUID,
    db: AsyncSession,
    builder: Optional[EmailDNABuilder] = None,
) -> EmailDNABundle:
    """
    Gathers all forensic layers, compiles the Email DNA profile,
    and updates/inserts the EmailDNAProfile record in PostgreSQL.
    """
    dna_builder = builder or EmailDNABuilder()
    now_utc = datetime.now(timezone.utc)

    # 1. Fetch Email metadata
    stmt_email = select(Email).where(Email.id == email_id)
    res_email = await db.execute(stmt_email)
    email_obj = res_email.scalar_one_or_none()
    if not email_obj:
        raise ValueError(f"Email with ID '{email_id}' not found")

    # Fetch Recipients
    stmt_rec = select(EmailRecipient).where(EmailRecipient.email_id == email_id)
    res_rec = await db.execute(stmt_rec)
    recipients_objs = res_rec.scalars().all()
    recipients_list = [
        {"recipient_type": r.recipient_type, "address": r.address, "display_name": r.display_name}
        for r in recipients_objs
    ]

    email_metadata = {
        "subject": email_obj.subject,
        "sender_address": email_obj.sender_address,
        "sender_display_name": email_obj.sender_display_name,
        "sent_at": email_obj.sent_at.isoformat() if email_obj.sent_at else None,
        "recipients": recipients_list,
    }

    # 2. Fetch Headers
    stmt_headers = select(EmailHeader).where(EmailHeader.email_id == email_id).order_by(EmailHeader.header_order.asc())
    res_headers = await db.execute(stmt_headers)
    headers_objs = res_headers.scalars().all()
    headers_list = [
        {"header_name": h.header_name, "header_value": h.header_value, "header_order": h.header_order}
        for h in headers_objs
    ]

    # 3. Fetch Auth Results
    stmt_auth = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
    res_auth = await db.execute(stmt_auth)
    auth_obj = res_auth.scalar_one_or_none()
    auth_dict = {
        "spf_verdict": auth_obj.spf_result if auth_obj else None,
        "dkim_verdict": auth_obj.dkim_result if auth_obj else None,
        "dmarc_verdict": auth_obj.dmarc_result if auth_obj else None,
        "from_domain_aligned": auth_obj.from_alignment_result if auth_obj else None,
    } if auth_obj else {}

    # 4. Fetch Relay Hops
    stmt_hops = select(RelayHop).where(RelayHop.email_id == email_id).order_by(RelayHop.sequence_number.asc())
    res_hops = await db.execute(stmt_hops)
    hops_objs = res_hops.scalars().all()
    hops_list = [
        {
            "sequence_number": h.sequence_number,
            "source_host": h.source_host,
            "source_ip": h.source_ip,
            "destination_host": h.destination_host,
            "delay_seconds": (h.evidence.get("transit_delay_seconds") if h.evidence else None),
            "reliability": h.reliability,
        }
        for h in hops_objs
    ]

    # 5. Fetch Artifacts
    stmt_evidence = select(EvidenceObject).where(
        EvidenceObject.email_id == email_id,
        EvidenceObject.evidence_type == "ATTACHMENT",
    )
    res_evidence = await db.execute(stmt_evidence)
    evidence_objs = res_evidence.scalars().all()
    attachments_list = [
        {
            "filename": ev.original_filename,
            "sha256_hash": ev.sha256_hash,
            "size_bytes": ev.size_bytes,
            "extension": (ev.metadata_json.get("extension") if ev.metadata_json else ""),
        }
        for ev in evidence_objs
    ]

    stmt_urls = (
        select(URL.normalized_url)
        .join(EmailURL, EmailURL.url_id == URL.id)
        .where(EmailURL.email_id == email_id)
    )
    res_urls = await db.execute(stmt_urls)
    urls_list = [{"url": r[0]} for r in res_urls.all()]

    artifacts_dict = {
        "attachments": attachments_list,
        "urls": urls_list,
    }

    # 6. Fetch Domain Intelligence
    from app.services.domain_intel_service import enrich_email_domains
    try:
        domain_bundles = await enrich_email_domains(email_id=email_id, db=db)
        domain_intel_list = [b.to_dict() for b in domain_bundles]
    except Exception as e:
        logger.warning(f"Domain intel error during DNA generation: {e}")
        domain_intel_list = []

    # 7. Fetch Infrastructure Intelligence
    from app.services.infrastructure_service import enrich_email_infrastructure
    try:
        ip_bundles = await enrich_email_infrastructure(email_id=email_id, db=db)
        infra_intel_list = [b.to_dict() for b in ip_bundles]
    except Exception as e:
        logger.warning(f"Infrastructure intel error during DNA generation: {e}")
        infra_intel_list = []

    # 8. Build DNA Bundle
    bundle = dna_builder.build_dna_profile(
        email_id=str(email_id),
        email_metadata=email_metadata,
        headers=headers_list,
        structure={},
        auth_results=auth_dict,
        relay_hops=hops_list,
        artifacts=artifacts_dict,
        domain_intel=domain_intel_list,
        infrastructure_intel=infra_intel_list,
    )

    # 9. Upsert EmailDNAProfile in PostgreSQL
    stmt_dna = select(EmailDNAProfile).where(EmailDNAProfile.email_id == email_id)
    res_dna = await db.execute(stmt_dna)
    dna_rec = res_dna.scalar_one_or_none()

    if not dna_rec:
        dna_rec = EmailDNAProfile(
            id=uuid.uuid4(),
            email_id=email_id,
            content_fingerprint=bundle.content_fingerprint,
            technical_fingerprint=bundle.technical_fingerprint,
            infrastructure_fingerprint=bundle.infrastructure_fingerprint,
            behavioral_fingerprint=bundle.behavioral_fingerprint,
            temporal_fingerprint=bundle.temporal_fingerprint,
            dna_version=bundle.dna_version,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(dna_rec)
    else:
        dna_rec.content_fingerprint = bundle.content_fingerprint
        dna_rec.technical_fingerprint = bundle.technical_fingerprint
        dna_rec.infrastructure_fingerprint = bundle.infrastructure_fingerprint
        dna_rec.behavioral_fingerprint = bundle.behavioral_fingerprint
        dna_rec.temporal_fingerprint = bundle.temporal_fingerprint
        dna_rec.dna_version = bundle.dna_version
        dna_rec.updated_at = now_utc

    await db.commit()

    logger.info(
        f"Email DNA Profile generated and persisted for {email_id}: "
        f"Hash={bundle.overall_dna_hash[:16]}..., Version={bundle.dna_version}"
    )

    return bundle
