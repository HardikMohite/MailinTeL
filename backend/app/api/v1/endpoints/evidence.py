import hashlib
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.core.config import settings
from app.core.storage import storage
from app.api.deps import get_current_user, require_roles, ANALYST_ROLES, CROSS_ORG_ROLES, CurrentUser
from app.models.evidence import EvidenceObject, CustodyEvent
from app.models.emails import Email, EmailSource

logger = logging.getLogger(__name__)

router = APIRouter()


async def _get_authorized_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession,
) -> EvidenceObject:
    """
    Shared ownership check for every evidence_id route below.

    SECURITY: evidence_objects has no organization_id of its own — ownership
    is derived transitively via evidence.email_id -> emails.source_id ->
    email_sources.organization_id. Every endpoint in this router MUST route
    through this helper rather than querying EvidenceObject directly, or it
    silently becomes cross-tenant accessible (any authenticated user from any
    organization could read/download/verify another organization's evidence
    just by knowing its UUID). Returns 404 — never 403 — for both "does not
    exist" and "belongs to another organization", matching the same
    indistinguishable-404 policy used for emails (see emails.py).
    """
    stmt = (
        select(EvidenceObject, EmailSource)
        .outerjoin(Email, EvidenceObject.email_id == Email.id)
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .where(EvidenceObject.id == evidence_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Evidence object with ID '{evidence_id}' not found",
    )
    if not row:
        raise not_found

    evidence, source_obj = row
    # Evidence with no linked email (e.g. a standalone/derived artifact) has
    # no organization to check against — fail closed only when we *can*
    # determine an owning org and it doesn't match the caller's. CROSS_ORG_ROLES
    # (CYBER_CELL_INVESTIGATOR, SYSTEM_ADMIN) are exempt from the org match,
    # matching get_authorized_email's cross-org bypass — otherwise a cross-org
    # investigator would get 404s on every other organization's evidence,
    # contradicting their cross-organization read scope in the RBAC matrix.
    source_org_id = source_obj.organization_id if source_obj else None
    if source_org_id is not None and (
        current_user.role_code not in CROSS_ORG_ROLES
        and source_org_id != current_user.organization_id
    ):
        raise not_found

    return evidence


class CustodyEventResponse(BaseModel):
    """
    Chain of custody event record.
    """
    id: str
    evidence_id: str
    event_type: str
    actor_user_id: Optional[str] = None
    case_id: Optional[str] = None
    event_at: str
    event_metadata: Optional[Dict[str, Any]] = None
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None
    created_at: str


class EvidenceObjectResponse(BaseModel):
    """
    Evidence metadata referencing MinIO storage and integrity hash.
    """
    id: str
    email_id: Optional[str] = None
    case_id: Optional[str] = None
    parent_evidence_id: Optional[str] = None
    evidence_type: str
    original_filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    bucket_name: str
    object_key: str
    immutable: bool
    retention_status: str
    acquired_at: str
    stored_at: str
    created_at: str


class EvidenceDownloadResponse(BaseModel):
    """
    Presigned download URL response for accessing preserved raw evidence.
    """
    evidence_id: str
    filename: str
    sha256_hash: str
    download_url: str
    expires_in_seconds: int = 3600
    message: str = "Presigned URL generated; download event recorded in chain-of-custody"


class EvidenceVerificationResponse(BaseModel):
    """
    Forensic cryptographic integrity verification report.
    """
    evidence_id: str
    original_filename: str
    stored_sha256: str
    computed_sha256: Optional[str] = None
    is_valid: bool
    status: str  # VERIFIED, TAMPERED, OBJECT_NOT_FOUND
    verified_at: str
    details: Dict[str, Any]


@router.get(
    "/{evidence_id}",
    response_model=EvidenceObjectResponse,
    summary="Get Evidence Object Metadata",
    description="Retrieve authoritative forensic metadata, SHA-256 hash, and MinIO storage location.",
)
async def get_evidence_metadata(
    evidence_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EvidenceObjectResponse:
    """Fetch evidence object record by UUID (scoped to the caller's organization)."""
    evidence = await _get_authorized_evidence(evidence_id, current_user, db)

    return EvidenceObjectResponse(
        id=str(evidence.id),
        email_id=str(evidence.email_id) if evidence.email_id else None,
        case_id=str(evidence.case_id) if evidence.case_id else None,
        parent_evidence_id=str(evidence.parent_evidence_id) if evidence.parent_evidence_id else None,
        evidence_type=evidence.evidence_type,
        original_filename=evidence.original_filename,
        content_type=evidence.content_type,
        size_bytes=evidence.size_bytes,
        sha256_hash=evidence.sha256_hash,
        bucket_name=evidence.bucket_name,
        object_key=evidence.object_key,
        immutable=evidence.immutable,
        retention_status=evidence.retention_status,
        acquired_at=evidence.acquired_at.isoformat(),
        stored_at=evidence.stored_at.isoformat(),
        created_at=evidence.created_at.isoformat(),
    )


@router.get(
    "/{evidence_id}/download",
    response_model=EvidenceDownloadResponse,
    summary="Get Presigned Evidence Download URL",
    description="Generate a secure, time-limited presigned download URL for preserved evidence and log custody event.",
)
async def get_evidence_download_url(
    evidence_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EvidenceDownloadResponse:
    """Generate time-limited presigned download URL and record VIEWED custody event."""
    evidence = await _get_authorized_evidence(evidence_id, current_user, db)

    # Generate presigned URL from MinIO storage manager
    expires_seconds = 3600
    try:
        download_url = storage.generate_presigned_download_url(
            bucket_name=evidence.bucket_name,
            object_key=evidence.object_key,
            expires_seconds=expires_seconds,
        )
    except Exception as e:
        logger.warning(f"Error generating presigned URL from MinIO: {e}")
        download_url = f"/api/v1/storage/objects/{evidence.bucket_name}/{evidence.object_key}"

    # Log chain of custody event for evidence access/download
    now_utc = datetime.now(timezone.utc)
    custody_event = CustodyEvent(
        evidence_id=evidence.id,
        event_type="VIEWED",
        event_at=now_utc,
        event_metadata={
            "action": "presigned_download_url_generated",
            "expires_in_seconds": expires_seconds,
            "filename": evidence.original_filename,
            "sha256": evidence.sha256_hash,
        },
        created_at=now_utc,
    )
    db.add(custody_event)
    await db.commit()

    logger.info(f"Generated download URL for evidence {evidence_id}, logged custody event")

    return EvidenceDownloadResponse(
        evidence_id=str(evidence.id),
        filename=evidence.original_filename,
        sha256_hash=evidence.sha256_hash,
        download_url=download_url,
        expires_in_seconds=expires_seconds,
    )


@router.post(
    "/{evidence_id}/verify",
    response_model=EvidenceVerificationResponse,
    summary="Verify Evidence Cryptographic Integrity",
    description=(
        "Retrieve the stored binary object from MinIO, recompute its SHA-256 checksum, "
        "and compare it against the immutable hash in PostgreSQL. Logs the verification outcome "
        "in the immutable chain-of-custody audit log."
    ),
)
async def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    # MVP-04: evidence/chain-of-custody verification is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
    db: AsyncSession = Depends(get_db),
) -> EvidenceVerificationResponse:
    """
    Perform forensic integrity verification comparing MinIO stored bytes against PostgreSQL SHA-256 hash.
    """
    evidence = await _get_authorized_evidence(evidence_id, current_user, db)

    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    # 1. Retrieve raw binary bytes from MinIO
    raw_data: Optional[bytes] = None
    try:
        if storage.client is not None:
            raw_data = storage.get_evidence_object(
                bucket_name=evidence.bucket_name,
                object_key=evidence.object_key,
            )
    except Exception as e:
        logger.error(f"Failed to retrieve object from storage for evidence {evidence_id}: {e}")

    # 2. Handle missing object in storage
    if raw_data is None:
        custody_event = CustodyEvent(
            evidence_id=evidence.id,
            event_type="VERIFICATION_FAILED",
            event_at=now_utc,
            event_metadata={
                "reason": "OBJECT_NOT_FOUND_IN_STORAGE",
                "bucket": evidence.bucket_name,
                "key": evidence.object_key,
            },
            created_at=now_utc,
        )
        db.add(custody_event)
        await db.commit()

        return EvidenceVerificationResponse(
            evidence_id=str(evidence.id),
            original_filename=evidence.original_filename,
            stored_sha256=evidence.sha256_hash,
            computed_sha256=None,
            is_valid=False,
            status="OBJECT_NOT_FOUND",
            verified_at=now_iso,
            details={
                "error": "The binary evidence object could not be retrieved from object storage.",
                "bucket": evidence.bucket_name,
                "key": evidence.object_key,
            },
        )

    # 3. Compute SHA-256 checksum of retrieved bytes
    computed_sha256 = hashlib.sha256(raw_data).hexdigest()
    is_valid = (computed_sha256.lower() == evidence.sha256_hash.lower())

    if is_valid:
        verification_status = "VERIFIED"
        custody_event = CustodyEvent(
            evidence_id=evidence.id,
            event_type="VERIFIED",
            event_at=now_utc,
            event_metadata={
                "status": "VERIFIED",
                "sha256": computed_sha256,
                "size_bytes": len(raw_data),
            },
            created_at=now_utc,
        )
        db.add(custody_event)
        await db.commit()

        logger.info(f"Evidence {evidence_id} integrity VERIFIED (SHA-256: {computed_sha256[:12]}...)")

        return EvidenceVerificationResponse(
            evidence_id=str(evidence.id),
            original_filename=evidence.original_filename,
            stored_sha256=evidence.sha256_hash,
            computed_sha256=computed_sha256,
            is_valid=True,
            status=verification_status,
            verified_at=now_iso,
            details={
                "message": "Cryptographic integrity verified. Stored hash matches object checksum exactly.",
                "algorithm": "SHA-256",
                "size_bytes": len(raw_data),
            },
        )
    else:
        verification_status = "TAMPERED"
        custody_event = CustodyEvent(
            evidence_id=evidence.id,
            event_type="VERIFICATION_FAILED",
            event_at=now_utc,
            event_metadata={
                "status": "TAMPERED",
                "stored_sha256": evidence.sha256_hash,
                "computed_sha256": computed_sha256,
                "size_bytes": len(raw_data),
            },
            created_at=now_utc,
        )
        db.add(custody_event)
        await db.commit()

        logger.critical(
            f"Evidence {evidence_id} INTEGRITY TAMPERING DETECTED! "
            f"Stored: {evidence.sha256_hash}, Computed: {computed_sha256}"
        )

        return EvidenceVerificationResponse(
            evidence_id=str(evidence.id),
            original_filename=evidence.original_filename,
            stored_sha256=evidence.sha256_hash,
            computed_sha256=computed_sha256,
            is_valid=False,
            status=verification_status,
            verified_at=now_iso,
            details={
                "alert": "CRITICAL: Hash mismatch detected. Evidence may have been altered or corrupted.",
                "stored_sha256": evidence.sha256_hash,
                "computed_sha256": computed_sha256,
                "algorithm": "SHA-256",
            },
        )


@router.get(
    "/{evidence_id}/custody",
    response_model=List[CustodyEventResponse],
    summary="Get Evidence Chain of Custody",
    description="Retrieve the complete chronological chain of custody event log for an evidence object.",
)
async def get_evidence_custody(
    evidence_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[CustodyEventResponse]:
    """Fetch chronological chain-of-custody events for an evidence object."""
    # Ownership check — also confirms the evidence exists.
    await _get_authorized_evidence(evidence_id, current_user, db)

    stmt = (
        select(CustodyEvent)
        .where(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.event_at)
    )
    result = await db.execute(stmt)
    events = result.scalars().all()

    return [
        CustodyEventResponse(
            id=str(event.id),
            evidence_id=str(event.evidence_id),
            event_type=event.event_type,
            actor_user_id=str(event.actor_user_id) if event.actor_user_id else None,
            case_id=str(event.case_id) if event.case_id else None,
            event_at=event.event_at.isoformat(),
            event_metadata=event.event_metadata,
            previous_event_hash=event.previous_event_hash,
            event_hash=event.event_hash,
            created_at=event.created_at.isoformat(),
        )
        for event in events
    ]
