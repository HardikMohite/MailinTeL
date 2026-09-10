import hashlib
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel, Field
from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException,
    Depends,
    Query,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db.session import get_db
from app.core.config import settings
from app.core.storage import storage
from app.core.redis import redis_manager
from app.core.tasks import job_manager, JobStage, JobStatus
from app.core.rate_limit import rate_limiter
from app.api.deps import get_current_user, require_organization_or_cross_org, CurrentUser, ANALYST_ROLES, CROSS_ORG_ROLES
from app.models.emails import Email, EmailSource, EmailHeader, EmailRecipient, RelayHop, EmailAuthenticationResult
from app.models.intelligence import Domain, URL, EmailURL, IPAddress
from app.models.evidence import EvidenceObject, CustodyEvent
import asyncio
import time
from app.services.parser_service import parse_and_persist_email, get_cached_structure, cache_structure
from app.services.header_analysis_service import analyze_and_persist_headers
from app.services.artifact_service import extract_and_persist_artifacts
from app.services.pipeline_service import run_full_email_analysis_pipeline
from app.parser.artifact_extractor import EmailArtifactExtractor

logger = logging.getLogger(__name__)

router = APIRouter()

# High-speed in-memory cache for email metadata endpoints
_EMAIL_CACHE: Dict[str, Tuple[float, Any]] = {}
_EMAIL_CACHE_TTL = 1800.0  # 30 minutes


async def invalidate_email_metadata_cache(email_id: uuid.UUID) -> None:
    """Invalidates cached metadata for an email."""
    try:
        prefix = str(email_id)
        keys_to_del = [k for k in _EMAIL_CACHE.keys() if prefix in k or k.startswith("list:")]
        for k in keys_to_del:
            _EMAIL_CACHE.pop(k, None)
        await redis_manager.delete(f"cache:email:details:{prefix}")
        await redis_manager.delete(f"cache:email:headers:{prefix}")
        await redis_manager.delete(f"cache:email:hops:{prefix}")
        await redis_manager.delete(f"cache:email:auth:{prefix}")
        await redis_manager.delete(f"cache:email:artifacts:{prefix}")
    except Exception as e:
        logger.warning(f"Email cache invalidation notice: {e}")


async def _get_authorized_email_and_evidence(
    email_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession,
):
    """
    Shared ownership check: loads (Email, EvidenceObject) and verifies the email's
    source organization matches the caller's organization. Returns 404 (never 403)
    for both "does not exist" and "belongs to someone else" so callers can't use
    this endpoint to enumerate which email IDs exist in other tenants.
    """
    stmt = (
        select(Email, EvidenceObject, EmailSource)
        .outerjoin(EvidenceObject, Email.id == EvidenceObject.email_id)
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .where(Email.id == email_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Email with ID '{email_id}' not found",
    )
    if not row:
        raise not_found

    email_obj, evidence_obj, source_obj = row
    source_org_id = source_obj.organization_id if source_obj else None
    if source_org_id is not None and current_user.role_code not in CROSS_ORG_ROLES and source_org_id != current_user.organization_id:
        raise not_found

    # SCOPING: plain USER accounts only reach emails they personally
    # uploaded; analyst/admin roles (ANALYST_ROLES) keep full org visibility.
    if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
        source_user_id = source_obj.user_id if source_obj else None
        if source_user_id is None or source_user_id != current_user.id:
            raise not_found

    return email_obj, evidence_obj

# Max allowed upload size: 25 MB
MAX_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml", ".rfc822", ".msg"}
ALLOWED_MIME_TYPES = {
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
    "message/rfc822-headers",
    "message/global",
}


class UploadEmailResponse(BaseModel):
    """
    Receipt returned immediately upon successful .eml upload.
    """
    email_id: str
    evidence_id: str
    job_id: str
    filename: str
    sha256_hash: str
    size_bytes: int
    analysis_status: str = "PENDING"
    qualification_status: str = "NORMAL"
    created_at: str
    message: str = "Email uploaded and queued for forensic analysis"


class EmailDetailResponse(BaseModel):
    """
    Normalized email detail response.
    """
    id: str
    source_type: str
    original_filename: Optional[str] = None
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    sender_display_name: Optional[str] = None
    sent_at: Optional[str] = None
    received_at: Optional[str] = None
    email_size_bytes: Optional[int] = None
    analysis_status: str
    qualification_status: str
    created_at: str
    updated_at: str
    sha256_hash: Optional[str] = None
    evidence_id: Optional[str] = None
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None


class EmailListResponse(BaseModel):
    total: int
    items: List[EmailDetailResponse]


class RecipientSchema(BaseModel):
    recipient_type: str  # TO, CC, BCC
    address: str
    display_name: Optional[str] = None


class HeaderSchema(BaseModel):
    header_name: str
    header_value: str
    normalized_value: Optional[str] = None
    header_order: int


class MimePartSchema(BaseModel):
    part_index: int
    content_type: str
    content_disposition: Optional[str] = None
    filename: Optional[str] = None
    charset: Optional[str] = None
    transfer_encoding: Optional[str] = None
    size_bytes: int
    is_attachment: bool
    content_id: Optional[str] = None
    sub_parts: List["MimePartSchema"] = Field(default_factory=list)


class EmailStructureResponse(BaseModel):
    email_id: str
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    sender_display_name: Optional[str] = None
    sent_at: Optional[str] = None
    raw_date_str: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_display_name: Optional[str] = None
    recipients: List[RecipientSchema] = Field(default_factory=list)
    plain_text_body: Optional[str] = None
    html_body: Optional[str] = None
    has_attachments: bool = False
    attachment_count: int = 0
    total_mime_parts: int = 0
    is_multipart: bool = False
    root_content_type: str = "text/plain"
    mime_parts: List[MimePartSchema] = Field(default_factory=list)


class EmailHeadersResponse(BaseModel):
    email_id: str
    total_headers: int
    headers: List[HeaderSchema]


class RelayHopSchema(BaseModel):
    sequence_number: int
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    destination_host: Optional[str] = None
    observed_at: Optional[str] = None
    reliability: str
    protocol: Optional[str] = None
    queue_id: Optional[str] = None
    envelope_to: Optional[str] = None
    tls_info: Optional[str] = None
    transit_delay_seconds: Optional[int] = None
    raw_header: Optional[str] = None


class RelayHopsResponse(BaseModel):
    email_id: str
    total_hops: int
    originating_ip: Optional[str] = None
    originating_host: Optional[str] = None
    hops: List[RelayHopSchema]


class DkimSignatureSchema(BaseModel):
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    body_hash: Optional[str] = None
    signature_preview: Optional[str] = None


class EmailAuthResponse(BaseModel):
    email_id: str
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    from_alignment_result: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    auth_serv_id: Optional[str] = None
    dkim_signatures: List[DkimSignatureSchema] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ExtractedURLSchema(BaseModel):
    url: str
    normalized_url: str
    url_hash: str
    domain: Optional[str] = None
    root_domain: Optional[str] = None
    context: str
    anchor_text: Optional[str] = None
    is_defanged: bool
    defanged_url: str


class ExtractedDomainSchema(BaseModel):
    domain: str
    root_domain: str
    source_contexts: List[str]
    is_suspicious_tld: bool
    is_punycode: bool


class ExtractedIPSchema(BaseModel):
    ip_address: str
    ip_version: int
    category: str
    source_contexts: List[str]


class ExtractedAttachmentSchema(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    extension: str
    is_dangerous: bool
    is_archive: bool
    has_double_extension: bool


class EmailArtifactsResponse(BaseModel):
    email_id: str
    total_urls: int
    total_domains: int
    total_ips: int
    total_attachments: int
    has_dangerous_attachments: bool
    urls: List[ExtractedURLSchema]
    domains: List[ExtractedDomainSchema]
    ip_addresses: List[ExtractedIPSchema]
    attachments: List[ExtractedAttachmentSchema]


# Magic-byte signatures for common executable/archive container formats. We don't
# block all of these outright (a .eml can legitimately contain a zipped attachment
# inside its MIME structure), but a file whose *top-level* bytes are a bare
# executable is never a valid RFC822 message and is rejected outright.
_DANGEROUS_TOP_LEVEL_SIGNATURES = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "Linux ELF executable",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class executable",
    b"\xfe\xed\xfa": "Mach-O executable",
    b"%PDF": "PDF document",
}


def sanitize_filename(filename: str) -> str:
    """
    Strip directory components and any characters that could enable path
    traversal or be misinterpreted downstream, while preserving the extension.
    We never use the client-supplied filename as a storage path (object keys
    are always server-generated UUIDs) — this only protects the *metadata*
    value shown back to the user and stored in the DB.
    """
    import os
    import re
    base = os.path.basename(filename or "uploaded_email.eml")
    base = base.replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._\-]", "_", base)
    return base[:255] or "uploaded_email.eml"


def validate_uploaded_file(file: UploadFile, content: bytes) -> None:
    """Validate filename extension, MIME type, content signature, and file size."""
    filename = file.filename or ""
    lower_filename = filename.lower()

    # Reject path traversal / null bytes in the original filename outright.
    if ".." in filename or "/" in filename or "\\" in filename or "\x00" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename contains invalid path characters.",
        )

    # Check extension
    if not any(lower_filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid file extension for '{filename}'. "
                f"Only RFC822 email files ({', '.join(ALLOWED_EXTENSIONS)}) are supported."
            ),
        )

    # Check file size
    size_bytes = len(content)
    if size_bytes == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"The uploaded file '{filename}' is empty (0 bytes).",
        )

    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"The uploaded file exceeds the maximum permitted size of "
                f"{MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB (file size: {size_bytes / (1024 * 1024):.2f}MB)."
            ),
        )

    # Content-sniffing: a genuine .eml is 7-bit/8-bit text starting with RFC822
    # header lines. Reject anything whose top-level bytes are a known
    # executable/binary container signature, regardless of its claimed extension —
    # this stops a renamed .exe/.pdf being smuggled in as "invoice.eml".
    head = content[:8]
    for signature, label in _DANGEROUS_TOP_LEVEL_SIGNATURES.items():
        if head.startswith(signature):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Uploaded file content does not match an RFC822 email (detected: {label}).",
            )


@router.post(
    "/upload",
    response_model=UploadEmailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload .eml Evidence File",
    description=(
        "Ingest an RFC822 email file (.eml). Calculates SHA-256 integrity hash, preserves the "
        "original binary object in MinIO object storage, creates evidence custody records, parses "
        "structural headers & recipients, analyzes transmission hops/auth, extracts IOC artifacts, and dispatches analysis job."
    ),
    dependencies=[Depends(rate_limiter(key_prefix="upload", max_requests=30, window_seconds=300))],
)
async def upload_eml_file(
    file: UploadFile = File(..., description="The .eml or RFC822 format email file to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
) -> UploadEmailResponse:
    """
    Accepts multipart .eml upload, preserves evidence, parses structure, creates database records,
    and initializes background analysis.
    """
    # 1. Read file content and validate
    content = await file.read()
    validate_uploaded_file(file, content)

    filename = sanitize_filename(file.filename or "uploaded_email.eml")
    content_type = file.content_type or "message/rfc822"
    size_bytes = len(content)

    # 2. Calculate authoritative SHA-256 hash
    sha256_hash = hashlib.sha256(content).hexdigest()
    now_utc = datetime.now(timezone.utc)
    email_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    source_id = uuid.uuid4()

    # 3. Store original object in MinIO (year/month partitioned)
    object_key = f"originals/emails/{now_utc.year}/{now_utc.month:02d}/{evidence_id}.eml"
    storage_metadata = {
        "evidence_id": str(evidence_id),
        "email_id": str(email_id),
        "original_filename": filename,
        "content_type": content_type,
        "sha256": sha256_hash,
        "source_type": "FILE_UPLOAD",
        "acquired_at": now_utc.isoformat(),
    }

    try:
        if storage.client is not None:
            storage.upload_evidence_object(
                bucket_name=settings.evidence_bucket,
                object_key=object_key,
                data=content,
                content_type=content_type,
                metadata=storage_metadata,
            )
    except Exception as e:
        logger.warning(f"Storage warning during upload: {e}")

    # 4. Create database records in PostgreSQL
    email_source = EmailSource(
        id=source_id,
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        source_type="FILE_UPLOAD",
        source_provider="GENERIC",
        source_reference=filename,
        metadata_json={
            "original_filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
        },
        created_at=now_utc,
    )
    db.add(email_source)

    email_record = Email(
        id=email_id,
        source_id=source_id,
        organization_id=current_user.organization_id,
        email_size_bytes=size_bytes,
        analysis_status="PENDING",
        qualification_status="NORMAL",
        created_at=now_utc,
        updated_at=now_utc,
    )
    db.add(email_record)
    await db.flush()

    evidence_record = EvidenceObject(
        id=evidence_id,
        email_id=email_id,
        evidence_type="ORIGINAL_EMAIL",
        original_filename=filename,
        content_type=content_type,
        size_bytes=size_bytes,
        sha256_hash=sha256_hash,
        bucket_name=settings.evidence_bucket,
        object_key=object_key,
        source_type="UPLOAD",
        acquired_at=now_utc,
        stored_at=now_utc,
        immutable=True,
        retention_status="ACTIVE",
        created_at=now_utc,
    )
    db.add(evidence_record)
    await db.flush()

    custody_event = CustodyEvent(
        evidence_id=evidence_id,
        event_type="ACQUIRED",
        actor_user_id=current_user.id,
        event_at=now_utc,
        event_metadata={
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
            "filename": filename,
            "source": "api_upload",
        },
        created_at=now_utc,
    )
    db.add(custody_event)

    await db.commit()

    # 5. Parse email structure and persist headers/recipients into DB
    try:
        await parse_and_persist_email(email_id=email_id, raw_bytes=content, db=db)
    except Exception as e:
        logger.error(f"Error parsing email structure during upload for {email_id}: {e}")

    # 6. Parse and persist transmission headers and authentication results
    try:
        await analyze_and_persist_headers(email_id=email_id, raw_bytes=content, db=db)
    except Exception as e:
        logger.error(f"Error analyzing transmission headers during upload for {email_id}: {e}")

    # 7. Extract and persist forensic artifacts (URLs, Domains, IPs, Attachments)
    try:
        await extract_and_persist_artifacts(email_id=email_id, raw_bytes=content, db=db)
    except Exception as e:
        logger.error(f"Error extracting artifacts during upload for {email_id}: {e}")

    # 8. Create and queue background job
    job = await job_manager.create_job(
        job_type="EMAIL_ANALYSIS",
        email_id=str(email_id),
        organization_id=str(current_user.organization_id) if current_user.organization_id else None,
        metadata={
            "filename": filename,
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
            "evidence_id": str(evidence_id),
            "object_key": object_key,
        },
    )

    # 9. Dispatch the job as an actual background asyncio task. Without this call the
    # job record above sits in PENDING/QUEUED forever and the frontend's processing
    # timeline polls indefinitely — this is what actually runs the full downstream
    # pipeline (explainable scoring, threat-intel enrichment, DNA fingerprinting,
    # semantic similarity, campaign correlation, infrastructure geolocation).
    job_manager.dispatch_background_task(
        job.job_id,
        run_full_email_analysis_pipeline,
        email_id=str(email_id),
    )

    logger.info(
        f"Uploaded .eml evidence {evidence_id} (email_id: {email_id}, sha256: {sha256_hash[:12]}...), "
        f"analysis job {job.job_id} dispatched."
    )

    return UploadEmailResponse(
        email_id=str(email_id),
        evidence_id=str(evidence_id),
        job_id=job.job_id,
        filename=filename,
        sha256_hash=sha256_hash,
        size_bytes=size_bytes,
        analysis_status="PENDING",
        qualification_status="NORMAL",
        created_at=now_utc.isoformat(),
        message="Email successfully uploaded, parsed, and queued for forensic analysis",
    )


@router.get(
    "/{email_id}/structure",
    response_model=EmailStructureResponse,
    summary="Get Parsed Email Structure & MIME Hierarchy",
    description="Retrieve parsed RFC822 metadata, recipients, body previews, and recursive MIME part tree.",
)
async def get_email_structure(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailStructureResponse:
    """Retrieve full structural decomposition of an email."""
    email_obj, evidence_obj = await _get_authorized_email_and_evidence(email_id, current_user, db)

    recipients_stmt = select(EmailRecipient).where(EmailRecipient.email_id == email_id)
    recipients_res = await db.execute(recipients_stmt)
    recipients_rows = recipients_res.scalars().all()

    recipients_list = [
        RecipientSchema(
            recipient_type=r.recipient_type,
            address=r.address,
            display_name=r.display_name,
        )
        for r in recipients_rows
    ]

    from app.parser.email_parser import EmailStructureParser, ParsedEmailStructure
    parser = EmailStructureParser()
    parsed = get_cached_structure(str(email_id))

    if not parsed and evidence_obj and evidence_obj.object_key:
        try:
            data_res = await asyncio.to_thread(
                storage.get_evidence_object,
                bucket_name=evidence_obj.bucket_name,
                object_key=evidence_obj.object_key,
            )
            raw_bytes = data_res[0] if isinstance(data_res, tuple) else data_res
            parsed = parser.parse_bytes(raw_bytes)
            cache_structure(str(email_id), parsed)
        except Exception as e:
            logger.warning(f"Could not load storage object for email {email_id}: {e}")
            parsed = ParsedEmailStructure()
    elif not parsed:
        parsed = ParsedEmailStructure()

    return EmailStructureResponse(
        email_id=str(email_obj.id),
        subject=parsed.subject or email_obj.subject,
        sender_address=parsed.sender_address or email_obj.sender_address,
        sender_display_name=parsed.sender_display_name or email_obj.sender_display_name,
        sent_at=(parsed.sent_at or email_obj.sent_at).isoformat() if (parsed.sent_at or email_obj.sent_at) else None,
        raw_date_str=parsed.raw_date_str,
        message_id=parsed.message_id or email_obj.message_id_header,
        return_path=parsed.return_path,
        reply_to=parsed.reply_to,
        reply_to_display_name=parsed.reply_to_display_name,
        recipients=recipients_list if recipients_list else [RecipientSchema(recipient_type=r.recipient_type, address=r.address, display_name=r.display_name) for r in parsed.recipients],
        plain_text_body=parsed.plain_text_body,
        html_body=parsed.html_body,
        has_attachments=parsed.has_attachments,
        attachment_count=parsed.attachment_count,
        total_mime_parts=parsed.total_mime_parts,
        is_multipart=parsed.is_multipart,
        root_content_type=parsed.root_content_type,
        mime_parts=[MimePartSchema(**p.to_dict()) for p in parsed.mime_parts],
    )


@router.get(
    "/{email_id}/headers",
    response_model=EmailHeadersResponse,
    summary="Get Extracted Email Headers",
    description="Retrieve all RFC822 headers extracted from the email in their original sequence.",
)
async def get_email_headers(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailHeadersResponse:
    """Retrieve ordered RFC822 headers for an email."""
    await _get_authorized_email_and_evidence(email_id, current_user, db)

    cache_key = f"headers:{email_id}"
    now = time.time()
    if cache_key in _EMAIL_CACHE:
        ts, data = _EMAIL_CACHE[cache_key]
        if now - ts < _EMAIL_CACHE_TTL:
            return EmailHeadersResponse(**data)
    try:
        r_data = await redis_manager.get_json(f"cache:email:{cache_key}")
        if r_data:
            _EMAIL_CACHE[cache_key] = (now, r_data)
            return EmailHeadersResponse(**r_data)
    except Exception:
        pass

    stmt = select(EmailHeader).where(EmailHeader.email_id == email_id).order_by(EmailHeader.header_order)
    result = await db.execute(stmt)
    headers_rows = result.scalars().all()

    header_items = [
        HeaderSchema(
            header_name=h.header_name,
            header_value=h.header_value,
            normalized_value=h.normalized_value,
            header_order=h.header_order,
        )
        for h in headers_rows
    ]

    resp = EmailHeadersResponse(
        email_id=str(email_id),
        total_headers=len(header_items),
        headers=header_items,
    )
    _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
    try:
        await redis_manager.set_json(f"cache:email:{cache_key}", resp.model_dump(), expire_seconds=1800)
    except Exception:
        pass
    return resp


@router.get(
    "/{email_id}/hops",
    response_model=RelayHopsResponse,
    summary="Get Reconstructed SMTP Relay Hops",
    description="Retrieve reconstructed chronological SMTP relay hops, transit delays, and reliability classifications.",
)
async def get_email_relay_hops(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> RelayHopsResponse:
    """Retrieve chronological SMTP relay hops for an email."""
    await _get_authorized_email_and_evidence(email_id, current_user, db)

    cache_key = f"hops:{email_id}"
    now = time.time()
    if cache_key in _EMAIL_CACHE:
        ts, data = _EMAIL_CACHE[cache_key]
        if now - ts < _EMAIL_CACHE_TTL:
            return RelayHopsResponse(**data)
    try:
        r_data = await redis_manager.get_json(f"cache:email:{cache_key}")
        if r_data:
            _EMAIL_CACHE[cache_key] = (now, r_data)
            return RelayHopsResponse(**r_data)
    except Exception:
        pass

    stmt = select(RelayHop).where(RelayHop.email_id == email_id).order_by(RelayHop.sequence_number)
    result = await db.execute(stmt)
    hops_rows = result.scalars().all()

    hop_items = [
        RelayHopSchema(
            sequence_number=h.sequence_number,
            source_host=h.source_host,
            source_ip=h.source_ip,
            destination_host=h.destination_host,
            observed_at=h.observed_at.isoformat() if h.observed_at else None,
            reliability=h.reliability,
            protocol=h.evidence.get("protocol") if h.evidence else None,
            queue_id=h.evidence.get("queue_id") if h.evidence else None,
            envelope_to=h.evidence.get("envelope_to") if h.evidence else None,
            tls_info=h.evidence.get("tls_info") if h.evidence else None,
            transit_delay_seconds=h.evidence.get("transit_delay_seconds") if h.evidence else None,
            raw_header=h.evidence.get("raw_header") if h.evidence else None,
        )
        for h in hops_rows
    ]

    originating_ip = hop_items[0].source_ip if hop_items else None
    originating_host = hop_items[0].source_host if hop_items else None

    resp = RelayHopsResponse(
        email_id=str(email_id),
        total_hops=len(hop_items),
        originating_ip=originating_ip,
        originating_host=originating_host,
        hops=hop_items,
    )
    _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
    try:
        await redis_manager.set_json(f"cache:email:{cache_key}", resp.model_dump(), expire_seconds=1800)
    except Exception:
        pass
    return resp


@router.get(
    "/{email_id}/auth",
    response_model=EmailAuthResponse,
    summary="Get Email Authentication Results (SPF, DKIM, DMARC)",
    description="Retrieve cryptographic authentication verdicts, DKIM signature details, and From-domain alignment.",
)
async def get_email_auth_results(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailAuthResponse:
    """Retrieve SPF, DKIM, DMARC, and alignment results."""
    await _get_authorized_email_and_evidence(email_id, current_user, db)

    cache_key = f"auth:{email_id}"
    now = time.time()
    if cache_key in _EMAIL_CACHE:
        ts, data = _EMAIL_CACHE[cache_key]
        if now - ts < _EMAIL_CACHE_TTL:
            return EmailAuthResponse(**data)
    try:
        r_data = await redis_manager.get_json(f"cache:email:{cache_key}")
        if r_data:
            _EMAIL_CACHE[cache_key] = (now, r_data)
            return EmailAuthResponse(**r_data)
    except Exception:
        pass

    stmt = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
    result = await db.execute(stmt)
    auth_obj = result.scalar_one_or_none()

    if not auth_obj:
        resp = EmailAuthResponse(
            email_id=str(email_id),
            spf_result="NONE",
            dkim_result="NONE",
            dmarc_result="NONE",
            from_alignment_result="NONE",
        )
        _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
        return resp

    evidence_dict = auth_obj.evidence or {}
    dkim_sigs = [
        DkimSignatureSchema(**s)
        for s in evidence_dict.get("dkim_signatures", [])
    ]

    resp = EmailAuthResponse(
        email_id=str(email_id),
        spf_result=auth_obj.spf_result,
        dkim_result=auth_obj.dkim_result,
        dmarc_result=auth_obj.dmarc_result,
        from_alignment_result=auth_obj.from_alignment_result,
        return_path=auth_obj.return_path,
        reply_to=auth_obj.reply_to,
        auth_serv_id=evidence_dict.get("auth_serv_id"),
        dkim_signatures=dkim_sigs,
        evidence=evidence_dict,
    )
    _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
    try:
        await redis_manager.set_json(f"cache:email:{cache_key}", resp.model_dump(), expire_seconds=1800)
    except Exception:
        pass
    return resp


@router.get(
    "/{email_id}/artifacts",
    response_model=EmailArtifactsResponse,
    summary="Get Extracted Email Artifacts (URLs, Domains, IPs, Attachments)",
    description="Retrieve all forensic artifacts extracted from the email with normalization, defanging, and hash verification.",
)
async def get_email_artifacts(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailArtifactsResponse:
    """Retrieve extracted IOC artifacts and attachments for an email."""
    _, evidence_obj = await _get_authorized_email_and_evidence(email_id, current_user, db)

    cache_key = f"artifacts:{email_id}"
    now = time.time()
    if cache_key in _EMAIL_CACHE:
        ts, data = _EMAIL_CACHE[cache_key]
        if now - ts < _EMAIL_CACHE_TTL:
            return EmailArtifactsResponse(**data)
    try:
        r_data = await redis_manager.get_json(f"cache:email:{cache_key}")
        if r_data:
            _EMAIL_CACHE[cache_key] = (now, r_data)
            return EmailArtifactsResponse(**r_data)
    except Exception:
        pass

    if not evidence_obj or not evidence_obj.object_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No stored evidence object found for email '{email_id}'",
        )

    try:
        raw_bytes = storage.get_evidence_object(
            bucket_name=evidence_obj.bucket_name,
            object_key=evidence_obj.object_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch evidence from object storage: {e}",
        )

    extractor = EmailArtifactExtractor()
    bundle = extractor.extract_artifacts(raw_bytes)

    resp = EmailArtifactsResponse(
        email_id=str(email_id),
        total_urls=bundle.total_urls,
        total_domains=bundle.total_domains,
        total_ips=bundle.total_ips,
        total_attachments=bundle.total_attachments,
        has_dangerous_attachments=bundle.has_dangerous_attachments,
        urls=[ExtractedURLSchema(**u.to_dict()) for u in bundle.urls],
        domains=[ExtractedDomainSchema(**d.to_dict()) for d in bundle.domains],
        ip_addresses=[ExtractedIPSchema(**i.to_dict()) for i in bundle.ip_addresses],
        attachments=[ExtractedAttachmentSchema(**a.to_dict()) for a in bundle.attachments],
    )
    _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
    try:
        await redis_manager.set_json(f"cache:email:{cache_key}", resp.model_dump(), expire_seconds=1800)
    except Exception:
        pass
    return resp


@router.post(
    "/{email_id}/extract-artifacts",
    response_model=EmailArtifactsResponse,
    summary="Trigger Artifact Extraction & Persistence",
    description="Explicitly re-run artifact extraction and sync extracted URLs, domains, IPs, and attachments to the database and MinIO.",
)
async def trigger_artifact_extraction(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailArtifactsResponse:
    """Explicitly trigger forensic artifact extraction on stored evidence."""
    _, evidence_obj = await _get_authorized_email_and_evidence(email_id, current_user, db)

    if not evidence_obj or not evidence_obj.object_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No stored evidence object found for email '{email_id}'",
        )

    try:
        raw_bytes = storage.get_evidence_object(
            bucket_name=evidence_obj.bucket_name,
            object_key=evidence_obj.object_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch evidence from object storage: {e}",
        )

    bundle = await extract_and_persist_artifacts(email_id=email_id, raw_bytes=raw_bytes, db=db)

    return EmailArtifactsResponse(
        email_id=str(email_id),
        total_urls=bundle.total_urls,
        total_domains=bundle.total_domains,
        total_ips=bundle.total_ips,
        total_attachments=bundle.total_attachments,
        has_dangerous_attachments=bundle.has_dangerous_attachments,
        urls=[ExtractedURLSchema(**u.to_dict()) for u in bundle.urls],
        domains=[ExtractedDomainSchema(**d.to_dict()) for d in bundle.domains],
        ip_addresses=[ExtractedIPSchema(**i.to_dict()) for i in bundle.ip_addresses],
        attachments=[ExtractedAttachmentSchema(**a.to_dict()) for a in bundle.attachments],
    )


@router.post(
    "/{email_id}/analyze-headers",
    response_model=RelayHopsResponse,
    summary="Trigger Transmission Header & Authentication Analysis",
    description="Re-run Received relay hop extraction and SPF/DKIM/DMARC analysis on stored evidence.",
)
async def trigger_header_analysis(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> RelayHopsResponse:
    """Explicitly trigger transmission header and authentication analysis."""
    _, evidence_obj = await _get_authorized_email_and_evidence(email_id, current_user, db)

    if not evidence_obj or not evidence_obj.object_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No stored evidence object found for email '{email_id}'",
        )

    try:
        raw_bytes = storage.get_evidence_object(
            bucket_name=evidence_obj.bucket_name,
            object_key=evidence_obj.object_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch evidence from object storage: {e}",
        )

    parsed_hops, _ = await analyze_and_persist_headers(email_id=email_id, raw_bytes=raw_bytes, db=db)

    hop_items = [
        RelayHopSchema(
            sequence_number=h.sequence_number,
            source_host=h.source_host,
            source_ip=h.source_ip,
            destination_host=h.destination_host,
            observed_at=h.observed_at.isoformat() if h.observed_at else None,
            reliability=h.reliability,
            protocol=h.evidence.get("protocol") if h.evidence else None,
            queue_id=h.evidence.get("queue_id") if h.evidence else None,
            envelope_to=h.evidence.get("envelope_to") if h.evidence else None,
            tls_info=h.evidence.get("tls_info") if h.evidence else None,
            transit_delay_seconds=h.evidence.get("transit_delay_seconds") if h.evidence else None,
            raw_header=h.evidence.get("raw_header") if h.evidence else None,
        )
        for h in parsed_hops
    ]

    return RelayHopsResponse(
        email_id=str(email_id),
        total_hops=len(hop_items),
        originating_ip=hop_items[0].source_ip if hop_items else None,
        originating_host=hop_items[0].source_host if hop_items else None,
        hops=hop_items,
    )


@router.post(
    "/{email_id}/parse",
    response_model=EmailStructureResponse,
    summary="Trigger Email Re-parsing",
    description="Fetch original evidence from MinIO and execute comprehensive RFC822/MIME parsing and DB sync.",
)
async def trigger_email_parse(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailStructureResponse:
    """Explicitly trigger parsing of email from stored MinIO evidence."""
    email_obj, evidence_obj = await _get_authorized_email_and_evidence(email_id, current_user, db)

    if not evidence_obj or not evidence_obj.object_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No stored evidence object found for email '{email_id}'",
        )

    try:
        raw_bytes = storage.get_evidence_object(
            bucket_name=evidence_obj.bucket_name,
            object_key=evidence_obj.object_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch evidence from object storage: {e}",
        )

    structure = await parse_and_persist_email(email_id=email_id, raw_bytes=raw_bytes, db=db)
    await analyze_and_persist_headers(email_id=email_id, raw_bytes=raw_bytes, db=db)
    await extract_and_persist_artifacts(email_id=email_id, raw_bytes=raw_bytes, db=db)

    return EmailStructureResponse(
        email_id=str(email_obj.id),
        subject=structure.subject,
        sender_address=structure.sender_address,
        sender_display_name=structure.sender_display_name,
        sent_at=structure.sent_at.isoformat() if structure.sent_at else None,
        raw_date_str=structure.raw_date_str,
        message_id=structure.message_id,
        return_path=structure.return_path,
        reply_to=structure.reply_to,
        reply_to_display_name=structure.reply_to_display_name,
        recipients=[RecipientSchema(recipient_type=r.recipient_type, address=r.address, display_name=r.display_name) for r in structure.recipients],
        plain_text_body=structure.plain_text_body,
        html_body=structure.html_body,
        has_attachments=structure.has_attachments,
        attachment_count=structure.attachment_count,
        total_mime_parts=structure.total_mime_parts,
        is_multipart=structure.is_multipart,
        root_content_type=structure.root_content_type,
        mime_parts=[MimePartSchema(**p.to_dict()) for p in structure.mime_parts],
    )


@router.get(
    "/{email_id}",
    response_model=EmailDetailResponse,
    summary="Get Email Ingestion Details",
    description="Retrieve normalized metadata, forensic status, and SHA-256 reference for an ingested email.",
)
async def get_email_details(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailDetailResponse:
    """Retrieve detailed email record by UUID."""
    cache_key = f"details:{email_id}"
    now = time.time()
    if cache_key in _EMAIL_CACHE:
        ts, data = _EMAIL_CACHE[cache_key]
        if now - ts < _EMAIL_CACHE_TTL:
            return EmailDetailResponse(**data)
    try:
        r_data = await redis_manager.get_json(f"cache:email:{cache_key}")
        if r_data:
            _EMAIL_CACHE[cache_key] = (now, r_data)
            return EmailDetailResponse(**r_data)
    except Exception:
        pass

    stmt = (
        select(Email, EmailSource, EvidenceObject)
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .outerjoin(EvidenceObject, Email.id == EvidenceObject.email_id)
        .where(Email.id == email_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Email with ID '{email_id}' not found",
    )
    if not row:
        raise not_found

    email, source, evidence = row
    source_org_id = source.organization_id if source else None
    if source_org_id is not None and current_user.role_code not in CROSS_ORG_ROLES and source_org_id != current_user.organization_id:
        raise not_found

    resp = EmailDetailResponse(
        id=str(email.id),
        source_type=source.source_type if source else "UNKNOWN",
        original_filename=evidence.original_filename if evidence else (source.source_reference if source else None),
        subject=email.subject,
        sender_address=email.sender_address,
        sender_display_name=email.sender_display_name,
        sent_at=email.sent_at.isoformat() if email.sent_at else None,
        received_at=email.received_at.isoformat() if email.received_at else None,
        email_size_bytes=email.email_size_bytes,
        analysis_status=email.analysis_status,
        qualification_status=email.qualification_status,
        created_at=(email.created_at or datetime.now(timezone.utc)).isoformat(),
        updated_at=(email.updated_at or datetime.now(timezone.utc)).isoformat(),
        sha256_hash=evidence.sha256_hash if evidence else None,
        evidence_id=str(evidence.id) if evidence else None,
    )
    _EMAIL_CACHE[cache_key] = (now, resp.model_dump())
    try:
        await redis_manager.set_json(f"cache:email:{cache_key}", resp.model_dump(), expire_seconds=1800)
    except Exception:
        pass
    return resp


@router.get(
    "",
    response_model=EmailListResponse,
    summary="List Ingested Emails",
    description="List uploaded emails belonging to your organization, with pagination and status filters.",
)
async def list_emails(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    analysis_status: Optional[str] = Query(default=None, description="Filter by analysis status"),
    qualification_status: Optional[str] = Query(default=None, description="Filter by qualification status"),
    organization_id: Optional[uuid.UUID] = Query(default=None, description="Optional organization filter for cross-org roles"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailListResponse:
    """
    List emails belonging to the caller's organization, with metadata and pagination.

    SCOPING: plain USER accounts (not analyst/admin roles) only see emails
    they personally uploaded — EmailSource.user_id must match the caller.
    Analyst/admin roles (ANALYST_ROLES) keep full org-wide visibility.
    """
    from sqlalchemy import func, or_
    from app.models.identity import Organization

    requested_org_id = organization_id if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id

    # Fast 30s caching for default paginated listings across panels (Dashboard, Vault, Workspace)
    list_cache_key = f"list:{requested_org_id or 'all'}:{current_user.id if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES else 'org'}:{skip}:{limit}"
    now = time.time()
    if not analysis_status and not qualification_status:
        if list_cache_key in _EMAIL_CACHE:
            ts, data = _EMAIL_CACHE[list_cache_key]
            if now - ts < 30.0:
                return EmailListResponse(**data)
        try:
            r_data = await redis_manager.get_json(f"cache:email:{list_cache_key}")
            if r_data:
                _EMAIL_CACHE[list_cache_key] = (now, r_data)
                return EmailListResponse(**r_data)
        except Exception:
            pass
    list_query = (
        select(Email, EmailSource, EvidenceObject)
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .outerjoin(EvidenceObject, Email.id == EvidenceObject.email_id)
        .order_by(desc(Email.created_at))
    )

    if requested_org_id is not None:
        list_query = list_query.where(
            or_(EmailSource.organization_id == requested_org_id, EmailSource.organization_id.is_(None))
        )

    if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
        list_query = list_query.where(EmailSource.user_id == current_user.id)

    if analysis_status:
        list_query = list_query.where(Email.analysis_status == analysis_status)
    if qualification_status:
        list_query = list_query.where(Email.qualification_status == qualification_status)

    paginated_query = list_query.offset(skip).limit(limit)
    result = await db.execute(paginated_query)
    rows = result.all()

    # Fast-path: first page and not full → total is exactly what we fetched.
    if skip == 0 and len(rows) < limit:
        total_count = len(rows)
    else:
        # Lightweight count: only touch Email + EmailSource (no EvidenceObject join).
        count_base = (
            select(func.count(Email.id))
            .select_from(Email)
            .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        )
        if requested_org_id is not None:
            count_base = count_base.where(
                or_(EmailSource.organization_id == requested_org_id, EmailSource.organization_id.is_(None))
            )
        if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
            count_base = count_base.where(EmailSource.user_id == current_user.id)
        if analysis_status:
            count_base = count_base.where(Email.analysis_status == analysis_status)
        if qualification_status:
            count_base = count_base.where(Email.qualification_status == qualification_status)
        count_result = await db.execute(count_base)
        total_count = count_result.scalar_one()

    items = []
    for row in rows:
        email = row[0]
        source = row[1] if len(row) > 1 else None
        evidence = row[2] if len(row) > 2 else None
        items.append(
            EmailDetailResponse(
                id=str(email.id),
                source_type=source.source_type if source else "UNKNOWN",
                original_filename=evidence.original_filename if evidence else (source.source_reference if source else None),
                subject=email.subject,
                sender_address=email.sender_address,
                sender_display_name=email.sender_display_name,
                sent_at=email.sent_at.isoformat() if email.sent_at else None,
                received_at=email.received_at.isoformat() if email.received_at else None,
                email_size_bytes=email.email_size_bytes,
                analysis_status=email.analysis_status,
                qualification_status=email.qualification_status,
                created_at=(email.created_at or datetime.now(timezone.utc)).isoformat(),
                updated_at=(email.updated_at or datetime.now(timezone.utc)).isoformat(),
                sha256_hash=evidence.sha256_hash if evidence else None,
                evidence_id=str(evidence.id) if evidence else None,
                organization_id=str(source.organization_id) if (source and source.organization_id) else (str(email.organization_id) if email.organization_id else None),
                organization_name="Personal Workspace" if (source and source.organization_id) else "Global",
            )
        )

    resp = EmailListResponse(total=total_count, items=items)
    if not analysis_status and not qualification_status:
        _EMAIL_CACHE[list_cache_key] = (now, resp.model_dump())
        try:
            await redis_manager.set_json(f"cache:email:{list_cache_key}", resp.model_dump(), expire_seconds=30)
        except Exception:
            pass
    return resp
