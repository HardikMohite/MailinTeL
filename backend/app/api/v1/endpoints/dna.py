import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.api.deps import get_current_user, get_authorized_email, CurrentUser
from app.models.emails import Email
from app.models.dna import EmailDNAProfile
from app.dna.dna_builder import compute_stable_json_hash
from app.services.dna_service import generate_and_persist_email_dna

logger = logging.getLogger(__name__)

router = APIRouter()


class EmailDNAProfileResponse(BaseModel):
    email_id: str
    dna_version: str
    overall_dna_hash: str
    content_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    technical_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    infrastructure_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    behavioral_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    temporal_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


@router.get(
    "/{email_id}/dna",
    response_model=EmailDNAProfileResponse,
    summary="Get Email DNA Profile",
    description="Retrieve structured multi-layer Email DNA (content, technical, infrastructure, behavioral, temporal fingerprints).",
)
async def get_email_dna(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailDNAProfileResponse:
    """Retrieve existing DNA profile or compute live DNA for an email."""
    await get_authorized_email(email_id, current_user, db)

    # Check for existing profile
    stmt_dna = select(EmailDNAProfile).where(EmailDNAProfile.email_id == email_id)
    res_dna = await db.execute(stmt_dna)
    dna_rec = res_dna.scalar_one_or_none()

    if dna_rec:
        composite_data = {
            "content": dna_rec.content_fingerprint or {},
            "technical": dna_rec.technical_fingerprint or {},
            "infrastructure": dna_rec.infrastructure_fingerprint or {},
            "behavioral": dna_rec.behavioral_fingerprint or {},
            "temporal": dna_rec.temporal_fingerprint or {},
        }
        dna_hash = compute_stable_json_hash(composite_data)

        return EmailDNAProfileResponse(
            email_id=str(email_id),
            dna_version=dna_rec.dna_version,
            overall_dna_hash=dna_hash,
            content_fingerprint=dna_rec.content_fingerprint or {},
            technical_fingerprint=dna_rec.technical_fingerprint or {},
            infrastructure_fingerprint=dna_rec.infrastructure_fingerprint or {},
            behavioral_fingerprint=dna_rec.behavioral_fingerprint or {},
            temporal_fingerprint=dna_rec.temporal_fingerprint or {},
            created_at=dna_rec.created_at.isoformat(),
            updated_at=dna_rec.updated_at.isoformat(),
        )

    # Generate live DNA
    bundle = await generate_and_persist_email_dna(email_id=email_id, db=db)
    return EmailDNAProfileResponse(
        email_id=bundle.email_id,
        dna_version=bundle.dna_version,
        overall_dna_hash=bundle.overall_dna_hash,
        content_fingerprint=bundle.content_fingerprint,
        technical_fingerprint=bundle.technical_fingerprint,
        infrastructure_fingerprint=bundle.infrastructure_fingerprint,
        behavioral_fingerprint=bundle.behavioral_fingerprint,
        temporal_fingerprint=bundle.temporal_fingerprint,
        created_at=bundle.generated_at.isoformat(),
        updated_at=bundle.generated_at.isoformat(),
    )


@router.post(
    "/{email_id}/dna",
    response_model=EmailDNAProfileResponse,
    summary="Generate / Refresh Email DNA Profile",
    description="Compile and persist fresh multi-layer Email DNA fingerprint.",
)
async def generate_email_dna(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailDNAProfileResponse:
    """Live generate and upsert Email DNA profile."""
    await get_authorized_email(email_id, current_user, db)

    bundle = await generate_and_persist_email_dna(email_id=email_id, db=db)
    return EmailDNAProfileResponse(
        email_id=bundle.email_id,
        dna_version=bundle.dna_version,
        overall_dna_hash=bundle.overall_dna_hash,
        content_fingerprint=bundle.content_fingerprint,
        technical_fingerprint=bundle.technical_fingerprint,
        infrastructure_fingerprint=bundle.infrastructure_fingerprint,
        behavioral_fingerprint=bundle.behavioral_fingerprint,
        temporal_fingerprint=bundle.temporal_fingerprint,
        created_at=bundle.generated_at.isoformat(),
        updated_at=bundle.generated_at.isoformat(),
    )
