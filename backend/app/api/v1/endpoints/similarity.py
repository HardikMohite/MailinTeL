import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.api.deps import get_current_user, get_authorized_email, require_roles, ANALYST_ROLES, CROSS_ORG_ROLES, CurrentUser
from app.models.embeddings import EmailEmbedding
from app.services.similarity_service import default_similarity_service

router = APIRouter()


class EmbeddingItemResponse(BaseModel):
    id: str
    email_id: str
    embedding_type: str
    model_name: str
    dimension: int
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class SimilarityLinkResponse(BaseModel):
    id: str
    source_email_id: str
    related_email_id: str
    similarity_type: str
    similarity_score: float
    evidence: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class SimilaritySearchRequest(BaseModel):
    min_similarity_threshold: float = Field(0.65, ge=0.0, le=1.0, description="Minimum cosine similarity threshold")
    top_k: int = Field(10, ge=1, le=100, description="Max similar emails to link")


@router.post(
    "/{email_id}/embeddings",
    response_model=List[EmbeddingItemResponse],
    summary="Generate and persist vector embeddings for an email",
    status_code=status.HTTP_201_CREATED,
)
async def generate_email_embeddings(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Generates 384-dimensional dense semantic and DNA feature vector embeddings for an email.
    Stores EMAIL_CONTENT, SUBJECT, EMAIL_DNA, and THREAT_PATTERN embeddings in pgvector.
    """
    await get_authorized_email(email_id, current_user, session)
    try:
        embeddings = await default_similarity_service.generate_and_persist_embeddings(session, email_id)
        return [
            EmbeddingItemResponse(
                id=str(e.id),
                email_id=str(e.email_id),
                embedding_type=e.embedding_type,
                model_name=e.model_name,
                dimension=e.dimension,
                metadata=e.metadata_json or {},
                created_at=e.created_at.isoformat() if e.created_at else None,
            )
            for e in embeddings
        ]
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate embeddings: {str(exc)}",
        )


@router.get(
    "/{email_id}/embeddings",
    response_model=List[EmbeddingItemResponse],
    summary="Get vector embeddings for an email",
)
async def get_email_embeddings(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Retrieves all stored vector embeddings for a given email.
    """
    await get_authorized_email(email_id, current_user, session)
    result = await session.execute(
        select(EmailEmbedding).where(EmailEmbedding.email_id == email_id)
    )
    embeddings = result.scalars().all()
    if not embeddings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No embeddings found for email {email_id}. Please generate them first.",
        )

    return [
        EmbeddingItemResponse(
            id=str(e.id),
            email_id=str(e.email_id),
            embedding_type=e.embedding_type,
            model_name=e.model_name,
            dimension=e.dimension,
            metadata=e.metadata_json or {},
            created_at=e.created_at.isoformat() if e.created_at else None,
        )
        for e in embeddings
    ]


@router.post(
    "/{email_id}/similar",
    response_model=List[SimilarityLinkResponse],
    summary="Compute and link semantically similar emails",
)
async def compute_similar_emails(
    email_id: uuid.UUID,
    params: SimilaritySearchRequest = SimilaritySearchRequest(),
    session: AsyncSession = Depends(get_db),
    # SCOPING: results here name other emails (possibly other users')
    # as correlated — this is the cross-mail "interconnection" view and
    # is restricted to ANALYST_ROLES, CROSS_ORG_ROLES, same as the investigation graph.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Computes pairwise multi-channel cosine similarities between this email and other emails
    in the caller's organization. Establishes and persists EmailSimilarityLink records with evidence.
    """
    await get_authorized_email(email_id, current_user, session)
    try:
        # SCOPING: the source email is already authorized above (which lets
        # CROSS_ORG_ROLES reach an email outside their own organization_id).
        # Restricting candidates to current_user.organization_id here would
        # wrongly scope a cross-org investigator's search to their own org
        # instead of "all organizations", so only org-scoped roles pass their
        # organization_id; cross-org roles pass None (no filter).
        requested_org_id = None if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id
        links = await default_similarity_service.find_and_link_similar_emails(
            session=session,
            email_id=email_id,
            min_similarity_threshold=params.min_similarity_threshold,
            top_k=params.top_k,
            organization_id=requested_org_id,
        )
        return [
            SimilarityLinkResponse(
                id=str(l.id),
                source_email_id=str(l.source_email_id),
                related_email_id=str(l.related_email_id),
                similarity_type=l.similarity_type,
                similarity_score=float(l.similarity_score),
                evidence=l.evidence or {},
                created_at=l.created_at.isoformat() if l.created_at else None,
            )
            for l in links
        ]
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to find similar emails: {str(exc)}",
        )


@router.get(
    "/{email_id}/similar",
    response_model=List[SimilarityLinkResponse],
    summary="Get similar email links for an email",
)
async def get_similar_emails(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Retrieves all established similarity links for an email.
    """
    await get_authorized_email(email_id, current_user, session)
    requested_org_id = None if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id
    links = await default_similarity_service.get_email_similarity_links(
        session, email_id, organization_id=requested_org_id
    )
    return [
        SimilarityLinkResponse(
            id=l["id"],
            source_email_id=l["source_email_id"],
            related_email_id=l["related_email_id"],
            similarity_type=l["similarity_type"],
            similarity_score=l["similarity_score"],
            evidence=l["evidence"],
            created_at=l["created_at"],
        )
        for l in links
    ]
