import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.api.deps import (
    get_current_user,
    require_organization_or_cross_org,
    require_roles,
    ANALYST_ROLES, CROSS_ORG_ROLES,
    get_authorized_email,
    get_authorized_campaign,
    CurrentUser,
)
from app.services.campaign_service import default_campaign_service

router = APIRouter()


# --- Models ---

class CorrelationSignalItem(BaseModel):
    signal_type: str
    confidence: float
    weight: float
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class CorrelatedEmailItem(BaseModel):
    source_email_id: str
    target_email_id: str
    target_subject: Optional[str] = None
    target_sender: Optional[str] = None
    composite_correlation_score: float
    primary_link_reason: str
    evidence_count: int
    is_actionable_correlation: bool
    signals: List[CorrelationSignalItem] = Field(default_factory=list)


class EmailCorrelationsResponse(BaseModel):
    email_id: str
    total_correlated_emails: int
    correlations: List[CorrelatedEmailItem] = Field(default_factory=list)


class CreateCampaignRequest(BaseModel):
    campaign_name: str = Field(..., min_length=2, max_length=255)
    threat_summary: Optional[str] = None
    campaign_status: str = Field("ACTIVE", description="ACTIVE, INVESTIGATING, MITIGATED, ARCHIVED")
    campaign_confidence: float = Field(80.0, ge=0.0, le=100.0)
    initial_email_ids: Optional[List[uuid.UUID]] = None


class AddEmailMembershipRequest(BaseModel):
    membership_confidence: float = Field(80.0, ge=0.0, le=100.0)
    membership_status: str = Field("CONFIRMED", description="CONFIRMED, HYPOTHETICAL, EXCLUDED")
    evidence_summary: Optional[Dict[str, Any]] = None


class CampaignMembershipItem(BaseModel):
    id: str
    email_id: str
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    membership_confidence: float
    membership_status: str
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class CampaignEvidenceItem(BaseModel):
    id: str
    evidence_type: str
    confidence: float
    explanation: str
    created_at: Optional[str] = None


class CampaignEventItem(BaseModel):
    id: str
    event_type: str
    occurred_at: Optional[str] = None
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CampaignDetailResponse(BaseModel):
    id: str
    campaign_name: Optional[str] = None
    campaign_status: str
    campaign_confidence: float
    threat_summary: Optional[str] = None
    first_detected_at: Optional[str] = None
    last_activity_at: Optional[str] = None
    total_members: int
    total_evidence_links: int
    memberships: List[CampaignMembershipItem] = Field(default_factory=list)
    evidence: List[CampaignEvidenceItem] = Field(default_factory=list)
    events: List[CampaignEventItem] = Field(default_factory=list)


class CampaignListItemResponse(BaseModel):
    id: str
    campaign_name: Optional[str] = None
    campaign_status: str
    campaign_confidence: float
    threat_summary: Optional[str] = None
    first_detected_at: Optional[str] = None
    last_activity_at: Optional[str] = None
    member_count: int


class EmailCampaignMembershipItem(BaseModel):
    membership_id: str
    campaign_id: str
    campaign_name: Optional[str] = None
    campaign_status: str
    membership_confidence: float
    membership_status: str
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)


class EmailMembershipsResponse(BaseModel):
    email_id: str
    is_bridge_entity: bool
    total_campaigns: int
    investigation_note: str
    memberships: List[EmailCampaignMembershipItem] = Field(default_factory=list)


class AutoClusterClusterItem(BaseModel):
    campaign_id: str
    campaign_name: Optional[str] = None
    members_count: int


class AutoClusterResponse(BaseModel):
    total_clusters_created: int
    clusters: List[AutoClusterClusterItem] = Field(default_factory=list)


# --- Endpoints ---

@router.post(
    "",
    response_model=CampaignDetailResponse,
    summary="Create a new threat campaign",
    status_code=status.HTTP_201_CREATED,
)
async def create_campaign(
    body: CreateCampaignRequest,
    session: AsyncSession = Depends(get_db),
    # MVP-04: campaign mutation is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Creates a new campaign entity with optional initial email memberships and audit event.
    """
    camp = await default_campaign_service.create_campaign(
        session=session,
        campaign_name=body.campaign_name,
        threat_summary=body.threat_summary,
        campaign_status=body.campaign_status,
        campaign_confidence=body.campaign_confidence,
        initial_email_ids=body.initial_email_ids,
        organization_id=current_user.organization_id,
    )
    details = await default_campaign_service.get_campaign_details(session, camp.id)
    if not details:
        raise HTTPException(status_code=500, detail="Failed to retrieve created campaign details")
    return CampaignDetailResponse(**details)


@router.get(
    "",
    response_model=List[CampaignListItemResponse],
    summary="List threat campaigns",
)
async def list_campaigns(
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    organization_id: Optional[uuid.UUID] = Query(None, description="Optional organization filter for cross-org roles"),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
):
    """
    Lists campaigns belonging to the caller's organization, with member counts and activity timelines.

    SCOPING: plain USER accounts only see campaigns that contain at least
    one email they personally uploaded ("my campaigns"). Analyst/admin
    roles (ANALYST_ROLES, which includes INSTITUTION_ADMIN/SYSTEM_ADMIN)
    see every campaign in the organization.
    """
    owner_user_id = None if current_user.role_code in ANALYST_ROLES or current_user.role_code in CROSS_ORG_ROLES else current_user.id
    requested_org_id = organization_id if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id
    items = await default_campaign_service.list_campaigns(
        session=session,
        status_filter=status_filter,
        skip=skip,
        limit=limit,
        organization_id=requested_org_id,
        owner_user_id=owner_user_id,
    )
    return [CampaignListItemResponse(**item) for item in items]


@router.get(
    "/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Get campaign details by ID",
)
async def get_campaign(
    campaign_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Retrieves full campaign information including all member emails, evidence links, and timeline events.
    """
    await get_authorized_campaign(campaign_id, current_user, session)
    details = await default_campaign_service.get_campaign_details(session, campaign_id)
    if not details:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign {campaign_id} not found.")
    return CampaignDetailResponse(**details)


@router.post(
    "/{campaign_id}/emails/{email_id}",
    response_model=CampaignMembershipItem,
    summary="Add email to campaign (supports overlapping memberships)",
)
async def add_email_to_campaign(
    campaign_id: uuid.UUID,
    email_id: uuid.UUID,
    body: AddEmailMembershipRequest = AddEmailMembershipRequest(),
    session: AsyncSession = Depends(get_db),
    # MVP-04: campaign mutation is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Links an email to a campaign. Preserves multi-campaign membership without forced single-assignment.
    """
    await get_authorized_campaign(campaign_id, current_user, session)
    await get_authorized_email(email_id, current_user, session)
    try:
        mem = await default_campaign_service.add_email_to_campaign(
            session=session,
            campaign_id=campaign_id,
            email_id=email_id,
            membership_confidence=body.membership_confidence,
            membership_status=body.membership_status,
            evidence_summary=body.evidence_summary,
            organization_id=current_user.organization_id,
        )
        return CampaignMembershipItem(
            id=str(mem.id),
            email_id=str(mem.email_id),
            membership_confidence=float(mem.membership_confidence),
            membership_status=mem.membership_status,
            evidence_summary=mem.evidence_summary or {},
            created_at=mem.created_at.isoformat() if mem.created_at else None,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))


@router.delete(
    "/{campaign_id}/emails/{email_id}",
    summary="Remove email from campaign",
)
async def remove_email_from_campaign(
    campaign_id: uuid.UUID,
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    # MVP-04: campaign mutation is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Removes an email membership from a campaign.
    """
    await get_authorized_campaign(campaign_id, current_user, session)
    removed = await default_campaign_service.remove_email_from_campaign(
        session, campaign_id, email_id, organization_id=current_user.organization_id
    )
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found.")
    return {"message": f"Email {email_id} removed from campaign {campaign_id} successfully."}


@router.get(
    "/emails/{email_id}/memberships",
    response_model=EmailMembershipsResponse,
    summary="Get all campaign memberships for an email",
)
async def get_email_campaign_memberships(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Retrieves all campaigns an email belongs to, indicating if it acts as a bridge entity between campaigns.
    """
    await get_authorized_email(email_id, current_user, session)
    result = await default_campaign_service.get_email_campaign_memberships(
        session, email_id, organization_id=current_user.organization_id
    )
    return EmailMembershipsResponse(**result)


@router.post(
    "/auto-cluster",
    response_model=AutoClusterResponse,
    summary="Auto-cluster correlated emails into candidate campaigns",
)
async def auto_cluster_campaigns(
    min_score: float = Query(60.0, ge=0.0, le=100.0, description="Minimum correlation threshold for clustering"),
    session: AsyncSession = Depends(get_db),
    # MVP-04: creates/mutates campaigns, so analyst-and-up.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """
    Discovers correlated clusters across the caller's organization's emails, creating or linking campaigns
    while preserving overlapping bridge entities without destructive partition mergers.
    """
    clusters = await default_campaign_service.auto_cluster_campaigns(
        session, min_correlation_score=min_score, organization_id=current_user.organization_id
    )
    return AutoClusterResponse(
        total_clusters_created=len(clusters),
        clusters=[AutoClusterClusterItem(**c) for c in clusters],
    )


# --- Correlation Endpoints ---

@router.post(
    "/correlate/{email_id}",
    response_model=EmailCorrelationsResponse,
    summary="Compute live multi-vector correlation signals for an email",
)
async def compute_email_correlations(
    email_id: uuid.UUID,
    min_score: float = Query(40.0, ge=0.0, le=100.0, description="Minimum correlation score threshold"),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
):
    """
    Computes live pairwise correlation signals against candidate emails in the caller's
    organization across URLs, domains, IPs, infrastructure, attachment hashes, DNA,
    semantic similarity, and temporal patterns.
    """
    await get_authorized_email(email_id, current_user, session)
    try:
        correlations = await default_campaign_service.correlate_email(
            session=session,
            email_id=email_id,
            min_score=min_score,
            organization_id=current_user.organization_id,
        )
        return EmailCorrelationsResponse(
            email_id=str(email_id),
            total_correlated_emails=len(correlations),
            correlations=correlations,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute correlations: {str(exc)}",
        )


@router.get(
    "/correlations/{email_id}",
    response_model=EmailCorrelationsResponse,
    summary="Get correlation signals and linked emails for an email",
)
async def get_email_correlations(
    email_id: uuid.UUID,
    min_score: float = Query(40.0, ge=0.0, le=100.0),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
):
    """
    Retrieves correlation signals for a specific email, scoped to the caller's organization.
    """
    await get_authorized_email(email_id, current_user, session)
    try:
        correlations = await default_campaign_service.correlate_email(
            session=session,
            email_id=email_id,
            min_score=min_score,
            organization_id=current_user.organization_id,
        )
        return EmailCorrelationsResponse(
            email_id=str(email_id),
            total_correlated_emails=len(correlations),
            correlations=correlations,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch correlations: {str(exc)}",
        )
