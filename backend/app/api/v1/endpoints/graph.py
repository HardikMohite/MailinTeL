import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.api.deps import get_current_user, require_organization, require_roles, get_authorized_email, get_authorized_campaign, CurrentUser, ANALYST_ROLES, CROSS_ORG_ROLES
from app.services.graph_service import default_graph_service

router = APIRouter()


class GraphNodeItem(BaseModel):
    id: str
    label: str
    node_type: str
    display_name: str
    risk_level: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdgeItem(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    label: str
    confidence: float
    evidence: Dict[str, Any] = Field(default_factory=dict)


class InvestigationGraphResponse(BaseModel):
    focal_node_id: Optional[str] = None
    total_nodes: int
    total_edges: int
    statistics: Dict[str, int] = Field(default_factory=dict)
    nodes: List[GraphNodeItem] = Field(default_factory=list)
    edges: List[GraphEdgeItem] = Field(default_factory=list)


@router.get(
    "/email/{email_id}",
    response_model=InvestigationGraphResponse,
    summary="Get multi-hop investigation graph focused on an email",
)
async def get_email_investigation_graph(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Constructs an interactive investigation graph centered on an email, traversing its
    sender, extracted URLs, domains, IP addresses, ASNs, attachments, campaigns, and similarity links.
    """
    await get_authorized_email(email_id, current_user, session)
    graph = await default_graph_service.build_email_investigation_graph(session, email_id)
    if graph.total_nodes == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email {email_id} not found.")
    return InvestigationGraphResponse(**graph.to_dict())


@router.get(
    "/campaign/{campaign_id}",
    response_model=InvestigationGraphResponse,
    summary="Get complete investigation graph for a threat campaign",
)
async def get_campaign_investigation_graph(
    campaign_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Constructs the complete investigation graph of all emails, artifacts, infrastructure, and
    correlations clustered inside a campaign.
    """
    await get_authorized_campaign(campaign_id, current_user, session)
    graph = await default_graph_service.build_campaign_investigation_graph(session, campaign_id)
    if not graph:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign {campaign_id} not found.")
    return InvestigationGraphResponse(**graph.to_dict())


@router.get(
    "/global",
    response_model=InvestigationGraphResponse,
    summary="Get global investigation graph summary",
)
async def get_global_investigation_graph(
    limit: int = Query(30, ge=5, le=100, description="Max recent emails to include"),
    organization_id: Optional[uuid.UUID] = Query(None, description="Optional organization filter for cross-org roles"),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Constructs an investigation graph connecting the caller's organization's recent emails
    and active campaigns.
    """
    graph = await default_graph_service.build_global_investigation_graph(
        session, limit_emails=limit, organization_id=(organization_id if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id)
    )
    return InvestigationGraphResponse(**graph.to_dict())
