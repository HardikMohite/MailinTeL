import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.api.deps import get_current_user, require_organization_or_cross_org, get_authorized_email, get_authorized_campaign, CurrentUser, CROSS_ORG_ROLES
from app.services.geo_service import default_geo_service

router = APIRouter()


class GeoIPLookupResponse(BaseModel):
    ip_address: str
    is_private: bool
    country_code: str
    country_name: str
    region_name: Optional[str] = None
    city_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None
    source: str
    confidence: float
    attribution_statement: str
    connection_type: Optional[str] = "RELAY"
    provider: Optional[str] = None
    is_tor: Optional[bool] = False
    is_vpn: Optional[bool] = False
    is_datacenter: Optional[bool] = False
    is_cloud: Optional[bool] = False
    is_personal_mail: Optional[bool] = False
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    classification_badges: Optional[List[str]] = Field(default_factory=list)


class GeoMarkerItem(BaseModel):
    id: str
    entity_type: Optional[str] = "RELAY_HOP"
    sequence_number: Optional[int] = None
    ip_address: str
    host: Optional[str] = None
    latitude: float
    longitude: float
    country_code: str
    country_name: str
    region_name: Optional[str] = None
    city_name: Optional[str] = None
    accuracy_radius_km: Optional[int] = None
    confidence: float
    role: Optional[str] = None
    associated_email_count: Optional[int] = None
    associated_email_ids: Optional[List[str]] = None
    connection_type: Optional[str] = "RELAY"
    provider: Optional[str] = None
    is_tor: Optional[bool] = False
    is_vpn: Optional[bool] = False
    is_datacenter: Optional[bool] = False
    is_cloud: Optional[bool] = False
    is_personal_mail: Optional[bool] = False
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    classification_badges: Optional[List[str]] = Field(default_factory=list)


class GeoPathSegment(BaseModel):
    from_hop: int
    to_hop: int
    from_ip: str
    to_ip: str
    from_coords: List[float]
    to_coords: List[float]
    label: str


class HopGeoNode(BaseModel):
    sequence_number: int
    source_host: Optional[str] = None
    source_ip: str
    destination_host: Optional[str] = None
    reliability: str
    geolocation: Dict[str, Any]
    connection_type: Optional[str] = "RELAY"
    provider: Optional[str] = None
    is_tor: Optional[bool] = False
    is_vpn: Optional[bool] = False
    is_datacenter: Optional[bool] = False
    is_cloud: Optional[bool] = False
    is_personal_mail: Optional[bool] = False
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    classification_badges: Optional[List[str]] = Field(default_factory=list)


class EmailGeoInfrastructureResponse(BaseModel):
    email_id: str
    subject: Optional[str] = None
    total_hops: int
    total_markers: int
    tor_node_count: Optional[int] = 0
    vpn_node_count: Optional[int] = 0
    cloud_node_count: Optional[int] = 0
    personal_mail_node_count: Optional[int] = 0
    hops: List[HopGeoNode] = Field(default_factory=list)
    markers: List[GeoMarkerItem] = Field(default_factory=list)
    paths: List[GeoPathSegment] = Field(default_factory=list)
    country_distribution: Dict[str, int] = Field(default_factory=dict)
    attribution_disclaimer: str


class CampaignGeoInfrastructureResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    campaign_type: Optional[str] = None
    total_emails: int
    total_unique_ips: int
    total_markers: int
    tor_node_count: Optional[int] = 0
    vpn_node_count: Optional[int] = 0
    cloud_node_count: Optional[int] = 0
    personal_mail_node_count: Optional[int] = 0
    markers: List[GeoMarkerItem] = Field(default_factory=list)
    country_distribution: Dict[str, int] = Field(default_factory=dict)
    attribution_disclaimer: str


class GlobalGeoInfrastructureResponse(BaseModel):
    total_emails_scanned: int
    total_unique_ips: int
    total_markers: int
    tor_node_count: Optional[int] = 0
    vpn_node_count: Optional[int] = 0
    cloud_node_count: Optional[int] = 0
    personal_mail_node_count: Optional[int] = 0
    markers: List[Dict[str, Any]] = Field(default_factory=list)
    country_distribution: Dict[str, int] = Field(default_factory=dict)
    attribution_disclaimer: str


@router.get(
    "/ip/{ip_address}",
    response_model=GeoIPLookupResponse,
    summary="Resolve and geolocate a single IP address",
)
async def get_ip_geolocation(
    ip_address: str,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Resolves the geographic coordinates and administrative hosting region of an observable IP address.
    Adheres strictly to forensic attribution disclaimers. This indicator lookup is not tenant-owned
    data (any authenticated user may query any public IP), so no organization check applies here.
    """
    res = await default_geo_service.geolocate_ip(session, ip_address)
    return GeoIPLookupResponse(**res)


@router.get(
    "/email/{email_id}",
    response_model=EmailGeoInfrastructureResponse,
    summary="Geolocate all transmission relay hops for an email",
)
async def get_email_geo_infrastructure(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Maps the physical/geographic transmission hops reconstructed from email Received headers,
    producing markers and flight paths across international transit servers.
    """
    await get_authorized_email(email_id, current_user, session)
    res = await default_geo_service.geolocate_email_infrastructure(session, email_id)
    return EmailGeoInfrastructureResponse(**res)


@router.get(
    "/campaign/{campaign_id}",
    response_model=CampaignGeoInfrastructureResponse,
    summary="Geolocate all aggregate infrastructure for a threat campaign",
)
async def get_campaign_geo_infrastructure(
    campaign_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Aggregates all observable routing IPs and hosting endpoints across emails grouped in a campaign.
    """
    await get_authorized_campaign(campaign_id, current_user, session)
    res = await default_geo_service.geolocate_campaign_infrastructure(session, campaign_id)
    return CampaignGeoInfrastructureResponse(**res)


@router.get(
    "/global",
    response_model=GlobalGeoInfrastructureResponse,
    summary="Get global infrastructure geolocation overview",
)
async def get_global_geo_infrastructure(
    limit: int = Query(50, ge=5, le=200, description="Max recent emails to scan"),
    organization_id: Optional[uuid.UUID] = Query(None, description="Optional organization filter for cross-org roles"),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
):
    """
    Produces infrastructure markers and geographic distributions.

    SCOPING: matches the pattern used by list_campaigns/list_reports. Org-scoped
    roles (SECURITY_ANALYST, INSTITUTION_ADMIN, and SYSTEM_ADMIN when they carry
    an active organization membership) always see only their own organization's
    recent emails. CROSS_ORG_ROLES (CYBER_CELL_INVESTIGATOR, and SYSTEM_ADMIN
    even with no organization membership) see all organizations by default and
    may narrow to one via the optional `organization_id` query param.
    """
    requested_org_id = organization_id if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id
    res = await default_geo_service.get_global_geo_infrastructure(
        session, limit_emails=limit, organization_id=requested_org_id
    )
    return GlobalGeoInfrastructureResponse(**res)
