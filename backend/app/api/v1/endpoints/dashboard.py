import time
import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.session import get_db
from app.api.deps import (
    get_current_user,
    CurrentUser,
    CROSS_ORG_ROLES,
)
from app.models.emails import Email, EmailSource
from app.models.campaign import Campaign, CampaignMembership
from app.models.reports import Report
from app.models.identity import User, Organization, OrganizationMember

router = APIRouter()

# Fast in-memory cache: (cache_key) -> (timestamp, response_data)
_DASHBOARD_CACHE: Dict[str, tuple[float, "DashboardSummaryResponse"]] = {}
_CACHE_TTL_SECONDS = 30.0

SAFE_STATUSES = {"NORMAL", "SAFE", "BENIGN"}
THREAT_STATUSES = {"SUSPICIOUS", "HIGH_RISK", "MALICIOUS", "CAMPAIGN_RELATED", "CRITICAL"}


class ThreatDistributionItem(BaseModel):
    status: str
    count: int


class RecentThreatItem(BaseModel):
    id: str
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    qualification_status: str
    created_at: str
    original_filename: Optional[str] = None


class ActiveCampaignItem(BaseModel):
    id: str
    campaign_name: Optional[str] = None
    member_count: int


class DashboardSummaryResponse(BaseModel):
    total_phishing: int = 0
    threat_count: int = 0
    total_campaigns: int = 0
    total_reports: int = 0
    distribution: List[ThreatDistributionItem] = Field(default_factory=list)
    recent_threats: List[RecentThreatItem] = Field(default_factory=list)
    active_campaigns: List[ActiveCampaignItem] = Field(default_factory=list)


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    summary="Get aggregated dashboard metrics and telemetry",
    description="Returns all 6 KPI counts, severity breakdown, recent ingestions, and active campaigns in a single ultra-fast response.",
)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> DashboardSummaryResponse:
    is_cross_org = current_user.role_code in CROSS_ORG_ROLES
    org_id = None if is_cross_org else current_user.organization_id
    cache_key = f"dashboard:{current_user.id}:{current_user.role_code}:{org_id}"
    now = time.time()

    # 1. Fast L1 in-memory cache hit (< 0.05ms)
    cached = _DASHBOARD_CACHE.get(cache_key)
    if cached and (now - cached[0] < _CACHE_TTL_SECONDS):
        return cached[1]

    # 2. Email qualification breakdown (single GROUP BY query)
    status_query = select(Email.qualification_status, func.count(Email.id))
    if org_id is not None:
        status_query = status_query.join(EmailSource, Email.source_id == EmailSource.id).where(
            EmailSource.organization_id == org_id
        )
    status_query = status_query.group_by(Email.qualification_status)
    res_status = await db.execute(status_query)
    status_counts = dict(res_status.all())

    total_phishing = sum(count for status, count in status_counts.items() if (status or "").upper() not in SAFE_STATUSES)
    threat_count = sum(count for status, count in status_counts.items() if (status or "").upper() in THREAT_STATUSES)

    distribution_order = ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "CAMPAIGN_RELATED", "QUALIFIED_FOR_INVESTIGATION"]
    distribution = [
        ThreatDistributionItem(status=st, count=status_counts.get(st, 0))
        for st in distribution_order
        if status_counts.get(st, 0) > 0
    ]

    # 3. Recent 8 threat emails (single query with limit 8)
    recent_query = (
        select(
            Email.id,
            Email.subject,
            Email.sender_address,
            Email.qualification_status,
            Email.created_at,
            EmailSource.source_reference,
        )
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .where(Email.qualification_status.notin_(list(SAFE_STATUSES)))
        .order_by(desc(Email.created_at))
        .limit(8)
    )
    if org_id is not None:
        recent_query = recent_query.where(EmailSource.organization_id == org_id)

    res_recent = await db.execute(recent_query)
    recent_threats = [
        RecentThreatItem(
            id=str(r[0]),
            subject=r[1],
            sender_address=r[2],
            qualification_status=r[3] or "SUSPICIOUS",
            created_at=r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
            original_filename=r[5],
        )
        for r in res_recent.all()
    ]

    # 4. Campaigns (counts & top 4 active)
    camps_query = (
        select(Campaign.id, Campaign.campaign_name, func.count(CampaignMembership.id))
        .outerjoin(CampaignMembership, Campaign.id == CampaignMembership.campaign_id)
        .group_by(Campaign.id)
        .order_by(desc(Campaign.last_activity_at))
        .limit(4)
    )
    total_camps_query = select(func.count(Campaign.id))
    if org_id is not None:
        camps_query = camps_query.where(Campaign.organization_id == org_id)
        total_camps_query = total_camps_query.where(Campaign.organization_id == org_id)

    res_camps = await db.execute(camps_query)
    res_total_camps = await db.execute(total_camps_query)

    active_campaigns = [
        ActiveCampaignItem(
            id=str(r[0]),
            campaign_name=r[1],
            member_count=int(r[2] or 0),
        )
        for r in res_camps.all()
    ]
    total_campaigns = res_total_camps.scalar_one() or 0

    # 5. Reports count
    rep_query = select(func.count(Report.id))
    if org_id is not None:
        # org-owned reports
        org_owned_emails = select(Email.id).join(EmailSource, EmailSource.id == Email.source_id).where(EmailSource.organization_id == org_id)
        org_owned_camps = select(Campaign.id).where(Campaign.organization_id == org_id)
        from sqlalchemy import or_, and_
        rep_query = rep_query.where(
            or_(
                and_(Report.email_id.isnot(None), Report.email_id.in_(org_owned_emails)),
                and_(Report.campaign_id.isnot(None), Report.campaign_id.in_(org_owned_camps)),
            )
        )
    res_reports = await db.execute(rep_query)
    total_reports = res_reports.scalar_one() or 0

    summary_response = DashboardSummaryResponse(
        total_phishing=total_phishing,
        threat_count=threat_count,
        total_campaigns=total_campaigns,
        total_reports=total_reports,
        distribution=distribution,
        recent_threats=recent_threats,
        active_campaigns=active_campaigns,
    )

    _DASHBOARD_CACHE[cache_key] = (now, summary_response)
    return summary_response
