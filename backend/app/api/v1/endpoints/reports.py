import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    Query,
    Response,
    status,
)
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from app.db.session import get_db
from app.api.deps import (
    get_current_user,
    require_organization_or_cross_org, CROSS_ORG_ROLES,
    require_roles,
    ANALYST_ROLES,
    get_authorized_email,
    get_authorized_campaign,
    get_authorized_report,
    CurrentUser,
)
from app.models.emails import Email, EmailSource
from app.models.campaign import Campaign
from app.models.reports import Report
from app.models.evidence import EvidenceObject
from app.services.report_service import ReportService
from app.core.storage import storage
from app.core.config import settings

logger = logging.getLogger("mailintel.api.reports")

router = APIRouter()


class ReportItemResponse(BaseModel):
    id: str
    report_type: str
    email_id: Optional[str] = None
    campaign_id: Optional[str] = None
    evidence_object_id: Optional[str] = None
    report_version: str
    generated_at: str
    summary: Dict[str, Any] = Field(default_factory=dict)


class ReportListResponse(BaseModel):
    total_reports: int
    reports: List[ReportItemResponse]


class GenerateReportResponse(BaseModel):
    report_id: str
    report_type: str
    format: str
    email_id: Optional[str] = None
    campaign_id: Optional[str] = None
    generated_at: str
    summary: Dict[str, Any]
    report_data: Dict[str, Any]


@router.post(
    "/email/{email_id}",
    response_model=GenerateReportResponse,
    summary="Generate & Preserve Email Forensic Report",
    description="Synthesize multi-layer forensic intelligence into a verifiable report and preserve in MinIO and PostgreSQL.",
)
async def generate_email_report(
    email_id: uuid.UUID,
    format: str = Query("html", description="Output format: 'html', 'markdown', or 'json'"),
    db: AsyncSession = Depends(get_db),
    # MVP-04: generating/preserving a forensic report artifact is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
) -> GenerateReportResponse:
    """Generate and store an immutable forensic report artifact for an email."""
    await get_authorized_email(email_id, current_user, db)

    try:
        report_model, rendered_content, report_data = await ReportService.generate_and_save_email_report(
            email_id=email_id,
            format_type=format,
            db=db,
        )

        return GenerateReportResponse(
            report_id=str(report_model.id),
            report_type=report_model.report_type,
            format=format.lower(),
            email_id=str(email_id),
            campaign_id=None,
            generated_at=report_model.generated_at.isoformat(),
            summary=report_model.summary or {},
            report_data=report_data,
        )
    except Exception as e:
        logger.exception(f"Failed to generate forensic report for email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )


@router.get(
    "/email/{email_id}",
    summary="Get Email Forensic Report Data",
    description="Retrieve live forensic report data structure for an email without saving a new report artifact.",
)
async def get_email_report_data(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve full structured forensic intelligence data for an email."""
    await get_authorized_email(email_id, current_user, db)

    try:
        return await ReportService.build_email_report_data(email_id=email_id, db=db)
    except Exception as e:
        logger.exception(f"Failed to build report data for email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build report data: {str(e)}",
        )


@router.get(
    "/email/{email_id}/export",
    summary="Export Email Forensic Report File",
    description="Directly stream / download forensic report file in HTML, Markdown, or JSON format.",
)
async def export_email_report(
    email_id: uuid.UUID,
    format: str = Query("html", description="Output format: 'html', 'markdown', or 'json'"),
    db: AsyncSession = Depends(get_db),
    # MVP-04: report export is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """Export formatted forensic report as downloadable file."""
    await get_authorized_email(email_id, current_user, db)

    report_data = await ReportService.build_email_report_data(email_id=email_id, db=db)
    fmt = format.strip().lower()

    if fmt in ("markdown", "md"):
        content = ReportService.render_markdown_report(report_data)
        filename = f"MailIntel_Forensic_Report_{str(email_id)[:8]}.md"
        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    elif fmt == "json":
        content = ReportService.render_json_report(report_data)
        filename = f"MailIntel_Forensic_Report_{str(email_id)[:8]}.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        content = ReportService.render_html_report(report_data)
        filename = f"MailIntel_Forensic_Report_{str(email_id)[:8]}.html"
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )


@router.post(
    "/campaign/{campaign_id}",
    response_model=GenerateReportResponse,
    summary="Generate & Preserve Campaign Intelligence Dossier",
    description="Synthesize multi-email campaign intelligence and preserve report.",
)
async def generate_campaign_report(
    campaign_id: uuid.UUID,
    format: str = Query("html", description="Output format: 'html', 'markdown', or 'json'"),
    db: AsyncSession = Depends(get_db),
    # MVP-04: generating/preserving a campaign dossier is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
) -> GenerateReportResponse:
    """Generate and store campaign dossier."""
    await get_authorized_campaign(campaign_id, current_user, db)

    try:
        report_model, rendered_content, report_data = await ReportService.generate_and_save_campaign_report(
            campaign_id=campaign_id,
            format_type=format,
            db=db,
        )

        return GenerateReportResponse(
            report_id=str(report_model.id),
            report_type=report_model.report_type,
            format=format.lower(),
            email_id=None,
            campaign_id=str(campaign_id),
            generated_at=report_model.generated_at.isoformat(),
            summary=report_model.summary or {},
            report_data=report_data,
        )
    except Exception as e:
        logger.exception(f"Failed to generate campaign report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Campaign report generation failed: {str(e)}",
        )


@router.get(
    "/campaign/{campaign_id}",
    summary="Get Campaign Dossier Data",
    description="Retrieve structured campaign dossier data.",
)
async def get_campaign_report_data(
    campaign_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve structured campaign dossier data."""
    await get_authorized_campaign(campaign_id, current_user, db)

    try:
        return await ReportService.build_campaign_report_data(campaign_id=campaign_id, db=db)
    except Exception as e:
        logger.exception(f"Failed to build campaign report data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build campaign report: {str(e)}",
        )


@router.get(
    "",
    response_model=ReportListResponse,
    summary="List Generated Forensic Reports",
    description="Retrieve historical forensic reports with filtering.",
)
async def list_reports(
    email_id: Optional[uuid.UUID] = Query(None, description="Filter by Email ID"),
    campaign_id: Optional[uuid.UUID] = Query(None, description="Filter by Campaign ID"),
    organization_id: Optional[uuid.UUID] = Query(None, description="Optional organization filter for cross-org roles"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
) -> ReportListResponse:
    """
    List historical reports belonging to the caller's organization.

    SECURITY: reports have no organization_id of their own — ownership is
    derived transitively via report.email_id -> email_sources.organization_id
    or report.campaign_id -> campaigns.organization_id. Every report in the
    result set must resolve to the caller's org (or have no resolvable
    owner at all, which is excluded rather than shown to everyone).
    """
    if email_id is not None:
        await get_authorized_email(email_id, current_user, db)
    if campaign_id is not None:
        await get_authorized_campaign(campaign_id, current_user, db)

    requested_org_id = organization_id if current_user.role_code in CROSS_ORG_ROLES else current_user.organization_id
    org_owned_emails = (
        select(Email.id)
        .join(EmailSource, EmailSource.id == Email.source_id)
        .where(EmailSource.organization_id == requested_org_id)
    )
    org_owned_campaigns = select(Campaign.id).where(Campaign.organization_id == requested_org_id)

    stmt = (
        select(Report)
        .where(
            or_(
                and_(Report.email_id.isnot(None), Report.email_id.in_(org_owned_emails)),
                and_(Report.campaign_id.isnot(None), Report.campaign_id.in_(org_owned_campaigns)),
            )
        )
        .order_by(Report.generated_at.desc())
    )
    if email_id:
        stmt = stmt.where(Report.email_id == email_id)
    if campaign_id:
        stmt = stmt.where(Report.campaign_id == campaign_id)
    stmt = stmt.limit(limit)

    res = await db.execute(stmt)
    reports_objs = res.scalars().all()

    return ReportListResponse(
        total_reports=len(reports_objs),
        reports=[
            ReportItemResponse(
                id=str(r.id),
                report_type=r.report_type,
                email_id=str(r.email_id) if r.email_id else None,
                campaign_id=str(r.campaign_id) if r.campaign_id else None,
                evidence_object_id=str(r.evidence_object_id) if r.evidence_object_id else None,
                report_version=r.report_version,
                generated_at=r.generated_at.isoformat(),
                summary=r.summary or {},
            )
            for r in reports_objs
        ],
    )


@router.get(
    "/{report_id}",
    response_model=ReportItemResponse,
    summary="Get Report Metadata by ID",
)
async def get_report_by_id(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> ReportItemResponse:
    """Get metadata for single report."""
    report = await get_authorized_report(report_id, current_user, db)

    return ReportItemResponse(
        id=str(report.id),
        report_type=report.report_type,
        email_id=str(report.email_id) if report.email_id else None,
        campaign_id=str(report.campaign_id) if report.campaign_id else None,
        evidence_object_id=str(report.evidence_object_id) if report.evidence_object_id else None,
        report_version=report.report_version,
        generated_at=report.generated_at.isoformat(),
        summary=report.summary or {},
    )
