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
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.api.deps import get_current_user, get_authorized_email, CurrentUser
from app.models.emails import Email
from app.models.analysis import AnalysisRun, EmailAnalysis, AnalysisFinding
from app.services.scoring_service import execute_email_analysis_and_scoring

logger = logging.getLogger(__name__)

router = APIRouter()


class AnalysisFindingSchema(BaseModel):
    finding_type: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class EmailAnalysisResponse(BaseModel):
    analysis_run_id: str
    email_id: str
    threat_classification: str
    threat_risk_score: float
    evidence_confidence_score: float
    summary: str
    compromised_account_likelihood: str
    spoofed_domain_likelihood: str
    anonymized_infrastructure_likelihood: str
    malicious_environment_likelihood: str
    findings: List[AnalysisFindingSchema] = Field(default_factory=list)
    scoring_pillars: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class FindingsListResponse(BaseModel):
    email_id: str
    total_findings: int
    findings: List[AnalysisFindingSchema]


@router.get(
    "/{email_id}/analysis",
    response_model=EmailAnalysisResponse,
    summary="Get Email Explainable Scoring Analysis",
    description="Retrieve Threat Risk Score, Evidence Confidence Score, compromise likelihoods, and forensic findings.",
)
async def get_email_analysis(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailAnalysisResponse:
    """Retrieve existing analysis or compute live scoring for an email."""
    await get_authorized_email(email_id, current_user, db)

    # Check for existing completed analysis
    stmt_analysis = (
        select(EmailAnalysis, AnalysisRun)
        .join(AnalysisRun, EmailAnalysis.analysis_run_id == AnalysisRun.id)
        .where(EmailAnalysis.email_id == email_id)
        .order_by(EmailAnalysis.created_at.desc())
    )
    res_analysis = await db.execute(stmt_analysis)
    row = res_analysis.first()

    if row:
        analysis_obj, run_obj = row
        # Fetch findings
        stmt_findings = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_obj.id)
        res_findings = await db.execute(stmt_findings)
        findings_objs = res_findings.scalars().all()
        pillars = (run_obj.metadata_json or {}).get("scoring_pillars", {})

        return EmailAnalysisResponse(
            analysis_run_id=str(run_obj.id),
            email_id=str(email_id),
            threat_classification=analysis_obj.threat_classification,
            threat_risk_score=float(analysis_obj.threat_risk_score),
            evidence_confidence_score=float(analysis_obj.evidence_confidence_score),
            summary=analysis_obj.summary,
            compromised_account_likelihood=analysis_obj.compromised_account_likelihood or "UNLIKELY",
            spoofed_domain_likelihood=analysis_obj.spoofed_domain_likelihood or "UNLIKELY",
            anonymized_infrastructure_likelihood=analysis_obj.anonymized_infrastructure_likelihood or "UNLIKELY",
            malicious_environment_likelihood=analysis_obj.malicious_environment_likelihood or "UNLIKELY",
            findings=[
                AnalysisFindingSchema(
                    finding_type=f.finding_type,
                    severity=f.severity,
                    confidence=float(f.confidence),
                    title=f.title,
                    description=f.description,
                    evidence=f.evidence or {},
                )
                for f in findings_objs
            ],
            scoring_pillars=pillars,
            created_at=analysis_obj.created_at.isoformat(),
        )

    # If no analysis exists, execute live scoring pipeline
    result = await execute_email_analysis_and_scoring(email_id=email_id, db=db)
    return EmailAnalysisResponse(
        analysis_run_id=result["analysis_run_id"],
        email_id=result["email_id"],
        threat_classification=result["threat_classification"],
        threat_risk_score=result["threat_risk_score"],
        evidence_confidence_score=result["evidence_confidence_score"],
        summary=result["summary"],
        compromised_account_likelihood=result["compromised_account_likelihood"],
        spoofed_domain_likelihood=result["spoofed_domain_likelihood"],
        anonymized_infrastructure_likelihood=result["anonymized_infrastructure_likelihood"],
        malicious_environment_likelihood=result["malicious_environment_likelihood"],
        findings=[AnalysisFindingSchema(**f) for f in result["findings"]],
        scoring_pillars=result.get("scoring_pillars", {}),
        created_at=result.get("created_at", datetime.now(timezone.utc).isoformat()),
    )


@router.post(
    "/{email_id}/analyze",
    response_model=EmailAnalysisResponse,
    summary="Trigger Live Email Analysis & Explainable Scoring",
    description="Run the complete forensic analysis and explainable scoring pipeline.",
)
async def trigger_email_analysis(
    email_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> EmailAnalysisResponse:
    """Execute live full-pipeline analysis and calculate explainable score."""
    await get_authorized_email(email_id, current_user, db)

    result = await execute_email_analysis_and_scoring(email_id=email_id, db=db)
    return EmailAnalysisResponse(
        analysis_run_id=result["analysis_run_id"],
        email_id=result["email_id"],
        threat_classification=result["threat_classification"],
        threat_risk_score=result["threat_risk_score"],
        evidence_confidence_score=result["evidence_confidence_score"],
        summary=result["summary"],
        compromised_account_likelihood=result["compromised_account_likelihood"],
        spoofed_domain_likelihood=result["spoofed_domain_likelihood"],
        anonymized_infrastructure_likelihood=result["anonymized_infrastructure_likelihood"],
        malicious_environment_likelihood=result["malicious_environment_likelihood"],
        findings=[AnalysisFindingSchema(**f) for f in result["findings"]],
        created_at=result["created_at"],
    )


@router.get(
    "/{email_id}/findings",
    response_model=FindingsListResponse,
    summary="Get Granular Email Findings",
    description="Retrieve all granular forensic findings for an email, with optional severity filtering.",
)
async def get_email_findings(
    email_id: uuid.UUID,
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> FindingsListResponse:
    """Retrieve list of granular findings."""
    await get_authorized_email(email_id, current_user, db)

    stmt_findings = select(AnalysisFinding).where(AnalysisFinding.email_id == email_id)
    if severity:
        stmt_findings = stmt_findings.where(AnalysisFinding.severity == severity.strip().upper())

    res_findings = await db.execute(stmt_findings)
    findings_objs = res_findings.scalars().all()

    return FindingsListResponse(
        email_id=str(email_id),
        total_findings=len(findings_objs),
        findings=[
            AnalysisFindingSchema(
                finding_type=f.finding_type,
                severity=f.severity,
                confidence=float(f.confidence),
                title=f.title,
                description=f.description,
                evidence=f.evidence or {},
            )
            for f in findings_objs
        ],
    )
