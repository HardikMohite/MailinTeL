import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.emails import Email, RelayHop, EmailAuthenticationResult
from app.models.intelligence import Domain, URL, EmailURL, IPAddress, IPIntelligence, InfrastructureClassification
from app.models.evidence import EvidenceObject
from app.models.analysis import AnalysisRun, EmailAnalysis, AnalysisFinding
from app.scoring.explainable_scorer import ExplainableScoringEngine, ScoringResult

logger = logging.getLogger(__name__)


async def execute_email_analysis_and_scoring(
    email_id: uuid.UUID,
    db: AsyncSession,
    scoring_engine: Optional[ExplainableScoringEngine] = None,
) -> Dict[str, Any]:
    """
    Executes the full pipeline explainable scoring for an email,
    aggregating all forensic evidence, domain intel, infrastructure intel,
    and threat intel into an AnalysisRun, EmailAnalysis, and AnalysisFindings.
    """
    engine = scoring_engine or ExplainableScoringEngine()
    now_utc = datetime.now(timezone.utc)

    # 1. Fetch Email
    stmt_email = select(Email).where(Email.id == email_id)
    res_email = await db.execute(stmt_email)
    email_obj = res_email.scalar_one_or_none()
    if not email_obj:
        raise ValueError(f"Email with ID '{email_id}' not found")

    # 2. Fetch Authentication Results
    stmt_auth = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
    res_auth = await db.execute(stmt_auth)
    auth_obj = res_auth.scalar_one_or_none()
    auth_dict = {
        "spf_verdict": auth_obj.spf_result if auth_obj else None,
        "spf_domain": (auth_obj.evidence.get("spf_domain") if auth_obj and auth_obj.evidence else None),
        "dkim_verdict": auth_obj.dkim_result if auth_obj else None,
        "dmarc_verdict": auth_obj.dmarc_result if auth_obj else None,
        "from_domain_aligned": auth_obj.from_alignment_result if auth_obj else None,
        "reply_to": auth_obj.reply_to if auth_obj else None,
        "return_path": auth_obj.return_path if auth_obj else None,
    } if auth_obj else {}

    # 3. Fetch Relay Hops
    stmt_hops = select(RelayHop).where(RelayHop.email_id == email_id).order_by(RelayHop.sequence_number.asc())
    res_hops = await db.execute(stmt_hops)
    hops_objs = res_hops.scalars().all()
    hops_list = [
        {
            "hop_index": h.sequence_number,
            "source_host": h.source_host,
            "source_ip": h.source_ip,
            "destination_host": h.destination_host,
            "delay_seconds": (h.evidence.get("transit_delay_seconds") if h.evidence else None),
            "is_hop_reliable": h.reliability,
        }
        for h in hops_objs
    ]

    # 4. Fetch Artifacts (Attachments, URLs)
    stmt_evidence = select(EvidenceObject).where(
        EvidenceObject.email_id == email_id,
        EvidenceObject.evidence_type == "ATTACHMENT",
    )
    res_evidence = await db.execute(stmt_evidence)
    evidence_objs = res_evidence.scalars().all()
    attachments_list = [
        {
            "filename": ev.original_filename,
            "sha256_hash": ev.sha256_hash,
            "size_bytes": ev.size_bytes,
            "is_dangerous": bool(getattr(ev, "metadata_json", None) and ev.metadata_json.get("is_dangerous")),
            "extension": ("." + ev.original_filename.rsplit(".", 1)[-1].lower() if "." in ev.original_filename else ""),
        }
        for ev in evidence_objs
    ]

    stmt_urls = (
        select(URL.normalized_url)
        .join(EmailURL, EmailURL.url_id == URL.id)
        .where(EmailURL.email_id == email_id)
    )
    res_urls = await db.execute(stmt_urls)
    urls_list = [{"url": r[0]} for r in res_urls.all()]

    artifacts_dict = {
        "attachments": attachments_list,
        "urls": urls_list,
        "total_urls": len(urls_list),
        "total_attachments": len(attachments_list),
    }

    # 5. Fetch Domain Intelligence
    from app.services.domain_intel_service import enrich_email_domains
    try:
        domain_bundles = await enrich_email_domains(email_id=email_id, db=db)
        domain_intel_list = [b.to_dict() for b in domain_bundles]
    except Exception as e:
        logger.warning(f"Domain intel enrichment error during scoring: {e}")
        domain_intel_list = []

    # 6. Fetch Infrastructure Intelligence
    from app.services.infrastructure_service import enrich_email_infrastructure
    try:
        ip_bundles = await enrich_email_infrastructure(email_id=email_id, db=db)
        infra_intel_list = [b.to_dict() for b in ip_bundles]
    except Exception as e:
        logger.warning(f"Infrastructure intel enrichment error during scoring: {e}")
        infra_intel_list = []

    # 7. Fetch Threat Intelligence
    from app.services.threat_intel_service import enrich_email_threat_intelligence
    try:
        threat_intel_dict = await enrich_email_threat_intelligence(email_id=email_id, db=db)
    except Exception as e:
        logger.warning(f"Threat intel enrichment error during scoring: {e}")
        threat_intel_dict = {}

    # 8. Create AnalysisRun record
    analysis_run = AnalysisRun(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_type="FULL_PIPELINE",
        analysis_version="1.0",
        status="RUNNING",
        started_at=now_utc,
    )
    db.add(analysis_run)
    await db.flush()

    # 9. Evaluate scoring
    email_metadata = {
        "sender_address": email_obj.sender_address,
        "sender_display_name": email_obj.sender_display_name,
        "reply_to": auth_dict.get("reply_to"),
        "return_path": auth_dict.get("return_path"),
        "subject": email_obj.subject,
        "sent_at": email_obj.sent_at.isoformat() if email_obj.sent_at else None,
    }

    scoring_result = engine.evaluate_email(
        email_metadata=email_metadata,
        auth_results=auth_dict,
        relay_hops=hops_list,
        artifacts=artifacts_dict,
        domain_intel=domain_intel_list,
        infrastructure_intel=infra_intel_list,
        threat_intel=threat_intel_dict,
    )

    # 10. Persist EmailAnalysis
    email_analysis = EmailAnalysis(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=analysis_run.id,
        threat_classification=scoring_result.threat_classification,
        threat_risk_score=scoring_result.threat_risk_score,
        evidence_confidence_score=scoring_result.evidence_confidence_score,
        summary=scoring_result.summary,
        compromised_account_likelihood=scoring_result.compromised_account_likelihood,
        spoofed_domain_likelihood=scoring_result.spoofed_domain_likelihood,
        anonymized_infrastructure_likelihood=scoring_result.anonymized_infrastructure_likelihood,
        malicious_environment_likelihood=scoring_result.malicious_environment_likelihood,
        created_at=now_utc,
        updated_at=now_utc,
    )
    db.add(email_analysis)

    # 11. Persist AnalysisFindings
    for f in scoring_result.findings:
        finding_rec = AnalysisFinding(
            id=uuid.uuid4(),
            email_id=email_id,
            analysis_run_id=analysis_run.id,
            finding_type=f.finding_type,
            severity=f.severity,
            confidence=f.confidence,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            created_at=now_utc,
        )
        db.add(finding_rec)

    # 12. Mark AnalysisRun and Email as COMPLETED
    analysis_run.status = "COMPLETED"
    analysis_run.completed_at = datetime.now(timezone.utc)
    analysis_run.metadata_json = {
        "scoring_pillars": scoring_result.scoring_pillars,
    }
    email_obj.analysis_status = "COMPLETED"

    await db.commit()

    logger.info(
        f"Email analysis and explainable scoring completed for {email_id}: "
        f"Threat={scoring_result.threat_classification}, Risk={scoring_result.threat_risk_score}, "
        f"Confidence={scoring_result.evidence_confidence_score}, Findings={len(scoring_result.findings)}"
    )

    return {
        "analysis_run_id": str(analysis_run.id),
        "email_id": str(email_id),
        "threat_classification": scoring_result.threat_classification,
        "threat_risk_score": scoring_result.threat_risk_score,
        "evidence_confidence_score": scoring_result.evidence_confidence_score,
        "summary": scoring_result.summary,
        "compromised_account_likelihood": scoring_result.compromised_account_likelihood,
        "spoofed_domain_likelihood": scoring_result.spoofed_domain_likelihood,
        "anonymized_infrastructure_likelihood": scoring_result.anonymized_infrastructure_likelihood,
        "malicious_environment_likelihood": scoring_result.malicious_environment_likelihood,
        "findings": [f.to_dict() for f in scoring_result.findings],
        "scoring_pillars": scoring_result.scoring_pillars,
        "created_at": now_utc.isoformat(),
    }
