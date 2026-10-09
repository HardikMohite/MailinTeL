"""
End-to-end forensic intelligence pipeline orchestration.

`upload_eml_file()` (see app/api/v1/endpoints/emails.py) performs evidence
preservation, structural parsing, header/auth analysis, and artifact
extraction synchronously, then creates a BackgroundJobManager job and
dispatches this module's `run_full_email_analysis_pipeline` coroutine via
`job_manager.dispatch_background_task`.

This is the piece that was previously missing: nothing ever invoked
`dispatch_background_task`, so jobs were created and then never
progressed past PENDING/QUEUED, and none of the downstream analysis
stages (explainable scoring, threat-intel enrichment, DNA fingerprinting,
semantic similarity, campaign correlation, infrastructure geolocation)
were ever triggered for an uploaded email. This module wires all of that
together and reports granular JobStage/progress updates so the frontend's
processing timeline (AnalysisWorkspace.tsx) reflects real progress and
resolves to COMPLETED once the dossier is populated.
"""

import logging
import uuid
from typing import Any, Callable, Coroutine, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tasks import job_manager, JobStage
from app.db.session import async_session_maker
from app.models.emails import Email
from app.services.scoring_service import execute_email_analysis_and_scoring
from app.services.threat_intel_service import enrich_email_threat_intelligence
from app.services.dna_service import generate_and_persist_email_dna
from app.services.similarity_service import default_similarity_service
from app.services.campaign_service import default_campaign_service
from app.services.geo_service import default_geo_service
from app.services.report_service import ReportService

logger = logging.getLogger("mailintel.services.pipeline")


async def _run_threat_scoring(session: AsyncSession, email_id: uuid.UUID) -> Any:
    return await execute_email_analysis_and_scoring(email_id=email_id, db=session)


async def _run_threat_intel(session: AsyncSession, email_id: uuid.UUID) -> Any:
    return await enrich_email_threat_intelligence(email_id=email_id, db=session)


async def _run_dna_generation(session: AsyncSession, email_id: uuid.UUID) -> Any:
    return await generate_and_persist_email_dna(email_id=email_id, db=session)


async def _run_similarity(session: AsyncSession, email_id: uuid.UUID) -> Any:
    # Generates embeddings first (if missing) then links semantically similar emails.
    email_obj = await session.get(Email, email_id)
    org_id = email_obj.organization_id if email_obj else None
    return await default_similarity_service.find_and_link_similar_emails(
        session=session, email_id=email_id, organization_id=org_id
    )


async def _run_geolocation(session: AsyncSession, email_id: uuid.UUID) -> Any:
    return await default_geo_service.geolocate_email_infrastructure(session, email_id)


async def _run_campaign_correlation(session: AsyncSession, email_id: uuid.UUID) -> Any:
    email_obj = await session.get(Email, email_id)
    org_id = email_obj.organization_id if email_obj else None
    return await default_campaign_service.correlate_email(
        session=session, email_id=email_id, organization_id=org_id
    )


# Ordered pipeline stages. Each stage owns its own DB session/transaction and is
# individually fault-tolerant: a failure in one stage (e.g. an unreachable
# threat-intel provider, or too few emails yet ingested for correlation) is
# logged and recorded, but never aborts the remaining stages, so the
# investigation dossier ends up as complete as the environment allows instead
# of an all-or-nothing job failure hiding otherwise-successful stages.
_PIPELINE_STAGES: list[tuple[JobStage, int, str, Callable[[AsyncSession, uuid.UUID], Coroutine[Any, Any, Any]]]] = [
    (JobStage.ANALYZING_THREATS, 40, "threat_scoring", _run_threat_scoring),
    (JobStage.ANALYZING_THREATS, 50, "threat_intel_enrichment", _run_threat_intel),
    (JobStage.GENERATING_DNA, 65, "dna_generation", _run_dna_generation),
    (JobStage.GEO_LOCATING, 75, "semantic_similarity", _run_similarity),
    (JobStage.GEO_LOCATING, 85, "infrastructure_geolocation", _run_geolocation),
    (JobStage.CORRELATING_CAMPAIGN, 95, "campaign_correlation", _run_campaign_correlation),
]


import asyncio


async def run_full_email_analysis_pipeline(job_id: str, email_id: str) -> Dict[str, Any]:
    """
    Runs downstream analysis stages concurrently where independent, reporting
    progress against the background job with low latency.
    """
    email_uuid = uuid.UUID(email_id)
    summary: Dict[str, Any] = {
        "email_id": email_id,
        "stages_completed": [],
        "stages_failed": [],
    }

    # 1. Structural parsing and IOC extraction already ran during upload
    await job_manager.update_progress(job_id, JobStage.PARSING_EMAIL, 15)
    await job_manager.update_progress(job_id, JobStage.EXTRACTING_IOCS, 25)

    # 2. Fast Threat Scoring Heuristics (local CPU, ~10ms)
    await job_manager.update_progress(job_id, JobStage.ANALYZING_THREATS, 40)
    try:
        async with async_session_maker() as session:
            await _run_threat_scoring(session, email_uuid)
            await session.commit()
        summary["stages_completed"].append("threat_scoring")
    except Exception as exc:
        logger.exception(f"Threat scoring failed for {email_id}: {exc}")
        summary["stages_failed"].append({"stage": "threat_scoring", "error": str(exc)})

    # 3. Concurrent Phase: Threat Intel, DNA Generation, and Geolocation
    # These three stages are completely independent and run in parallel
    await job_manager.update_progress(job_id, JobStage.GENERATING_DNA, 60)

    async def _safe_run(label: str, runner: Callable[[AsyncSession, uuid.UUID], Coroutine[Any, Any, Any]]):
        try:
            async with async_session_maker() as session:
                await runner(session, email_uuid)
                await session.commit()
            return label, None
        except Exception as exc:
            logger.exception(f"Stage '{label}' failed for {email_id}: {exc}")
            return label, str(exc)

    phase2_tasks = [
        _safe_run("threat_intel_enrichment", _run_threat_intel),
        _safe_run("dna_generation", _run_dna_generation),
        _safe_run("infrastructure_geolocation", _run_geolocation),
    ]
    phase2_results = await asyncio.gather(*phase2_tasks)
    for label, err in phase2_results:
        if err:
            summary["stages_failed"].append({"stage": label, "error": err})
        else:
            summary["stages_completed"].append(label)

    # 4. Phase 3: Concurrent Semantic Similarity & Campaign Correlation
    await job_manager.update_progress(job_id, JobStage.GEO_LOCATING, 75)
    phase3_tasks = [
        _safe_run("semantic_similarity", _run_similarity),
        _safe_run("campaign_correlation", _run_campaign_correlation),
    ]
    phase3_results = await asyncio.gather(*phase3_tasks)
    for label, err in phase3_results:
        if err:
            summary["stages_failed"].append({"stage": label, "error": err})
        else:
            summary["stages_completed"].append(label)

    # Invalidate all caches across panels so next views reflect updated pipeline findings
    try:
        from app.services.report_service import ReportService
        from app.services.graph_service import InvestigationGraphService
        from app.services.geo_service import GeolocationService
        from app.api.v1.endpoints.emails import invalidate_email_metadata_cache
        await ReportService.invalidate_report_cache(email_uuid)
        await InvestigationGraphService.invalidate_graph_cache(email_id=email_uuid)
        await GeolocationService.invalidate_geo_cache(email_id=email_uuid)
        await invalidate_email_metadata_cache(email_uuid)
    except Exception as inv_err:
        logger.debug(f"Cache invalidation notice for {email_id}: {inv_err}")

    if summary["stages_failed"]:
        logger.warning(
            f"Analysis pipeline for email {email_id} (job {job_id}) completed with "
            f"{len(summary['stages_failed'])} failed stage(s): "
            f"{[s['stage'] for s in summary['stages_failed']]}"
        )
    else:
        logger.info(f"Analysis pipeline for email {email_id} (job {job_id}) completed successfully.")

    return summary
