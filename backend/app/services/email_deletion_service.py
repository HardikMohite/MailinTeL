import uuid
import logging
import asyncio
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, or_

from app.core.storage import storage
from app.core.redis import redis_manager
from app.models.emails import (
    Email,
    EmailSource,
    EmailHeader,
    EmailRecipient,
    RelayHop,
    EmailAuthenticationResult,
)
from app.models.evidence import EvidenceObject, CustodyEvent
from app.models.intelligence import EmailURL, EntityGeolocation
from app.models.indicators import IndicatorSighting
from app.models.analysis import AnalysisRun, EmailAnalysis, AnalysisFinding
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.embeddings import EmailEmbedding
from app.models.campaign import CampaignMembership
from app.models.disposition import EmailDisposition
from app.models.reports import Report

logger = logging.getLogger("mailintel.services.deletion")


class EmailDeletionService:
    """
    Comprehensive forensic deletion service for emails.
    Permanently purges:
      1. MinIO binary evidence objects (original .eml and derived attachments)
      2. Custody events and cryptographic chains
      3. Forensic analysis, findings, scores, and explainability records
      4. RFC822 headers, recipients, SMTP relay hops, and authentication verdicts
      5. DNA profiles, semantic embeddings, and similarity links
      6. Campaign memberships and human disposition records
      7. Threat indicator sightings and entity geolocations
      8. Generated forensic intelligence reports and dossiers
      9. The core Email record and orphaned EmailSource records
      10. Multi-tier Redis and in-memory caches across all platform panels
    """

    @staticmethod
    async def purge_caches(email_id: uuid.UUID) -> None:
        """Purges all L1 and L2 caches related to an email."""
        eid_str = str(email_id)
        try:
            from app.api.v1.endpoints.emails import _EMAIL_CACHE, _AUTH_CACHE
            # Clear L1 memory caches
            keys_to_del = [k for k in _EMAIL_CACHE.keys() if eid_str in k or k.startswith("list:")]
            for k in keys_to_del:
                _EMAIL_CACHE.pop(k, None)
            auth_keys = [k for k in _AUTH_CACHE.keys() if k[0] == eid_str]
            for k in auth_keys:
                _AUTH_CACHE.pop(k, None)

            # Invalidate service caches
            from app.services.graph_service import InvestigationGraphService, _GRAPH_CACHE
            await InvestigationGraphService.invalidate_graph_cache(email_id=email_id)
            _GRAPH_CACHE.clear()

            from app.services.geo_service import GeolocationService, _GEO_EMAIL_CACHE, _GEO_GLOBAL_CACHE
            await GeolocationService.invalidate_geo_cache(email_id=email_id)
            _GEO_EMAIL_CACHE.clear()
            _GEO_GLOBAL_CACHE.clear()

            from app.services.report_service import ReportService
            await ReportService.invalidate_report_cache(email_id)

            from app.api.v1.endpoints.dashboard import _DASHBOARD_CACHE
            _DASHBOARD_CACHE.clear()

            from app.services.campaign_service import _CAMPAIGN_LIST_CACHE, _BUNDLE_CACHE
            _CAMPAIGN_LIST_CACHE.clear()
            _BUNDLE_CACHE.pop(email_id, None)

            # Invalidate Redis L2 caches
            await redis_manager.delete(f"cache:email:details:{eid_str}")
            await redis_manager.delete(f"cache:email:headers:{eid_str}")
            await redis_manager.delete(f"cache:email:hops:{eid_str}")
            await redis_manager.delete(f"cache:email:auth:{eid_str}")
            await redis_manager.delete(f"cache:email:structure:{eid_str}")
            await redis_manager.delete(f"cache:email:artifacts:{eid_str}")
            await redis_manager.delete(f"cache:graph:email:{eid_str}")
            await redis_manager.delete(f"cache:geo:email:{eid_str}")
            await redis_manager.delete(f"cache:report:data:email:{eid_str}")
            await redis_manager.delete(f"rendered_report:html:{eid_str}")
            await redis_manager.delete(f"rendered_report:markdown:{eid_str}")
            await redis_manager.delete(f"rendered_report:json:{eid_str}")
            await redis_manager.delete(f"rendered_report:pdf:{eid_str}")
        except Exception as e:
            logger.warning(f"Cache purge warning during email {email_id} deletion: {e}")

    @classmethod
    async def delete_email_cascade(
        cls,
        email_id: uuid.UUID,
        db: AsyncSession,
        actor_user_id: Optional[uuid.UUID] = None,
    ) -> bool:
        """
        Executes a complete, transactional forensic deletion of an email and all related records.
        Returns True if deleted, False if email did not exist.
        """
        # 1. Fetch target Email record
        email_res = await db.execute(select(Email).where(Email.id == email_id))
        email_obj = email_res.scalar_one_or_none()
        if not email_obj:
            return False

        source_id = email_obj.source_id
        org_id = email_obj.organization_id

        # 2. Collect and remove MinIO evidence objects (original .eml, attachments, derived artifacts)
        evidence_res = await db.execute(
            select(EvidenceObject).where(EvidenceObject.email_id == email_id)
        )
        evidence_objs = evidence_res.scalars().all()
        evidence_ids = [ev.id for ev in evidence_objs]

        for ev in evidence_objs:
            if ev.bucket_name and ev.object_key:
                try:
                    await asyncio.to_thread(
                        storage.delete_evidence_object,
                        bucket_name=ev.bucket_name,
                        object_key=ev.object_key,
                    )
                except Exception as sto_err:
                    logger.warning(f"Failed to delete storage object {ev.object_key}: {sto_err}")

        # 3. Delete Reports and associated report artifacts
        reports_res = await db.execute(select(Report).where(Report.email_id == email_id))
        reports_list = reports_res.scalars().all()
        for rep in reports_list:
            if rep.evidence_object_id:
                rep_ev_res = await db.execute(
                    select(EvidenceObject).where(EvidenceObject.id == rep.evidence_object_id)
                )
                rep_ev = rep_ev_res.scalar_one_or_none()
                if rep_ev and rep_ev.bucket_name and rep_ev.object_key:
                    try:
                        await asyncio.to_thread(
                            storage.delete_evidence_object,
                            bucket_name=rep_ev.bucket_name,
                            object_key=rep_ev.object_key,
                        )
                    except Exception:
                        pass
        await db.execute(delete(Report).where(Report.email_id == email_id))

        # 4. Delete Custody Events and Evidence Objects
        if evidence_ids:
            await db.execute(delete(CustodyEvent).where(CustodyEvent.evidence_id.in_(evidence_ids)))
        await db.execute(delete(EvidenceObject).where(EvidenceObject.email_id == email_id))

        # 5. Delete Analysis, Explainability Findings, and Runs
        await db.execute(delete(AnalysisFinding).where(AnalysisFinding.email_id == email_id))
        await db.execute(delete(EmailAnalysis).where(EmailAnalysis.email_id == email_id))
        await db.execute(delete(AnalysisRun).where(AnalysisRun.email_id == email_id))

        # 6. Delete Transmission Headers, Recipients, Relay Hops, and Authentication
        await db.execute(delete(EmailHeader).where(EmailHeader.email_id == email_id))
        await db.execute(delete(EmailRecipient).where(EmailRecipient.email_id == email_id))
        await db.execute(delete(RelayHop).where(RelayHop.email_id == email_id))
        await db.execute(delete(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id))
        await db.execute(delete(EmailURL).where(EmailURL.email_id == email_id))

        # 7. Delete DNA Profiles, Similarity Links, and Embeddings
        await db.execute(delete(EmailDNAProfile).where(EmailDNAProfile.email_id == email_id))
        await db.execute(
            delete(EmailSimilarityLink).where(
                or_(
                    EmailSimilarityLink.source_email_id == email_id,
                    EmailSimilarityLink.related_email_id == email_id,
                )
            )
        )
        try:
            await db.execute(delete(EmailEmbedding).where(EmailEmbedding.email_id == email_id))
        except Exception:
            pass

        # 8. Delete Threat Sightings and Entity Geolocations
        await db.execute(delete(IndicatorSighting).where(IndicatorSighting.email_id == email_id))
        try:
            await db.execute(
                delete(EntityGeolocation).where(
                    EntityGeolocation.entity_id == email_id,
                )
            )
        except Exception:
            pass

        # 9. Delete Campaign Memberships and Analyst Dispositions
        await db.execute(delete(CampaignMembership).where(CampaignMembership.email_id == email_id))
        try:
            await db.execute(delete(EmailDisposition).where(EmailDisposition.email_id == email_id))
        except Exception:
            pass

        # 10. Delete the Email Record itself
        await db.execute(delete(Email).where(Email.id == email_id))

        # 11. Clean up orphaned EmailSource if no other email references it
        if source_id:
            count_res = await db.execute(
                select(func.count(Email.id)).where(Email.source_id == source_id)
            )
            other_count = count_res.scalar_one()
            if other_count == 0:
                await db.execute(delete(EmailSource).where(EmailSource.id == source_id))

        await db.commit()

        # 12. Record Audit Event
        try:
            from app.core.audit import record_audit
            await record_audit(
                db,
                actor_user_id=actor_user_id,
                organization_id=org_id,
                action="DELETE",
                resource_type="EMAIL",
                resource_id=email_id,
                metadata_json={"email_id": str(email_id)},
            )
            await db.commit()
        except Exception as aud_err:
            logger.debug(f"Audit record notice: {aud_err}")

        # 13. Purge all multi-tier caches
        await cls.purge_caches(email_id)

        logger.info(f"Permanently purged email {email_id} and all associated forensic data.")
        return True


default_email_deletion_service = EmailDeletionService()
