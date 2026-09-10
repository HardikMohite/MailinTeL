import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy import select, and_, or_, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import redis_manager
from app.models.emails import Email, EmailSource, RelayHop
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.intelligence import URL, EmailURL, Domain, IPAddress
from app.models.evidence import EvidenceObject
from app.models.campaign import Campaign, CampaignMembership, CampaignEvidence, CampaignEvent
from app.campaigns.correlation_engine import default_correlation_engine, CorrelationEngine, CorrelationResult

logger = logging.getLogger("mailintel.services.campaigns")


# Fast in-memory cache for forensic bundles to eliminate redundant DB round trips
_BUNDLE_CACHE: Dict[uuid.UUID, Tuple[float, Dict[str, Any]]] = {}
_BUNDLE_CACHE_TTL_SECONDS: float = 1800.0  # 30 minutes

# Cache for campaign details
_CAMPAIGN_DETAILS_CACHE: Dict[uuid.UUID, Tuple[float, Dict[str, Any]]] = {}
_CAMPAIGN_CACHE_TTL: float = 1800.0


class CampaignCorrelationService:
    """
    Service for discovering correlation signals, clustering threat campaigns,
    and managing overlapping multi-campaign relationships with full evidence preservation.
    """

    def __init__(self, engine: Optional[CorrelationEngine] = None):
        self.engine = engine or default_correlation_engine

    async def _gather_email_forensic_bundle(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> Optional[Dict[str, Any]]:
        """Gathers all forensic artifacts, DNA, and metadata for correlation evaluation."""
        now_ts = datetime.now(timezone.utc).timestamp()
        cached = _BUNDLE_CACHE.get(email_id)
        if cached and (now_ts - cached[0]) < _BUNDLE_CACHE_TTL_SECONDS:
            return cached[1]

        email_res = await session.execute(select(Email).where(Email.id == email_id))
        email_obj = email_res.scalar_one_or_none()
        if not email_obj:
            return None

        # 1. URLs
        urls_res = await session.execute(
            select(URL.normalized_url, URL.url_hash)
            .join(EmailURL, EmailURL.url_id == URL.id)
            .where(EmailURL.email_id == email_id)
        )
        urls = [{"normalized_url": r[0], "url_hash": r[1]} for r in urls_res.all()]

        # 2. Domains
        domains_res = await session.execute(
            select(Domain.normalized_domain, Domain.root_domain)
            .where(Domain.id.in_(
                select(URL.domain_id)
                .join(EmailURL, EmailURL.url_id == URL.id)
                .where(EmailURL.email_id == email_id)
            ))
        )
        domains = [{"domain_name": r[0], "root_domain": r[1]} for r in domains_res.all()]

        # 3. IPs & Infrastructure
        hops_res = await session.execute(
            select(RelayHop.source_ip).where(RelayHop.email_id == email_id)
        )
        ips = [
            {"ip_address": r[0], "asn": None, "is_private": False, "is_tor": False}
            for r in hops_res.all() if r[0]
        ]

        # 4. Attachments (EvidenceObjects)
        att_res = await session.execute(
            select(EvidenceObject.sha256_hash, EvidenceObject.original_filename, EvidenceObject.size_bytes)
            .where(
                and_(
                    EvidenceObject.email_id == email_id,
                    EvidenceObject.evidence_type == "ATTACHMENT",
                )
            )
        )
        attachments = [
            {"sha256_hash": r[0], "filename": r[1], "size_bytes": r[2]}
            for r in att_res.all()
        ]

        # 5. DNA Profile
        dna_res = await session.execute(
            select(EmailDNAProfile)
            .where(EmailDNAProfile.email_id == email_id)
            .order_by(EmailDNAProfile.created_at.desc())
        )
        dna_obj = dna_res.scalars().first()
        dna_profile = {
            "content_fingerprint": dna_obj.content_fingerprint if dna_obj else {},
            "technical_fingerprint": dna_obj.technical_fingerprint if dna_obj else {},
            "infrastructure_fingerprint": dna_obj.infrastructure_fingerprint if dna_obj else {},
            "behavioral_fingerprint": dna_obj.behavioral_fingerprint if dna_obj else {},
            "temporal_fingerprint": dna_obj.temporal_fingerprint if dna_obj else {},
        } if dna_obj else None

        bundle = {
            "email_id": email_id,
            "subject": email_obj.subject,
            "sender_address": email_obj.sender_address,
            "sent_at": email_obj.sent_at,
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "attachments": attachments,
            "dna_profile": dna_profile,
        }
        _BUNDLE_CACHE[email_id] = (now_ts, bundle)
        return bundle

    async def correlate_email(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        min_score: float = 40.0,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Computes pairwise multi-signal correlation between source email and candidate emails.
        Limits to top 30 most recent candidate emails to prevent unbounded processing latency.
        """
        source_bundle = await self._gather_email_forensic_bundle(session, email_id)
        if not source_bundle:
            raise ValueError(f"Email {email_id} not found.")

        candidates_stmt = select(Email.id).where(Email.id != email_id)
        if organization_id is not None:
            candidates_stmt = candidates_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
        candidates_stmt = candidates_stmt.order_by(Email.created_at.desc()).limit(30)
        candidates_res = await session.execute(candidates_stmt)
        candidate_ids = [r[0] for r in candidates_res.all()]

        sim_res = await session.execute(
            select(EmailSimilarityLink.related_email_id, EmailSimilarityLink.similarity_score)
            .where(EmailSimilarityLink.source_email_id == email_id)
        )
        similarity_map = {r[0]: float(r[1]) for r in sim_res.all()}

        results: List[Dict[str, Any]] = []

        for cid in candidate_ids:
            target_bundle = await self._gather_email_forensic_bundle(session, cid)
            if not target_bundle:
                continue

            source_bundle["semantic_similarity_to_target"] = similarity_map.get(cid)
            corr_result = self.engine.correlate_email_pair(source_bundle, target_bundle)

            if corr_result.composite_correlation_score >= min_score:
                results.append({
                    "source_email_id": str(email_id),
                    "target_email_id": str(cid),
                    "target_subject": target_bundle["subject"],
                    "target_sender": target_bundle["sender_address"],
                    "composite_correlation_score": corr_result.composite_correlation_score,
                    "primary_link_reason": corr_result.primary_link_reason,
                    "evidence_count": corr_result.evidence_count,
                    "is_actionable_correlation": corr_result.is_actionable_correlation,
                    "signals": [
                        {
                            "signal_type": s.signal_type,
                            "confidence": s.confidence,
                            "weight": s.weight,
                            "description": s.description,
                            "evidence": s.evidence,
                        }
                        for s in corr_result.signals
                    ],
                })

        results.sort(key=lambda x: x["composite_correlation_score"], reverse=True)
        return results

    async def create_campaign(
        self,
        session: AsyncSession,
        campaign_name: str,
        threat_summary: Optional[str] = None,
        campaign_status: str = "ACTIVE",
        campaign_confidence: float = 80.0,
        initial_email_ids: Optional[List[uuid.UUID]] = None,
        organization_id: Optional[uuid.UUID] = None,
    ) -> Campaign:
        """
        Creates a new campaign entity with initial memberships and creation event.

        SECURITY: `organization_id` (the creating user's organization) is
        stamped onto the campaign and is the tenant boundary every
        campaign-scoped endpoint checks against. When provided, any
        `initial_email_ids` that don't belong to that organization are
        silently dropped rather than attached — an authenticated user from
        org A must not be able to seed a campaign with org B's emails by ID.
        """
        now = datetime.now(timezone.utc)
        campaign = Campaign(
            campaign_name=campaign_name,
            campaign_status=campaign_status,
            campaign_confidence=campaign_confidence,
            threat_summary=threat_summary,
            organization_id=organization_id,
            first_detected_at=now,
            last_activity_at=now,
        )
        session.add(campaign)
        await session.flush()  # obtain campaign.id

        # Add initial memberships
        if initial_email_ids:
            allowed_email_ids = set(initial_email_ids)
            if organization_id is not None:
                owned_res = await session.execute(
                    select(Email.id)
                    .join(EmailSource, EmailSource.id == Email.source_id)
                    .where(
                        Email.id.in_(allowed_email_ids),
                        EmailSource.organization_id == organization_id,
                    )
                )
                allowed_email_ids = {r[0] for r in owned_res.all()}

            for eid in allowed_email_ids:
                membership = CampaignMembership(
                    campaign_id=campaign.id,
                    email_id=eid,
                    membership_confidence=campaign_confidence,
                    membership_status="CONFIRMED",
                    evidence_summary={"created_with_campaign": True},
                )
                session.add(membership)

        # Log creation event
        event = CampaignEvent(
            campaign_id=campaign.id,
            event_type="CAMPAIGN_CREATED",
            occurred_at=now,
            description=f"Campaign '{campaign_name}' created with {len(initial_email_ids or [])} initial emails.",
            metadata_json={"confidence": campaign_confidence, "status": campaign_status},
        )
        session.add(event)

        await session.commit()
        await session.refresh(campaign)
        return campaign

    async def add_email_to_campaign(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
        email_id: uuid.UUID,
        membership_confidence: float = 80.0,
        membership_status: str = "CONFIRMED",
        evidence_summary: Optional[Dict[str, Any]] = None,
        organization_id: Optional[uuid.UUID] = None,
    ) -> CampaignMembership:
        """
        Links an email to a campaign, explicitly supporting overlapping memberships
        if the email already belongs to other campaigns.

        SECURITY: when `organization_id` is provided, both the campaign and
        the email must belong to it — otherwise a caller could attach their
        own org's email into another org's campaign (or vice versa) despite
        the endpoint-level ownership check on the campaign alone.
        """
        # Verify campaign exists
        c_res = await session.execute(select(Campaign).where(Campaign.id == campaign_id))
        campaign = c_res.scalar_one_or_none()
        if not campaign:
            raise ValueError(f"Campaign {campaign_id} not found.")
        if organization_id is not None and campaign.organization_id not in (None, organization_id):
            raise ValueError(f"Campaign {campaign_id} not found.")

        if organization_id is not None:
            email_org_res = await session.execute(
                select(EmailSource.organization_id)
                .join(Email, Email.source_id == EmailSource.id)
                .where(Email.id == email_id)
            )
            email_org_row = email_org_res.first()
            email_org_id = email_org_row[0] if email_org_row else None
            if email_org_id is not None and email_org_id != organization_id:
                raise ValueError(f"Email {email_id} not found.")

        # Check existing membership
        m_res = await session.execute(
            select(CampaignMembership).where(
                and_(
                    CampaignMembership.campaign_id == campaign_id,
                    CampaignMembership.email_id == email_id,
                )
            )
        )
        membership = m_res.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if membership:
            membership.membership_confidence = membership_confidence
            membership.membership_status = membership_status
            if evidence_summary:
                membership.evidence_summary = evidence_summary
        else:
            membership = CampaignMembership(
                campaign_id=campaign_id,
                email_id=email_id,
                membership_confidence=membership_confidence,
                membership_status=membership_status,
                evidence_summary=evidence_summary or {},
            )
            session.add(membership)

            # Update campaign last_activity_at
            campaign.last_activity_at = now

            # Log event
            event = CampaignEvent(
                campaign_id=campaign_id,
                event_type="EMAIL_ATTACHED",
                occurred_at=now,
                description=f"Email {email_id} attached with confidence {membership_confidence}%.",
                metadata_json={"email_id": str(email_id), "status": membership_status},
            )
            session.add(event)

        await session.commit()
        await session.refresh(membership)
        await self.invalidate_campaign_cache(campaign_id)
        return membership

    async def remove_email_from_campaign(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
        email_id: uuid.UUID,
        organization_id: Optional[uuid.UUID] = None,
    ) -> bool:
        """
        Removes an email membership from a campaign.

        SECURITY: defense-in-depth — even though the endpoint layer verifies
        campaign ownership via get_authorized_campaign before calling this,
        we re-verify here so this service method is safe to call directly.
        """
        if organization_id is not None:
            c_res = await session.execute(select(Campaign.organization_id).where(Campaign.id == campaign_id))
            row = c_res.first()
            if not row or (row[0] is not None and row[0] != organization_id):
                return False

        del_res = await session.execute(
            delete(CampaignMembership).where(
                and_(
                    CampaignMembership.campaign_id == campaign_id,
                    CampaignMembership.email_id == email_id,
                )
            )
        )
        await session.commit()
        await self.invalidate_campaign_cache(campaign_id)
        return del_res.rowcount > 0

    @staticmethod
    async def invalidate_campaign_cache(campaign_id: uuid.UUID) -> None:
        """Invalidates campaign detail caches upon modification."""
        try:
            _CAMPAIGN_DETAILS_CACHE.pop(campaign_id, None)
            await redis_manager.delete(f"cache:campaign:details:{campaign_id}")
        except Exception as e:
            logger.warning(f"Campaign cache invalidation notice: {e}")

    async def get_campaign_details(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves comprehensive details for a campaign with memberships, evidence, and events."""
        now = time.time()
        if campaign_id in _CAMPAIGN_DETAILS_CACHE:
            ts, data = _CAMPAIGN_DETAILS_CACHE[campaign_id]
            if now - ts < _CAMPAIGN_CACHE_TTL:
                return data
        try:
            r_data = await redis_manager.get_json(f"cache:campaign:details:{campaign_id}")
            if r_data:
                _CAMPAIGN_DETAILS_CACHE[campaign_id] = (now, r_data)
                return r_data
        except Exception:
            pass

        c_res = await session.execute(select(Campaign).where(Campaign.id == campaign_id))
        c = c_res.scalar_one_or_none()
        if not c:
            return None

        # Fetch memberships with email subjects
        m_res = await session.execute(
            select(CampaignMembership, Email.subject, Email.sender_address)
            .join(Email, Email.id == CampaignMembership.email_id)
            .where(CampaignMembership.campaign_id == campaign_id)
        )
        memberships_data = []
        for m, subj, sender in m_res.all():
            memberships_data.append({
                "id": str(m.id),
                "email_id": str(m.email_id),
                "email_subject": subj,
                "email_sender": sender,
                "membership_confidence": float(m.membership_confidence),
                "membership_status": m.membership_status,
                "evidence_summary": m.evidence_summary or {},
                "created_at": m.created_at.isoformat() if m.created_at else None,
            })

        # Fetch evidence items
        ev_res = await session.execute(
            select(CampaignEvidence).where(CampaignEvidence.campaign_id == campaign_id)
        )
        evidence_data = [
            {
                "id": str(e.id),
                "evidence_type": e.evidence_type,
                "confidence": float(e.confidence),
                "explanation": e.explanation,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in ev_res.scalars().all()
        ]

        # Fetch timeline events
        evts_res = await session.execute(
            select(CampaignEvent)
            .where(CampaignEvent.campaign_id == campaign_id)
            .order_by(CampaignEvent.occurred_at.asc())
        )
        events_data = [
            {
                "id": str(evt.id),
                "event_type": evt.event_type,
                "occurred_at": evt.occurred_at.isoformat() if evt.occurred_at else None,
                "description": evt.description,
                "metadata": evt.metadata_json or {},
            }
            for evt in evts_res.scalars().all()
        ]

        res_dict = {
            "id": str(c.id),
            "campaign_name": c.campaign_name,
            "campaign_status": c.campaign_status,
            "campaign_confidence": float(c.campaign_confidence),
            "threat_summary": c.threat_summary,
            "first_detected_at": c.first_detected_at.isoformat() if c.first_detected_at else None,
            "last_activity_at": c.last_activity_at.isoformat() if c.last_activity_at else None,
            "total_members": len(memberships_data),
            "total_evidence_links": len(evidence_data),
            "memberships": memberships_data,
            "evidence": evidence_data,
            "events": events_data,
        }
        _CAMPAIGN_DETAILS_CACHE[campaign_id] = (now, res_dict)
        try:
            await redis_manager.set_json(f"cache:campaign:details:{campaign_id}", res_dict, expire_seconds=1800)
        except Exception:
            pass
        return res_dict

    async def list_campaigns(
        self,
        session: AsyncSession,
        status_filter: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        organization_id: Optional[uuid.UUID] = None,
        owner_user_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lists campaigns with member counts and last activity timestamps.

        SECURITY: `organization_id` scopes the listing to the caller's
        tenant. Without it every authenticated user on the platform would
        see every organization's campaigns. Legacy rows with a NULL
        organization_id (pre-migration, unresolvable backfill) are excluded
        rather than shown to everyone.

        `owner_user_id`, when provided, further restricts the listing to
        campaigns that contain at least one email uploaded by that user
        (via CampaignMembership -> Email -> EmailSource.user_id). This is
        how the USER role's "my campaigns only" view is enforced — see
        app.api.deps.ADMIN_ROLES / ANALYST_ROLES vs plain USER callers in
        the campaigns router.
        """
        from app.models.emails import Email, EmailSource  # local import avoids a cycle

        query = select(Campaign)
        if organization_id is not None:
            query = query.where(Campaign.organization_id == organization_id)
        if status_filter:
            query = query.where(Campaign.campaign_status == status_filter)
        if owner_user_id is not None:
            query = query.where(
                Campaign.id.in_(
                    select(CampaignMembership.campaign_id)
                    .join(Email, Email.id == CampaignMembership.email_id)
                    .join(EmailSource, EmailSource.id == Email.source_id)
                    .where(EmailSource.user_id == owner_user_id)
                )
            )
        query = query.order_by(Campaign.last_activity_at.desc()).offset(skip).limit(limit)

        result = await session.execute(query)
        campaigns = result.scalars().all()

        output: List[Dict[str, Any]] = []
        for c in campaigns:
            # Count members
            cnt_res = await session.execute(
                select(func.count(CampaignMembership.id)).where(CampaignMembership.campaign_id == c.id)
            )
            member_count = cnt_res.scalar() or 0

            output.append({
                "id": str(c.id),
                "campaign_name": c.campaign_name,
                "campaign_status": c.campaign_status,
                "campaign_confidence": float(c.campaign_confidence),
                "threat_summary": c.threat_summary,
                "first_detected_at": c.first_detected_at.isoformat() if c.first_detected_at else None,
                "last_activity_at": c.last_activity_at.isoformat() if c.last_activity_at else None,
                "member_count": member_count,
            })
        return output

    async def get_email_campaign_memberships(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        organization_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """
        Returns all campaigns an email belongs to, explicitly detecting if it is a
        'bridge entity' connecting multiple overlapping campaign investigations.

        SECURITY: defense-in-depth org filter on the joined campaigns, on top
        of the endpoint-level ownership check on `email_id` itself.
        """
        stmt = (
            select(CampaignMembership, Campaign.campaign_name, Campaign.campaign_status)
            .join(Campaign, Campaign.id == CampaignMembership.campaign_id)
            .where(CampaignMembership.email_id == email_id)
        )
        if organization_id is not None:
            stmt = stmt.where(
                or_(Campaign.organization_id.is_(None), Campaign.organization_id == organization_id)
            )
        result = await session.execute(stmt)
        memberships = []
        for m, c_name, c_status in result.all():
            memberships.append({
                "membership_id": str(m.id),
                "campaign_id": str(m.campaign_id),
                "campaign_name": c_name,
                "campaign_status": c_status,
                "membership_confidence": float(m.membership_confidence),
                "membership_status": m.membership_status,
                "evidence_summary": m.evidence_summary or {},
            })

        is_bridge = len(memberships) >= 2
        return {
            "email_id": str(email_id),
            "is_bridge_entity": is_bridge,
            "total_campaigns": len(memberships),
            "memberships": memberships,
            "investigation_note": (
                "Entity acts as an investigation bridge connecting multiple distinct campaign clusters."
                if is_bridge
                else "Entity associated with a single campaign hypothesis."
            ),
        }

    async def auto_cluster_campaigns(
        self,
        session: AsyncSession,
        min_correlation_score: float = 60.0,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers correlation clusters across all emails, creating or linking campaigns
        while preserving overlapping bridge entities without destructive partition mergers.

        SECURITY: `organization_id` restricts clustering to the caller's own
        tenant. Without it this would cluster and permanently link emails
        (and their subjects, senders, and forensic evidence) across every
        organization on the platform into shared Campaign rows — a
        cross-tenant data leak baked directly into the database, not just a
        response. Callers MUST pass the caller's organization_id.
        """
        # Fetch candidate emails, scoped to the caller's organization
        emails_stmt = select(Email.id)
        if organization_id is not None:
            emails_stmt = emails_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
        emails_res = await session.execute(emails_stmt)
        all_ids = [r[0] for r in emails_res.all()]
        if len(all_ids) < 2:
            return []

        # Map of email_id -> list of correlated (other_id, score, reason)
        corr_graph: Dict[uuid.UUID, List[Dict[str, Any]]] = {eid: [] for eid in all_ids}

        for eid in all_ids:
            corr_list = await self.correlate_email(
                session, eid, min_score=min_correlation_score, organization_id=organization_id
            )
            for c in corr_list:
                corr_graph[eid].append(c)

        created_campaigns: List[Dict[str, Any]] = []

        # Find connected clusters (cliques / connected subgraphs)
        visited: Set[uuid.UUID] = set()
        for eid in all_ids:
            if eid in visited or not corr_graph[eid]:
                continue

            cluster_members: Set[uuid.UUID] = {eid}
            primary_reasons: List[str] = []
            for item in corr_graph[eid]:
                target_uuid = uuid.UUID(item["target_email_id"])
                cluster_members.add(target_uuid)
                if item.get("primary_link_reason"):
                    primary_reasons.append(item["primary_link_reason"])

            if len(cluster_members) >= 2:
                # Name campaign based on primary link reason or generated moniker
                top_reason = primary_reasons[0] if primary_reasons else "Multi-signal Correlation"
                camp_name = f"Cluster: {top_reason[:40]}"
                
                campaign = await self.create_campaign(
                    session=session,
                    campaign_name=camp_name,
                    threat_summary=f"Automated cluster identified with {len(cluster_members)} emails linked by {top_reason}.",
                    campaign_confidence=75.0,
                    initial_email_ids=list(cluster_members),
                    organization_id=organization_id,
                )
                
                # Add CampaignEvidence record
                ev = CampaignEvidence(
                    campaign_id=campaign.id,
                    evidence_type="CORRELATION_CLUSTER",
                    confidence=75.0,
                    explanation=f"Correlated cluster based on: {top_reason}",
                )
                session.add(ev)
                await session.commit()

                created_campaigns.append({
                    "campaign_id": str(campaign.id),
                    "campaign_name": campaign.campaign_name,
                    "members_count": len(cluster_members),
                })
                visited.update(cluster_members)

        return created_campaigns


default_campaign_service = CampaignCorrelationService()
