import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from sqlalchemy import select, and_, or_, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.emails import Email, EmailSource, RelayHop, EmailRecipient
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.intelligence import URL, EmailURL, Domain, IPAddress
from app.models.evidence import EvidenceObject
from app.models.campaign import Campaign, CampaignMembership, CampaignEvidence, CampaignEvent
from app.models.identity import User
from app.models.analysis import EmailAnalysis
from app.campaigns.correlation_engine import default_correlation_engine, CorrelationEngine, CorrelationResult
from sqlalchemy.orm import aliased

logger = logging.getLogger("mailintel.services.campaigns")


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

        return {
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

    async def correlate_email(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        min_score: float = 40.0,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Computes pairwise multi-signal correlation between source email and all other emails.

        SECURITY: candidate emails are restricted to `organization_id` (the
        caller's organization). Without this filter, correlation results —
        including another tenant's subject lines, sender addresses, and
        forensic evidence — would be computed against and returned about
        emails the caller has no access to. Callers MUST pass the caller's
        organization_id; it is optional only so existing internal callers
        that have already scoped `email_id` themselves keep working.
        """
        source_bundle = await self._gather_email_forensic_bundle(session, email_id)
        if not source_bundle:
            raise ValueError(f"Email {email_id} not found.")

        candidates_stmt = select(Email.id).where(Email.id != email_id)
        if organization_id is not None:
            # NOTE: Email.organization_id is not populated at ingest time
            # (only email_sources.organization_id is) — see emails.py upload
            # flow — so tenant scoping must go through the source join.
            candidates_stmt = candidates_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
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

        # Ensure benign emails cannot be added to adversary attack campaigns
        threat_check_res = await session.execute(
            select(EmailAnalysis.threat_classification, EmailAnalysis.threat_risk_score, Email.qualification_status)
            .outerjoin(EmailAnalysis, Email.id == EmailAnalysis.email_id)
            .where(Email.id == email_id)
        )
        t_row = threat_check_res.first()
        if t_row:
            t_cls, t_score, t_qual = t_row[0], t_row[1], t_row[2]
            if t_cls == "BENIGN" and (t_score is None or float(t_score) < 40.0) and t_qual not in ("SUSPICIOUS", "MALICIOUS", "CAMPAIGN_RELATED", "QUALIFIED_FOR_INVESTIGATION"):
                raise ValueError(f"Email {email_id} is benign and cannot be added to a threat campaign.")

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
        return del_res.rowcount > 0

    async def get_campaign_details(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves comprehensive details for a campaign with memberships, evidence, and events."""
        c_res = await session.execute(select(Campaign).where(Campaign.id == campaign_id))
        c = c_res.scalar_one_or_none()
        if not c:
            return None

        # Fetch memberships with email subjects, real timestamps, and uploader user metadata
        m_res = await session.execute(
            select(
                CampaignMembership,
                Email.subject,
                Email.sender_address,
                Email.sent_at,
                Email.received_at,
                Email.created_at,
                Email.qualification_status,
                Email.analysis_status,
                EmailSource.user_id,
                User.full_name,
                User.email,
                EmailAnalysis.threat_classification,
                EmailAnalysis.threat_risk_score,
            )
            .join(Email, Email.id == CampaignMembership.email_id)
            .outerjoin(EmailSource, Email.source_id == EmailSource.id)
            .outerjoin(User, EmailSource.user_id == User.id)
            .outerjoin(EmailAnalysis, Email.id == EmailAnalysis.email_id)
            .where(CampaignMembership.campaign_id == campaign_id)
        )
        memberships_data = []
        member_email_ids: List[uuid.UUID] = []
        real_dates: List[datetime] = []
        reporting_users_map: Dict[str, Dict[str, Any]] = {}
        seen_email_ids: Set[uuid.UUID] = set()

        for row in m_res.all():
            m = row[0]
            if m.email_id in seen_email_ids:
                continue
            subj = row[1]
            sender = row[2]
            sent_at = row[3]
            recvd_at = row[4]
            created_at = row[5]
            qual = row[6]
            astatus = row[7]
            uploader_id = row[8]
            uploader_name = row[9]
            uploader_email = row[10]
            threat_cls = row[11] if len(row) > 11 else None
            risk_score = row[12] if len(row) > 12 else None
            if threat_cls == "BENIGN" and (risk_score is None or float(risk_score) < 40.0) and qual not in ("SUSPICIOUS", "MALICIOUS", "CAMPAIGN_RELATED", "QUALIFIED_FOR_INVESTIGATION"):
                continue
            seen_email_ids.add(m.email_id)
            member_email_ids.append(m.email_id)
            dt = sent_at or recvd_at or created_at
            if dt:
                real_dates.append(dt)

            if uploader_id:
                uid_str = str(uploader_id)
                if uid_str not in reporting_users_map:
                    reporting_users_map[uid_str] = {
                        "user_id": uid_str,
                        "username": uploader_name or uploader_email or "Unknown",
                        "email": uploader_email or "",
                        "emails_count": 0,
                    }
                reporting_users_map[uid_str]["emails_count"] += 1

            memberships_data.append({
                "id": str(m.id),
                "email_id": str(m.email_id),
                "email_subject": subj,
                "email_sender": sender,
                "submitted_by_id": str(uploader_id) if uploader_id else None,
                "submitted_by_name": uploader_name or uploader_email or "Direct Ingest",
                "submitted_by_email": uploader_email,
                "membership_confidence": float(m.membership_confidence),
                "membership_status": m.membership_status,
                "evidence_summary": m.evidence_summary or {},
                "created_at": (sent_at or created_at or m.created_at).isoformat() if (sent_at or created_at or m.created_at) else None,
                "sent_at": sent_at.isoformat() if sent_at else None,
            })

        reporting_users = list(reporting_users_map.values())

        # Dynamically compute observed campaign date bounds from real email timestamps
        real_first_detected = min(real_dates).isoformat() if real_dates else (c.first_detected_at.isoformat() if c.first_detected_at else None)
        real_last_activity = max(real_dates).isoformat() if real_dates else (c.last_activity_at.isoformat() if c.last_activity_at else None)

        # Fetch targeted recipients/users across member emails
        targeted_users: List[Dict[str, Any]] = []
        if member_email_ids:
            UploaderUser = aliased(User)
            RegisteredRecipientUser = aliased(User)

            recip_stmt = (
                select(
                    EmailRecipient.address,
                    EmailRecipient.display_name,
                    Email.id,
                    Email.subject,
                    Email.sender_address,
                    Email.sent_at,
                    Email.qualification_status,
                    Email.analysis_status,
                    Email.created_at,
                    RegisteredRecipientUser.id.label("registered_user_id"),
                    RegisteredRecipientUser.full_name.label("registered_user_name"),
                    EmailSource.user_id.label("uploader_id"),
                    UploaderUser.full_name.label("uploader_name"),
                    UploaderUser.email.label("uploader_email"),
                )
                .join(Email, Email.id == EmailRecipient.email_id)
                .outerjoin(RegisteredRecipientUser, func.lower(RegisteredRecipientUser.email) == func.lower(EmailRecipient.address))
                .outerjoin(EmailSource, Email.source_id == EmailSource.id)
                .outerjoin(UploaderUser, EmailSource.user_id == UploaderUser.id)
                .where(EmailRecipient.email_id.in_(member_email_ids))
            )
            recip_res = await session.execute(recip_stmt)
            targeted_map: Dict[str, Dict[str, Any]] = {}
            seen_victim_emails: Set[tuple] = set()
            for addr, dname, eid, subj, sender, sent_at, qual, astatus, created_at, reg_uid, reg_uname, uploader_id, uploader_name, uploader_email in recip_res.all():
                if not addr:
                    continue
                norm = addr.strip().lower()
                key = (norm, str(eid))
                if key in seen_victim_emails:
                    continue
                seen_victim_emails.add(key)
                if norm not in targeted_map:
                    effective_display_name = dname or reg_uname or None
                    targeted_map[norm] = {
                        "recipient_address": addr.strip(),
                        "display_name": effective_display_name,
                        "is_internal_account": reg_uid is not None,
                        "emails_count": 0,
                        "first_targeted_at": None,
                        "last_targeted_at": None,
                        "emails": [],
                    }
                entry = targeted_map[norm]
                entry["emails_count"] += 1
                if (dname or reg_uname) and not entry["display_name"]:
                    entry["display_name"] = dname or reg_uname
                ts = (sent_at or created_at).isoformat() if (sent_at or created_at) else None
                if ts:
                    if not entry["first_targeted_at"] or ts < entry["first_targeted_at"]:
                        entry["first_targeted_at"] = ts
                    if not entry["last_targeted_at"] or ts > entry["last_targeted_at"]:
                        entry["last_targeted_at"] = ts
                entry["emails"].append({
                    "id": str(eid),
                    "subject": subj,
                    "sender_address": sender,
                    "sent_at": ts,
                    "qualification_status": qual or "SUSPICIOUS",
                    "analysis_status": astatus or "COMPLETED",
                    "submitted_by_id": str(uploader_id) if uploader_id else None,
                    "submitted_by_name": uploader_name or uploader_email or "System Ingest",
                    "submitted_by_email": uploader_email,
                })
            targeted_users = sorted(targeted_map.values(), key=lambda x: x["emails_count"], reverse=True)

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

        return {
            "id": str(c.id),
            "campaign_name": c.campaign_name,
            "campaign_status": c.campaign_status,
            "campaign_confidence": float(c.campaign_confidence),
            "threat_summary": c.threat_summary,
            "first_detected_at": real_first_detected,
            "last_activity_at": real_last_activity,
            "total_members": len(memberships_data),
            "total_evidence_links": len(evidence_data),
            "memberships": memberships_data,
            "targeted_users": targeted_users,
            "reporting_users": reporting_users,
            "evidence": evidence_data,
            "events": events_data,
        }

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

    async def detect_distributed_attack_campaigns(
        self,
        session: AsyncSession,
        min_targets: int = 2,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers distributed multi-user phishing attacks where a single adversary
        (sender address or originating relay IP) sends emails targeting multiple
        distinct users / mailboxes (>= min_targets).
        """
        base_query = (
            select(
                Email.id,
                Email.sender_address,
                Email.subject,
                Email.created_at,
                EmailRecipient.address.label("recipient_address"),
                RelayHop.source_ip,
                EmailSource.organization_id.label("email_org_id"),
            )
            .outerjoin(EmailRecipient, Email.id == EmailRecipient.email_id)
            .outerjoin(RelayHop, and_(Email.id == RelayHop.email_id, RelayHop.sequence_number == 1))
            .outerjoin(EmailSource, Email.source_id == EmailSource.id)
            .outerjoin(EmailAnalysis, Email.id == EmailAnalysis.email_id)
            .where(
                or_(
                    EmailAnalysis.threat_classification.in_(["SUSPICIOUS", "MALICIOUS", "PHISHING", "SPOOFING"]),
                    EmailAnalysis.threat_risk_score >= 40.0,
                    Email.qualification_status.in_(["SUSPICIOUS", "HIGH_RISK", "MALICIOUS", "CAMPAIGN_RELATED", "QUALIFIED_FOR_INVESTIGATION"]),
                )
            )
        )
        if organization_id is not None:
            base_query = base_query.where(
                EmailSource.organization_id == organization_id
            )

        result = await session.execute(base_query)
        rows = result.all()
        if not rows:
            return []

        # Group emails by sender_address and by originating source_ip
        senders_map: Dict[str, Dict[str, Any]] = {}
        ips_map: Dict[str, Dict[str, Any]] = {}

        for eid, sender, subj, created_at, recip_addr, source_ip, email_org_id in rows:
            if not recip_addr:
                continue
            recip_norm = recip_addr.strip().lower()

            if sender and sender.strip():
                sndr_key = sender.strip().lower()
                if sndr_key not in senders_map:
                    senders_map[sndr_key] = {
                        "key_type": "SENDER",
                        "identifier": sender.strip(),
                        "email_ids": set(),
                        "recipients": set(),
                        "org_ids": set(),
                    }
                senders_map[sndr_key]["email_ids"].add(eid)
                senders_map[sndr_key]["recipients"].add(recip_norm)
                if email_org_id:
                    senders_map[sndr_key]["org_ids"].add(email_org_id)

            if source_ip and source_ip.strip():
                ip_key = source_ip.strip()
                if ip_key not in ips_map:
                    ips_map[ip_key] = {
                        "key_type": "ORIGINATING_IP",
                        "identifier": ip_key,
                        "email_ids": set(),
                        "recipients": set(),
                        "org_ids": set(),
                    }
                ips_map[ip_key]["email_ids"].add(eid)
                ips_map[ip_key]["recipients"].add(recip_norm)
                if email_org_id:
                    ips_map[ip_key]["org_ids"].add(email_org_id)

        candidate_clusters: List[Dict[str, Any]] = []
        for group in list(senders_map.values()) + list(ips_map.values()):
            if len(group["recipients"]) >= min_targets:
                candidate_clusters.append(group)

        created_campaigns: List[Dict[str, Any]] = []

        for cluster in candidate_clusters:
            key_type = cluster["key_type"]
            ident = cluster["identifier"]
            eids = list(cluster["email_ids"])
            recip_count = len(cluster["recipients"])
            cluster_org_ids = cluster.get("org_ids", set())
            target_org_id = organization_id or (next(iter(cluster_org_ids)) if cluster_org_ids else None)

            camp_name = f"Targeted Campaign: {ident} ({recip_count} Users)"
            camp_query = select(Campaign).where(Campaign.campaign_name == camp_name)
            if target_org_id is not None:
                camp_query = camp_query.where(
                    or_(Campaign.organization_id.is_(None), Campaign.organization_id == target_org_id)
                )
            existing_res = await session.execute(camp_query)
            existing_camp = existing_res.scalar_one_or_none()

            if existing_camp:
                if existing_camp.organization_id is None and target_org_id is not None:
                    existing_camp.organization_id = target_org_id
                    session.add(existing_camp)
                    await session.commit()
                for eid in eids:
                    await self.add_email_to_campaign(
                        session=session,
                        campaign_id=existing_camp.id,
                        email_id=eid,
                        membership_confidence=85.0,
                        organization_id=target_org_id,
                    )
                created_campaigns.append({
                    "campaign_id": str(existing_camp.id),
                    "campaign_name": existing_camp.campaign_name,
                    "members_count": len(eids),
                    "targeted_users_count": recip_count,
                })
                continue

            confidence = min(95.0, 75.0 + recip_count * 3.0)
            campaign = await self.create_campaign(
                session=session,
                campaign_name=camp_name,
                threat_summary=(
                    f"Coordinated multi-user attack from {key_type.lower()} '{ident}' "
                    f"targeting {recip_count} distinct mailboxes across the organization."
                ),
                campaign_confidence=confidence,
                initial_email_ids=eids,
                organization_id=target_org_id,
            )

            # Add CampaignEvidence record
            ev = CampaignEvidence(
                campaign_id=campaign.id,
                evidence_type="MULTI_USER_TARGETING",
                confidence=confidence,
                explanation=(
                    f"Adversary {key_type.lower()} '{ident}' dispatched emails across {recip_count} distinct users: "
                    f"{', '.join(sorted(cluster['recipients'])[:5])}"
                ),
            )
            session.add(ev)

            # Add CampaignEvent
            evt = CampaignEvent(
                campaign_id=campaign.id,
                event_type="DISTRIBUTED_ATTACK_DETECTED",
                occurred_at=datetime.now(timezone.utc),
                description=f"Multi-user attack flagged: {recip_count} mailboxes targeted by {ident}.",
                metadata_json={
                    "identifier": ident,
                    "key_type": key_type,
                    "targeted_users_count": recip_count,
                    "email_count": len(eids),
                },
            )
            session.add(evt)
            await session.commit()

            created_campaigns.append({
                "campaign_id": str(campaign.id),
                "campaign_name": campaign.campaign_name,
                "members_count": len(eids),
                "targeted_users_count": recip_count,
            })

        return created_campaigns

    async def auto_cluster_campaigns(
        self,
        session: AsyncSession,
        min_correlation_score: float = 60.0,
        min_targets: int = 2,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers correlation clusters across all emails, creating or linking campaigns
        while preserving overlapping bridge entities without destructive partition mergers.
        Also discovers distributed multi-user targeting campaigns.

        SECURITY: `organization_id` restricts clustering to the caller's own
        tenant. Callers MUST pass the caller's organization_id.
        """
        created_campaigns: List[Dict[str, Any]] = []

        # 1. Discover multi-user targeting distributed attacks
        distributed_campaigns = await self.detect_distributed_attack_campaigns(
            session=session,
            min_targets=min_targets,
            organization_id=organization_id,
        )
        created_campaigns.extend(distributed_campaigns)

        # 2. Discover pairwise multi-signal correlation clusters
        emails_stmt = (
            select(Email.id)
            .outerjoin(EmailAnalysis, Email.id == EmailAnalysis.email_id)
            .where(
                or_(
                    EmailAnalysis.threat_classification.in_(["SUSPICIOUS", "MALICIOUS", "PHISHING", "SPOOFING"]),
                    EmailAnalysis.threat_risk_score >= 40.0,
                    Email.qualification_status.in_(["SUSPICIOUS", "HIGH_RISK", "MALICIOUS", "CAMPAIGN_RELATED", "QUALIFIED_FOR_INVESTIGATION"]),
                )
            )
        )
        if organization_id is not None:
            emails_stmt = emails_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
        emails_res = await session.execute(emails_stmt)
        all_ids = [r[0] for r in emails_res.all()]
        if len(all_ids) < 2:
            return created_campaigns

        # Map of email_id -> list of correlated (other_id, score, reason)
        corr_graph: Dict[uuid.UUID, List[Dict[str, Any]]] = {eid: [] for eid in all_ids}

        for eid in all_ids:
            corr_list = await self.correlate_email(
                session, eid, min_score=min_correlation_score, organization_id=organization_id
            )
            for c in corr_list:
                corr_graph[eid].append(c)

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
                top_reason = primary_reasons[0] if primary_reasons else "Multi-signal Correlation"
                
                # Derive a recognizable, relatable campaign name from cluster emails
                rep_subj = None
                try:
                    sub_stmt = (
                        select(Email.subject)
                        .where(Email.id.in_(list(cluster_members)), Email.subject.is_not(None))
                        .limit(1)
                    )
                    sub_res = await session.execute(sub_stmt)
                    rep_subj = sub_res.scalar_one_or_none()
                except Exception:
                    rep_subj = None

                if rep_subj:
                    import re
                    clean_subj = re.sub(r'^(re|fwd|fw):\s*', '', rep_subj, flags=re.I).strip()
                    clean_subj = clean_subj[:65].strip()
                    camp_name = f"Campaign: {clean_subj}"
                else:
                    camp_name = f"Cluster: {top_reason}"

                target_org_id = organization_id
                if target_org_id is None:
                    org_stmt = (
                        select(EmailSource.organization_id)
                        .join(Email, Email.source_id == EmailSource.id)
                        .where(Email.id.in_(list(cluster_members)), EmailSource.organization_id.is_not(None))
                        .limit(1)
                    )
                    org_res = await session.execute(org_stmt)
                    org_row = org_res.first()
                    if org_row:
                        target_org_id = org_row[0]

                camp_query = select(Campaign).where(Campaign.campaign_name == camp_name)
                if target_org_id is not None:
                    camp_query = camp_query.where(
                        or_(Campaign.organization_id.is_(None), Campaign.organization_id == target_org_id)
                    )
                existing_res = await session.execute(camp_query)
                existing_camp = existing_res.scalar_one_or_none()

                if existing_camp:
                    for mid in cluster_members:
                        await self.add_email_to_campaign(
                            session=session,
                            campaign_id=existing_camp.id,
                            email_id=mid,
                            membership_confidence=75.0,
                            organization_id=target_org_id,
                        )
                    created_campaigns.append({
                        "campaign_id": str(existing_camp.id),
                        "campaign_name": existing_camp.campaign_name,
                        "members_count": len(cluster_members),
                    })
                    visited.update(cluster_members)
                    continue

                campaign = await self.create_campaign(
                    session=session,
                    campaign_name=camp_name,
                    threat_summary=f"Automated cluster identified with {len(cluster_members)} emails linked by {top_reason}.",
                    campaign_confidence=75.0,
                    initial_email_ids=list(cluster_members),
                    organization_id=target_org_id,
                )
                
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
