import uuid
import logging
from typing import List, Dict, Any, Optional, Set
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.emails import Email, EmailSource, RelayHop
from app.models.intelligence import URL, EmailURL, Domain, IPAddress
from app.models.indicators import ThreatIndicator, IndicatorSighting
from app.models.evidence import EvidenceObject
from app.models.campaign import Campaign, CampaignMembership
from app.models.dna import EmailSimilarityLink
from app.models.analysis import EmailAnalysis
from app.graph.graph_builder import InvestigationGraphBuilder, InvestigationGraph

logger = logging.getLogger("mailintel.services.graph")


def _defang_url(url_str: str) -> str:
    """Safely defangs URLs to prevent accidental clicks in SOC telemetry."""
    if not url_str:
        return ""
    return url_str.replace("https://", "hxxps://").replace("http://", "hxxp://")


def _classify_url_category(url_str: str, context: Optional[str] = None) -> str:
    """Categorizes extracted URLs based on protocol, context, and known ESP telemetry patterns."""
    url_lower = url_str.lower()
    ctx_upper = (context or "").upper()
    if ctx_upper == "HEADER" or "/un/" in url_lower or "unsubscribe" in url_lower:
        return "List-Unsubscribe Header"
    elif "/op/" in url_lower or "pixel" in url_lower or (ctx_upper == "IMAGE_SRC" and (".png" in url_lower or ".gif" in url_lower)):
        return "Open Tracking Beacon (Pixel)"
    elif "/cl/" in url_lower or "/track/" in url_lower or "click" in url_lower or "sendibt" in url_lower:
        return "ESP Click Redirect / Telemetry"
    elif ctx_upper == "IMAGE_SRC":
        return "Embedded Remote Image"
    elif ctx_upper == "BUTTON_HREF":
        return "Call-To-Action Button Target"
    elif "phish" in url_lower or "login" in url_lower or "verify" in url_lower:
        return "Phishing Campaign Target"
    return "Body Hyperlink"



import time
from app.core.redis import redis_manager

# High-speed in-memory L1 cache for sub-millisecond local graph retrieval
_GRAPH_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_GRAPH_CACHE_TTL_SECONDS: float = 1800.0  # 30 minutes


class InvestigationGraphService:
    """
    Forensic graph query and construction service connecting multi-hop investigative entities.
    """

    @staticmethod
    async def invalidate_graph_cache(email_id: Optional[uuid.UUID] = None, campaign_id: Optional[uuid.UUID] = None) -> None:
        """Invalidates graph caches upon new email analysis or campaign updates."""
        try:
            # Clear L1
            keys_to_del = [k for k in _GRAPH_CACHE.keys() if (
                k.startswith("global:") or 
                (email_id and f"email:{email_id}" in k) or 
                (campaign_id and f"campaign:{campaign_id}" in k)
            )]
            for k in keys_to_del:
                _GRAPH_CACHE.pop(k, None)

            # Clear L2 Redis
            if email_id:
                await redis_manager.delete(f"cache:graph:email:{email_id}")
            if campaign_id:
                await redis_manager.delete(f"cache:graph:campaign:{campaign_id}")
        except Exception as e:
            logger.warning(f"Graph cache invalidation notice: {e}")

    async def _populate_email_subgraph(
        self,
        session: AsyncSession,
        builder: InvestigationGraphBuilder,
        email_id: uuid.UUID,
        include_correlations: bool = True,
    ) -> Optional[str]:
        """Gathers and links all first-order entities for a single email."""
        # 1. Fetch Email
        email_res = await session.execute(select(Email).where(Email.id == email_id))
        email_obj = email_res.scalar_one_or_none()
        if not email_obj:
            return None

        # Fetch threat analysis for risk score
        analysis_res = await session.execute(
            select(EmailAnalysis)
            .where(EmailAnalysis.email_id == email_id)
            .order_by(EmailAnalysis.created_at.desc())
        )
        analysis_obj = analysis_res.scalars().first()
        risk_score = float(analysis_obj.threat_risk_score) if analysis_obj else 0.0
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 35 else "LOW"

        email_node_id = f"email:{email_id}"
        builder.add_node(
            node_id=email_node_id,
            node_type="EMAIL",
            display_name=email_obj.subject or "(No Subject)",
            label=f"Email: {email_obj.subject[:30] if email_obj.subject else 'Untitled'}",
            risk_level=risk_level,
            metadata={
                "email_id": str(email_id),
                "sender_address": email_obj.sender_address,
                "sent_at": email_obj.sent_at.isoformat() if email_obj.sent_at else None,
                "threat_risk_score": risk_score,
                "qualification_status": email_obj.qualification_status,
            },
        )

        # 2. Sender Node & Edge
        if email_obj.sender_address:
            sender_id = f"sender:{email_obj.sender_address.lower()}"
            builder.add_node(
                node_id=sender_id,
                node_type="SENDER",
                display_name=email_obj.sender_display_name or email_obj.sender_address,
                label=f"Sender: {email_obj.sender_address}",
                risk_level="MEDIUM" if risk_score >= 60 else "LOW",
                metadata={"address": email_obj.sender_address, "display_name": email_obj.sender_display_name},
            )
            builder.add_edge(
                source_id=email_node_id,
                target_id=sender_id,
                relationship_type="SENT_BY",
                label="Sent By",
                confidence=100.0,
            )

        # 3. URLs & Domains
        urls_res = await session.execute(
            select(URL, Domain, EmailURL.context)
            .join(EmailURL, EmailURL.url_id == URL.id)
            .outerjoin(Domain, Domain.id == URL.domain_id)
            .where(EmailURL.email_id == email_id)
        )
        url_records = urls_res.all()

        # Query sightings for threat indicators linked to this email
        sightings_res = await session.execute(
            select(IndicatorSighting, ThreatIndicator)
            .join(ThreatIndicator, IndicatorSighting.indicator_id == ThreatIndicator.id)
            .where(IndicatorSighting.email_id == email_id)
        )
        threat_intel_by_val: Dict[str, ThreatIndicator] = {}
        for s, ti in sightings_res.all():
            threat_intel_by_val[ti.normalized_value] = ti

        for url_obj, dom_obj, url_ctx in url_records:
            url_node_id = f"url:{url_obj.id}"
            norm_url = url_obj.normalized_url or ""
            dom_name = dom_obj.normalized_domain if dom_obj else ""
            root_dom = dom_obj.root_domain if dom_obj else ""

            # Threat Indicator lookup
            ti = threat_intel_by_val.get(norm_url)
            verdict = ti.reputation if ti and ti.reputation else "BENIGN"
            confidence = float(ti.confidence) if ti and ti.confidence is not None else 0.50
            feed_status = ti.status if ti else "ACTIVE"

            category = _classify_url_category(norm_url, url_ctx)
            defanged = _defang_url(norm_url)

            # Determine accurate risk level for the individual URL
            if verdict == "MALICIOUS":
                url_risk = "CRITICAL" if confidence >= 0.8 else "HIGH"
            elif verdict == "SUSPICIOUS":
                url_risk = "MEDIUM"
            elif category == "Phishing Campaign Target":
                url_risk = "HIGH"
            else:
                url_risk = "LOW"

            # Create clean, distinct short display name based on category and host
            if category == "List-Unsubscribe Header":
                short_disp = f"Unsubscribe ({root_dom or dom_name})"
            elif "Tracking Beacon" in category or "Pixel" in category:
                short_disp = f"Open Beacon ({root_dom or dom_name})"
            elif "Click Redirect" in category:
                short_disp = f"Click Redirect ({root_dom or dom_name})"
            elif "Phishing" in category:
                short_disp = f"Phish Target ({root_dom or dom_name})"
            elif dom_name:
                short_disp = dom_name
            else:
                short_disp = norm_url[:24] + "..."

            builder.add_node(
                node_id=url_node_id,
                node_type="URL",
                display_name=short_disp,
                label=norm_url,
                risk_level=url_risk,
                metadata={
                    "url": norm_url,
                    "defanged_url": defanged,
                    "url_hash": url_obj.url_hash,
                    "domain": dom_name,
                    "root_domain": root_dom,
                    "context": url_ctx or "BODY_LINK",
                    "category": category,
                    "verdict": verdict,
                    "confidence": round(confidence, 2),
                    "status": feed_status,
                },
            )
            builder.add_edge(
                source_id=email_node_id,
                target_id=url_node_id,
                relationship_type="CONTAINS_URL",
                label="Contains URL",
                confidence=95.0,
            )

            if dom_obj:
                dom_node_id = f"domain:{dom_name.lower()}"
                dom_ti = threat_intel_by_val.get(dom_name)
                dom_verdict = dom_ti.reputation if dom_ti and dom_ti.reputation else "BENIGN"
                dom_risk = "HIGH" if dom_verdict == "MALICIOUS" else "MEDIUM" if dom_verdict == "SUSPICIOUS" else "LOW"

                builder.add_node(
                    node_id=dom_node_id,
                    node_type="DOMAIN",
                    display_name=dom_name,
                    label=f"Domain: {dom_name}",
                    risk_level=dom_risk,
                    metadata={
                        "domain": dom_name,
                        "root_domain": dom_obj.root_domain,
                        "verdict": dom_verdict,
                        "reputation": dom_verdict,
                    },
                )
                builder.add_edge(
                    source_id=url_node_id,
                    target_id=dom_node_id,
                    relationship_type="HOSTED_ON_DOMAIN",
                    label="Hosted On",
                    confidence=95.0,
                )

        # 4. IP Addresses & ASNs (via RelayHops)
        hops_res = await session.execute(
            select(RelayHop).where(RelayHop.email_id == email_id)
        )
        for hop in hops_res.scalars().all():
            if not hop.source_ip:
                continue
            ip_str = hop.source_ip
            ip_node_id = f"ip:{ip_str}"
            builder.add_node(
                node_id=ip_node_id,
                node_type="IP",
                display_name=ip_str,
                label=f"IP: {ip_str}",
                risk_level="LOW",
                metadata={
                    "ip": ip_str,
                    "reliability": hop.reliability,
                    "sequence_number": hop.sequence_number,
                },
            )
            builder.add_edge(
                source_id=email_node_id,
                target_id=ip_node_id,
                relationship_type="ROUTED_THROUGH_IP",
                label=f"Hop #{hop.sequence_number}",
                confidence=90.0,
            )


        # 5. Attachments
        att_res = await session.execute(
            select(EvidenceObject).where(
                and_(
                    EvidenceObject.email_id == email_id,
                    EvidenceObject.evidence_type == "ATTACHMENT",
                )
            )
        )
        for att in att_res.scalars().all():
            att_node_id = f"attachment:{att.id}"
            is_mal = ".exe" in (att.original_filename or "").lower() or ".bat" in (att.original_filename or "").lower()
            builder.add_node(
                node_id=att_node_id,
                node_type="ATTACHMENT",
                display_name=att.original_filename or "attachment.bin",
                label=f"File: {att.original_filename}",
                risk_level="CRITICAL" if is_mal else "MEDIUM",
                metadata={
                    "filename": att.original_filename,
                    "sha256": att.sha256_hash,
                    "size_bytes": att.size_bytes,
                },
            )
            builder.add_edge(
                source_id=email_node_id,
                target_id=att_node_id,
                relationship_type="CONTAINS_ATTACHMENT",
                label="Contains Attachment",
                confidence=100.0,
            )

        # 6. Campaign Memberships
        m_res = await session.execute(
            select(CampaignMembership, Campaign)
            .join(Campaign, Campaign.id == CampaignMembership.campaign_id)
            .where(CampaignMembership.email_id == email_id)
        )
        for mem, camp in m_res.all():
            camp_node_id = f"campaign:{camp.id}"
            builder.add_node(
                node_id=camp_node_id,
                node_type="CAMPAIGN",
                display_name=camp.campaign_name or "Threat Campaign",
                label=f"Campaign: {camp.campaign_name}",
                risk_level="CRITICAL" if float(camp.campaign_confidence) >= 80 else "HIGH",
                metadata={
                    "campaign_id": str(camp.id),
                    "status": camp.campaign_status,
                    "confidence": float(camp.campaign_confidence),
                },
            )
            builder.add_edge(
                source_id=email_node_id,
                target_id=camp_node_id,
                relationship_type="MEMBER_OF_CAMPAIGN",
                label="Member Of",
                confidence=float(mem.membership_confidence),
                evidence=mem.evidence_summary or {},
            )

        # 7. Semantic Similarity Links
        if include_correlations:
            sim_res = await session.execute(
                select(EmailSimilarityLink)
                .where(
                    or_(
                        EmailSimilarityLink.source_email_id == email_id,
                        EmailSimilarityLink.related_email_id == email_id,
                    )
                )
            )
            for link in sim_res.scalars().all():
                other_id = link.related_email_id if link.source_email_id == email_id else link.source_email_id
                target_email_node = f"email:{other_id}"
                
                # Fetch minimal details for the related email node
                other_email_res = await session.execute(select(Email).where(Email.id == other_id))
                other_obj = other_email_res.scalar_one_or_none()
                if other_obj:
                    builder.add_node(
                        node_id=target_email_node,
                        node_type="EMAIL",
                        display_name=other_obj.subject or "(Related Email)",
                        label=f"Email: {other_obj.subject[:30] if other_obj.subject else 'Untitled'}",
                        risk_level="MEDIUM",
                        metadata={"email_id": str(other_id), "sender_address": other_obj.sender_address},
                    )
                    builder.add_edge(
                        source_id=email_node_id,
                        target_id=target_email_node,
                        relationship_type="SIMILAR_TO",
                        label=f"Similar ({round(float(link.similarity_score) * 100, 1)}%)",
                        confidence=round(float(link.similarity_score) * 100.0, 1),
                        evidence=link.evidence or {},
                    )

        return email_node_id

    async def build_email_investigation_graph(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> InvestigationGraph:
        """Constructs an investigation subgraph focused around an email."""
        cache_key = f"email:{email_id}"
        now = time.time()

        # 1. L1 Memory Cache Hit
        if cache_key in _GRAPH_CACHE:
            ts, cached_data = _GRAPH_CACHE[cache_key]
            if now - ts < _GRAPH_CACHE_TTL_SECONDS:
                return InvestigationGraph.from_dict(cached_data)

        # 2. L2 Redis Cache Hit
        try:
            redis_data = await redis_manager.get_json(f"cache:graph:{cache_key}")
            if redis_data:
                _GRAPH_CACHE[cache_key] = (now, redis_data)
                return InvestigationGraph.from_dict(redis_data)
        except Exception as e:
            logger.warning(f"Redis graph lookup error: {e}")

        builder = InvestigationGraphBuilder()
        focal_id = await self._populate_email_subgraph(session, builder, email_id, include_correlations=True)
        graph = builder.build(focal_node_id=focal_id)

        # Store in L1 and L2
        graph_dict = graph.to_dict()
        _GRAPH_CACHE[cache_key] = (now, graph_dict)
        try:
            await redis_manager.set_json(f"cache:graph:{cache_key}", graph_dict, expire_seconds=1800)
        except Exception:
            pass

        return graph

    async def build_campaign_investigation_graph(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
    ) -> Optional[InvestigationGraph]:
        """Constructs the complete multi-email, multi-artifact graph for a threat campaign."""
        cache_key = f"campaign:{campaign_id}"
        now = time.time()

        # 1. L1 Memory Cache Hit
        if cache_key in _GRAPH_CACHE:
            ts, cached_data = _GRAPH_CACHE[cache_key]
            if now - ts < _GRAPH_CACHE_TTL_SECONDS:
                return InvestigationGraph.from_dict(cached_data)

        # 2. L2 Redis Cache Hit
        try:
            redis_data = await redis_manager.get_json(f"cache:graph:{cache_key}")
            if redis_data:
                _GRAPH_CACHE[cache_key] = (now, redis_data)
                return InvestigationGraph.from_dict(redis_data)
        except Exception as e:
            logger.warning(f"Redis graph lookup error: {e}")

        c_res = await session.execute(select(Campaign).where(Campaign.id == campaign_id))
        campaign = c_res.scalar_one_or_none()
        if not campaign:
            return None

        builder = InvestigationGraphBuilder()
        camp_node_id = f"campaign:{campaign.id}"
        builder.add_node(
            node_id=camp_node_id,
            node_type="CAMPAIGN",
            display_name=campaign.campaign_name or "Threat Campaign",
            label=f"Campaign: {campaign.campaign_name}",
            risk_level="CRITICAL" if float(campaign.campaign_confidence) >= 80 else "HIGH",
            metadata={
                "campaign_id": str(campaign.id),
                "status": campaign.campaign_status,
                "confidence": float(campaign.campaign_confidence),
                "threat_summary": campaign.threat_summary,
            },
        )

        # Fetch all member email IDs
        m_res = await session.execute(
            select(CampaignMembership.email_id).where(CampaignMembership.campaign_id == campaign_id)
        )
        email_ids = [r[0] for r in m_res.all()]

        for eid in email_ids:
            await self._populate_email_subgraph(session, builder, eid, include_correlations=True)

        graph = builder.build(focal_node_id=camp_node_id)

        # Store in L1 and L2
        graph_dict = graph.to_dict()
        _GRAPH_CACHE[cache_key] = (now, graph_dict)
        try:
            await redis_manager.set_json(f"cache:graph:{cache_key}", graph_dict, expire_seconds=1800)
        except Exception:
            pass

        return graph

    async def build_global_investigation_graph(
        self,
        session: AsyncSession,
        limit_emails: int = 30,
        organization_id: Optional[uuid.UUID] = None,
    ) -> InvestigationGraph:
        """
        Constructs a high-level graph across recent emails and active campaigns.

        SECURITY: `organization_id` restricts the emails included to the
        caller's own tenant. Without it every authenticated user would see
        an investigation graph built from every organization's recent
        emails. Callers MUST pass the caller's organization_id.
        """
        cache_key = f"global:{organization_id or 'all'}:{limit_emails}"
        now = time.time()

        # 1. L1 Memory Cache Hit
        if cache_key in _GRAPH_CACHE:
            ts, cached_data = _GRAPH_CACHE[cache_key]
            if now - ts < 600.0:  # 10 minutes for global
                return InvestigationGraph.from_dict(cached_data)

        # 2. L2 Redis Cache Hit
        try:
            redis_data = await redis_manager.get_json(f"cache:graph:{cache_key}")
            if redis_data:
                _GRAPH_CACHE[cache_key] = (now, redis_data)
                return InvestigationGraph.from_dict(redis_data)
        except Exception as e:
            logger.warning(f"Redis graph lookup error: {e}")

        builder = InvestigationGraphBuilder()

        emails_stmt = select(Email.id).order_by(Email.created_at.desc()).limit(limit_emails)
        if organization_id is not None:
            emails_stmt = emails_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
        emails_res = await session.execute(emails_stmt)
        email_ids = [r[0] for r in emails_res.all()]

        for eid in email_ids:
            # For global graph, disable per-email correlation expansion to avoid N*10 SQL loop latency
            await self._populate_email_subgraph(session, builder, eid, include_correlations=False)

        graph = builder.build(focal_node_id=None)

        # Store in L1 and L2
        graph_dict = graph.to_dict()
        _GRAPH_CACHE[cache_key] = (now, graph_dict)
        try:
            await redis_manager.set_json(f"cache:graph:{cache_key}", graph_dict, expire_seconds=600)
        except Exception:
            pass

        return graph


default_graph_service = InvestigationGraphService()
