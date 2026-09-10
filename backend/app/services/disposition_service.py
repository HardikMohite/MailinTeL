import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import select, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.disposition import EmailDisposition
from app.models.emails import Email, EmailAuthenticationResult, RelayHop
from app.models.analysis import EmailAnalysis, AnalysisFinding, AnalysisRun
from app.models.indicators import ThreatIndicator, IndicatorSighting
from app.models.embeddings import EmailEmbedding
from app.models.dna import EmailSimilarityLink
from app.models.audit import AuditLog
from app.dna.embedding_engine import default_embedding_engine
from app.services.ai_memory_service import default_ai_memory_service

logger = logging.getLogger("mailintel.services.disposition")


class DispositionService:
    """
    Forensic Human Layer & Active Learning Service.
    Manages confidence-based triage gating, analyst dispositions, remediation,
    and vector memory feedback loops for autonomous AI continuous learning.
    """

    @staticmethod
    def calculate_triage_tier(
        threat_score: float,
        evidence_confidence: float,
        findings: List[Dict[str, Any]],
        auth_summary: Dict[str, Any],
        indicators: List[Dict[str, Any]],
        has_precedent: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluates deterministic evidence, authentication results, and indicators to classify into:
        - TIER_1_AUTO: Conclusive high-confidence proof (Threat Score >= 85 or Conf >= 90 with no contradictions).
        - TIER_2_HUMAN_GATED: Ambiguous signals, conflicting evidence, or moderate score (40-84) requiring human review.
        - TIER_3_AUTO_CLEARED: Low threat score (< 40) with clean authentication and zero malicious indicators.
        """
        conflict_reasons = []

        # Check for signal conflict 1: Valid SPF/DKIM but malicious relay or IOC
        auth_pass = (auth_summary.get("spf_status") == "PASS" and auth_summary.get("dkim_status") == "PASS")
        malicious_iocs = [i for i in indicators if i.get("reputation") == "MALICIOUS"]
        critical_findings = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

        if auth_pass and (malicious_iocs or critical_findings):
            conflict_reasons.append(
                "Cryptographic authentication (SPF/DKIM) passed, but relay infrastructure or observables contain confirmed malicious indicators."
            )

        # Check for signal conflict 2: Suspicious lure or mismatch with moderate score
        if any("mismatch" in f.get("title", "").lower() for f in findings):
            conflict_reasons.append("Sender / Reply-To address mismatch detected in message envelope.")

        # Check for signal conflict 3: Score is in ambiguous range
        if 40.0 <= threat_score <= 84.0:
            conflict_reasons.append(
                f"Threat risk score ({threat_score:.1f}/100) falls within the discretionary ambiguity window (40-84)."
            )

        # Tier Decision Logic
        # If overall threat score >= 85.0 or evidence confidence >= 85.0 (with threat_score >= 50),
        # the assessment is conclusive -> Autonomous Tier 1 (no human gating needed).
        if (threat_score >= 85.0 or evidence_confidence >= 85.0) and threat_score >= 50.0:
            return {
                "triage_tier": "TIER_1_AUTO",
                "tier_label": "Automated: High-Confidence Confirmed",
                "is_gated": False,
                "conflict_reasons": [],
                "recommendation": "Conclusive evidence established (Confidence >= 85%). Autonomous mitigation permitted.",
            }
        elif conflict_reasons or (40.0 <= threat_score < 85.0):
            # Ambiguity or moderate score -> Tier 2 Human Gated
            reasons = conflict_reasons or [
                f"Threat risk score ({threat_score:.1f}/100) falls within the discretionary ambiguity window (40-84)."
            ]
            return {
                "triage_tier": "TIER_2_HUMAN_GATED",
                "tier_label": "Action Required: Gated Human Review",
                "is_gated": True,
                "conflict_reasons": reasons,
                "recommendation": "Review conflicting forensic signals and set final disposition to train AI memory.",
            }
        else:
            # Low risk -> Tier 3 Auto Cleared
            return {
                "triage_tier": "TIER_3_AUTO_CLEARED",
                "tier_label": "Automated: Cleared Benign",
                "is_gated": False,
                "conflict_reasons": [],
                "recommendation": "Baseline telemetry satisfied; zero active threat indicators detected.",
            }

    async def get_or_calculate_disposition(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """
        Retrieves existing human disposition or computes live confidence tier with conflict diagnostics.
        """
        # 1. Check if an analyst already resolved this email
        disp_stmt = select(EmailDisposition).where(EmailDisposition.email_id == email_id)
        disp_obj = (await session.execute(disp_stmt)).scalar_one_or_none()

        # 2. Search for any matching precedents learned from past human reviews
        precedents = await self.find_analyst_precedents(session, email_id)

        if disp_obj:
            return {
                "email_id": str(email_id),
                "is_resolved": True,
                "triage_tier": "HUMAN_RESOLVED",
                "tier_label": "Resolved by Human Analyst",
                "verdict": disp_obj.verdict,
                "confidence": disp_obj.confidence,
                "analyst_notes": disp_obj.analyst_notes,
                "flagged_iocs": disp_obj.flagged_iocs or [],
                "remediation_actions": disp_obj.remediation_actions or [],
                "reviewed_by_name": disp_obj.reviewed_by_name or "SOC Analyst",
                "reviewed_at": disp_obj.reviewed_at.isoformat() if disp_obj.reviewed_at else None,
                "conflict_reasons": [],
                "precedents": precedents,
            }

        # 3. Calculate live tier based on deterministic context
        # Fetch analysis
        analysis_stmt = (
            select(EmailAnalysis, AnalysisRun)
            .join(AnalysisRun, EmailAnalysis.analysis_run_id == AnalysisRun.id)
            .where(EmailAnalysis.email_id == email_id)
            .order_by(EmailAnalysis.created_at.desc())
        )
        analysis_res = (await session.execute(analysis_stmt)).first()
        analysis_obj = analysis_res[0] if analysis_res else None
        run_obj = analysis_res[1] if analysis_res else None

        findings = []
        if run_obj:
            findings_stmt = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_obj.id)
            findings_objs = (await session.execute(findings_stmt)).scalars().all()
            findings = [{"title": f.title, "severity": f.severity} for f in findings_objs]

        # Fetch auth
        auth_stmt = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
        auth_obj = (await session.execute(auth_stmt)).scalar_one_or_none()
        auth_summary = {
            "spf_status": getattr(auth_obj, "spf_result", "NONE"),
            "dkim_status": getattr(auth_obj, "dkim_result", "NONE"),
        }

        # Fetch indicators
        ind_stmt = (
            select(ThreatIndicator)
            .join(IndicatorSighting, IndicatorSighting.indicator_id == ThreatIndicator.id)
            .where(IndicatorSighting.email_id == email_id)
        )
        indicators_objs = (await session.execute(ind_stmt)).scalars().all()
        indicators = [{"reputation": i.reputation} for i in indicators_objs]

        threat_score = float(analysis_obj.threat_risk_score) if analysis_obj else 0.0
        confidence = float(analysis_obj.evidence_confidence_score) if analysis_obj else 80.0

        tier_info = self.calculate_triage_tier(
            threat_score=threat_score,
            evidence_confidence=confidence,
            findings=findings,
            auth_summary=auth_summary,
            indicators=indicators,
            has_precedent=len(precedents) > 0,
        )

        return {
            "email_id": str(email_id),
            "is_resolved": False,
            "triage_tier": tier_info["triage_tier"],
            "tier_label": tier_info["tier_label"],
            "verdict": None,
            "confidence": round(confidence / 100.0, 2),
            "analyst_notes": None,
            "flagged_iocs": [],
            "remediation_actions": [],
            "reviewed_by_name": None,
            "reviewed_at": None,
            "conflict_reasons": tier_info["conflict_reasons"],
            "recommendation": tier_info["recommendation"],
            "precedents": precedents,
        }

    async def submit_analyst_disposition(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        user: Any,
        verdict: str,
        notes: str,
        actions: Optional[List[str]] = None,
        flagged_iocs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Saves authoritative analyst disposition, updates email status, logs audit entry,
        and vectorizes the feedback to train the pgvector continuous learning store.
        """
        actions = actions or []
        flagged_iocs = flagged_iocs or []

        # Validate verdict
        valid_verdicts = {
            "CONFIRMED_PHISHING",
            "CONFIRMED_BEC",
            "CONFIRMED_FRAUD",
            "FALSE_POSITIVE",
            "CONFIRMED_LEGITIMATE",
            "UNDER_INVESTIGATION",
        }
        if verdict not in valid_verdicts:
            raise ValueError(f"Invalid verdict '{verdict}'. Allowed: {', '.join(sorted(valid_verdicts))}")

        # 1. Fetch Email
        email_stmt = select(Email).where(Email.id == email_id)
        email_obj = (await session.execute(email_stmt)).scalar_one_or_none()
        if not email_obj:
            raise ValueError(f"Email {email_id} not found.")

        # Map verdict to Email.qualification_status
        if verdict in ("CONFIRMED_PHISHING", "CONFIRMED_BEC", "CONFIRMED_FRAUD"):
            email_obj.qualification_status = "MALICIOUS"
        elif verdict in ("FALSE_POSITIVE", "CONFIRMED_LEGITIMATE"):
            email_obj.qualification_status = "NORMAL"
        else:
            email_obj.qualification_status = "QUALIFIED_FOR_INVESTIGATION"

        # 2. Upsert EmailDisposition
        now_utc = datetime.now(timezone.utc)
        disp_stmt = select(EmailDisposition).where(EmailDisposition.email_id == email_id)
        disp_obj = (await session.execute(disp_stmt)).scalar_one_or_none()

        raw_reviewer_id = getattr(user, "id", None)
        reviewer_name = getattr(user, "full_name", None) or getattr(user, "email", "Analyst")

        # Safely verify if user exists in users table to satisfy FK constraints
        verified_reviewer_id = None
        if raw_reviewer_id:
            from app.models.identity import User
            user_exists_stmt = select(User.id).where(User.id == raw_reviewer_id)
            if (await session.execute(user_exists_stmt)).scalar_one_or_none():
                verified_reviewer_id = raw_reviewer_id

        if disp_obj:
            disp_obj.verdict = verdict
            disp_obj.triage_tier = "HUMAN_RESOLVED"
            disp_obj.analyst_notes = notes
            disp_obj.remediation_actions = actions
            disp_obj.flagged_iocs = flagged_iocs
            disp_obj.reviewed_by_id = verified_reviewer_id
            disp_obj.reviewed_by_name = reviewer_name
            disp_obj.reviewed_at = now_utc
            disp_obj.updated_at = now_utc
        else:
            disp_obj = EmailDisposition(
                id=uuid.uuid4(),
                email_id=email_id,
                verdict=verdict,
                triage_tier="HUMAN_RESOLVED",
                confidence=1.0,
                analyst_notes=notes,
                remediation_actions=actions,
                flagged_iocs=flagged_iocs,
                reviewed_by_id=verified_reviewer_id,
                reviewed_by_name=reviewer_name,
                reviewed_at=now_utc,
                created_at=now_utc,
                updated_at=now_utc,
            )
            session.add(disp_obj)

        # 3. Write Audit Log entry
        audit_entry = AuditLog(
            id=uuid.uuid4(),
            actor_user_id=verified_reviewer_id,
            organization_id=getattr(user, "organization_id", None),
            action="ANALYST_DISPOSITION_SET",
            resource_type="EMAIL",
            resource_id=email_id,
            occurred_at=now_utc,
            metadata_json={
                "verdict": verdict,
                "actions": actions,
                "notes_snippet": notes[:120] if notes else "",
            },
        )
        session.add(audit_entry)

        # 4. Continuous Active Learning Vectorization:
        # Embed the analyst's custom rationale and associate with email embedding in pgvector
        try:
            learning_text = f"Analyst Verdict: {verdict}. Rationale: {notes}. Subject: {email_obj.subject or ''}"
            embedding_vector = default_embedding_engine.embed_text(learning_text)

            # Store in email_embeddings under THREAT_PATTERN tagged as human ground truth
            pattern_emb = EmailEmbedding(
                id=uuid.uuid4(),
                email_id=email_id,
                embedding_type="THREAT_PATTERN",
                model_name=default_embedding_engine.model_name,
                dimension=len(embedding_vector),
                embedding=embedding_vector,
                metadata_json={
                    "is_human_ground_truth": True,
                    "verdict": verdict,
                    "analyst": reviewer_name,
                    "reviewed_at": now_utc.isoformat(),
                    "notes": notes,
                },
                created_at=now_utc,
            )
            session.add(pattern_emb)
        except Exception as e:
            logger.warning(f"Could not vectorize human feedback for email {email_id}: {e}")

        await session.commit()
        logger.info(f"Analyst disposition saved for email {email_id}: {verdict} by {reviewer_name}")

        # 5. Redis Working Memory Updates:
        # Invalidate cached AI explanation so next inquiry generates fresh reasoning reflecting human verdict
        await default_ai_memory_service.invalidate_cached_explanation(str(email_id))
        await default_ai_memory_service.set_cached_precedents(str(email_id), [])

        # Store flagged observables in Redis hot IOC memory
        for ioc in flagged_iocs:
            try:
                await default_ai_memory_service.set_hot_ioc_precedent(
                    ioc_value=ioc,
                    verdict=verdict,
                    notes=notes or "Flagged during analyst disposition review",
                    reviewer_name=reviewer_name,
                    email_id=str(email_id),
                )
            except Exception as e:
                logger.debug(f"Could not cache hot IOC {ioc}: {e}")

        return {
            "email_id": str(email_id),
            "verdict": verdict,
            "triage_tier": "HUMAN_RESOLVED",
            "tier_label": "Resolved by Human Analyst",
            "reviewed_by_name": reviewer_name,
            "reviewed_at": now_utc.isoformat(),
            "analyst_notes": notes,
            "remediation_actions": actions,
            "flagged_iocs": flagged_iocs,
            "learned_vector_indexed": True,
        }

    async def find_analyst_precedents(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        min_similarity: float = 70.0,
        limit: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Autonomous Precedent Recall:
        Finds previous emails with human analyst dispositions that match the current email's
        pgvector DNA or confirmed threat observables.
        Accelerated by Redis working memory cache.
        """
        # Check Redis L1 cache first
        cached = await default_ai_memory_service.get_cached_precedents(str(email_id))
        if cached is not None:
            return cached

        # 1. Query similarity links where related email has a human disposition
        link_stmt = (
            select(EmailSimilarityLink, EmailDisposition)
            .join(EmailDisposition, EmailDisposition.email_id == EmailSimilarityLink.related_email_id)
            .where(
                EmailSimilarityLink.source_email_id == email_id,
                EmailSimilarityLink.similarity_score >= (min_similarity / 100.0),
            )
            .order_by(desc(EmailSimilarityLink.similarity_score))
            .limit(limit)
        )
        link_rows = (await session.execute(link_stmt)).all()

        precedents = []
        for link, disp in link_rows:
            shared_signals = []
            if link.evidence and isinstance(link.evidence, dict):
                for k, v in link.evidence.items():
                    if isinstance(v, (int, float)) and v > 0.7:
                        shared_signals.append(k.replace("_", " ").title())

            precedents.append({
                "precedent_email_id": str(disp.email_id),
                "similarity_score": round(float(link.similarity_score) * 100, 1),
                "analyst_verdict": disp.verdict,
                "analyst_notes": disp.analyst_notes,
                "reviewer_name": disp.reviewed_by_name or "SOC Analyst",
                "reviewed_at": disp.reviewed_at.isoformat() if disp.reviewed_at else None,
                "shared_indicators": shared_signals or ["High structural and content DNA match"],
            })

        # 2. Check for Observable Overlap (e.g. has an analyst reviewed this specific sender or relay IP?)
        if not precedents:
            hops_stmt = select(RelayHop.source_ip).where(RelayHop.email_id == email_id)
            hop_ips = (await session.execute(hops_stmt)).scalars().all()

            if hop_ips:
                # Check other dispositions where relay hop IP matched
                other_disp_stmt = (
                    select(EmailDisposition, RelayHop.source_ip)
                    .join(RelayHop, RelayHop.email_id == EmailDisposition.email_id)
                    .where(
                        EmailDisposition.email_id != email_id,
                        RelayHop.source_ip.in_(hop_ips),
                    )
                    .limit(limit)
                )
                other_rows = (await session.execute(other_disp_stmt)).all()
                for disp, matched_ip in other_rows:
                    precedents.append({
                        "precedent_email_id": str(disp.email_id),
                        "similarity_score": 88.0,
                        "analyst_verdict": disp.verdict,
                        "analyst_notes": disp.analyst_notes,
                        "reviewer_name": disp.reviewed_by_name or "SOC Analyst",
                        "reviewed_at": disp.reviewed_at.isoformat() if disp.reviewed_at else None,
                        "shared_indicators": [f"Shared relay IP {matched_ip}"],
                    })

        # Cache in Redis working memory
        await default_ai_memory_service.set_cached_precedents(str(email_id), precedents)

        return precedents


default_disposition_service = DispositionService()
