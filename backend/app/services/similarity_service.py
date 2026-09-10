import uuid
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy import select, and_, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.emails import Email, EmailHeader, EmailSource
from app.models.embeddings import EmailEmbedding, DEFAULT_EMBEDDING_DIM
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.analysis import EmailAnalysis, AnalysisFinding
from app.models.intelligence import URL, EmailURL, Domain, IPAddress
from app.dna.dna_builder import compute_stable_json_hash
from app.dna.embedding_engine import default_embedding_engine, SemanticEmbeddingEngine
from app.db.vector import calculate_cosine_similarity

logger = logging.getLogger("mailintel.services.similarity")


class SimilarityService:
    """
    Forensic email vectorization and semantic similarity link discovery service.
    Computes dense vector representations and establishes multi-dimensional similarity links.
    """

    def __init__(self, embedding_engine: Optional[SemanticEmbeddingEngine] = None):
        self.engine = embedding_engine or default_embedding_engine

    async def generate_and_persist_embeddings(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> List[EmailEmbedding]:
        """
        Generates and saves embeddings across all 4 vector domains:
        - EMAIL_CONTENT
        - SUBJECT
        - EMAIL_DNA
        - THREAT_PATTERN
        """
        # Fetch email
        result = await session.execute(select(Email).where(Email.id == email_id))
        email_obj = result.scalar_one_or_none()
        if not email_obj:
            raise ValueError(f"Email {email_id} not found.")

        # Fetch DNA profile if present
        dna_result = await session.execute(
            select(EmailDNAProfile)
            .where(EmailDNAProfile.email_id == email_id)
            .order_by(EmailDNAProfile.created_at.desc())
        )
        dna_obj = dna_result.scalars().first()

        # Fetch threat analysis & findings if present
        analysis_result = await session.execute(
            select(EmailAnalysis)
            .where(EmailAnalysis.email_id == email_id)
            .order_by(EmailAnalysis.created_at.desc())
        )
        analysis_obj = analysis_result.scalars().first()

        findings_result = await session.execute(
            select(AnalysisFinding).where(AnalysisFinding.email_id == email_id)
        )
        findings = [
            {"finding_type": f.finding_type, "severity": f.severity}
            for f in findings_result.scalars().all()
        ]

        # Fetch URLs/domains/IPs for threat pattern embedding
        urls_res = await session.execute(
            select(URL.normalized_url)
            .join(EmailURL, EmailURL.url_id == URL.id)
            .where(EmailURL.email_id == email_id)
        )
        url_list = [{"indicator_type": "URL", "val": u} for u in urls_res.scalars().all()]

        embeddings_to_save: List[EmailEmbedding] = []

        # Extract body from attributes or fallback to DNA lexical tokens
        body_plain = getattr(email_obj, "body_plain", None)
        body_html = getattr(email_obj, "body_html", None)
        if not body_plain and dna_obj and dna_obj.content_fingerprint:
            tokens = dna_obj.content_fingerprint.get("lexical_tokens") or []
            if tokens:
                body_plain = " ".join(tokens)

        # 1. EMAIL_CONTENT
        content_vec = self.engine.embed_content(
            subject=email_obj.subject,
            body_plain=body_plain,
            body_html=body_html,
        )
        embeddings_to_save.append(
            EmailEmbedding(
                email_id=email_id,
                embedding_type="EMAIL_CONTENT",
                model_name=self.engine.model_name,
                dimension=self.engine.dimension,
                embedding=content_vec,
                metadata_json={
                    "has_subject": bool(email_obj.subject),
                    "has_body_plain": bool(body_plain),
                    "has_body_html": bool(body_html),
                },
            )
        )

        # 2. SUBJECT
        subject_vec = self.engine.embed_subject(email_obj.subject)
        embeddings_to_save.append(
            EmailEmbedding(
                email_id=email_id,
                embedding_type="SUBJECT",
                model_name=self.engine.model_name,
                dimension=self.engine.dimension,
                embedding=subject_vec,
                metadata_json={"subject_length": len(email_obj.subject or "")},
            )
        )

        # 3. EMAIL_DNA
        if dna_obj:
            dna_data = {
                "content_fingerprint": dna_obj.content_fingerprint or {},
                "technical_fingerprint": dna_obj.technical_fingerprint or {},
                "infrastructure_fingerprint": dna_obj.infrastructure_fingerprint or {},
                "behavioral_fingerprint": dna_obj.behavioral_fingerprint or {},
                "temporal_fingerprint": dna_obj.temporal_fingerprint or {},
            }
            dna_vec = self.engine.embed_dna_profile(dna_data)
            dna_hash = compute_stable_json_hash(dna_data)
            embeddings_to_save.append(
                EmailEmbedding(
                    email_id=email_id,
                    embedding_type="EMAIL_DNA",
                    model_name=self.engine.model_name,
                    dimension=self.engine.dimension,
                    embedding=dna_vec,
                    metadata_json={"overall_dna_hash": dna_hash},
                )
            )

        # 4. THREAT_PATTERN
        risk_score = float(analysis_obj.threat_risk_score) if analysis_obj else 0.0
        threat_vec = self.engine.embed_threat_pattern(
            risk_score=risk_score,
            findings=findings,
            indicators=url_list,
        )
        embeddings_to_save.append(
            EmailEmbedding(
                email_id=email_id,
                embedding_type="THREAT_PATTERN",
                model_name=self.engine.model_name,
                dimension=self.engine.dimension,
                embedding=threat_vec,
                metadata_json={"finding_count": len(findings), "risk_score": risk_score},
            )
        )

        # Delete existing embeddings for this email to avoid duplicates
        await session.execute(delete(EmailEmbedding).where(EmailEmbedding.email_id == email_id))

        for emb in embeddings_to_save:
            session.add(emb)

        await session.commit()
        logger.info("Persisted %d embeddings for email %s", len(embeddings_to_save), email_id)
        return embeddings_to_save

    async def find_and_link_similar_emails(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        min_similarity_threshold: float = 0.65,
        top_k: int = 10,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[EmailSimilarityLink]:
        """
        Calculates pairwise cosine similarity between source email and candidate emails
        in the same organization. Establishes and persists directed EmailSimilarityLink
        records with evidence.

        SECURITY: `organization_id` restricts candidates to the caller's own
        tenant. Without it this permanently persists EmailSimilarityLink rows
        (with another tenant's subject/sender in the `evidence` JSON) linking
        emails across organizations — a stored cross-tenant data leak, not
        just a response-time one. Callers MUST pass the caller's
        organization_id.
        """
        # Ensure embeddings exist for source email
        source_embs_res = await session.execute(
            select(EmailEmbedding).where(EmailEmbedding.email_id == email_id)
        )
        source_embs = source_embs_res.scalars().all()
        if not source_embs:
            source_embs = await self.generate_and_persist_embeddings(session, email_id)

        source_by_type = {e.embedding_type: e.embedding for e in source_embs}

        # Fetch candidate target embeddings (excluding the source email itself),
        # scoped to the caller's organization.
        target_embs_stmt = select(EmailEmbedding).where(EmailEmbedding.email_id != email_id)
        if organization_id is not None:
            target_embs_stmt = target_embs_stmt.where(
                EmailEmbedding.email_id.in_(
                    select(Email.id)
                    .join(EmailSource, EmailSource.id == Email.source_id)
                    .where(EmailSource.organization_id == organization_id)
                )
            )
        target_embs_res = await session.execute(target_embs_stmt)
        target_embs = target_embs_res.scalars().all()

        # Group target embeddings by email_id
        targets_by_email: Dict[uuid.UUID, Dict[str, List[float]]] = {}
        for te in target_embs:
            if te.email_id not in targets_by_email:
                targets_by_email[te.email_id] = {}
            targets_by_email[te.email_id][te.embedding_type] = list(te.embedding)

        # Fetch candidate email subjects for richer evidence
        email_ids = list(targets_by_email.keys())
        emails_res = await session.execute(select(Email).where(Email.id.in_(email_ids)))
        email_map = {e.id: e for e in emails_res.scalars().all()}

        created_links: List[EmailSimilarityLink] = []

        # Clear existing similarity links for this source
        await session.execute(
            delete(EmailSimilarityLink).where(
                or_(
                    EmailSimilarityLink.source_email_id == email_id,
                    EmailSimilarityLink.related_email_id == email_id,
                )
            )
        )

        for target_id, t_vectors in targets_by_email.items():
            # Calculate similarity across available embedding types
            scores: Dict[str, float] = {}
            for emb_type, src_vec in source_by_type.items():
                if emb_type in t_vectors:
                    tgt_vec = t_vectors[emb_type]
                    try:
                        sim = calculate_cosine_similarity(src_vec, tgt_vec)
                        scores[emb_type] = max(0.0, min(1.0, sim))
                    except Exception as e:
                        logger.warning("Error computing similarity for type %s: %s", emb_type, e)

            if not scores:
                continue

            # Composite weighted similarity score
            # Content: 40%, Subject: 25%, DNA: 25%, Threat: 10%
            weights = {
                "EMAIL_CONTENT": 0.40,
                "SUBJECT": 0.25,
                "EMAIL_DNA": 0.25,
                "THREAT_PATTERN": 0.10,
            }
            weighted_sum = 0.0
            total_weight = 0.0
            for k, w in weights.items():
                if k in scores:
                    weighted_sum += scores[k] * w
                    total_weight += w

            overall_sim = (weighted_sum / total_weight) if total_weight > 0 else 0.0

            if overall_sim >= min_similarity_threshold:
                target_email = email_map.get(target_id)
                evidence = {
                    "scores_by_type": {k: round(v, 4) for k, v in scores.items()},
                    "weighted_overall_score": round(overall_sim, 4),
                    "target_subject": target_email.subject if target_email else None,
                    "target_sender": target_email.sender_address if target_email else None,
                    "attribution_disclaimer": "Similarity alone does not establish campaign membership.",
                }

                # Save forward link
                link = EmailSimilarityLink(
                    source_email_id=email_id,
                    related_email_id=target_id,
                    similarity_type="SEMANTIC",
                    similarity_score=round(overall_sim, 5),
                    evidence=evidence,
                )
                session.add(link)
                created_links.append(link)

        # Sort by similarity score descending and keep top_k
        created_links.sort(key=lambda x: float(x.similarity_score), reverse=True)
        created_links = created_links[:top_k]

        await session.commit()
        logger.info("Created %d similarity links for email %s", len(created_links), email_id)
        return created_links

    async def get_email_similarity_links(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        organization_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves all similarity links related to an email.

        SECURITY: defense-in-depth — restricts the *other* side of each link
        to the caller's organization too, in case any pre-fix cross-tenant
        links exist from before candidate scoping was added above.
        """
        stmt = (
            select(EmailSimilarityLink)
            .where(
                or_(
                    EmailSimilarityLink.source_email_id == email_id,
                    EmailSimilarityLink.related_email_id == email_id,
                )
            )
        )
        if organization_id is not None:
            same_org_emails = (
                select(Email.id)
                .join(EmailSource, EmailSource.id == Email.source_id)
                .where(EmailSource.organization_id == organization_id)
            )
            stmt = stmt.where(
                and_(
                    EmailSimilarityLink.source_email_id.in_(same_org_emails),
                    EmailSimilarityLink.related_email_id.in_(same_org_emails),
                )
            )
        stmt = stmt.order_by(EmailSimilarityLink.similarity_score.desc())
        result = await session.execute(stmt)
        links = result.scalars().all()

        output: List[Dict[str, Any]] = []
        for l in links:
            output.append({
                "id": str(l.id),
                "source_email_id": str(l.source_email_id),
                "related_email_id": str(l.related_email_id),
                "similarity_type": l.similarity_type,
                "similarity_score": float(l.similarity_score),
                "evidence": l.evidence or {},
                "created_at": l.created_at.isoformat() if l.created_at else None,
            })
        return output


default_similarity_service = SimilarityService()
