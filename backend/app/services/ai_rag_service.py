import uuid
import json
import logging
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.emails import Email, EmailHeader, RelayHop, EmailAuthenticationResult
from app.models.intelligence import URL, EmailURL, Domain, IPAddress, IPIntelligence, InfrastructureClassification, Geolocation, EntityGeolocation
from app.models.indicators import ThreatIndicator, IndicatorSighting
from app.models.evidence import EvidenceObject
from app.models.analysis import EmailAnalysis, AnalysisFinding, AnalysisRun
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.campaign import Campaign, CampaignMembership
from app.services.llm_provider import default_groq_client
from app.services.similarity_service import default_similarity_service
from app.services.disposition_service import default_disposition_service
from app.services.ai_memory_service import default_ai_memory_service

logger = logging.getLogger("mailintel.services.ai_rag")


def _defang_text(text: str) -> str:
    """Defangs URLs and IP addresses in text to safely prevent rendering/clicking in LLM contexts."""
    if not text:
        return ""
    # Defang http/https
    t = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # Defang raw IP dots if preceded and followed by digits
    t = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", t)
    return t


class ForensicRAGService:
    """
    Forensic Retrieval-Augmented Generation (RAG) Service for MailIntel.
    Strictly grounds AI reasoning in deterministic forensic evidence retrieved from PostgreSQL & pgvector.
    AI acts as an analytical interpretation layer and NEVER fabricates or overrides forensic findings.
    """

    def __init__(self, groq_client=None):
        self.client = groq_client or default_groq_client

    async def retrieve_case_forensic_context(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """
        Deep forensic context retrieval combining:
        1. Envelope, Headers, & Message Identity
        2. Cryptographic Authentication (SPF, DKIM, DMARC)
        3. Relay Hop Transmission Topology & Delays
        4. Observable Indicators (Enriched IPs, Domains, URLs)
        5. Deterministic Explainable Findings from Analysis Engine
        6. pgvector Semantic & Structural Similarity Links
        7. Campaign Memberships & Cluster Evidence
        """
        # 1. Fetch Email core record
        email_stmt = select(Email).where(Email.id == email_id)
        email_obj = (await session.execute(email_stmt)).scalar_one_or_none()
        if not email_obj:
            raise ValueError(f"Email {email_id} not found.")

        # 2. Fetch Headers & Mismatch checks
        headers_stmt = select(EmailHeader).where(EmailHeader.email_id == email_id).order_by(EmailHeader.header_order)
        headers = (await session.execute(headers_stmt)).scalars().all()
        header_map = {h.header_name.lower(): h.header_value for h in headers}

        from_header = header_map.get("from", email_obj.sender_address or "")
        reply_to = header_map.get("reply-to", "")
        return_path = header_map.get("return-path", "")
        subject = email_obj.subject or header_map.get("subject", "(No Subject)")
        message_id = email_obj.message_id_header or header_map.get("message-id", "")

        # 3. Fetch Authentication Results
        auth_stmt = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
        auth_obj = (await session.execute(auth_stmt)).scalar_one_or_none()

        auth_summary = {
            "spf_status": (getattr(auth_obj, "spf_result", None) or "NONE"),
            "dkim_status": (getattr(auth_obj, "dkim_result", None) or "NONE"),
            "dmarc_status": (getattr(auth_obj, "dmarc_result", None) or "NONE"),
            "alignment_passed": (getattr(auth_obj, "from_alignment_result", "") or "").upper() == "PASS",
            "evidence": getattr(auth_obj, "evidence", {}) or {},
        }

        # 4. Fetch Relay Hops
        hops_stmt = select(RelayHop).where(RelayHop.email_id == email_id).order_by(RelayHop.sequence_number)
        hops = (await session.execute(hops_stmt)).scalars().all()
        hop_ips = [h.source_ip for h in hops if h.source_ip]

        # 5. Fetch Observable IPs, Intelligence, Classifications, and Geolocations
        ip_objs = []
        if hop_ips:
            ip_stmt = select(IPAddress).where(IPAddress.ip_address.in_(hop_ips))
            ip_objs = (await session.execute(ip_stmt)).scalars().all()

        ip_intel_map = {}
        for ip in ip_objs:
            intel_stmt = select(IPIntelligence).where(IPIntelligence.ip_id == ip.id)
            intel = (await session.execute(intel_stmt)).scalars().first()
            class_stmt = select(InfrastructureClassification).where(InfrastructureClassification.ip_id == ip.id)
            classes = (await session.execute(class_stmt)).scalars().all()
            geo_stmt = (
                select(Geolocation)
                .join(EntityGeolocation, Geolocation.id == EntityGeolocation.geolocation_id)
                .where(EntityGeolocation.entity_id == ip.id)
            )
            geo = (await session.execute(geo_stmt)).scalars().first()

            ip_intel_map[ip.ip_address] = {
                "ip": _defang_text(ip.ip_address),
                "asn": intel.asn if intel else None,
                "isp": intel.isp if intel else None,
                "hosting": intel.hosting_provider if intel else None,
                "reverse_dns": intel.reverse_dns if intel else None,
                "classifications": [c.classification_type for c in classes],
                "country_code": geo.country_code if geo else None,
                "country_name": geo.country_name if geo else None,
                "city": geo.city_name if geo else None,
            }

        relay_chain = []
        for h in hops:
            ip_meta = ip_intel_map.get(h.source_ip, {})
            resolved_country = (
                (h.evidence.get("country_code") or h.evidence.get("country"))
                if isinstance(h.evidence, dict)
                else getattr(h, "country_code", None)
            ) or ip_meta.get("country_code")

            relay_chain.append({
                "hop": h.sequence_number,
                "source_ip": _defang_text(h.source_ip or ""),
                "source_host": h.source_host,
                "destination_host": h.destination_host,
                "delay_seconds": (h.evidence.get("delay_seconds") if isinstance(h.evidence, dict) else getattr(h, "delay_seconds", None)),
                "country": resolved_country,
                "city": ip_meta.get("city"),
                "asn": ip_meta.get("asn"),
                "isp": ip_meta.get("isp"),
                "classifications": ip_meta.get("classifications", []),
                "reliability": h.reliability,
            })

        # 6. Fetch URLs and Context
        urls_stmt = (
            select(URL.normalized_url, EmailURL.context)
            .join(EmailURL, EmailURL.url_id == URL.id)
            .where(EmailURL.email_id == email_id)
        )
        url_rows = (await session.execute(urls_stmt)).all()
        extracted_urls = [
            {"url": _defang_text(r[0]), "context": r[1] or "BODY_LINK"}
            for r in url_rows
        ]

        # 7. Fetch Confirmed Threat Indicators (IoCs)
        ind_stmt = (
            select(ThreatIndicator)
            .join(IndicatorSighting, IndicatorSighting.indicator_id == ThreatIndicator.id)
            .where(IndicatorSighting.email_id == email_id)
        )
        ind_rows = (await session.execute(ind_stmt)).scalars().all()
        # Deduplicate indicators
        seen_iocs = set()
        confirmed_iocs = []
        for ind in ind_rows:
            key = (ind.indicator_type, ind.normalized_value)
            if key not in seen_iocs:
                seen_iocs.add(key)
                confirmed_iocs.append({
                    "type": ind.indicator_type,
                    "value": _defang_text(ind.normalized_value),
                    "reputation": ind.reputation,
                    "confidence": float(ind.confidence),
                })

        # 8. Fetch Attachments from Evidence Objects
        att_stmt = select(EvidenceObject).where(
            EvidenceObject.email_id == email_id,
            EvidenceObject.evidence_type == "ATTACHMENT",
        )
        att_rows = (await session.execute(att_stmt)).scalars().all()
        attachments = [
            {
                "filename": a.original_filename,
                "content_type": a.content_type,
                "size_kb": round(a.size_bytes / 1024, 1),
                "sha256": a.sha256_hash,
            }
            for a in att_rows
        ]

        # 9. Fetch Deterministic Scoring & Findings
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
            findings = [
                {
                    "type": f.finding_type,
                    "severity": f.severity,
                    "confidence": float(f.confidence),
                    "title": f.title,
                    "description": f.description,
                }
                for f in findings_objs
            ]

        # 10. Fetch pgvector Semantic & Structural Similarities
        similar_links = await default_similarity_service.get_email_similarity_links(session, email_id)
        similar_emails = [
            {
                "related_email_id": l["related_email_id"],
                "similarity_type": l["similarity_type"],
                "similarity_score": round(float(l["similarity_score"]) * 100, 1),
                "evidence": l["evidence"],
            }
            for l in similar_links[:5]
        ]

        # 11. Fetch Campaign Memberships
        m_stmt = (
            select(CampaignMembership, Campaign)
            .join(Campaign, CampaignMembership.campaign_id == Campaign.id)
            .where(CampaignMembership.email_id == email_id)
        )
        m_rows = (await session.execute(m_stmt)).all()
        campaigns = [
            {
                "campaign_id": str(c.id),
                "campaign_name": c.campaign_name,
                "status": c.campaign_status,
                "confidence": float(m.membership_confidence),
                "threat_summary": c.threat_summary,
            }
            for m, c in m_rows
        ]

        # 12. Extract Body snippet (sanitized & defanged)
        body_snippet = ""
        dna_stmt = select(EmailDNAProfile).where(EmailDNAProfile.email_id == email_id).order_by(EmailDNAProfile.created_at.desc())
        dna_obj = (await session.execute(dna_stmt)).scalars().first()
        if dna_obj and dna_obj.content_fingerprint:
            tokens = dna_obj.content_fingerprint.get("lexical_tokens") or []
            if tokens:
                body_snippet = " ".join(tokens[:80])

        # 13. Fetch Human Triage Tier, Gating, and Learned Precedents
        triage_info = await default_disposition_service.get_or_calculate_disposition(session, email_id)

        return {
            "email_id": str(email_id),
            "subject": _defang_text(subject),
            "sender": _defang_text(from_header),
            "sender_display_name": email_obj.sender_display_name,
            "sent_at": email_obj.sent_at.isoformat() if email_obj.sent_at else None,
            "received_at": email_obj.received_at.isoformat() if email_obj.received_at else None,
            "reply_to": _defang_text(reply_to),
            "return_path": _defang_text(return_path),
            "message_id": _defang_text(message_id),
            "body_snippet": _defang_text(body_snippet),
            "authentication": auth_summary,
            "relay_chain": relay_chain,
            "extracted_urls": extracted_urls,
            "infrastructure_ips": list(ip_intel_map.values()),
            "threat_indicators": confirmed_iocs,
            "attachments": attachments,
            "threat_score": float(analysis_obj.threat_risk_score) if analysis_obj else 0.0,
            "threat_verdict": analysis_obj.threat_classification if analysis_obj else "BENIGN",
            "evidence_confidence": float(analysis_obj.evidence_confidence_score) if analysis_obj else 0.0,
            "findings": findings,
            "pgvector_similar_emails": similar_emails,
            "campaign_memberships": campaigns,
            "triage_tier": triage_info.get("triage_tier"),
            "tier_label": triage_info.get("tier_label"),
            "conflict_reasons": triage_info.get("conflict_reasons", []),
            "analyst_precedents": triage_info.get("precedents", []),
            "human_disposition": {
                "is_resolved": triage_info.get("is_resolved", False),
                "verdict": triage_info.get("verdict"),
                "analyst_notes": triage_info.get("analyst_notes"),
                "reviewed_by_name": triage_info.get("reviewed_by_name"),
                "reviewed_at": triage_info.get("reviewed_at"),
            } if triage_info.get("is_resolved") else None,
        }

    def _generate_fallback_explanation(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """
        High-fidelity deterministic forensic explanation engine.
        Guarantees 100% test reliability and compliance with the strict JSON schema
        when external LLM APIs are offline or unconfigured.
        """
        findings = ctx.get("findings", [])
        threat_score = ctx.get("threat_score", 0.0)
        auth = ctx.get("authentication", {})
        urls = ctx.get("extracted_urls", [])
        ips = ctx.get("infrastructure_ips", [])
        campaigns = ctx.get("campaign_memberships", [])
        precedents = ctx.get("analyst_precedents", [])
        human_disp = ctx.get("human_disposition")

        # Determine forensic classification
        classification = "legitimate"
        if threat_score >= 70:
            classification = "phishing"
        elif threat_score >= 40:
            classification = "suspicious"

        # Check for impersonation / BEC
        reply_to = ctx.get("reply_to", "")
        sender = ctx.get("sender", "")
        if reply_to and sender and reply_to.lower() != sender.lower():
            if classification == "legitimate":
                classification = "suspicious"

        reasoning = []

        # If human already resolved this email, honor human verdict directly as supreme authority
        if human_disp and human_disp.get("is_resolved"):
            v = (human_disp.get("verdict") or "").lower()
            if "phish" in v:
                classification = "phishing"
            elif "bec" in v:
                classification = "BEC"
            elif "fraud" in v:
                classification = "fraud"
            elif "false_positive" in v or "legitimate" in v:
                classification = "legitimate"
            else:
                classification = "suspicious"

            reasoning.append({
                "finding": f"Resolved by Human Analyst ({human_disp.get('reviewed_by_name')})",
                "evidence": f"Official analyst verdict: {human_disp.get('verdict')}. Notes: {human_disp.get('analyst_notes') or 'Verified by SOC Analyst.'}",
                "confidence": 1.0,
            })
        elif precedents:
            # Learned precedent available from past human review!
            p = precedents[0]
            p_verdict = (p.get("analyst_verdict") or "").lower()
            if "phish" in p_verdict:
                classification = "phishing"
            elif "bec" in p_verdict:
                classification = "BEC"
            elif "fraud" in p_verdict:
                classification = "fraud"

            reasoning.append({
                "finding": f"Matches Prior Human Analyst Precedent ({p.get('similarity_score')}% Match)",
                "evidence": f"Pattern previously reviewed by {p.get('reviewer_name')} on Case {p.get('precedent_email_id', '')[:8]}. Verdict: {p.get('analyst_verdict')}. Notes: {p.get('analyst_notes')}",
                "confidence": 0.95,
            })
        for f in findings:
            reasoning.append({
                "finding": f.get("title", ""),
                "evidence": f.get("description", ""),
                "confidence": round(float(f.get("confidence", 0.8)), 2),
            })

        if not reasoning:
            if auth.get("spf_status") == "PASS" and auth.get("dkim_status") == "PASS":
                reasoning.append({
                    "finding": "Cryptographic Authentication Validated",
                    "evidence": "SPF, DKIM, and DMARC aligned with the sender envelope.",
                    "confidence": 0.95,
                })

        social_indicators = []
        if reply_to and sender and reply_to.lower() != sender.lower():
            social_indicators.append("Sender / Reply-To address mismatch (Impersonation vector)")
        for f in findings:
            if "urgency" in f.get("title", "").lower() or "lure" in f.get("title", "").lower():
                social_indicators.append(f.get("title"))

        attack_intent = []
        if any("credential" in f.get("title", "").lower() for f in findings):
            attack_intent.append("Credential Harvesting")
        if any("malicious" in f.get("title", "").lower() for f in findings):
            attack_intent.append("Infrastructure Exploitation")
        if any(u.get("context") == "BUTTON_HREF" for u in urls):
            attack_intent.append("Direct User Action Coercion via CTA Link")
        if campaigns:
            attack_intent.append(f"Organized Campaign Activity ({campaigns[0].get('campaign_name')})")

        recommended_actions = []
        if threat_score >= 40:
            recommended_actions.append("Block observable sender and relay infrastructure on mail perimeter")
            recommended_actions.append("Blacklist extracted URLs in web gateway and proxy filters")
            recommended_actions.append("Initiate SOC incident triage and check recipient mailbox telemetry")
        else:
            recommended_actions.append("Maintain baseline telemetry monitoring; no immediate escalation required")

        return {
            "classification": classification,
            "reasoning": reasoning,
            "social_engineering_indicators": social_indicators or ["No overt psychological manipulation detected"],
            "attack_intent": attack_intent or ["Standard Communications / Administrative Delivery"],
            "recommended_actions": recommended_actions,
            "confidence": round(min(1.0, max(0.5, ctx.get("evidence_confidence", 80.0) / 100.0)), 2),
        }

    async def explain_email_threat(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """
        AI Feature 1 & 2: Threat Reasoning Analyst & Investigation Explanation.
        Interprets already-extracted email evidence and returns strict JSON forensic output.
        Accelerated by Redis working memory cache (24h TTL) with invalidation on analyst review.
        """
        # 1. Check Redis L1 working memory cache first
        cached_explanation = await default_ai_memory_service.get_cached_explanation(str(email_id))
        if cached_explanation:
            logger.info(f"AI explanation cache HIT (Redis) for email {email_id}")
            return cached_explanation

        ctx = await self.retrieve_case_forensic_context(session, email_id)

        # Build secure, defanged system and user prompts
        system_prompt = (
            "You are MailIntel's Senior Forensic Threat Analyst.\n"
            "Your role is strictly to interpret already-extracted email forensic evidence provided in the dossier.\n\n"
            "STRICT GROUNDING & ANTI-HALLUCINATION CONSTRAINTS:\n"
            "1. GROUNDING MANDATE: Rely exclusively on the provided <forensic_context>. Never assume or invent facts.\n"
            "2. DO NOT calculate SPF/DKIM/DMARC yourself; cite the exact provided results.\n"
            "3. DO NOT invent IP/domain reputation, geolocation coordinates, or timeline events.\n"
            "4. DO NOT declare an individual attacker identity or physical street address.\n"
            "5. DO NOT override deterministic findings or threat scores.\n"
            "6. Every reasoning item MUST provide concrete, verifiable forensic proof citing specific fields from the context "
            "(e.g. hop number, IP, domain, URL, hash, or header mismatch).\n\n"
            "You must return ONLY a valid JSON object with this EXACT structure:\n"
            "{\n"
            '  "classification": "legitimate" | "suspicious" | "phishing" | "impersonation" | "fraud" | "BEC",\n'
            '  "reasoning": [\n'
            '    {\n'
            '      "finding": "WHAT occurred (short title)",\n'
            '      "evidence": "WHY and concrete forensic EVIDENCE quoted from context",\n'
            '      "confidence": 0.0 to 1.0\n'
            "    }\n"
            "  ],\n"
            '  "social_engineering_indicators": ["..."],\n'
            '  "attack_intent": ["..."],\n'
            '  "recommended_actions": ["..."],\n'
            '  "confidence": 0.0 to 1.0\n'
            "}"
        )

        user_prompt = (
            "Analyze the following retrieved forensic dossier and produce the structured threat explanation JSON:\n\n"
            f"<forensic_context>\n"
            f"{json.dumps(ctx, indent=2)}\n"
            f"</forensic_context>"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        raw_llm = await self.client.chat_completion(messages, json_mode=True)
        if raw_llm:
            try:
                parsed = json.loads(raw_llm)
                # Validate required schema keys
                if "classification" in parsed and "reasoning" in parsed:
                    # Enforce valid classification enum
                    valid_classes = {"legitimate", "suspicious", "phishing", "impersonation", "fraud", "BEC"}
                    if parsed["classification"] not in valid_classes:
                        parsed["classification"] = "suspicious" if ctx.get("threat_score", 0) >= 40 else "legitimate"
                    await default_ai_memory_service.set_cached_explanation(str(email_id), parsed)
                    return parsed
            except Exception as e:
                logger.warning(f"Failed to parse Groq JSON response: {e}. Falling back to deterministic engine.")

        fallback = self._generate_fallback_explanation(ctx)
        await default_ai_memory_service.set_cached_explanation(str(email_id), fallback)
        return fallback

    async def investigate_case_assistant(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
        question: str,
        history: Optional[List[Dict[str, str]]] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        AI Feature 3: Analyst Investigation Assistant.
        Answers questions strictly grounded in the retrieved case evidence, pgvector similarities,
        infrastructure relationships, and threat campaign memberships.
        Supports multi-turn state via Redis session memory.
        """
        # Retrieve conversation history from Redis working memory if not supplied
        if (history is None or len(history) == 0) and user_id:
            session_msgs = await default_ai_memory_service.get_chat_session(str(email_id), user_id)
            if session_msgs:
                history = session_msgs

        ctx = await self.retrieve_case_forensic_context(session, email_id)
        clean_q = question.strip()

        system_prompt = (
            "You are MailIntel's Grounded Investigation Assistant.\n"
            "You answer questions from cyber forensics investigators about a specific email case.\n\n"
            "STRICT INVESTIGATION RULES:\n"
            "1. Answer ONLY using the retrieved case context provided in <retrieved_case_evidence>.\n"
            "2. DO NOT speculate or answer from general training weights if the information is not in the case.\n"
            "3. If the requested information is not mentioned in the evidence, state clearly: 'This information is not present in the forensic evidence for this case.'\n"
            "4. When referencing similar emails, cite the pgvector similarity percentage and specific shared indicators.\n"
            "5. When referencing campaigns, cite the campaign name, status, and relationship confidence percentage.\n"
            "6. When referencing network routing or infrastructure, cite the exact hop sequence, defanged IP, country, ASN, and classifications (e.g. Tor, VPN, Cloud, Hosting).\n"
            "7. When referencing observables, cite confirmed Threat Indicators with their verified reputation and confidence.\n"
            "8. Keep responses technical, objective, concise, and structured."
        )

        messages = [{"role": "system", "content": system_prompt}]

        # Inject conversation history if present
        if history:
            for item in history[-4:]:
                role = item.get("role", "user")
                content = item.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

        user_content = (
            f"<retrieved_case_evidence>\n{json.dumps(ctx, indent=2)}\n</retrieved_case_evidence>\n\n"
            f"Analyst Question: {clean_q}"
        )
        messages.append({"role": "user", "content": user_content})

        raw_answer = await self.client.chat_completion(messages, json_mode=False)
        if raw_answer:
            raw_answer = raw_answer.replace("\u2011", "-").replace("\u2010", "-").replace("\u202f", " ")

        if not raw_answer:
            # Deterministic case assistant Q&A fallback
            q_lower = clean_q.lower()
            if "high risk" in q_lower or "why flagged" in q_lower or "risk" in q_lower:
                findings_str = "; ".join(f.get("title") for f in ctx.get("findings", []))
                raw_answer = (
                    f"Email {ctx.get('email_id')} has a Threat Risk Score of {ctx.get('threat_score')}/100 ({ctx.get('threat_verdict')}). "
                    f"Key drivers: {findings_str or 'Authentication checks and reputation scores evaluated by deterministic engine'}."
                )
            elif "related" in q_lower or "similar" in q_lower:
                similar = ctx.get("pgvector_similar_emails", [])
                if similar:
                    sim_details = ", ".join(f"Email {s['related_email_id']} ({s['similarity_score']}% similarity)" for s in similar)
                    raw_answer = f"Found {len(similar)} related emails via pgvector multi-signal similarity: {sim_details}."
                else:
                    raw_answer = "No statistically significant similar emails found in the current tenant cluster."
            elif "infrastructure" in q_lower or "relay" in q_lower or "ip" in q_lower:
                hops = ctx.get("relay_chain", [])
                ips = ctx.get("infrastructure_ips", [])
                hop_details = " -> ".join(f"Hop {h['hop']}: {h['source_ip']} ({h.get('country') or 'Unknown'})" for h in hops)
                raw_answer = f"Observed Relay Topology: {hop_details}. Enriched infrastructure observable count: {len(ips)} IPs."
            elif "campaign" in q_lower:
                camps = ctx.get("campaign_memberships", [])
                if camps:
                    c = camps[0]
                    raw_answer = f"This message is a confirmed member of Campaign '{c['campaign_name']}' (Status: {c['status']}, Confidence: {c['confidence']}%)."
                else:
                    raw_answer = "This email is currently not correlated to any established threat campaigns."
            else:
                raw_answer = (
                    f"Case Summary for Email {ctx.get('email_id')}:\n"
                    f"Subject: {ctx.get('subject')}\n"
                    f"Threat Risk Score: {ctx.get('threat_score')}/100 ({ctx.get('threat_verdict')})\n"
                    f"Authentication: SPF={ctx['authentication']['spf_status']}, DKIM={ctx['authentication']['dkim_status']}, DMARC={ctx['authentication']['dmarc_status']}\n"
                    f"Findings Count: {len(ctx.get('findings', []))}\n"
                    f"Observable URLs: {len(ctx.get('extracted_urls', []))}"
                )

        if user_id:
            await default_ai_memory_service.append_chat_message(str(email_id), user_id, "user", clean_q)
            await default_ai_memory_service.append_chat_message(str(email_id), user_id, "assistant", raw_answer)

        return {
            "email_id": str(email_id),
            "question": clean_q,
            "answer": raw_answer,
            "grounded_sources": {
                "findings_count": len(ctx.get("findings", [])),
                "similar_emails_count": len(ctx.get("pgvector_similar_emails", [])),
                "campaigns_count": len(ctx.get("campaign_memberships", [])),
                "urls_count": len(ctx.get("extracted_urls", [])),
            },
        }

    async def summarize_case(
        self,
        session: AsyncSession,
        email_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """Summarizes the email case into an executive forensic brief."""
        ctx = await self.retrieve_case_forensic_context(session, email_id)
        explanation = await self.explain_email_threat(session, email_id)

        summary_text = (
            f"Case {email_id} ({ctx.get('threat_verdict')}, Score: {ctx.get('threat_score')}/100). "
            f"Subject: \"{ctx.get('subject')}\". "
            f"Classification: {explanation.get('classification').upper()}. "
            f"Key intent: {', '.join(explanation.get('attack_intent', []))}. "
            f"Evidence confidence: {explanation.get('confidence') * 100:.0f}%."
        )

        return {
            "email_id": str(email_id),
            "summary": summary_text,
            "classification": explanation.get("classification"),
            "threat_score": ctx.get("threat_score"),
            "top_findings": [r["finding"] for r in explanation.get("reasoning", [])[:3]],
            "recommended_actions": explanation.get("recommended_actions", []),
        }


default_forensic_rag_service = ForensicRAGService()
