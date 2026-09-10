import uuid
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.storage import storage
from app.models.emails import Email, EmailRecipient, EmailAuthenticationResult, EmailHeader, RelayHop
from app.models.evidence import EvidenceObject, CustodyEvent
from app.models.analysis import EmailAnalysis, AnalysisFinding
from app.models.reports import Report
from app.models.intelligence import Domain, URL, EmailURL, IPAddress, Geolocation, EntityGeolocation
from app.models.indicators import ThreatIndicator, IndicatorSighting
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.campaign import Campaign, CampaignMembership

logger = logging.getLogger("mailintel.reports")

ATTRIBUTION_DISCLAIMER = (
    "NOTICE & ATTRIBUTION DISCLAIMER: This forensic report is automatically synthesized from available "
    "RFC 822 email headers, cryptographic authentication assertions, DNS/RDAP records, and threat intelligence "
    "sources. Infrastructure observations (IP addresses, ASNs, geolocations) indicate intermediate transit, "
    "relay, or hosting facilities and do NOT establish the physical identity or geographical location of the "
    "human threat actor. All risk scores and likelihood assessments are probabilistic intelligence signals to "
    "assist qualified human investigators."
)


class ReportService:
    """
    Forensic Report Generation & Preservation Engine for MailIntel.
    Produces comprehensive, verifiable JSON, Markdown, and Standalone HTML dossiers.
    """

    @staticmethod
    async def build_email_report_data(
        email_id: uuid.UUID,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """Aggregates all multi-layer forensic intelligence for a single email."""
        # 1. Fetch Email
        stmt_email = select(Email).where(Email.id == email_id)
        res_email = await db.execute(stmt_email)
        email = res_email.scalar_one_or_none()
        if not email:
            raise ValueError(f"Email with ID {email_id} not found")

        # 2. Fetch Evidence & Integrity
        stmt_evidence = select(EvidenceObject).where(
            EvidenceObject.email_id == email_id,
            EvidenceObject.evidence_type == "ORIGINAL_EMAIL",
        )
        res_evidence = await db.execute(stmt_evidence)
        evidence = res_evidence.scalar_one_or_none()

        integrity_status = {
            "verified": False,
            "original_sha256": evidence.sha256_hash if evidence else "UNKNOWN",
            "size_bytes": evidence.size_bytes if evidence else (email.email_size_bytes or 0),
            "bucket": evidence.bucket_name if evidence else settings.MINIO_EVIDENCE_BUCKET,
            "object_key": evidence.object_key if evidence else "unknown",
            "stored_at": evidence.stored_at.isoformat() if evidence and evidence.stored_at else None,
            "immutable": evidence.immutable if evidence else True,
        }

        # 3. Fetch Custody Events
        custody_list: List[Dict[str, Any]] = []
        if evidence:
            stmt_custody = select(CustodyEvent).where(CustodyEvent.evidence_id == evidence.id).order_by(CustodyEvent.event_at)
            res_custody = await db.execute(stmt_custody)
            for c in res_custody.scalars().all():
                custody_list.append({
                    "event_type": c.event_type,
                    "timestamp": c.event_at.isoformat() if c.event_at else None,
                    "metadata": c.event_metadata or {},
                })

        # 4. Fetch Recipients
        stmt_recip = select(EmailRecipient).where(EmailRecipient.email_id == email_id)
        res_recip = await db.execute(stmt_recip)
        recipients = res_recip.scalars().all()
        to_addrs = [r.address for r in recipients if r.recipient_type == "TO"]
        cc_addrs = [r.address for r in recipients if r.recipient_type == "CC"]

        # 5. Fetch Authentication Result
        stmt_auth = select(EmailAuthenticationResult).where(EmailAuthenticationResult.email_id == email_id)
        res_auth = await db.execute(stmt_auth)
        auth_res = res_auth.scalar_one_or_none()

        # 6. Fetch Headers
        stmt_headers = select(EmailHeader).where(EmailHeader.email_id == email_id).order_by(EmailHeader.header_order)
        res_headers = await db.execute(stmt_headers)
        raw_headers = {h.header_name: h.header_value for h in res_headers.scalars().all()}

        # 7. Fetch Analysis & Scoring Findings
        stmt_analysis = select(EmailAnalysis).where(EmailAnalysis.email_id == email_id).order_by(EmailAnalysis.created_at.desc())
        res_analysis = await db.execute(stmt_analysis)
        analysis = res_analysis.scalars().first()

        findings_list: List[Dict[str, Any]] = []
        if analysis and analysis.analysis_run_id:
            stmt_findings = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == analysis.analysis_run_id)
            res_findings = await db.execute(stmt_findings)
            for f in res_findings.scalars().all():
                findings_list.append({
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "confidence": float(f.confidence),
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence or {},
                })

        # 8. Fetch URLs & Domains
        stmt_urls = (
            select(URL, EmailURL.context)
            .join(EmailURL, URL.id == EmailURL.url_id)
            .where(EmailURL.email_id == email_id)
        )
        res_urls = await db.execute(stmt_urls)
        urls_list: List[Dict[str, Any]] = []
        for u, ctx in res_urls.all():
            urls_list.append({
                "normalized_url": u.normalized_url,
                "url_hash": u.url_hash,
                "context": ctx,
            })

        # 9. Fetch Threat Indicators
        stmt_ti = (
            select(ThreatIndicator, IndicatorSighting.context)
            .join(IndicatorSighting, ThreatIndicator.id == IndicatorSighting.indicator_id)
            .where(IndicatorSighting.email_id == email_id)
        )
        res_ti = await db.execute(stmt_ti)
        indicators_list: List[Dict[str, Any]] = []
        for ti, ctx in res_ti.all():
            ctx_dict = ctx or {}
            indicators_list.append({
                "indicator_type": ti.indicator_type,
                "value": ti.normalized_value,
                "verdict": ti.reputation or "UNKNOWN",
                "threat_score": float(ti.confidence) if ti.confidence is not None else 0.0,
                "source": ctx_dict.get("provider", "Threat Intelligence Engine"),
                "details": ctx_dict,
            })

        # 7. Fetch Email DNA
        stmt_dna = select(EmailDNAProfile).where(EmailDNAProfile.email_id == email_id)
        res_dna = await db.execute(stmt_dna)
        dna_obj = res_dna.scalar_one_or_none()
        dna_data = None
        if dna_obj:
            overall_hash = None
            if dna_obj.technical_fingerprint and isinstance(dna_obj.technical_fingerprint, dict):
                overall_hash = dna_obj.technical_fingerprint.get("overall_dna_hash")
            dna_data = {
                "overall_dna_hash": overall_hash,
                "content_fingerprint": dna_obj.content_fingerprint or {},
                "technical_fingerprint": dna_obj.technical_fingerprint or {},
                "infrastructure_fingerprint": dna_obj.infrastructure_fingerprint or {},
                "behavioral_fingerprint": dna_obj.behavioral_fingerprint or {},
                "temporal_fingerprint": dna_obj.temporal_fingerprint or {},
            }

        # 8. Fetch Similar Emails
        stmt_sim = (
            select(EmailSimilarityLink)
            .where(EmailSimilarityLink.source_email_id == email_id)
            .order_by(EmailSimilarityLink.similarity_score.desc())
            .limit(5)
        )
        res_sim = await db.execute(stmt_sim)
        similar_list: List[Dict[str, Any]] = []
        for sim in res_sim.scalars().all():
            ev = sim.evidence or {}
            similar_list.append({
                "target_email_id": str(sim.related_email_id),
                "weighted_similarity_score": float(sim.similarity_score),
                "similarity_type": sim.similarity_type,
                "target_subject": ev.get("target_subject", "Correlated Suspicious Email"),
                "target_sender": ev.get("target_sender", "Unknown"),
            })

        # 9. Fetch Campaign Memberships
        stmt_camp = (
            select(Campaign, CampaignMembership)
            .join(CampaignMembership, Campaign.id == CampaignMembership.campaign_id)
            .where(CampaignMembership.email_id == email_id)
        )
        res_camp = await db.execute(stmt_camp)
        campaigns_list: List[Dict[str, Any]] = []
        for camp, memb in res_camp.all():
            ev_sum = memb.evidence_summary or {}
            campaigns_list.append({
                "campaign_id": str(camp.id),
                "name": camp.campaign_name or f"Campaign-{str(camp.id)[:8]}",
                "status": camp.campaign_status,
                "confidence_score": float(memb.membership_confidence) if memb.membership_confidence else float(camp.campaign_confidence),
                "is_bridge_entity": ev_sum.get("is_bridge_entity", False),
                "total_campaigns": ev_sum.get("total_campaigns", 1),
                "contributing_signals": ev_sum.get("contributing_signals", []),
            })

        # 10. Fetch Geolocations
        stmt_geo = (
            select(Geolocation, EntityGeolocation.relationship_type, EntityGeolocation.evidence)
            .join(EntityGeolocation, Geolocation.id == EntityGeolocation.geolocation_id)
            .where(EntityGeolocation.entity_id == email_id)
        )
        res_geo = await db.execute(stmt_geo)
        geo_list: List[Dict[str, Any]] = []
        for g, rel_type, ev in res_geo.all():
            ev_dict = ev or {}
            geo_list.append({
                "ip_address": ev_dict.get("ip_address", "N/A"),
                "role": rel_type,
                "country": g.country_name,
                "country_code": g.country_code,
                "city": g.city_name,
                "region": g.region_name,
                "latitude": float(g.latitude) if g.latitude is not None else None,
                "longitude": float(g.longitude) if g.longitude is not None else None,
                "asn": ev_dict.get("asn"),
                "isp": ev_dict.get("isp"),
            })

        report_timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": report_timestamp,
            "report_type": "FORENSIC_SUMMARY",
            "report_version": "1.0",
            "email_id": str(email.id),
            "email_metadata": {
                "subject": email.subject,
                "from_address": email.sender_address,
                "from_name": email.sender_display_name,
                "to_addresses": to_addrs,
                "cc_addresses": cc_addrs,
                "date_header": email.sent_at.isoformat() if email.sent_at else None,
                "message_id": email.message_id_header,
                "reply_to": auth_res.return_path if auth_res else None,
                "return_path": auth_res.return_path if auth_res else None,
                "file_size_bytes": email.email_size_bytes or 0,
                "sha256_hash": integrity_status.get("original_sha256"),
            },
            "custody_and_integrity": {
                "integrity": integrity_status,
                "custody_events": custody_list,
            },
            "authentication_and_headers": {
                "spf_result": auth_res.spf_result if auth_res else "NONE",
                "dkim_result": auth_res.dkim_result if auth_res else "NONE",
                "dmarc_result": auth_res.dmarc_result if auth_res else "NONE",
                "from_domain_alignment": auth_res.from_alignment_result if auth_res else "NONE",
                "raw_headers": raw_headers,
            },
            "explainable_scores": {
                "threat_classification": analysis.threat_classification if analysis else "UNKNOWN",
                "threat_risk_score": float(analysis.threat_risk_score) if analysis else 0.0,
                "evidence_confidence_score": float(analysis.evidence_confidence_score) if analysis else 0.0,
                "summary": analysis.summary if analysis else "No automated summary available.",
                "likelihoods": {
                    "compromised_account": analysis.compromised_account_likelihood if analysis else "UNLIKELY",
                    "spoofed_domain": analysis.spoofed_domain_likelihood if analysis else "UNLIKELY",
                    "anonymized_infrastructure": analysis.anonymized_infrastructure_likelihood if analysis else "UNLIKELY",
                    "malicious_environment": analysis.malicious_environment_likelihood if analysis else "UNLIKELY",
                },
                "findings": findings_list,
            },
            "email_dna": dna_data,
            "threat_intelligence": {
                "urls": urls_list,
                "threat_indicators": indicators_list,
            },
            "similarity_and_clusters": {
                "similar_emails": similar_list,
                "campaigns": campaigns_list,
            },
            "geo_intelligence": {
                "locations": geo_list,
            },
            "limitations_and_disclaimer": {
                "disclaimer": ATTRIBUTION_DISCLAIMER,
                "uncertainty_notes": [
                    "Email header routing hops may be forged by previous relays prior to receipt by first trusted MTA.",
                    "WHOIS and domain age heuristics depend on third-party registry availability and RDAP responses.",
                    "Semantic similarity indicates stylistic / textual overlap and does not alone establish identical authorship.",
                    "Infrastructure geolocation denotes server hosting coordinates and must not be conflated with the actor's physical location.",
                ],
            },
        }

    @staticmethod
    async def build_campaign_report_data(
        campaign_id: uuid.UUID,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """Aggregates multi-email campaign dossier."""
        stmt_camp = select(Campaign).where(Campaign.id == campaign_id)
        res_camp = await db.execute(stmt_camp)
        campaign = res_camp.scalar_one_or_none()
        if not campaign:
            raise ValueError(f"Campaign with ID {campaign_id} not found")

        # Get members
        stmt_m = (
            select(Email, CampaignMembership)
            .join(CampaignMembership, Email.id == CampaignMembership.email_id)
            .where(CampaignMembership.campaign_id == campaign_id)
        )
        res_m = await db.execute(stmt_m)
        members: List[Dict[str, Any]] = []
        for em, memb in res_m.all():
            ev_sum = memb.evidence_summary or {}
            members.append({
                "email_id": str(em.id),
                "subject": em.subject,
                "from_address": em.from_address,
                "date_header": em.date_header.isoformat() if em.date_header else None,
                "sha256": em.sha256_hash,
                "is_bridge_entity": ev_sum.get("is_bridge_entity", False),
                "total_campaigns": ev_sum.get("total_campaigns", 1),
                "contributing_signals": ev_sum.get("contributing_signals", []),
                "added_at": memb.created_at.isoformat() if memb.created_at else None,
            })

        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "CAMPAIGN_DOSSIER",
            "report_version": "1.0",
            "campaign_id": str(campaign.id),
            "campaign_metadata": {
                "name": campaign.campaign_name or f"Campaign-{str(campaign.id)[:8]}",
                "description": campaign.threat_summary,
                "status": campaign.campaign_status,
                "confidence_score": float(campaign.campaign_confidence) if campaign.campaign_confidence else 0.0,
                "first_seen_at": campaign.first_detected_at.isoformat() if campaign.first_detected_at else None,
                "last_seen_at": campaign.last_activity_at.isoformat() if campaign.last_activity_at else None,
                "member_count": len(members),
                "tactics": [],
                "target_sectors": [],
            },
            "member_emails": members,
            "cluster_evidence": {},
            "limitations_and_disclaimer": {
                "disclaimer": ATTRIBUTION_DISCLAIMER,
                "uncertainty_notes": [
                    "Campaign clustering synthesizes technical correlations; shared hosting alone does not prove identical threat actors.",
                    "Bridge entities connect clusters across shared observables and must be investigated individually.",
                ],
            },
        }

    @staticmethod
    def render_markdown_report(data: Dict[str, Any]) -> str:
        """Renders comprehensive, clean GitHub Flavored Markdown forensic report."""
        if data.get("report_type") == "CAMPAIGN_DOSSIER":
            return ReportService._render_campaign_markdown(data)
        return ReportService._render_email_markdown(data)

    @staticmethod
    def _render_email_markdown(data: Dict[str, Any]) -> str:
        meta = data.get("email_metadata", {})
        scores = data.get("explainable_scores", {})
        auth = data.get("authentication_and_headers", {})
        custody = data.get("custody_and_integrity", {})
        dna = data.get("email_dna") or {}
        intel = data.get("threat_intelligence", {})
        sim = data.get("similarity_and_clusters", {})
        geo = data.get("geo_intelligence", {})
        limitations = data.get("limitations_and_disclaimer", {})

        md = []
        md.append(f"# MailIntel Forensic Intelligence Report")
        md.append(f"**Report ID:** `{data.get('report_id')}` | **Generated:** {data.get('generated_at')} | **Version:** {data.get('report_version')}")
        md.append(f"\n> **EXECUTIVE VERDICT: {scores.get('threat_classification', 'UNKNOWN')} (Threat Score: {scores.get('threat_risk_score', 0):.1f}/100 | Evidence Confidence: {scores.get('evidence_confidence_score', 0):.1f}%)**\n")
        md.append(f"**Forensic Summary:** {scores.get('summary', 'N/A')}\n")

        md.append("---")
        md.append("## 1. Digital Evidence & Custody")
        md.append(f"- **Email ID:** `{data.get('email_id')}`")
        md.append(f"- **Subject:** {meta.get('subject')}")
        md.append(f"- **Sender (From):** `{meta.get('from_address')}` ({meta.get('from_name') or 'N/A'})")
        md.append(f"- **Recipient (To):** `{', '.join(meta.get('to_addresses', []))}`")
        md.append(f"- **Date Header:** {meta.get('date_header')}")
        md.append(f"- **SHA-256 Digest:** `{meta.get('sha256_hash')}`")
        md.append(f"- **File Size:** {meta.get('file_size_bytes', 0):,} bytes")
        md.append(f"- **Attachments:** {meta.get('attachment_count', 0)} attached")

        integ = custody.get("integrity", {})
        md.append(f"\n### Chain of Custody & Immutability")
        md.append(f"- **Storage Bucket:** `{integ.get('bucket')}` / `{integ.get('object_key')}`")
        md.append(f"- **Immutable Archive:** `{'VERIFIED TRUE' if integ.get('immutable') else 'FALSE'}`")
        md.append(f"- **Stored At:** {integ.get('stored_at')}")
        
        events = custody.get("custody_events", [])
        if events:
            md.append("\n| Timestamp | Custody Action | Details |")
            md.append("|---|---|---|")
            for ev in events:
                md.append(f"| {ev.get('timestamp')} | `{ev.get('event_type')}` | {json.dumps(ev.get('metadata', {}))} |")

        md.append("\n---")
        md.append("## 2. Authentication & Header Forensics")
        md.append(f"- **SPF Status:** `{auth.get('spf_result', 'NONE')}`")
        md.append(f"- **DKIM Status:** `{auth.get('dkim_result', 'NONE')}`")
        md.append(f"- **DMARC Status:** `{auth.get('dmarc_result', 'NONE')}`")
        md.append(f"- **From-Domain Alignment:** `{auth.get('from_domain_alignment', 'NONE')}`")
        md.append(f"- **Return-Path:** `{meta.get('return_path')}`")
        md.append(f"- **Reply-To:** `{meta.get('reply_to')}`")
        md.append(f"- **Message-ID:** `{meta.get('message_id')}`")

        md.append("\n---")
        md.append("## 3. Explainable Risk Findings & Hypotheses")
        lik = scores.get("likelihoods", {})
        md.append(f"- **Compromised Account Likelihood:** `{lik.get('compromised_account')}`")
        md.append(f"- **Spoofed Domain Likelihood:** `{lik.get('spoofed_domain')}`")
        md.append(f"- **Anonymized Infrastructure Likelihood:** `{lik.get('anonymized_infrastructure')}`")
        md.append(f"- **Malicious Environment Likelihood:** `{lik.get('malicious_environment')}`")

        findings = scores.get("findings", [])
        if findings:
            md.append("\n### Detailed Forensic Findings")
            md.append("| Severity | Type | Title | Description |")
            md.append("|---|---|---|---|")
            for f in findings:
                md.append(f"| `{f.get('severity')}` | `{f.get('finding_type')}` | **{f.get('title')}** | {f.get('description')} |")

        md.append("\n---")
        md.append("## 4. Email DNA Structural Fingerprint")
        if dna:
            md.append(f"- **Overall DNA Hash:** `{dna.get('overall_dna_hash')}`")
            tech = dna.get("technical_fingerprint", {})
            md.append(f"- **Header Order Hash:** `{tech.get('header_order_hash')}`")
            md.append(f"- **X-Mailer Signature:** `{tech.get('x_mailer')}`")
            infra = dna.get("infrastructure_fingerprint", {})
            md.append(f"- **Originating IP:** `{infra.get('originating_ip')}`")
            md.append(f"- **ASN Sequence:** `{infra.get('asn_sequence')}`")
            md.append(f"- **Anonymized Flags:** TOR=`{infra.get('has_tor')}`, VPN=`{infra.get('has_vpn')}`, Cloud=`{infra.get('has_cloud')}`")
        else:
            md.append("_DNA Profile not yet generated for this email._")

        md.append("\n---")
        md.append("## 5. Threat Intelligence & Indicators")
        urls = intel.get("urls", [])
        if urls:
            md.append(f"\n### Extracted URLs ({len(urls)})")
            for u in urls:
                md.append(f"- `{u.get('normalized_url')}` (Context: {u.get('context', 'BODY')})")

        indicators = intel.get("threat_indicators", [])
        if indicators:
            md.append("\n### Indicator Threat Verdicts")
            md.append("| Type | Indicator | Source Provider | Verdict | Score |")
            md.append("|---|---|---|---|---|")
            for ind in indicators:
                md.append(f"| `{ind.get('indicator_type')}` | `{ind.get('value')}` | {ind.get('source')} | **{ind.get('verdict')}** | {ind.get('threat_score'):.1f} |")

        md.append("\n---")
        md.append("## 6. Correlation & Campaign Intelligence")
        camps = sim.get("campaigns", [])
        if camps:
            md.append(f"\n### Active Campaign Associations ({len(camps)})")
            for c in camps:
                md.append(f"- **Campaign:** {c.get('name')} (Status: `{c.get('status')}`, Confidence: {c.get('confidence_score'):.1f}%, Bridge Entity: `{c.get('is_bridge_entity')}`)")
        else:
            md.append("- No linked campaigns identified.")

        sims = sim.get("similar_emails", [])
        if sims:
            md.append("\n### Semantically Similar Lures")
            md.append("| Similar Email ID | Subject | Sender | Similarity Score |")
            md.append("|---|---|---|---|")
            for s in sims:
                md.append(f"| `{s.get('target_email_id')[:8]}...` | {s.get('target_subject')} | `{s.get('target_sender')}` | **{s.get('weighted_similarity_score') * 100:.1f}%** |")

        md.append("\n---")
        md.append("## 7. Infrastructure Geolocation")
        locs = geo.get("locations", [])
        if locs:
            md.append("\n| IP Address | Role | Country | City / Region | ASN / ISP | Coordinates |")
            md.append("|---|---|---|---|---|---|")
            for l in locs:
                coords = f"{l.get('latitude')}, {l.get('longitude')}" if l.get('latitude') else "N/A"
                md.append(f"| `{l.get('ip_address')}` | `{l.get('role')}` | {l.get('country')} ({l.get('country_code')}) | {l.get('city') or 'N/A'}, {l.get('region') or 'N/A'} | {l.get('asn') or 'N/A'} - {l.get('isp') or 'N/A'} | `{coords}` |")
        else:
            md.append("- No public infrastructure geolocations recorded.")

        md.append("\n---")
        md.append("## 8. Limitations & Attribution Disclaimers")
        md.append(f"> [!IMPORTANT]\n> **{limitations.get('disclaimer')}**\n")
        notes = limitations.get("uncertainty_notes", [])
        for n in notes:
            md.append(f"- {n}")

        return "\n".join(md)

    @staticmethod
    def _render_campaign_markdown(data: Dict[str, Any]) -> str:
        meta = data.get("campaign_metadata", {})
        members = data.get("member_emails", [])
        limitations = data.get("limitations_and_disclaimer", {})

        md = []
        md.append(f"# MailIntel Campaign Intelligence Dossier")
        md.append(f"**Report ID:** `{data.get('report_id')}` | **Generated:** {data.get('generated_at')}")
        md.append(f"\n## Campaign: **{meta.get('name')}**")
        md.append(f"- **Status:** `{meta.get('status')}`")
        md.append(f"- **Confidence:** {meta.get('confidence_score', 0):.1f}%")
        md.append(f"- **First Seen:** {meta.get('first_seen_at')}")
        md.append(f"- **Last Seen:** {meta.get('last_seen_at')}")
        md.append(f"- **Member Emails:** {meta.get('member_count', len(members))}")
        md.append(f"- **Tactics:** {', '.join(meta.get('tactics', [])) or 'N/A'}")
        md.append(f"- **Target Sectors:** {', '.join(meta.get('target_sectors', [])) or 'N/A'}")
        md.append(f"\n**Description:** {meta.get('description', 'N/A')}\n")

        md.append("---")
        md.append("## Associated Lures & Bridge Entities")
        md.append("| Email ID | Subject | Sender | Date | Bridge Entity? | Contributing Signals |")
        md.append("|---|---|---|---|---|---|")
        for m in members:
            signals = ", ".join(m.get("contributing_signals", []))
            md.append(f"| `{m.get('email_id')[:8]}...` | {m.get('subject')} | `{m.get('from_address')}` | {m.get('date_header')} | `{m.get('is_bridge_entity')}` | {signals} |")

        md.append("\n---")
        md.append("## Limitations & Uncertainty")
        md.append(f"> [!IMPORTANT]\n> **{limitations.get('disclaimer')}**\n")
        for n in limitations.get("uncertainty_notes", []):
            md.append(f"- {n}")

        return "\n".join(md)

    @staticmethod
    def render_html_report(data: Dict[str, Any]) -> str:
        """Renders standalone, beautifully styled dark/light print-ready HTML forensic document."""
        report_type = data.get("report_type", "FORENSIC_SUMMARY")
        title = "MailIntel Forensic Report" if report_type == "FORENSIC_SUMMARY" else "MailIntel Campaign Dossier"
        meta = data.get("email_metadata", {})
        scores = data.get("explainable_scores", {})
        auth = data.get("authentication_and_headers", {})
        custody = data.get("custody_and_integrity", {})
        integ = custody.get("integrity", {})
        dna = data.get("email_dna") or {}
        intel = data.get("threat_intelligence", {})
        geo = data.get("geo_intelligence", {})
        sim = data.get("similarity_and_clusters", {})
        limitations = data.get("limitations_and_disclaimer", {})

        classification = scores.get("threat_classification", "UNKNOWN")
        risk_score = scores.get("threat_risk_score", 0.0)
        conf_score = scores.get("evidence_confidence_score", 0.0)

        badge_color = "#dc2626" if classification in ("MALICIOUS", "CRITICAL") else "#d97706" if classification == "SUSPICIOUS" else "#16a34a"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} - {data.get('report_id')}</title>
  <style>
    :root {{
      --bg: #0b1329;
      --card-bg: #111c38;
      --border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #2563eb;
      --accent-glow: rgba(37, 99, 235, 0.2);
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
    }}
    @media print {{
      body {{ background: #fff !important; color: #111 !important; }}
      .card {{ background: #fff !important; border: 1px solid #ccc !important; box-shadow: none !important; }}
      .no-print {{ display: none !important; }}
      a {{ color: #111 !important; text-decoration: underline; }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 16px;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}
    .header-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .logo-badge {{
      background: var(--accent);
      color: #fff;
      font-weight: 800;
      font-size: 18px;
      padding: 6px 12px;
      border-radius: 6px;
      letter-spacing: 1px;
    }}
    .brand-title {{
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    .brand-sub {{
      font-size: 13px;
      color: var(--text-muted);
    }}
    .report-meta {{
      text-align: right;
      font-size: 12px;
      color: var(--text-muted);
      font-family: monospace;
    }}
    .verdict-banner {{
      background: linear-gradient(135deg, rgba(17, 28, 56, 0.9), rgba(15, 23, 42, 0.9));
      border: 1px solid var(--border);
      border-left: 6px solid {badge_color};
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .verdict-title {{
      font-size: 20px;
      font-weight: 700;
      color: #fff;
    }}
    .verdict-badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      background: {badge_color};
      color: #fff;
      font-size: 13px;
      font-weight: 700;
      margin-left: 10px;
    }}
    .scores-pill {{
      display: flex;
      gap: 20px;
      text-align: right;
    }}
    .score-item {{
      display: flex;
      flex-direction: column;
    }}
    .score-val {{
      font-size: 24px;
      font-weight: 800;
      color: #fff;
    }}
    .score-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    .card-title {{
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .kv-row {{
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 13px;
    }}
    .kv-key {{
      color: var(--text-muted);
      font-weight: 500;
    }}
    .kv-val {{
      font-family: monospace;
      color: #fff;
      word-break: break-all;
      max-width: 65%;
      text-align: right;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 13px;
    }}
    th, td {{
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: rgba(255, 255, 255, 0.03);
      color: var(--text-muted);
      font-size: 12px;
      text-transform: uppercase;
    }}
    .disclaimer-card {{
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 16px;
      margin-top: 24px;
      font-size: 12px;
      color: #cbd5e1;
    }}
    .disclaimer-card strong {{
      color: #fca5a5;
    }}
    .btn {{
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
    }}
    .btn:hover {{
      background: #1d4ed8;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-bar">
      <div class="brand">
        <div class="logo-badge">MAILINTEL</div>
        <div>
          <div class="brand-title">Forensic Intelligence Report</div>
          <div class="brand-sub">AI-Powered Email Threat Detection & Forensic Platform</div>
        </div>
      </div>
      <div class="report-meta">
        <div><strong>REPORT ID:</strong> {data.get('report_id')}</div>
        <div><strong>GENERATED:</strong> {data.get('generated_at')}</div>
        <div><strong>CLASSIFICATION:</strong> TLP:AMBER+STRICT</div>
        <div class="no-print" style="margin-top: 8px;">
          <button class="btn" onclick="window.print()">Print / Export PDF</button>
        </div>
      </div>
    </div>

    <div class="verdict-banner">
      <div>
        <div class="verdict-title">
          Threat Classification: <span class="verdict-badge">{classification}</span>
        </div>
        <div style="font-size: 13px; color: var(--text-muted); margin-top: 6px;">
          {scores.get('summary', 'No automated summary')}
        </div>
      </div>
      <div class="scores-pill">
        <div class="score-item">
          <div class="score-val" style="color: {badge_color};">{risk_score:.1f}</div>
          <div class="score-label">Threat Risk (0-100)</div>
        </div>
        <div class="score-item">
          <div class="score-val" style="color: var(--accent);">{conf_score:.1f}%</div>
          <div class="score-label">Confidence</div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Evidence & Custody -->
      <div class="card">
        <div class="card-title">1. Digital Evidence & Custody</div>
        <div class="kv-row"><span class="kv-key">Email ID</span><span class="kv-val">{data.get('email_id')}</span></div>
        <div class="kv-row"><span class="kv-key">Subject</span><span class="kv-val">{meta.get('subject')}</span></div>
        <div class="kv-row"><span class="kv-key">Sender (From)</span><span class="kv-val">{meta.get('from_address')}</span></div>
        <div class="kv-row"><span class="kv-key">Recipient (To)</span><span class="kv-val">{', '.join(meta.get('to_addresses', []))}</span></div>
        <div class="kv-row"><span class="kv-key">Date Header</span><span class="kv-val">{meta.get('date_header')}</span></div>
        <div class="kv-row"><span class="kv-key">SHA-256 Digest</span><span class="kv-val">{meta.get('sha256_hash')}</span></div>
        <div class="kv-row"><span class="kv-key">File Size</span><span class="kv-val">{meta.get('file_size_bytes', 0):,} bytes</span></div>
        <div class="kv-row"><span class="kv-key">MinIO Archive</span><span class="kv-val">{integ.get('bucket')} (Immutable: {integ.get('immutable')})</span></div>
      </div>

      <!-- Authentication & Headers -->
      <div class="card">
        <div class="card-title">2. Cryptographic Authentication & Origin</div>
        <div class="kv-row"><span class="kv-key">SPF Authentication</span><span class="kv-val">{auth.get('spf_result', 'NONE')}</span></div>
        <div class="kv-row"><span class="kv-key">DKIM Signature</span><span class="kv-val">{auth.get('dkim_result', 'NONE')}</span></div>
        <div class="kv-row"><span class="kv-key">DMARC Policy</span><span class="kv-val">{auth.get('dmarc_result', 'NONE')}</span></div>
        <div class="kv-row"><span class="kv-key">Domain Alignment</span><span class="kv-val">{auth.get('from_domain_alignment', 'NONE')}</span></div>
        <div class="kv-row"><span class="kv-key">Return-Path</span><span class="kv-val">{meta.get('return_path') or 'N/A'}</span></div>
        <div class="kv-row"><span class="kv-key">Reply-To</span><span class="kv-val">{meta.get('reply_to') or 'N/A'}</span></div>
        <div class="kv-row"><span class="kv-key">Message-ID</span><span class="kv-val">{meta.get('message_id') or 'N/A'}</span></div>
      </div>
    </div>

    <!-- Explainable Findings -->
    <div class="card">
      <div class="card-title">3. Explainable Forensic Findings ({len(scores.get('findings', []))})</div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Title</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {"".join([f"<tr><td><strong>{f.get('severity')}</strong></td><td><code>{f.get('finding_type')}</code></td><td>{f.get('title')}</td><td>{f.get('description')}</td></tr>" for f in scores.get('findings', [])]) or "<tr><td colspan='4'>No granular findings recorded.</td></tr>"}
        </tbody>
      </table>
    </div>

    <!-- Email DNA & Indicators -->
    <div class="grid-2">
      <div class="card">
        <div class="card-title">4. Email DNA Structural Fingerprint</div>
        <div class="kv-row"><span class="kv-key">Overall DNA Hash</span><span class="kv-val">{dna.get('overall_dna_hash') or 'N/A'}</span></div>
        <div class="kv-row"><span class="kv-key">Header Order Hash</span><span class="kv-val">{dna.get('technical_fingerprint', {}).get('header_order_hash', 'N/A')}</span></div>
        <div class="kv-row"><span class="kv-key">Originating IP</span><span class="kv-val">{dna.get('infrastructure_fingerprint', {}).get('originating_ip', 'N/A')}</span></div>
        <div class="kv-row"><span class="kv-key">ASN Chain</span><span class="kv-val">{dna.get('infrastructure_fingerprint', {}).get('asn_sequence', 'N/A')}</span></div>
      </div>

      <div class="card">
        <div class="card-title">5. Threat Indicators & URLs</div>
        <div style="font-size: 13px; max-height: 180px; overflow-y: auto;">
          {"".join([f"<div class='kv-row'><span class='kv-key'>{ind.get('source')}</span><span class='kv-val'>{ind.get('verdict')} ({ind.get('value')})</span></div>" for ind in intel.get('threat_indicators', [])]) or "<div style='color:var(--text-muted); padding:10px 0;'>No external threat indicators flagged.</div>"}
        </div>
      </div>
    </div>

    <!-- Infrastructure Geolocation -->
    <div class="card">
      <div class="card-title">6. Infrastructure Geolocation & Routing Nodes</div>
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Role</th>
            <th>Country</th>
            <th>City / Region</th>
            <th>ASN / ISP</th>
          </tr>
        </thead>
        <tbody>
          {"".join([f"<tr><td><code>{l.get('ip_address')}</code></td><td>{l.get('role')}</td><td>{l.get('country')} ({l.get('country_code')})</td><td>{l.get('city') or 'N/A'}, {l.get('region') or 'N/A'}</td><td>{l.get('asn') or 'N/A'} {l.get('isp') or ''}</td></tr>" for l in geo.get('locations', [])]) or "<tr><td colspan='5'>No public infrastructure geolocations mapped.</td></tr>"}
        </tbody>
      </table>
    </div>

    <!-- Attribution Disclaimer -->
    <div class="disclaimer-card">
      <strong>MANDATORY FORENSIC ATTRIBUTION DISCLAIMER & LIMITATIONS:</strong><br>
      {limitations.get('disclaimer')}<br><br>
      <ul>
        {"".join([f"<li>{note}</li>" for note in limitations.get('uncertainty_notes', [])])}
      </ul>
    </div>
  </div>
</body>
</html>
"""
        return html

    @staticmethod
    def render_json_report(data: Dict[str, Any]) -> str:
        """Renders canonical indented JSON report."""
        return json.dumps(data, indent=2, sort_keys=False, default=str)

    @classmethod
    async def generate_and_save_email_report(
        cls,
        email_id: uuid.UUID,
        format_type: str = "html",
        db: AsyncSession = None,
    ) -> Tuple[Report, str, Dict[str, Any]]:
        """
        Builds report, renders to requested format, calculates SHA-256 hash,
        saves artifact to MinIO 'mailintel-reports' bucket, persists Report & EvidenceObject in DB.
        """
        report_data = await cls.build_email_report_data(email_id=email_id, db=db)
        format_type_normalized = format_type.strip().lower()

        if format_type_normalized == "markdown" or format_type_normalized == "md":
            rendered_content = cls.render_markdown_report(report_data)
            content_type = "text/markdown"
            ext = "md"
        elif format_type_normalized == "json":
            rendered_content = cls.render_json_report(report_data)
            content_type = "application/json"
            ext = "json"
        else:
            rendered_content = cls.render_html_report(report_data)
            content_type = "text/html"
            ext = "html"

        content_bytes = rendered_content.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        report_id = uuid.uuid4()
        now_utc = datetime.now(timezone.utc)
        object_key = f"reports/{now_utc.year}/{now_utc.month:02d}/{email_id}_{report_id}.{ext}"

        # Upload to MinIO
        try:
            if storage.client is not None:
                storage.upload_evidence_object(
                    bucket_name=settings.MINIO_REPORTS_BUCKET,
                    object_key=object_key,
                    data=content_bytes,
                    content_type=content_type,
                    metadata={
                        "email_id": str(email_id),
                        "report_id": str(report_id),
                        "sha256": sha256_hash,
                        "format": ext,
                    },
                )
        except Exception as e:
            logger.warning(f"Could not upload report to MinIO: {e}")

        # Create EvidenceObject for report
        evidence_obj = EvidenceObject(
            id=uuid.uuid4(),
            email_id=email_id,
            evidence_type="FORENSIC_REPORT",
            original_filename=f"MailIntel_Forensic_Report_{str(email_id)[:8]}.{ext}",
            content_type=content_type,
            size_bytes=len(content_bytes),
            sha256_hash=sha256_hash,
            bucket_name=settings.MINIO_REPORTS_BUCKET,
            object_key=object_key,
            source_type="GENERATED",
            acquired_at=now_utc,
            stored_at=now_utc,
            immutable=True,
            retention_status="ACTIVE",
            created_at=now_utc,
        )
        db.add(evidence_obj)

        # Create Custody Event
        custody = CustodyEvent(
            evidence_id=evidence_obj.id,
            event_type="REPORTED",
            event_at=now_utc,
            event_metadata={
                "action": "FORENSIC_REPORT_GENERATION",
                "format": ext,
                "sha256": sha256_hash,
                "size_bytes": len(content_bytes),
            },
            created_at=now_utc,
        )
        db.add(custody)

        # Create Report ORM record
        report_model = Report(
            id=report_id,
            report_type="FORENSIC_SUMMARY",
            email_id=email_id,
            evidence_object_id=evidence_obj.id,
            report_version="1.0",
            generated_at=now_utc,
            summary={
                "format": ext,
                "threat_classification": report_data.get("explainable_scores", {}).get("threat_classification"),
                "threat_risk_score": report_data.get("explainable_scores", {}).get("threat_risk_score"),
                "evidence_confidence_score": report_data.get("explainable_scores", {}).get("evidence_confidence_score"),
                "sha256": sha256_hash,
                "object_key": object_key,
            },
        )
        db.add(report_model)
        await db.commit()
        await db.refresh(report_model)

        logger.info(f"Generated and persisted forensic report {report_id} for email {email_id} (format={ext}, sha256={sha256_hash[:12]}...)")
        return report_model, rendered_content, report_data

    @classmethod
    async def generate_and_save_campaign_report(
        cls,
        campaign_id: uuid.UUID,
        format_type: str = "html",
        db: AsyncSession = None,
    ) -> Tuple[Report, str, Dict[str, Any]]:
        """Builds, renders, and saves campaign dossier."""
        report_data = await cls.build_campaign_report_data(campaign_id=campaign_id, db=db)
        format_type_normalized = format_type.strip().lower()

        if format_type_normalized == "markdown" or format_type_normalized == "md":
            rendered_content = cls.render_markdown_report(report_data)
            content_type = "text/markdown"
            ext = "md"
        elif format_type_normalized == "json":
            rendered_content = cls.render_json_report(report_data)
            content_type = "application/json"
            ext = "json"
        else:
            rendered_content = cls.render_html_report(report_data)
            content_type = "text/html"
            ext = "html"

        content_bytes = rendered_content.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        report_id = uuid.uuid4()
        now_utc = datetime.now(timezone.utc)
        object_key = f"reports/campaigns/{campaign_id}_{report_id}.{ext}"

        # Upload to MinIO
        try:
            if storage.client is not None:
                storage.upload_evidence_object(
                    bucket_name=settings.MINIO_REPORTS_BUCKET,
                    object_key=object_key,
                    data=content_bytes,
                    content_type=content_type,
                    metadata={
                        "campaign_id": str(campaign_id),
                        "report_id": str(report_id),
                        "sha256": sha256_hash,
                        "format": ext,
                    },
                )
        except Exception as e:
            logger.warning(f"Could not upload campaign report to MinIO: {e}")

        # Create Report ORM record
        report_model = Report(
            id=report_id,
            report_type="CAMPAIGN_DOSSIER",
            campaign_id=campaign_id,
            report_version="1.0",
            generated_at=now_utc,
            summary={
                "format": ext,
                "campaign_name": report_data.get("campaign_metadata", {}).get("name"),
                "member_count": report_data.get("campaign_metadata", {}).get("member_count"),
                "sha256": sha256_hash,
                "object_key": object_key,
            },
        )
        db.add(report_model)
        await db.commit()
        await db.refresh(report_model)

        logger.info(f"Generated and persisted campaign dossier {report_id} for campaign {campaign_id}")
        return report_model, rendered_content, report_data
