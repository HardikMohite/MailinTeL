import math
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import uuid


@dataclass
class CorrelationSignal:
    signal_type: str  # SHARED_URL, SHARED_DOMAIN, SHARED_IP, SHARED_INFRASTRUCTURE, SHARED_ATTACHMENT_HASH, EMAIL_DNA_SIMILARITY, SEMANTIC_SIMILARITY, TEMPORAL_PATTERN, HEADER_PATTERN
    confidence: float  # 0.00 to 100.00
    weight: float      # relative signal weight
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationResult:
    source_email_id: uuid.UUID
    target_email_id: uuid.UUID
    composite_correlation_score: float  # 0.00 to 100.00
    signals: List[CorrelationSignal] = field(default_factory=list)
    primary_link_reason: str = ""
    evidence_count: int = 0
    is_actionable_correlation: bool = False


class CorrelationEngine:
    """
    Forensic correlation engine detecting multi-vector threat relationships across:
    - Shared URLs
    - Shared domains
    - Shared IPs & Infrastructure (ASN, ISP, TOR/VPN flags)
    - Shared attachment cryptographic hashes
    - Email DNA fingerprint matches
    - Semantic & lexical similarity
    - Temporal dispatch clustering
    """

    SIGNAL_WEIGHTS = {
        "SHARED_ATTACHMENT_HASH": 3.0,  # Cryptographic exact match of malware payload
        "SHARED_URL": 2.5,              # Exact phishing link reuse
        "SHARED_DOMAIN": 1.8,           # Domain reuse
        "SHARED_IP": 2.0,               # Originating / relay server reuse
        "SHARED_INFRASTRUCTURE": 1.5,   # Shared ASN / Tor exit / VPS provider
        "EMAIL_DNA_SIMILARITY": 1.8,    # Header ordering, DKIM selector, DOM tree match
        "SEMANTIC_SIMILARITY": 1.2,     # Content & subject semantic vector similarity
        "TEMPORAL_PATTERN": 1.0,        # Synchronized attack window (< 4 hours)
        "HEADER_PATTERN": 1.2,          # Matching X-Mailer, User-Agent, custom headers
    }

    def correlate_email_pair(
        self,
        source_data: Dict[str, Any],
        target_data: Dict[str, Any],
    ) -> CorrelationResult:
        """
        Computes all pairwise correlation signals between source and target email data packages.
        """
        src_id = source_data.get("email_id")
        tgt_id = target_data.get("email_id")
        signals: List[CorrelationSignal] = []

        # 1. Shared Attachment Hashes (SHA-256 / MD5)
        src_hashes = {a.get("sha256_hash") for a in source_data.get("attachments", []) if a.get("sha256_hash")}
        tgt_hashes = {a.get("sha256_hash") for a in target_data.get("attachments", []) if a.get("sha256_hash")}
        common_hashes = src_hashes.intersection(tgt_hashes)
        if common_hashes:
            signals.append(
                CorrelationSignal(
                    signal_type="SHARED_ATTACHMENT_HASH",
                    confidence=95.0,
                    weight=self.SIGNAL_WEIGHTS["SHARED_ATTACHMENT_HASH"],
                    description=f"Identical SHA-256 payload hash discovered in attachments: {', '.join(list(common_hashes)[:2])}",
                    evidence={"shared_sha256_hashes": list(common_hashes)},
                )
            )

        # 2. Shared URLs
        src_urls = {u.get("url_hash"): u.get("normalized_url") for u in source_data.get("urls", []) if u.get("url_hash")}
        tgt_urls = {u.get("url_hash"): u.get("normalized_url") for u in target_data.get("urls", []) if u.get("url_hash")}
        common_url_hashes = set(src_urls.keys()).intersection(set(tgt_urls.keys()))
        if common_url_hashes:
            matched_urls = [src_urls[h] for h in common_url_hashes if src_urls[h]]
            signals.append(
                CorrelationSignal(
                    signal_type="SHARED_URL",
                    confidence=90.0,
                    weight=self.SIGNAL_WEIGHTS["SHARED_URL"],
                    description=f"Shared normalized URL detected across emails ({len(matched_urls)} matched URLs)",
                    evidence={"matched_urls": matched_urls[:5], "total_shared": len(matched_urls)},
                )
            )

        # 3. Shared Domains (Root Domains)
        src_domains = {d.get("root_domain") for d in source_data.get("domains", []) if d.get("root_domain")}
        tgt_domains = {d.get("root_domain") for d in target_data.get("domains", []) if d.get("root_domain")}
        # Exclude ubiquitous benign public domains from direct campaign correlation
        benign_tlds = {"google.com", "microsoft.com", "apple.com", "github.com", "yahoo.com", "outlook.com"}
        candidate_domains = (src_domains.intersection(tgt_domains)) - benign_tlds
        if candidate_domains:
            signals.append(
                CorrelationSignal(
                    signal_type="SHARED_DOMAIN",
                    confidence=75.0,
                    weight=self.SIGNAL_WEIGHTS["SHARED_DOMAIN"],
                    description=f"Shared root domain(s) identified: {', '.join(list(candidate_domains)[:3])}",
                    evidence={"shared_root_domains": list(candidate_domains)},
                )
            )

        # 4. Shared Originating / Relay IPs
        src_ips = {ip.get("ip_address") for ip in source_data.get("ips", []) if ip.get("ip_address") and not ip.get("is_private")}
        tgt_ips = {ip.get("ip_address") for ip in target_data.get("ips", []) if ip.get("ip_address") and not ip.get("is_private")}
        common_ips = src_ips.intersection(tgt_ips)
        if common_ips:
            signals.append(
                CorrelationSignal(
                    signal_type="SHARED_IP",
                    confidence=85.0,
                    weight=self.SIGNAL_WEIGHTS["SHARED_IP"],
                    description=f"Shared public IP address observed in email relay path: {', '.join(list(common_ips)[:2])}",
                    evidence={"shared_ips": list(common_ips)},
                )
            )

        # 5. Shared Infrastructure (ASN & Tor/VPN classifications)
        src_asns = {ip.get("asn") for ip in source_data.get("ips", []) if ip.get("asn")}
        tgt_asns = {ip.get("asn") for ip in target_data.get("ips", []) if ip.get("asn")}
        common_asns = src_asns.intersection(tgt_asns) - {"AS15169", "AS8075"}  # exclude pure Google/Microsoft cloud ASNs if sole match
        
        src_tor = any(ip.get("is_tor") for ip in source_data.get("ips", []))
        tgt_tor = any(ip.get("is_tor") for ip in target_data.get("ips", []))
        if common_asns or (src_tor and tgt_tor):
            evidence_data: Dict[str, Any] = {}
            desc_parts = []
            if common_asns:
                desc_parts.append(f"Matching Autonomous System Number(s) ({', '.join(list(common_asns)[:2])})")
                evidence_data["shared_asns"] = list(common_asns)
            if src_tor and tgt_tor:
                desc_parts.append("Both routed through Tor exit relay infrastructure")
                evidence_data["both_use_tor"] = True

            signals.append(
                CorrelationSignal(
                    signal_type="SHARED_INFRASTRUCTURE",
                    confidence=70.0,
                    weight=self.SIGNAL_WEIGHTS["SHARED_INFRASTRUCTURE"],
                    description="; ".join(desc_parts),
                    evidence=evidence_data,
                )
            )

        # 6. Email DNA Similarity
        src_dna = source_data.get("dna_profile") or {}
        tgt_dna = target_data.get("dna_profile") or {}
        if src_dna and tgt_dna:
            src_tech = src_dna.get("technical_fingerprint") or {}
            tgt_tech = tgt_dna.get("technical_fingerprint") or {}

            # Exact header order hash match
            hdr_match = (
                src_tech.get("header_ordering_hash")
                and src_tech.get("header_ordering_hash") == tgt_tech.get("header_ordering_hash")
            )
            # DKIM selector + domain match
            dkim_match = (
                src_tech.get("dkim_selector")
                and src_tech.get("dkim_selector") == tgt_tech.get("dkim_selector")
                and src_tech.get("dkim_domain") == tgt_tech.get("dkim_domain")
            )

            if hdr_match or dkim_match:
                conf = 80.0 if (hdr_match and dkim_match) else 65.0
                signals.append(
                    CorrelationSignal(
                        signal_type="EMAIL_DNA_SIMILARITY",
                        confidence=conf,
                        weight=self.SIGNAL_WEIGHTS["EMAIL_DNA_SIMILARITY"],
                        description="Matching technical email fingerprint (header ordering and/or DKIM selector)",
                        evidence={
                            "header_ordering_hash_match": bool(hdr_match),
                            "dkim_selector_match": bool(dkim_match),
                        },
                    )
                )

        # 7. Semantic / Content Vector Similarity
        sim_score = source_data.get("semantic_similarity_to_target")
        if sim_score is not None and sim_score >= 0.70:
            signals.append(
                CorrelationSignal(
                    signal_type="SEMANTIC_SIMILARITY",
                    confidence=round(sim_score * 100.0, 1),
                    weight=self.SIGNAL_WEIGHTS["SEMANTIC_SIMILARITY"],
                    description=f"High semantic and lexical text similarity ({round(sim_score * 100.0, 1)}%)",
                    evidence={"cosine_similarity": round(sim_score, 4)},
                )
            )

        # 8. Temporal Dispatch Pattern (Clustering within attack burst window)
        src_sent = source_data.get("sent_at")
        tgt_sent = target_data.get("sent_at")
        if src_sent and tgt_sent:
            try:
                dt_src = datetime.fromisoformat(str(src_sent).replace("Z", "+00:00")) if isinstance(src_sent, str) else src_sent
                dt_tgt = datetime.fromisoformat(str(tgt_sent).replace("Z", "+00:00")) if isinstance(tgt_sent, str) else tgt_sent
                diff_sec = abs((dt_src - dt_tgt).total_seconds())
                diff_hours = diff_sec / 3600.0

                if diff_hours <= 4.0:
                    signals.append(
                        CorrelationSignal(
                            signal_type="TEMPORAL_PATTERN",
                            confidence=85.0 if diff_hours <= 1.0 else 65.0,
                            weight=self.SIGNAL_WEIGHTS["TEMPORAL_PATTERN"],
                            description=f"Synchronized dispatch within attack burst window ({round(diff_hours, 1)} hours apart)",
                            evidence={"delta_hours": round(diff_hours, 2), "delta_seconds": int(diff_sec)},
                        )
                    )
            except Exception:
                pass

        # Calculate composite correlation score
        if not signals:
            return CorrelationResult(
                source_email_id=src_id,
                target_email_id=tgt_id,
                composite_correlation_score=0.0,
                signals=[],
                primary_link_reason="No correlation signals detected",
                evidence_count=0,
                is_actionable_correlation=False,
            )

        total_weight = sum(s.weight for s in signals)
        weighted_confidence = sum(s.confidence * s.weight for s in signals)
        raw_score = (weighted_confidence / total_weight) if total_weight > 0 else 0.0

        # Multi-signal synergy bonus (corroborating independent evidence boosts confidence)
        signal_count = len(signals)
        synergy_multiplier = 1.0 + min(0.30, (signal_count - 1) * 0.08)
        composite_score = min(100.0, round(raw_score * synergy_multiplier, 2))

        # Select primary link reason based on strongest weighted signal
        strongest_signal = max(signals, key=lambda s: s.confidence * s.weight)

        return CorrelationResult(
            source_email_id=src_id,
            target_email_id=tgt_id,
            composite_correlation_score=composite_score,
            signals=signals,
            primary_link_reason=strongest_signal.description,
            evidence_count=len(signals),
            is_actionable_correlation=(composite_score >= 50.0 and len(signals) >= 1),
        )


default_correlation_engine = CorrelationEngine()
