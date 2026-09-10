import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field

from app.intelligence.adapters.base import BaseThreatIntelAdapter, ThreatIntelReport
from app.intelligence.adapters.virustotal import VirusTotalAdapter
from app.intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.intelligence.adapters.urlhaus import URLHausAdapter
from app.intelligence.adapters.internal_reputation import InternalReputationAdapter

logger = logging.getLogger(__name__)


@dataclass
class AggregatedThreatIntel:
    """
    Consolidated threat intelligence report synthesizing findings across multiple providers.
    Maintains clear attribution, timestamps, and confidence boundaries.
    """
    indicator_type: str  # IP, DOMAIN, URL, FILE_HASH, SENDER_EMAIL
    indicator_value: str
    consensus_verdict: str  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    consensus_threat_score: float  # 0.0 to 100.0
    consensus_confidence: float  # 0.0 to 1.0
    aggregated_tags: List[str] = field(default_factory=list)
    provider_reports: List[ThreatIntelReport] = field(default_factory=list)
    provider_count: int = 0
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "consensus_verdict": self.consensus_verdict,
            "consensus_threat_score": round(self.consensus_threat_score, 2),
            "consensus_confidence": round(self.consensus_confidence, 2),
            "aggregated_tags": self.aggregated_tags,
            "provider_reports": [r.to_dict() for r in self.provider_reports],
            "provider_count": self.provider_count,
            "queried_at": self.queried_at.isoformat(),
        }


class ThreatIntelEngine:
    """
    Orchestrates modular threat intelligence queries across all active adapters.
    Synthesizes provider results into explainable threat verdicts.
    """

    def __init__(self, adapters: Optional[List[BaseThreatIntelAdapter]] = None):
        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = [
                VirusTotalAdapter(),
                AbuseIPDBAdapter(),
                URLHausAdapter(),
                InternalReputationAdapter(),
            ]

    async def query_indicator(self, indicator_type: str, indicator_value: str) -> AggregatedThreatIntel:
        """
        Queries all applicable adapters concurrently for an indicator and computes consensus.
        """
        clean_type = indicator_type.strip().upper()
        clean_val = indicator_value.strip()

        tasks = []
        for adapter in self.adapters:
            if not adapter.is_enabled:
                continue

            if clean_type == "IP":
                tasks.append(adapter.query_ip(clean_val))
            elif clean_type == "DOMAIN":
                tasks.append(adapter.query_domain(clean_val))
            elif clean_type == "URL":
                tasks.append(adapter.query_url(clean_val))
            elif clean_type in ("FILE_HASH", "SHA256", "MD5"):
                tasks.append(adapter.query_hash(clean_val))

        if not tasks:
            # Fallback to internal reputation adapter if no tasks created
            internal_adapter = InternalReputationAdapter()
            if clean_type == "DOMAIN":
                rep = await internal_adapter.query_domain(clean_val)
                reports = [rep] if rep else []
            elif clean_type == "URL":
                rep = await internal_adapter.query_url(clean_val)
                reports = [rep] if rep else []
            else:
                reports = []
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            reports = [r for r in results if isinstance(r, ThreatIntelReport)]

        return self._synthesize_consensus(clean_type, clean_val, reports)

    def _synthesize_consensus(
        self,
        indicator_type: str,
        indicator_value: str,
        reports: List[ThreatIntelReport],
    ) -> AggregatedThreatIntel:
        """Synthesizes multiple threat reports into a single explainable verdict."""
        if not reports:
            return AggregatedThreatIntel(
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                consensus_verdict="UNKNOWN",
                consensus_threat_score=0.0,
                consensus_confidence=0.10,
                aggregated_tags=[],
                provider_reports=[],
                provider_count=0,
            )

        malicious_reports = [r for r in reports if r.verdict == "MALICIOUS"]
        suspicious_reports = [r for r in reports if r.verdict == "SUSPICIOUS"]
        benign_reports = [r for r in reports if r.verdict == "BENIGN"]

        # Collect deduplicated tags
        all_tags: Set[str] = set()
        for r in reports:
            all_tags.update(r.tags)

        # Weighted calculation
        if malicious_reports:
            consensus_verdict = "MALICIOUS"
            max_score = max(r.threat_score for r in malicious_reports)
            avg_score = sum(r.threat_score for r in malicious_reports) / len(malicious_reports)
            consensus_threat_score = max(max_score, (max_score * 0.7) + (avg_score * 0.3))
            base_conf = max(r.confidence for r in malicious_reports)
            # Boost confidence if multiple independent providers agree
            consensus_confidence = min(0.99, base_conf + (0.05 * (len(malicious_reports) - 1)))
        elif suspicious_reports:
            consensus_verdict = "SUSPICIOUS"
            max_score = max(r.threat_score for r in suspicious_reports)
            consensus_threat_score = max_score
            base_conf = max(r.confidence for r in suspicious_reports)
            consensus_confidence = min(0.85, base_conf + (0.05 * (len(suspicious_reports) - 1)))
        elif benign_reports:
            consensus_verdict = "BENIGN"
            consensus_threat_score = 0.0
            consensus_confidence = sum(r.confidence for r in benign_reports) / len(benign_reports)
        else:
            consensus_verdict = "UNKNOWN"
            consensus_threat_score = 0.0
            consensus_confidence = 0.30

        return AggregatedThreatIntel(
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            consensus_verdict=consensus_verdict,
            consensus_threat_score=consensus_threat_score,
            consensus_confidence=consensus_confidence,
            aggregated_tags=sorted(list(all_tags)),
            provider_reports=reports,
            provider_count=len(reports),
        )
