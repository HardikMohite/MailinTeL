import abc
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class ThreatIntelReport:
    """
    Standardized result from an external or internal threat intelligence provider.
    """
    indicator_type: str  # IP, DOMAIN, URL, FILE_HASH, SENDER_EMAIL
    indicator_value: str
    provider: str  # VIRUSTOTAL, ABUSEIPDB, URLHAUS, INTERNAL_REPUTATION, etc.
    verdict: str  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    threat_score: float  # 0.0 to 100.0
    confidence: float  # 0.0 to 1.0
    tags: List[str] = field(default_factory=list)
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    total_votes: int = 0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_fallback: bool = False
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "provider": self.provider,
            "verdict": self.verdict,
            "threat_score": round(self.threat_score, 2),
            "confidence": round(self.confidence, 2),
            "tags": self.tags,
            "malicious_votes": self.malicious_votes,
            "suspicious_votes": self.suspicious_votes,
            "harmless_votes": self.harmless_votes,
            "total_votes": self.total_votes,
            "raw_data": self.raw_data,
            "queried_at": self.queried_at.isoformat(),
            "is_fallback": self.is_fallback,
            "details": self.details,
        }


class BaseThreatIntelAdapter(abc.ABC):
    """
    Abstract base adapter for all threat intelligence providers.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider name identifier."""
        pass

    @property
    def is_enabled(self) -> bool:
        """Returns whether this adapter is configured and active."""
        return True

    async def query_ip(self, ip_str: str) -> Optional[ThreatIntelReport]:
        """Query threat intelligence for an IP address."""
        return None

    async def query_domain(self, domain_str: str) -> Optional[ThreatIntelReport]:
        """Query threat intelligence for a domain."""
        return None

    async def query_url(self, url_str: str) -> Optional[ThreatIntelReport]:
        """Query threat intelligence for a URL."""
        return None

    async def query_hash(self, file_hash: str) -> Optional[ThreatIntelReport]:
        """Query threat intelligence for a file hash (SHA-256 or MD5)."""
        return None
