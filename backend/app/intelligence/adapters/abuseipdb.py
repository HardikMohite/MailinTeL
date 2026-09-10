import logging
import httpx
from typing import Optional, Dict, Any

from app.core.config import settings
from app.intelligence.adapters.base import BaseThreatIntelAdapter, ThreatIntelReport

logger = logging.getLogger(__name__)

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 5.0


class AbuseIPDBAdapter(BaseThreatIntelAdapter):
    """
    Adapter for AbuseIPDB v2 API.
    Specializes in IP reputation, malicious report confidence scores, and abuse categories.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "ABUSEIPDB"

    @property
    def is_enabled(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    async def query_ip(self, ip_str: str) -> Optional[ThreatIntelReport]:
        if not self.is_enabled:
            return None

        clean_ip = ip_str.strip()
        headers = {
            "Key": self.api_key.strip() if self.api_key else "",
            "Accept": "application/json",
        }
        params = {
            "ipAddress": clean_ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(ABUSEIPDB_API_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0))
                    total_reports = int(data.get("totalReports", 0))
                    is_whitelisted = bool(data.get("isWhitelisted", False))

                    tags = []
                    if is_whitelisted:
                        verdict = "BENIGN"
                        confidence = 0.90
                    elif score >= 50 or total_reports >= 25:
                        verdict = "MALICIOUS"
                        confidence = min(0.95, 0.70 + (score / 300.0))
                        tags.append("HIGH_ABUSE_REPORTS")
                    elif score >= 25 or total_reports >= 8:
                        verdict = "SUSPICIOUS"
                        confidence = 0.65
                        tags.append("SUSPICIOUS_ABUSE_REPORTS")
                    else:
                        verdict = "BENIGN" if total_reports <= 3 else "UNKNOWN"
                        confidence = 0.80 if total_reports == 0 else 0.50

                    return ThreatIntelReport(
                        indicator_type="IP",
                        indicator_value=clean_ip,
                        provider=self.name,
                        verdict=verdict,
                        threat_score=score,
                        confidence=confidence,
                        tags=tags,
                        malicious_votes=total_reports if verdict == "MALICIOUS" else 0,
                        suspicious_votes=total_reports if verdict == "SUSPICIOUS" else 0,
                        harmless_votes=1 if is_whitelisted or total_reports == 0 else 0,
                        total_votes=total_reports + 1,
                        raw_data=data,
                        details=f"AbuseIPDB Confidence Score: {score}%, Total Reports: {total_reports}",
                    )
                logger.debug(f"AbuseIPDB query for {clean_ip} returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed for {clean_ip}: {e}")

        return None
