import logging
import httpx
from typing import Optional, Dict, Any

from app.intelligence.adapters.base import BaseThreatIntelAdapter, ThreatIntelReport

logger = logging.getLogger(__name__)

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"
DEFAULT_TIMEOUT = 1.5


class URLHausAdapter(BaseThreatIntelAdapter):
    """
    Adapter for URLHaus (abuse.ch) public malware URL and payload feed.
    Free, open, community-driven malware distribution intelligence.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "URLHAUS"

    @property
    def is_enabled(self) -> bool:
        return True

    async def query_url(self, url_str: str) -> Optional[ThreatIntelReport]:
        clean_url = url_str.strip()
        endpoint = f"{URLHAUS_API_URL}/url/"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=1.0)) as client:
                resp = await client.post(endpoint, data={"url": clean_url})
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        url_status = data.get("url_status", "online")
                        threat = data.get("threat", "malware_download")
                        tags = data.get("tags") or []
                        tags.append(f"URLHAUS_{threat.upper()}")

                        return ThreatIntelReport(
                            indicator_type="URL",
                            indicator_value=clean_url,
                            provider=self.name,
                            verdict="MALICIOUS",
                            threat_score=95.0,
                            confidence=0.98,
                            tags=tags,
                            malicious_votes=1,
                            total_votes=1,
                            raw_data=data,
                            details=f"URLHaus verified malware URL: {threat} ({url_status})",
                        )
                    elif query_status == "no_results":
                        return ThreatIntelReport(
                            indicator_type="URL",
                            indicator_value=clean_url,
                            provider=self.name,
                            verdict="UNKNOWN",
                            threat_score=0.0,
                            confidence=0.50,
                            tags=[],
                            raw_data=data,
                            details="Not listed in URLHaus malware database",
                        )
        except Exception as e:
            logger.debug(f"URLHaus query failed for {clean_url}: {e}")

        return None

    async def query_hash(self, file_hash: str) -> Optional[ThreatIntelReport]:
        clean_hash = file_hash.strip().lower()
        endpoint = f"{URLHAUS_API_URL}/payload/"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=1.0)) as client:
                resp = await client.post(endpoint, data={"sha256_hash": clean_hash})
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status")
                    if query_status == "ok":
                        file_type = data.get("file_type", "unknown")
                        signature = data.get("signature") or "malware_payload"
                        return ThreatIntelReport(
                            indicator_type="FILE_HASH",
                            indicator_value=clean_hash,
                            provider=self.name,
                            verdict="MALICIOUS",
                            threat_score=98.0,
                            confidence=0.99,
                            tags=["MALWARE_PAYLOAD", f"SIG_{signature.upper()}"],
                            malicious_votes=1,
                            total_votes=1,
                            raw_data=data,
                            details=f"URLHaus identified malware payload: {signature} ({file_type})",
                        )
        except Exception as e:
            logger.debug(f"URLHaus hash query failed for {clean_hash}: {e}")

        return None
