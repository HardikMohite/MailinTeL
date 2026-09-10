import base64
import logging
import httpx
from typing import Optional, Dict, Any

from app.core.config import settings
from app.intelligence.adapters.base import BaseThreatIntelAdapter, ThreatIntelReport

logger = logging.getLogger(__name__)

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 5.0


class VirusTotalAdapter(BaseThreatIntelAdapter):
    """
    Adapter for VirusTotal v3 API.
    Supports querying IP addresses, domains, URLs, and file hashes.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT):
        self.api_key = settings.VIRUSTOTAL_API_KEY if api_key is None else api_key
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "VIRUSTOTAL"

    @property
    def is_enabled(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _get_headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key.strip() if self.api_key else "",
            "Accept": "application/json",
        }

    def _parse_vt_stats(
        self,
        indicator_type: str,
        indicator_value: str,
        stats: Dict[str, int],
        raw_data: Dict[str, Any],
    ) -> ThreatIntelReport:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        tags = []
        if malicious >= 3:
            verdict = "MALICIOUS"
            threat_score = min(100.0, 50.0 + (malicious * 5.0))
            confidence = min(0.98, 0.70 + (malicious * 0.03))
            tags.append("MULTIPLE_ENGINE_DETECTIONS")
        elif malicious >= 1 or suspicious >= 2:
            verdict = "SUSPICIOUS"
            threat_score = min(60.0, 30.0 + ((malicious + suspicious) * 10.0))
            confidence = 0.65
            tags.append("SUSPICIOUS_DETECTION")
        elif harmless >= 5:
            verdict = "BENIGN"
            threat_score = 0.0
            confidence = 0.85
        else:
            verdict = "UNKNOWN"
            threat_score = 0.0
            confidence = 0.30

        return ThreatIntelReport(
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            provider=self.name,
            verdict=verdict,
            threat_score=threat_score,
            confidence=confidence,
            tags=tags,
            malicious_votes=malicious,
            suspicious_votes=suspicious,
            harmless_votes=harmless,
            total_votes=total,
            raw_data=raw_data,
            is_fallback=False,
            details=f"VirusTotal detected {malicious} malicious engines out of {total}",
        )

    async def query_ip(self, ip_str: str) -> Optional[ThreatIntelReport]:
        if not self.is_enabled:
            return None
        url = f"{VT_API_BASE_URL}/ip_addresses/{ip_str.strip()}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    return self._parse_vt_stats("IP", ip_str, stats, data)
                logger.debug(f"VirusTotal IP query for {ip_str} returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"VirusTotal query failed for IP {ip_str}: {e}")
        return None

    async def query_domain(self, domain_str: str) -> Optional[ThreatIntelReport]:
        if not self.is_enabled:
            return None
        url = f"{VT_API_BASE_URL}/domains/{domain_str.strip().lower()}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    return self._parse_vt_stats("DOMAIN", domain_str, stats, data)
                logger.debug(f"VirusTotal domain query for {domain_str} returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"VirusTotal query failed for domain {domain_str}: {e}")
        return None

    async def query_url(self, url_str: str) -> Optional[ThreatIntelReport]:
        if not self.is_enabled:
            return None
        # VirusTotal v3 URL identifier is url-safe base64 of URL without padding
        url_id = base64.urlsafe_b64encode(url_str.strip().encode()).decode().rstrip("=")
        endpoint = f"{VT_API_BASE_URL}/urls/{url_id}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    return self._parse_vt_stats("URL", url_str, stats, data)
                logger.debug(f"VirusTotal URL query returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"VirusTotal query failed for URL {url_str}: {e}")
        return None

    async def query_hash(self, file_hash: str) -> Optional[ThreatIntelReport]:
        if not self.is_enabled:
            return None
        url = f"{VT_API_BASE_URL}/files/{file_hash.strip().lower()}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    stats = data.get("attributes", {}).get("last_analysis_stats", {})
                    return self._parse_vt_stats("FILE_HASH", file_hash, stats, data)
                logger.debug(f"VirusTotal file query returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"VirusTotal query failed for hash {file_hash}: {e}")
        return None
