import re
import math
from typing import Optional, List, Dict, Any
from app.intelligence.adapters.base import BaseThreatIntelAdapter, ThreatIntelReport
from app.parser.header_analyzer import extract_domain_from_email_or_host, get_organizational_domain

SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".club", ".work", ".loan", ".click", ".link",
    ".gq", ".cf", ".tk", ".ml", ".ga", ".buzz", ".guru", ".icu",
    ".cam", ".rest", ".sbs", ".country", ".stream", ".download",
}

PHISHING_KEYWORDS = {

    "login", "verify", "account", "update", "banking", "secure",
    "password", "support", "service", "billing", "invoice", "signin",
    "portal", "auth", "confirm", "wallet", "recovery", "validation",
}

DISPOSABLE_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com",
    "throwawaymail.com", "temp-mail.org", "sharklasers.com", "dispostable.com",
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for string randomness (e.g. DGA domains)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


class InternalReputationAdapter(BaseThreatIntelAdapter):
    """
    Built-in local threat intelligence & heuristics engine.
    Ensures baseline threat scoring without requiring third-party API keys.
    """

    @property
    def name(self) -> str:
        return "INTERNAL_REPUTATION"

    @property
    def is_enabled(self) -> bool:
        return True

    async def query_domain(self, domain_str: str) -> Optional[ThreatIntelReport]:
        clean_d = domain_str.strip().lower()
        root_d = get_organizational_domain(clean_d) or clean_d
        entropy = calculate_entropy(clean_d.split(".")[0])

        tags: List[str] = []
        score = 0.0

        # 1. Suspicious TLD
        tld = "." + clean_d.split(".")[-1] if "." in clean_d else ""
        if tld in SUSPICIOUS_TLDS:
            tags.append(f"SUSPICIOUS_TLD_{tld.replace('.', '').upper()}")
            score += 25.0

        # 2. Punycode IDN
        if clean_d.startswith("xn--") or ".xn--" in clean_d:
            tags.append("PUNYCODE_HOMOGLYPH")
            score += 30.0

        # 3. Disposable Domain
        if root_d in DISPOSABLE_DOMAINS:
            tags.append("DISPOSABLE_EMAIL_DOMAIN")
            score += 45.0

        # 4. Phishing keywords in subdomain/name
        found_kw = [kw for kw in PHISHING_KEYWORDS if kw in clean_d]
        if len(found_kw) >= 2:
            tags.append("MULTIPLE_PHISHING_KEYWORDS")
            score += 35.0
        elif len(found_kw) == 1 and score > 0:
            tags.append("PHISHING_KEYWORD_MATCH")
            score += 15.0

        # 5. DGA High Entropy
        if entropy > 3.8 and len(clean_d.split(".")[0]) > 12:
            tags.append("HIGH_ENTROPY_DGA_PATTERN")
            score += 30.0

        score = min(100.0, score)
        if score >= 50.0:
            verdict = "MALICIOUS"
            confidence = 0.85
        elif score >= 20.0:
            verdict = "SUSPICIOUS"
            confidence = 0.70
        else:
            verdict = "BENIGN"
            confidence = 0.60

        return ThreatIntelReport(
            indicator_type="DOMAIN",
            indicator_value=clean_d,
            provider=self.name,
            verdict=verdict,
            threat_score=score,
            confidence=confidence,
            tags=tags,
            raw_data={"entropy": round(entropy, 2), "root_domain": root_d, "tld": tld},
            details=f"Internal heuristics evaluated domain with score {score} (entropy={round(entropy, 2)})",
        )

    async def query_url(self, url_str: str) -> Optional[ThreatIntelReport]:
        clean_url = url_str.strip().lower()
        tags: List[str] = []
        score = 0.0

        # Check for IP address in URL host (e.g. http://192.168.1.1/login)
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", clean_url):
            tags.append("IP_ADDRESS_IN_URL_HOST")
            score += 35.0

        # Check for multiple '@' or credential harvesting path keywords
        if "@" in clean_url.split("://")[-1]:
            tags.append("URL_EMBEDDED_USERINFO_AUTH")
            score += 40.0

        # Check for suspicious file download extensions
        if any(clean_url.endswith(ext) or f"{ext}?" in clean_url for ext in [".exe", ".scr", ".vbs", ".hta", ".iso", ".bat"]):
            tags.append("EXECUTABLE_PAYLOAD_DOWNLOAD")
            score += 50.0

        found_kw = [kw for kw in PHISHING_KEYWORDS if kw in clean_url]
        if len(found_kw) >= 2:
            tags.append("PHISHING_URL_STRUCTURE")
            score += 25.0

        score = min(100.0, score)
        if score >= 50.0:
            verdict = "MALICIOUS"
            confidence = 0.90
        elif score >= 20.0:
            verdict = "SUSPICIOUS"
            confidence = 0.70
        else:
            verdict = "BENIGN"
            confidence = 0.50

        return ThreatIntelReport(
            indicator_type="URL",
            indicator_value=clean_url,
            provider=self.name,
            verdict=verdict,
            threat_score=score,
            confidence=confidence,
            tags=tags,
            raw_data={"matched_keywords": found_kw},
            details=f"Internal URL heuristics score {score}",
        )
