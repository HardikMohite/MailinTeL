import logging
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ForensicFindingData:
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 - 1.0
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class ScoringResult:
    threat_classification: str  # BENIGN, SUSPICIOUS, MALICIOUS, PHISHING, SPOOFING
    threat_risk_score: float  # 0.00 to 100.00
    evidence_confidence_score: float  # 0.00 to 100.00
    summary: str
    compromised_account_likelihood: str  # HIGH, MEDIUM, LOW, UNLIKELY
    spoofed_domain_likelihood: str  # HIGH, MEDIUM, LOW, UNLIKELY
    anonymized_infrastructure_likelihood: str  # HIGH, MEDIUM, LOW, UNLIKELY
    malicious_environment_likelihood: str  # HIGH, MEDIUM, LOW, UNLIKELY
    findings: List[ForensicFindingData] = field(default_factory=list)
    scoring_pillars: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_classification": self.threat_classification,
            "threat_risk_score": round(self.threat_risk_score, 2),
            "evidence_confidence_score": round(self.evidence_confidence_score, 2),
            "summary": self.summary,
            "compromised_account_likelihood": self.compromised_account_likelihood,
            "spoofed_domain_likelihood": self.spoofed_domain_likelihood,
            "anonymized_infrastructure_likelihood": self.anonymized_infrastructure_likelihood,
            "malicious_environment_likelihood": self.malicious_environment_likelihood,
            "findings": [f.to_dict() for f in self.findings],
            "scoring_pillars": self.scoring_pillars,
        }

class ExplainableScoringEngine:
    """
    Forensic scoring engine evaluating multi-dimensional forensic criteria:
    1. Identity & Authentication Integrity (SPF, DKIM, DMARC, Reply-To & Return-Path alignment)
    2. Routing Infrastructure & Relay Telemetry (Malicious MTA IPs, Tor, VPN/Proxy, transit latency)
    3. Domain Intelligence & Age (Newly registered <30d/<90d, punycode/homoglyph, dynamic DNS, suspicious TLDs)
    4. URL & Threat Intelligence Consensus (VirusTotal, ThreatFox, AbuseIPDB, tracking redirectors, URL shorteners)
    5. Payload & Attachment Forensics (Dangerous executables, double extensions, macro payloads, known malware hashes)
    6. Social Engineering & Behavioral (Urgency language, brand impersonation, sender-URL domain mismatch)
    """

    # Suspicious TLDs frequently associated with abusive registration
    _SUSPICIOUS_TLDS = {
        ".top", ".xyz", ".click", ".online", ".site", ".fun", ".buzz", ".work",
        ".rest", ".gq", ".ml", ".cf", ".ga", ".tk", ".icu", ".cam", ".surf",
    }

    # Known URL shortener domains
    _URL_SHORTENERS = {
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
        "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "lnkd.in",
        "soo.gd", "s.id", "clck.ru", "rebrand.ly", "bl.ink",
    }

    @staticmethod
    def _extract_domain(address: Optional[str]) -> str:
        if not address or "@" not in address:
            return ""
        return address.split("@")[-1].strip().lower().rstrip(">")

    def evaluate_email(
        self,
        email_metadata: Dict[str, Any],
        auth_results: Optional[Dict[str, Any]] = None,
        relay_hops: Optional[List[Dict[str, Any]]] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        domain_intel: Optional[List[Dict[str, Any]]] = None,
        infrastructure_intel: Optional[List[Dict[str, Any]]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
    ) -> ScoringResult:
        """
        Evaluates an email across 6 forensic pillars.

        DNA fingerprint data can be injected via ``email_metadata`` using the
        private keys ``_dna_content`` (content fingerprint dict) and
        ``_dna_behavioral`` (behavioral fingerprint dict).  These are optional
        and callers that do not supply them will simply see zero contribution
        from Pillar 6.
        """
        findings: List[ForensicFindingData] = []
        raw_risk_score = 0.0

        auth_results = auth_results or {}
        relay_hops = relay_hops or []
        artifacts = artifacts or {}
        domain_intel = domain_intel or []
        infrastructure_intel = infrastructure_intel or []
        threat_intel = threat_intel or {}

        sender_address = email_metadata.get("sender_address") or ""
        reply_to = email_metadata.get("reply_to") or ""
        return_path = email_metadata.get("return_path") or ""
        sender_domain = self._extract_domain(sender_address)
        reply_domain = self._extract_domain(reply_to)
        return_path_domain = self._extract_domain(return_path)

        # ---------------------------------------------------------
        # PILLAR 1: Identity & Authentication Integrity (Max 35)
        #
        # NOTE: DMARC failure (+35) and SPF FAIL (+25) are mutually
        # exclusive — when DMARC already fires, SPF FAIL is
        # subsumed (DMARC encapsulates SPF alignment).
        # SPF SOFTFAIL (+15) is always independent.
        # ---------------------------------------------------------
        pillar_auth_score = 0.0
        spf_verdict = (auth_results.get("spf_verdict") or "").upper()
        dkim_verdict = (auth_results.get("dkim_verdict") or "").upper()
        dmarc_verdict = (auth_results.get("dmarc_verdict") or "").upper()
        from_align = (auth_results.get("from_domain_aligned") or "NONE").upper()

        spoofed_signals = 0
        dmarc_fired = False

        # DMARC / Alignment
        if dmarc_verdict == "FAIL" or from_align == "FAIL":
            findings.append(
                ForensicFindingData(
                    finding_type="AUTH_DMARC_ALIGNMENT_FAILURE",
                    severity="HIGH",
                    confidence=0.95,
                    title="DMARC Alignment & Domain Spoofing Detected",
                    description="The sender From domain does not align with SPF validation or DKIM signing domain.",
                    evidence={"dmarc": dmarc_verdict, "alignment": from_align, "sender": sender_address},
                )
            )
            pillar_auth_score += 35.0
            spoofed_signals += 2
            dmarc_fired = True

        # SPF — skip SPF FAIL penalty when DMARC already fired (prevents double-counting)
        if spf_verdict in ("FAIL", "SOFTFAIL"):
            sev = "HIGH" if spf_verdict == "FAIL" else "MEDIUM"
            penalty = 25.0 if spf_verdict == "FAIL" else 15.0
            findings.append(
                ForensicFindingData(
                    finding_type=f"AUTH_SPF_{spf_verdict}",
                    severity=sev,
                    confidence=0.90,
                    title=f"SPF Validation {spf_verdict}",
                    description=f"Sending MTA IP failed SPF policy for domain '{auth_results.get('spf_domain') or sender_domain}'.",
                    evidence={"spf_verdict": spf_verdict, "spf_domain": auth_results.get('spf_domain')},
                )
            )
            # Only add SPF FAIL penalty to pillar score if DMARC didn't already fire.
            # SPF SOFTFAIL always contributes (it's a weaker, independent signal).
            if not (dmarc_fired and spf_verdict == "FAIL"):
                pillar_auth_score += penalty
            spoofed_signals += 1

        # DKIM
        if dkim_verdict == "FAIL":
            findings.append(
                ForensicFindingData(
                    finding_type="AUTH_DKIM_SIGNATURE_INVALID",
                    severity="HIGH",
                    confidence=0.92,
                    title="DKIM Cryptographic Signature Invalid",
                    description="The cryptographic DKIM signature failed verification or body hash mismatched.",
                    evidence={"dkim_verdict": dkim_verdict},
                )
            )
            pillar_auth_score += 25.0
            spoofed_signals += 1

        # Inconsistent Reply-To vs Sender Address
        if reply_to and sender_address and reply_domain and sender_domain and (reply_domain != sender_domain):
            findings.append(
                ForensicFindingData(
                    finding_type="IDENTITY_REPLY_TO_MISMATCH",
                    severity="HIGH",
                    confidence=0.92,
                    title=f"Inconsistent Reply-To and Sender Address",
                    description=(
                        f"Sender address domain is '{sender_domain}' but Reply-To redirects responses to '{reply_domain}' ({reply_to}). "
                        f"Mismatched return channels are frequently utilized in phishing and BEC lures to capture responses on unauthenticated drop boxes."
                    ),
                    evidence={"sender_address": sender_address, "reply_to": reply_to},
                )
            )
            pillar_auth_score += 30.0
            spoofed_signals += 1

        # Inconsistent Return-Path vs From Address
        if return_path_domain and sender_domain and return_path_domain != sender_domain and from_align != "PASS":
            findings.append(
                ForensicFindingData(
                    finding_type="IDENTITY_RETURN_PATH_MISMATCH",
                    severity="MEDIUM",
                    confidence=0.85,
                    title=f"Return-Path Bounce Address Inconsistency",
                    description=f"Message envelope return_path domain '{return_path_domain}' mismatches visible From address domain '{sender_domain}'.",
                    evidence={"sender": sender_address, "return_path": return_path},
                )
            )
            pillar_auth_score += 15.0

        if dkim_verdict == "PASS" and spf_verdict == "PASS" and from_align == "PASS" and not (reply_domain and reply_domain != sender_domain):
            findings.append(
                ForensicFindingData(
                    finding_type="AUTH_AUTHENTICATION_PASSED",
                    severity="INFO",
                    confidence=0.98,
                    title="Email Authentication Fully Aligned",
                    description="SPF, DKIM, and DMARC cryptographic checks passed and aligned with From header.",
                    evidence={"spf": spf_verdict, "dkim": dkim_verdict, "dmarc": dmarc_verdict},
                )
            )

        # ---------------------------------------------------------
        # PILLAR 2: Routing Infrastructure & Relay Telemetry (Max 40)
        # ---------------------------------------------------------
        pillar_infra_score = 0.0
        anon_signals = 0

        for ip_item in infrastructure_intel:
            ip_val = ip_item.get("ip_address", "")
            classifications = ip_item.get("classifications", [])
            risk_tags = ip_item.get("risk_tags", [])
            reputation = ip_item.get("reputation", "")

            # Malicious IP Reputation in Threat Feeds
            if reputation == "MALICIOUS" or "THREAT_INTEL_MALICIOUS_IP" in risk_tags or "MALICIOUS_RELAY" in classifications:
                findings.append(
                    ForensicFindingData(
                        finding_type="RELAY_MALICIOUS_IP",
                        severity="CRITICAL",
                        confidence=0.98,
                        title=f"Relay MTA IP Flagged Malicious: {ip_val}",
                        description=f"Relay hop IP {ip_val} is flagged as confirmed malicious in threat intelligence feeds.",
                        evidence={"ip": ip_val, "reputation": reputation, "tags": risk_tags},
                    )
                )
                pillar_infra_score += 45.0
                anon_signals += 3

            # Tor Exit Node
            if "TOR_EXIT_NODE" in risk_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="RELAY_TOR_EXIT_NODE",
                        severity="CRITICAL",
                        confidence=0.98,
                        title=f"Transmission via Tor Exit Node: {ip_val}",
                        description="Email routing relay matches a verified Tor network exit relay.",
                        evidence={"ip": ip_val, "ptr": ip_item.get("reverse_dns")},
                    )
                )
                pillar_infra_score += 45.0
                anon_signals += 3

            # VPN / Proxy
            if "VPN_OR_PROXY_PROVIDER" in risk_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="RELAY_VPN_OR_PROXY",
                        severity="HIGH",
                        confidence=0.90,
                        title=f"Transmission via Commercial VPN / Proxy: {ip_val}",
                        description="Email transmitted through commercial VPN or proxy provider.",
                        evidence={"ip": ip_val, "isp": ip_item.get("isp"), "asn": ip_item.get("asn")},
                    )
                )
                pillar_infra_score += 25.0
                anon_signals += 2

        # Transit Latency Anomaly
        for hop in relay_hops:
            delay = hop.get("delay_seconds")
            if delay and delay > 300:
                findings.append(
                    ForensicFindingData(
                        finding_type="RELAY_SUSPICIOUS_TRANSIT_DELAY",
                        severity="LOW",
                        confidence=0.75,
                        title=f"Anomalous Relay Transit Delay ({delay}s)",
                        description=f"Hop {hop.get('hop_index')} experienced an abnormal transit latency of {delay} seconds.",
                        evidence={"hop_index": hop.get("hop_index"), "delay": delay, "source_host": hop.get("source_host")},
                    )
                )
                pillar_infra_score += 5.0

        # ---------------------------------------------------------
        # PILLAR 3: Domain Intelligence & Age (Max 35)
        # ---------------------------------------------------------
        pillar_domain_score = 0.0
        _seen_domain_findings: Set[str] = set()  # deduplicate per-domain

        for d in domain_intel:
            d_name = d.get("domain", "")
            d_tags = d.get("risk_tags", [])
            reg_intel = d.get("registration_intel") or {}
            age = reg_intel.get("domain_age_days")

            if "NEWLY_REGISTERED_DOMAIN_30D" in d_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="DOMAIN_NEWLY_REGISTERED_30D",
                        severity="HIGH",
                        confidence=0.95,
                        title=f"Newly Registered Domain (<30 Days): {d_name}",
                        description=f"Domain was registered only {age} days ago, a strong indicator of ephemeral attack infrastructure.",
                        evidence={"domain": d_name, "age_days": age, "registrar": reg_intel.get("registrar")},
                    )
                )
                pillar_domain_score += 30.0
            elif "NEWLY_REGISTERED_DOMAIN_90D" in d_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="DOMAIN_NEWLY_REGISTERED_90D",
                        severity="MEDIUM",
                        confidence=0.90,
                        title=f"Newly Registered Domain (<90 Days): {d_name}",
                        description=f"Domain age is {age} days.",
                        evidence={"domain": d_name, "age_days": age},
                    )
                )
                pillar_domain_score += 15.0

            if "DYNAMIC_DNS_PROVIDER" in d_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="DOMAIN_DYNAMIC_DNS_PROVIDER",
                        severity="HIGH",
                        confidence=0.95,
                        title=f"Dynamic DNS Domain Used: {d_name}",
                        description="Sender or link utilizes dynamic DNS infrastructure frequently abused for evasion.",
                        evidence={"domain": d_name},
                    )
                )
                pillar_domain_score += 30.0

            if "PUNYCODE_HOMOGLYPH" in d_tags:
                findings.append(
                    ForensicFindingData(
                        finding_type="DOMAIN_PUNYCODE_HOMOGLYPH",
                        severity="HIGH",
                        confidence=0.92,
                        title=f"Internationalized Homoglyph Domain: {d_name}",
                        description="Punycode encoding detected, suggesting potential brand lookalike / visual spoofing.",
                        evidence={"domain": d_name},
                    )
                )
                pillar_domain_score += 25.0

            # Suspicious TLD detection
            tld_key = f"TLD:{d_name}"
            if tld_key not in _seen_domain_findings:
                if "SUSPICIOUS_TLD" in d_tags or ("." in d_name and ("." + d_name.rsplit(".", 1)[-1].lower()) in self._SUSPICIOUS_TLDS):
                    findings.append(
                        ForensicFindingData(
                            finding_type="DOMAIN_SUSPICIOUS_TLD",
                            severity="MEDIUM",
                            confidence=0.85,
                            title=f"Suspicious Top-Level Domain: {d_name}",
                            description=f"Domain uses a TLD frequently associated with abusive registration and low-cost ephemeral infrastructure.",
                            evidence={"domain": d_name, "tld": "." + d_name.rsplit(".", 1)[-1].lower() if "." in d_name else ""},
                        )
                    )
                    pillar_domain_score += 15.0
                    _seen_domain_findings.add(tld_key)

        # ---------------------------------------------------------
        # PILLAR 4: URL & Threat Intelligence Feeds (Max 50)
        # ---------------------------------------------------------
        pillar_url_score = 0.0
        malicious_env_signals = 0

        # Extracted URLs inspection
        urls = artifacts.get("urls", [])
        tracking_regex = re.compile(r"(sendibt2\.com|phishpulse|tracking|click|track|beacon|redirect|\.onrender\.com/api/track)", re.IGNORECASE)
        ip_url_regex = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE)

        tracking_urls_found = []
        ip_urls_found = []
        shortener_urls_found = []

        for u_obj in urls:
            u_str = u_obj.get("url", "")
            u_domain = (u_obj.get("domain") or "").lower()
            if tracking_regex.search(u_str):
                tracking_urls_found.append(u_str)
            if ip_url_regex.search(u_str):
                ip_urls_found.append(u_str)
            # URL shortener detection
            if u_domain in self._URL_SHORTENERS:
                shortener_urls_found.append(u_str)

        if tracking_urls_found:
            findings.append(
                ForensicFindingData(
                    finding_type="URL_SUSPICIOUS_TRACKING_REDIRECT",
                    severity="MEDIUM",
                    confidence=0.88,
                    title="Suspicious Tracking or Redirect URLs Embedded",
                    description=f"Extracted URLs contain tracking endpoints or redirection gateways frequently leveraged to log victim opens: {tracking_urls_found[0][:60]}...",
                    evidence={"urls": tracking_urls_found[:3]},
                )
            )
            pillar_url_score += 20.0
            malicious_env_signals += 1

        if shortener_urls_found:
            findings.append(
                ForensicFindingData(
                    finding_type="URL_SHORTENER_DETECTED",
                    severity="MEDIUM",
                    confidence=0.85,
                    title="URL Shortener Service Used",
                    description=f"Email contains links using URL shortening services commonly used to obscure malicious destinations: {shortener_urls_found[0][:60]}",
                    evidence={"shortener_urls": shortener_urls_found[:3]},
                )
            )
            pillar_url_score += 15.0
            malicious_env_signals += 1

        if ip_urls_found:
            findings.append(
                ForensicFindingData(
                    finding_type="URL_IP_BASED_DESTINATION",
                    severity="HIGH",
                    confidence=0.94,
                    title="Raw IP-Based URL Destination",
                    description=f"Extracted URL targets an unmapped IP address rather than a registered domain: {ip_urls_found[0][:60]}",
                    evidence={"ip_urls": ip_urls_found[:3]},
                )
            )
            pillar_url_score += 25.0
            malicious_env_signals += 1

        # Threat Intelligence Hits (VirusTotal, ThreatFox, AbuseIPDB, Internal)
        threat_indicators = threat_intel.get("indicators", [])
        for ind in threat_indicators:
            verdict = ind.get("consensus_verdict")
            score = ind.get("consensus_threat_score", 0.0)
            val = ind.get("indicator_value", "")
            itype = ind.get("indicator_type", "")

            if verdict == "MALICIOUS":
                findings.append(
                    ForensicFindingData(
                        finding_type=f"THREAT_INTEL_MALICIOUS_{itype}",
                        severity="CRITICAL",
                        confidence=ind.get("consensus_confidence", 0.95),
                        title=f"Malicious {itype} Confirmed by Threat Intelligence: {val[:40]}",
                        description=f"Indicator flagged as MALICIOUS with consensus score {score}. Aggregated tags: {', '.join(ind.get('aggregated_tags', []))}",
                        evidence={"indicator": val, "score": score, "tags": ind.get("aggregated_tags")},
                    )
                )
                pillar_url_score += 45.0
                malicious_env_signals += 2
            elif verdict == "SUSPICIOUS":
                findings.append(
                    ForensicFindingData(
                        finding_type=f"THREAT_INTEL_SUSPICIOUS_{itype}",
                        severity="MEDIUM",
                        confidence=ind.get("consensus_confidence", 0.75),
                        title=f"Suspicious {itype}: {val[:40]}",
                        description=f"Threat intelligence flagged indicator as suspicious with score {score}.",
                        evidence={"indicator": val, "score": score},
                    )
                )
                pillar_url_score += 15.0

        # ---------------------------------------------------------
        # PILLAR 5: Payload & Attachment Forensics (Max 60)
        # ---------------------------------------------------------
        pillar_payload_score = 0.0
        attachments = artifacts.get("attachments", [])

        dangerous_exts = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".hta", ".js", ".ps1", ".jar"}
        macro_exts = {".docm", ".xlsm", ".pptm"}

        for att in attachments:
            fname = att.get("filename", "")
            ext = (att.get("extension") or "").lower()
            if not ext and "." in fname:
                ext = "." + fname.split(".")[-1].lower()

            if ext in dangerous_exts or att.get("is_dangerous"):
                findings.append(
                    ForensicFindingData(
                        finding_type="ATTACHMENT_DANGEROUS_EXECUTABLE",
                        severity="CRITICAL",
                        confidence=0.99,
                        title=f"Dangerous Executable Attachment: {fname}",
                        description=f"Attachment has dangerous executable or script extension '{ext}'.",
                        evidence={"filename": fname, "sha256": att.get("sha256_hash"), "size": att.get("size_bytes")},
                    )
                )
                pillar_payload_score += 50.0
                malicious_env_signals += 3

            # Double extension evasion
            parts = fname.split(".")
            if len(parts) > 2 and ("." + parts[-1].lower()) in dangerous_exts:
                findings.append(
                    ForensicFindingData(
                        finding_type="ATTACHMENT_DOUBLE_EXTENSION_EVASION",
                        severity="CRITICAL",
                        confidence=0.99,
                        title=f"Double Extension Malware Evasion: {fname}",
                        description=f"Attachment '{fname}' uses double extension technique to disguise dangerous executable as a benign document.",
                        evidence={"filename": fname, "sha256": att.get("sha256_hash")},
                    )
                )
                pillar_payload_score += 15.0
                malicious_env_signals += 1
            elif ext in macro_exts:
                findings.append(
                    ForensicFindingData(
                        finding_type="ATTACHMENT_MACRO_ENABLED",
                        severity="HIGH",
                        confidence=0.90,
                        title=f"Macro-Enabled Office Document: {fname}",
                        description=f"Attachment contains executable VBA macros ({ext}) commonly used for malware staging.",
                        evidence={"filename": fname, "sha256": att.get("sha256_hash")},
                    )
                )
                pillar_payload_score += 30.0
                malicious_env_signals += 1

        # Attachment hash vs threat intelligence check
        threat_intel_hashes: Set[str] = set()
        for ind in threat_indicators:
            if ind.get("indicator_type") == "HASH" and ind.get("consensus_verdict") == "MALICIOUS":
                threat_intel_hashes.add(ind.get("indicator_value", "").lower())
        for att in attachments:
            att_hash = (att.get("sha256_hash") or "").lower()
            if att_hash and att_hash in threat_intel_hashes:
                findings.append(
                    ForensicFindingData(
                        finding_type="ATTACHMENT_KNOWN_MALWARE_HASH",
                        severity="CRITICAL",
                        confidence=0.99,
                        title=f"Attachment Hash Matches Known Malware: {att.get('filename', 'unknown')}",
                        description=f"SHA-256 hash {att_hash[:16]}... confirmed as known malware in threat intelligence feeds.",
                        evidence={"filename": att.get("filename"), "sha256": att_hash},
                    )
                )
                pillar_payload_score += 50.0
                malicious_env_signals += 3

        # ---------------------------------------------------------
        # PILLAR 6: Social Engineering & Behavioral (Max 40)
        # ---------------------------------------------------------
        pillar_social_score = 0.0
        dna_content = email_metadata.get("_dna_content") or {}
        dna_behavioral = email_metadata.get("_dna_behavioral") or {}

        # Urgency keyword markers from DNA content fingerprint
        urgency_markers = dna_content.get("detected_urgency_markers") or []
        if urgency_markers:
            urgency_penalty = min(20.0, len(urgency_markers) * 10.0)
            findings.append(
                ForensicFindingData(
                    finding_type="SOCIAL_URGENCY_LANGUAGE_DETECTED",
                    severity="MEDIUM" if len(urgency_markers) <= 2 else "HIGH",
                    confidence=0.85,
                    title=f"Urgency / Pressure Language Detected ({len(urgency_markers)} markers)",
                    description=f"Email body and subject contain psychological pressure language commonly used in social engineering: {', '.join(urgency_markers[:5])}",
                    evidence={"markers": urgency_markers[:10], "count": len(urgency_markers)},
                )
            )
            pillar_social_score += urgency_penalty

        # Brand impersonation via display name mismatch (from behavioral DNA)
        if dna_behavioral.get("has_brand_display_mismatch"):
            sender_display = email_metadata.get("sender_display_name") or ""
            findings.append(
                ForensicFindingData(
                    finding_type="SOCIAL_BRAND_IMPERSONATION",
                    severity="HIGH",
                    confidence=0.92,
                    title="Display Name Brand Impersonation Detected",
                    description=f"Sender display name '{sender_display}' contains a well-known brand name but the sending domain '{sender_domain}' does not belong to that brand. This is a common BEC/phishing tactic.",
                    evidence={"display_name": sender_display, "sender_domain": sender_domain, "sender_root_domain": dna_behavioral.get("sender_root_domain")},
                )
            )
            pillar_social_score += 20.0
            spoofed_signals += 1

        # Sender domain vs URL domain mismatch
        url_domains_in_email: Set[str] = set()
        for u_obj in urls:
            ud = (u_obj.get("domain") or "").lower()
            if ud:
                url_domains_in_email.add(ud)
        # Remove sender's own domain and common benign domains
        benign_url_domains = {"google.com", "microsoft.com", "apple.com", "github.com", "outlook.com", "office.com", "windows.net"}
        suspicious_url_domains = url_domains_in_email - benign_url_domains - {sender_domain}
        if sender_domain and suspicious_url_domains and url_domains_in_email:
            # Only flag if ALL URL domains are external to sender
            if sender_domain not in url_domains_in_email:
                findings.append(
                    ForensicFindingData(
                        finding_type="SOCIAL_SENDER_URL_DOMAIN_MISMATCH",
                        severity="MEDIUM",
                        confidence=0.80,
                        title="Sender Domain Does Not Match Any URL Domains",
                        description=f"Email from '{sender_domain}' contains links exclusively to unrelated domains: {', '.join(list(suspicious_url_domains)[:3])}. This pattern is common in credential harvesting.",
                        evidence={"sender_domain": sender_domain, "url_domains": sorted(list(suspicious_url_domains))[:5]},
                    )
                )
                pillar_social_score += 10.0

        # ---------------------------------------------------------
        # Final Score Aggregation & Normalization (0.0 to 100.0)
        # Each pillar is capped at its declared maximum before summation
        # to prevent any single signal category from over-contributing.
        # ---------------------------------------------------------
        capped_auth = min(35.0, pillar_auth_score)
        capped_infra = min(40.0, pillar_infra_score)
        capped_domain = min(35.0, pillar_domain_score)
        capped_url = min(50.0, pillar_url_score)
        capped_payload = min(60.0, pillar_payload_score)
        capped_social = min(40.0, pillar_social_score)

        raw_risk_score = (
            capped_auth +
            capped_infra +
            capped_domain +
            capped_url +
            capped_payload +
            capped_social
        )
        threat_risk_score = min(100.0, max(0.0, raw_risk_score))

        # Evidence Confidence Score Calculation (0.0 to 100.0)
        conf_points = 0.0
        if sender_address:
            conf_points += 20.0
        if auth_results.get("spf_verdict") is not None or auth_results.get("dkim_verdict") is not None:
            conf_points += 20.0
        if relay_hops:
            conf_points += 20.0
        if domain_intel:
            conf_points += 20.0
        else:
            conf_points += 10.0
        if threat_intel.get("total_iocs_analyzed", 0) > 0 or artifacts.get("total_urls", 0) > 0:
            conf_points += 20.0
        else:
            conf_points += 10.0

        evidence_confidence_score = min(100.0, max(15.0, conf_points))

        # Determine Primary Threat Classification
        if threat_risk_score >= 70.0:
            if any(f.finding_type.startswith("ATTACHMENT_") or "MALICIOUS" in f.finding_type for f in findings):
                threat_classification = "MALICIOUS"
            elif spoofed_signals >= 2:
                threat_classification = "SPOOFING"
            else:
                threat_classification = "PHISHING"
        elif threat_risk_score >= 30.0:
            threat_classification = "SUSPICIOUS"
        else:
            threat_classification = "BENIGN"

        # Likelihood Indicators
        spoofed_domain_likelihood = (
            "HIGH" if spoofed_signals >= 2
            else "MEDIUM" if spoofed_signals == 1
            else "LOW" if threat_risk_score > 30.0
            else "UNLIKELY"
        )
        anonymized_infrastructure_likelihood = (
            "HIGH" if anon_signals >= 2
            else "MEDIUM" if anon_signals == 1
            else "LOW" if any((h.get("delay_seconds") or 0) > 300 for h in relay_hops)
            else "UNLIKELY"
        )
        malicious_environment_likelihood = (
            "HIGH" if malicious_env_signals >= 2
            else "MEDIUM" if malicious_env_signals == 1
            else "LOW" if threat_risk_score > 35.0
            else "UNLIKELY"
        )
        # Compromised account likelihood
        if dkim_verdict == "PASS" and spf_verdict == "PASS" and from_align == "PASS" and (malicious_env_signals >= 1 or pillar_infra_score >= 30.0):
            compromised_account_likelihood = "HIGH"
        elif dkim_verdict == "PASS" and (malicious_env_signals >= 1 or pillar_infra_score >= 20.0):
            compromised_account_likelihood = "MEDIUM"
        else:
            compromised_account_likelihood = "LOW" if threat_risk_score > 50.0 else "UNLIKELY"

        # Pillar Summary Breakdown
        scoring_pillars = {
            "identity_authentication": {
                "label": "Identity & Authentication Integrity",
                "score": round(capped_auth, 1),
                "max_score": 35.0,
                "status": "FAIL" if capped_auth >= 25.0 else "SUSPICIOUS" if capped_auth > 0 else "PASS",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith(("AUTH_", "IDENTITY_"))),
            },
            "routing_infrastructure": {
                "label": "Routing & Relay Telemetry",
                "score": round(capped_infra, 1),
                "max_score": 40.0,
                "status": "CRITICAL" if capped_infra >= 40.0 else "ANOMALOUS" if capped_infra > 0 else "CLEAN",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith("RELAY_")),
            },
            "domain_reputation": {
                "label": "Domain Age & Infrastructure",
                "score": round(capped_domain, 1),
                "max_score": 35.0,
                "status": "HIGH_RISK" if capped_domain >= 25.0 else "SUSPICIOUS" if capped_domain > 0 else "CLEAN",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith("DOMAIN_")),
            },
            "url_threat_intelligence": {
                "label": "URL & Threat Feeds Consensus",
                "score": round(capped_url, 1),
                "max_score": 50.0,
                "status": "MALICIOUS" if capped_url >= 40.0 else "SUSPICIOUS" if capped_url > 0 else "CLEAN",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith(("THREAT_INTEL_", "URL_"))),
            },
            "payload_attachment": {
                "label": "Payload & Attachment Forensics",
                "score": round(capped_payload, 1),
                "max_score": 60.0,
                "status": "CRITICAL" if capped_payload >= 40.0 else "SUSPICIOUS" if capped_payload > 0 else "CLEAN",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith("ATTACHMENT_")),
            },
            "social_engineering_behavioral": {
                "label": "Social Engineering & Behavioral",
                "score": round(capped_social, 1),
                "max_score": 40.0,
                "status": "HIGH_RISK" if capped_social >= 20.0 else "SUSPICIOUS" if capped_social > 0 else "CLEAN",
                "findings_count": sum(1 for f in findings if f.finding_type.startswith("SOCIAL_")),
            },
        }

        # Construct Human-Readable Summary
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")

        summary_parts = [
            f"Email forensic analysis evaluated overall Threat Risk Score at {threat_risk_score:.1f}/100 "
            f"({threat_classification}) with Evidence Confidence Score at {evidence_confidence_score:.1f}/100."
        ]
        if crit_count or high_count:
            top_findings = [f.title for f in findings if f.severity in ("CRITICAL", "HIGH")][:3]
            summary_parts.append(
                f"Identified {crit_count} critical and {high_count} high-severity forensic indicators: {'; '.join(top_findings)}."
            )
        elif med_count:
            top_findings = [f.title for f in findings if f.severity == "MEDIUM"][:2]
            summary_parts.append(f"Identified {med_count} moderate indicators: {'; '.join(top_findings)}.")
        else:
            summary_parts.append("No significant malicious or spoofing anomalies were detected in routing, headers, or body artifacts.")

        summary_text = " ".join(summary_parts)

        return ScoringResult(
            threat_classification=threat_classification,
            threat_risk_score=threat_risk_score,
            evidence_confidence_score=evidence_confidence_score,
            summary=summary_text,
            compromised_account_likelihood=compromised_account_likelihood,
            spoofed_domain_likelihood=spoofed_domain_likelihood,
            anonymized_infrastructure_likelihood=anonymized_infrastructure_likelihood,
            malicious_environment_likelihood=malicious_environment_likelihood,
            findings=findings,
            scoring_pillars=scoring_pillars,
        )
