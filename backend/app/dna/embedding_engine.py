import hashlib
import math
import re
from typing import List, Dict, Any, Optional

DEFAULT_EMBEDDING_DIM = 384


class SemanticEmbeddingEngine:
    """
    High-performance deterministic semantic and forensic embedding generator.
    Generates 384-dimensional normalized dense vectors for email subject, body content,
    Email DNA fingerprints, and threat patterns.
    """

    def __init__(self, dimension: int = DEFAULT_EMBEDDING_DIM, model_name: str = "mailintel-sha256-feature-hash-384d"):
        self.dimension = dimension
        self.model_name = model_name

    def _normalize_vector(self, vec: List[float]) -> List[float]:
        """L2-normalizes a vector to unit length so dot product equals cosine similarity."""
        norm_sq = sum(x * x for x in vec)
        if norm_sq <= 1e-12:
            # Return uniform unit vector if all zeros
            val = 1.0 / math.sqrt(self.dimension)
            return [val] * self.dimension
        norm = math.sqrt(norm_sq)
        return [round(x / norm, 6) for x in vec]

    def _tokenize(self, text: str) -> List[str]:
        """Extracts cleaned words and subwords from text."""
        if not text:
            return []
        tokens = re.findall(r"[a-zA-Z0-9_\-\.]{2,}", text.lower())
        return tokens

    def _hash_token_to_indices_and_weights(self, token: str, weight: float = 1.0) -> List[tuple[int, float]]:
        """
        Maps a token to multiple projection dimensions using murmur-like SHA-256 slicing
        for reduced collision distortion (Feature Hashing trick).
        """
        h = hashlib.sha256(token.encode("utf-8")).digest()
        results = []
        for i in range(4):
            # 4 hash projections per token for robust dense dispersion
            sub_val = int.from_bytes(h[i * 4 : (i + 1) * 4], byteorder="big", signed=False)
            idx = sub_val % self.dimension
            sign = 1.0 if (sub_val >> 31) & 1 == 0 else -1.0
            results.append((idx, weight * sign))
        return results

    def embed_text(self, text: str, extra_weight_tokens: Optional[List[str]] = None) -> List[float]:
        """
        Generates a 384-dimensional dense semantic embedding vector for text.
        Applies term frequency weighting, character n-grams (3-4 grams) for morphological similarity,
        and L2 normalization.
        """
        if not text or not text.strip():
            return self._normalize_vector([0.0] * self.dimension)

        vec = [0.0] * self.dimension
        tokens = self._tokenize(text)

        # Word-level term frequency
        tf: Dict[str, float] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0.0) + 1.0

        for token, count in tf.items():
            # Sub-linear term frequency scaling
            w = 1.0 + math.log(count)
            # Boost domain/security keywords
            if any(k in token for k in ["urgent", "verify", "password", "invoice", "bank", "account", "secure", "login"]):
                w *= 1.8

            for idx, val in self._hash_token_to_indices_and_weights(token, w):
                vec[idx] += val

            # Character n-grams for typo-tolerant / morphology matching
            if len(token) >= 4:
                for n in (3, 4):
                    for i in range(len(token) - n + 1):
                        ngram = f"__{token[i:i+n]}__"
                        for idx, val in self._hash_token_to_indices_and_weights(ngram, w * 0.35):
                            vec[idx] += val

        if extra_weight_tokens:
            for token in extra_weight_tokens:
                clean_t = token.lower().strip()
                if clean_t:
                    for idx, val in self._hash_token_to_indices_and_weights(clean_t, 2.5):
                        vec[idx] += val

        return self._normalize_vector(vec)

    def embed_subject(self, subject: Optional[str]) -> List[float]:
        """Generates embedding for email subject line."""
        clean_subj = subject.strip() if subject else ""
        return self.embed_text(clean_subj)

    def embed_content(self, subject: Optional[str], body_plain: Optional[str], body_html: Optional[str] = None) -> List[float]:
        """
        Generates embedding for email content combining subject, plain text body,
        and stripped HTML tokens.
        """
        parts = []
        if subject:
            parts.append(f"Subject: {subject}")
            parts.append(f"Subject: {subject}")  # 2x weight for subject
        if body_plain:
            parts.append(body_plain[:5000])  # bound processing to first 5KB
        elif body_html:
            # Strip tags for fallback
            clean_html = re.sub(r"<[^>]+>", " ", body_html[:10000])
            parts.append(clean_html[:5000])

        combined_text = "\n\n".join(parts)
        return self.embed_text(combined_text)

    def embed_dna_profile(self, dna_data: Dict[str, Any]) -> List[float]:
        """
        Generates a 384-dimensional dense feature vector representing the multi-layered
        Email DNA fingerprint (content, technical, infrastructure, behavioral, temporal).
        """
        vec = [0.0] * self.dimension

        content_fp = dna_data.get("content_fingerprint") or {}
        tech_fp = dna_data.get("technical_fingerprint") or {}
        infra_fp = dna_data.get("infrastructure_fingerprint") or {}
        behavioral_fp = dna_data.get("behavioral_fingerprint") or {}
        temporal_fp = dna_data.get("temporal_fingerprint") or {}

        # 1. Content features
        for token in content_fp.get("subject_tokens") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"lex:{token}", 1.5):
                vec[idx] += val

        for tag in content_fp.get("dom_tag_sequence") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"dom:{tag}", 0.8):
                vec[idx] += val

        for ext in content_fp.get("attachment_extensions") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"ext:{ext}", 2.0):
                vec[idx] += val

        # 2. Technical features
        if tech_fp.get("header_order_hash"):
            for idx, val in self._hash_token_to_indices_and_weights(f"hdr_hash:{tech_fp['header_order_hash'][:16]}", 2.0):
                vec[idx] += val

        if tech_fp.get("user_agent"):
            for idx, val in self._hash_token_to_indices_and_weights(f"ua:{tech_fp['user_agent']}", 1.8):
                vec[idx] += val

        if tech_fp.get("dkim_signing_domain"):
            for idx, val in self._hash_token_to_indices_and_weights(f"dkim_d:{tech_fp['dkim_signing_domain']}", 1.5):
                vec[idx] += val

        # 3. Infrastructure features
        for asn in infra_fp.get("asn_chain") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"asn:{asn}", 2.0):
                vec[idx] += val

        for cc in infra_fp.get("country_chain") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"cc:{cc}", 1.2):
                vec[idx] += val

        for flag in infra_fp.get("infrastructure_classifications") or []:
            for idx, val in self._hash_token_to_indices_and_weights(f"infra_flag:{flag}", 2.5):
                vec[idx] += val

        # 4. Behavioral features
        if behavioral_fp.get("has_brand_display_mismatch"):
            for idx, val in self._hash_token_to_indices_and_weights("behavior:brand_spoofing", 3.0):
                vec[idx] += val

        # 5. Temporal features (cyclical encoding into direct index slots 0..3)
        utc_hour = temporal_fp.get("utc_hour_of_day")
        if utc_hour is not None:
            angle = (utc_hour / 24.0) * 2.0 * math.pi
            vec[0] += math.sin(angle) * 2.0
            vec[1] += math.cos(angle) * 2.0

        utc_day = temporal_fp.get("utc_day_of_week")
        if utc_day is not None:
            angle_day = (utc_day / 7.0) * 2.0 * math.pi
            vec[2] += math.sin(angle_day) * 2.0
            vec[3] += math.cos(angle_day) * 2.0

        return self._normalize_vector(vec)

    def embed_threat_pattern(
        self,
        risk_score: float,
        findings: List[Dict[str, Any]],
        indicators: List[Dict[str, Any]],
    ) -> List[float]:
        """
        Generates a 384-dimensional dense vector representing the threat posture and findings.
        """
        vec = [0.0] * self.dimension
        # Slot 0 encodes normalized risk magnitude
        vec[0] += (risk_score / 100.0) * 3.0

        for finding in findings:
            ftype = finding.get("finding_type", "UNKNOWN")
            severity = finding.get("severity", "LOW")
            weight = {"CRITICAL": 3.0, "HIGH": 2.2, "MEDIUM": 1.4, "LOW": 0.8, "INFORMATIONAL": 0.4}.get(severity, 1.0)
            for idx, val in self._hash_token_to_indices_and_weights(f"finding:{ftype}", weight):
                vec[idx] += val

        for ind in indicators:
            itype = ind.get("indicator_type", "UNKNOWN")
            for idx, val in self._hash_token_to_indices_and_weights(f"indicator:{itype}", 1.5):
                vec[idx] += val

        return self._normalize_vector(vec)


default_embedding_engine = SemanticEmbeddingEngine()
