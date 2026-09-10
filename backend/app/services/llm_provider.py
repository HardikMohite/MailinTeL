import json
import logging
import httpx
from typing import List, Dict, Any, Optional

from app.core.config import settings

logger = logging.getLogger("mailintel.services.llm")


class GroqLLMClient:
    """
    High-speed client for Groq's LPUs and OpenAI-compatible Chat Completions API.
    Provides robust fallback to deterministic forensic reasoning if API keys
    are absent or external network calls are unreachable.
    """

    def __init__(self):
        self.api_key = (settings.GROQ_API_KEY or "").strip()
        self.api_base = settings.GROQ_API_BASE.rstrip("/")
        self.primary_model = settings.GROQ_MODEL
        self.fallback_model = settings.GROQ_FALLBACK_MODEL
        self.temperature = settings.AI_TEMPERATURE
        self.max_tokens = settings.AI_MAX_TOKENS

    @property
    def is_configured(self) -> bool:
        """Returns True if a valid-looking Groq API key is present."""
        return bool(self.api_key and len(self.api_key) >= 10 and not self.api_key.startswith("CHANGE"))

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = False,
        temperature: Optional[float] = None,
        model: Optional[str] = None,
    ) -> Optional[str]:
        """
        Sends a Chat Completion request to Groq API.
        Returns the raw string content, or None if external call fails or is unconfigured.
        """
        if not self.is_configured:
            logger.debug("Groq API key not configured; skipping remote call.")
            return None

        active_model = model or self.primary_model
        temp = temperature if temperature is not None else self.temperature

        payload: Dict[str, Any] = {
            "model": active_model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": self.max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        url = f"{self.api_base}/chat/completions"

        async with httpx.AsyncClient(timeout=25.0) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "").strip()
                
                # If model is deprecated or rate-limited, attempt fallback model
                if resp.status_code in (400, 404, 429) and active_model != self.fallback_model:
                    logger.warning(
                        f"Groq primary model {active_model} returned status {resp.status_code}. Retrying with {self.fallback_model}"
                    )
                    payload["model"] = self.fallback_model
                    retry_resp = await client.post(url, json=payload, headers=headers)
                    if retry_resp.status_code == 200:
                        data = retry_resp.json()
                        choices = data.get("choices", [])
                        if choices and "message" in choices[0]:
                            return choices[0]["message"].get("content", "").strip()

                logger.warning(f"Groq API call failed: {resp.status_code} - {resp.text[:200]}")
                return None
            except httpx.RequestError as exc:
                logger.warning(f"Network error connecting to Groq API: {exc}")
                return None
            except Exception as exc:
                logger.error(f"Unexpected error during Groq chat completion: {exc}")
                return None


default_groq_client = GroqLLMClient()
