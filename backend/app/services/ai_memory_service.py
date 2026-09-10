import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.core.redis import redis_manager

logger = logging.getLogger("mailintel.services.ai_memory")

# Key Prefixes and TTLs
EXPLAIN_TTL_SECONDS = 86400        # 24 Hours
PRECEDENT_TTL_SECONDS = 3600       # 1 Hour
IOC_MEMORY_TTL_SECONDS = 604800    # 7 Days
CHAT_SESSION_TTL_SECONDS = 7200    # 2 Hours


class AIMemoryService:
    """
    Redis In-Memory AI Acceleration and Working Memory Layer.
    Provides sub-millisecond retrieval for:
    1. Groq Threat Reasoning Explanations (avoids redundant API costs).
    2. Hot Precedents and IOC Ground-Truth Memory.
    3. Multi-turn Case Assistant Chat Sessions.
    """

    def __init__(self, manager=None):
        self.manager = manager or redis_manager

    # --- 1. Threat Reasoning Explanation Cache ---

    async def get_cached_explanation(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached threat reasoning explanation for an email."""
        key = f"ai:explain:{email_id}"
        try:
            return await self.manager.get_json(key)
        except Exception as e:
            logger.debug(f"Redis get_cached_explanation bypassed ({key}): {e}")
            return None

    async def set_cached_explanation(
        self,
        email_id: str,
        explanation: Dict[str, Any],
        ttl: int = EXPLAIN_TTL_SECONDS,
    ) -> bool:
        """Caches threat reasoning explanation in Redis."""
        key = f"ai:explain:{email_id}"
        try:
            await self.manager.set_json(key, explanation, expire_seconds=ttl)
            return True
        except Exception as e:
            logger.debug(f"Redis set_cached_explanation bypassed ({key}): {e}")
            return False

    async def invalidate_cached_explanation(self, email_id: str) -> bool:
        """Invalidates cached explanation when a human sets or overrides a disposition."""
        key = f"ai:explain:{email_id}"
        try:
            await self.manager.delete(key)
            logger.info(f"Invalidated AI explanation cache for email {email_id}")
            return True
        except Exception as e:
            logger.debug(f"Redis invalidate_cached_explanation bypassed ({key}): {e}")
            return False

    # --- 2. Hot Precedents & IOC Ground-Truth Memory ---

    async def get_cached_precedents(self, email_id: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieves cached precedents for an email."""
        key = f"ai:precedent:email:{email_id}"
        try:
            return await self.manager.get_json(key)
        except Exception as e:
            logger.debug(f"Redis get_cached_precedents bypassed ({key}): {e}")
            return None

    async def set_cached_precedents(
        self,
        email_id: str,
        precedents: List[Dict[str, Any]],
        ttl: int = PRECEDENT_TTL_SECONDS,
    ) -> bool:
        """Caches discovered precedents in Redis."""
        key = f"ai:precedent:email:{email_id}"
        try:
            await self.manager.set_json(key, precedents, expire_seconds=ttl)
            return True
        except Exception as e:
            logger.debug(f"Redis set_cached_precedents bypassed ({key}): {e}")
            return False

    async def get_hot_ioc_precedent(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Fast L1 lookup for a known observable reviewed by an analyst."""
        clean_val = ioc_value.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
        key = f"ai:precedent:ioc:{clean_val}"
        try:
            return await self.manager.get_json(key)
        except Exception as e:
            logger.debug(f"Redis get_hot_ioc_precedent bypassed ({key}): {e}")
            return None

    async def set_hot_ioc_precedent(
        self,
        ioc_value: str,
        verdict: str,
        notes: str,
        reviewer_name: str,
        email_id: str,
        ttl: int = IOC_MEMORY_TTL_SECONDS,
    ) -> bool:
        """Stores confirmed IOC disposition in Redis hot memory."""
        clean_val = ioc_value.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
        key = f"ai:precedent:ioc:{clean_val}"
        payload = {
            "ioc_value": clean_val,
            "verdict": verdict,
            "notes": notes,
            "reviewer_name": reviewer_name,
            "precedent_email_id": email_id,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self.manager.set_json(key, payload, expire_seconds=ttl)
            return True
        except Exception as e:
            logger.debug(f"Redis set_hot_ioc_precedent bypassed ({key}): {e}")
            return False

    # --- 3. Assistant Multi-Turn Conversation Memory ---

    async def get_chat_session(self, email_id: str, user_id: str) -> List[Dict[str, str]]:
        """Retrieves multi-turn conversation history for an analyst and case."""
        key = f"ai:chat:{email_id}:{user_id}"
        try:
            data = await self.manager.get_json(key)
            return data if isinstance(data, list) else []
        except Exception as e:
            logger.debug(f"Redis get_chat_session bypassed ({key}): {e}")
            return []

    async def append_chat_message(
        self,
        email_id: str,
        user_id: str,
        role: str,
        content: str,
        ttl: int = CHAT_SESSION_TTL_SECONDS,
    ) -> List[Dict[str, str]]:
        """Appends a user or assistant message to the chat session in Redis."""
        key = f"ai:chat:{email_id}:{user_id}"
        try:
            history = await self.get_chat_session(email_id, user_id)
            history.append({
                "role": role,
                "content": content,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            # Keep up to last 10 turns for token efficiency
            trimmed = history[-10:]
            await self.manager.set_json(key, trimmed, expire_seconds=ttl)
            return trimmed
        except Exception as e:
            logger.debug(f"Redis append_chat_message bypassed ({key}): {e}")
            return []

    async def clear_chat_session(self, email_id: str, user_id: str) -> bool:
        """Clears active assistant session memory."""
        key = f"ai:chat:{email_id}:{user_id}"
        try:
            await self.manager.delete(key)
            return True
        except Exception as e:
            logger.debug(f"Redis clear_chat_session bypassed ({key}): {e}")
            return False


default_ai_memory_service = AIMemoryService()
