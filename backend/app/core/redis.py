import json
import time
import logging
from typing import Dict, Any, Optional
import redis.asyncio as aioredis
from redis.asyncio import Redis

from app.core.config import settings

logger = logging.getLogger("mailintel.redis")

"""
REDIS ARCHITECTURAL PURPOSE (DEC-005):
Redis is supporting infrastructure for:
1. Fast ephemeral metadata caching (e.g. domain WHOIS lookups, threat indicator hits).
2. Background analysis job status tracking and pub/sub coordination.
3. API rate limiting and transient session state.

IMPORTANT FORENSIC RULE:
Redis is NOT permanent forensic evidence storage. Original .eml evidence must reside in MinIO,
and structured intelligence records and hashes must reside in PostgreSQL.
"""


class RedisManager:
    """
    Async Redis Client and Cache Manager for MailIntel.
    """

    def __init__(self):
        self._client: Optional[Redis] = None
        self._is_available: bool = True
        self._last_checked_time: float = 0.0
        self._cooldown_seconds: float = 15.0

    @property
    def is_available(self) -> bool:
        now = time.time()
        if not self._is_available and (now - self._last_checked_time) < self._cooldown_seconds:
            return False
        return self._is_available

    def mark_unavailable(self) -> None:
        self._is_available = False
        self._last_checked_time = time.time()

    @property
    def client(self) -> Redis:
        if self._client is None:
            url = settings.REDIS_URL
            # Auto-upgrade to rediss:// when SSL is enabled or Upstash endpoint is used
            if (settings.REDIS_SSL or "upstash.io" in url) and url.startswith("redis://"):
                url = "rediss://" + url[len("redis://"):]

            self._client = aioredis.from_url(
                url,
                decode_responses=True,
                socket_timeout=1.5,
                socket_connect_timeout=1.5,
                retry_on_timeout=False,
            )
        return self._client

    async def check_connectivity(self, timeout_seconds: float = 1.0) -> Dict[str, Any]:
        """
        Pings Redis server and measures latency. Uses a 15-second cooldown
        when Redis is offline to avoid blocking incoming HTTP requests.
        """
        now = time.time()
        # Fast fail if recently determined to be down
        if not self._is_available and (now - self._last_checked_time) < self._cooldown_seconds:
            return {
                "connected": False,
                "latency_ms": 0.0,
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
                "error": "Redis unavailable (cooldown active)",
            }

        start_time = time.perf_counter()
        try:
            pong = await self.client.ping()
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if pong:
                self._is_available = True
                self._last_checked_time = now
                return {
                    "connected": True,
                    "latency_ms": latency_ms,
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT,
                    "db": settings.REDIS_DB,
                    "error": None,
                }
            else:
                self._is_available = False
                self._last_checked_time = now
                return {
                    "connected": False,
                    "latency_ms": latency_ms,
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT,
                    "db": settings.REDIS_DB,
                    "error": "Ping did not return True",
                }
        except Exception as exc:
            self._is_available = False
            self._last_checked_time = now
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning("Redis connectivity check failed: %s", exc)
            return {
                "connected": False,
                "latency_ms": latency_ms,
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
                "error": str(exc),
            }

    async def set_json(
        self,
        key: str,
        value: Any,
        expire_seconds: Optional[int] = None,
    ) -> bool:
        """
        Serializes data to JSON and stores it in Redis with optional TTL.
        """
        payload = json.dumps(value)
        if expire_seconds:
            await self.client.set(key, payload, ex=expire_seconds)
        else:
            await self.client.set(key, payload)
        return True

    async def get_json(self, key: str) -> Optional[Any]:
        """
        Retrieves JSON payload from Redis and deserializes it.
        """
        data = await self.client.get(key)
        if data is None:
            return None
        return json.loads(data)

    async def delete(self, key: str) -> int:
        """
        Deletes a key from Redis.
        """
        return await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        """
        Checks if a key exists in Redis.
        """
        return bool(await self.client.exists(key))

    async def close(self) -> None:
        """
        Closes Redis connection pool cleanly.
        """
        if self._client is not None:
            await self._client.close()
            self._client = None
            logger.info("Redis connection pool closed.")


redis_manager = RedisManager()
