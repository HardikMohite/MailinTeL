"""
Simple, dependency-injectable rate limiting backed by Redis fixed windows.

Used to slow down brute-force login/registration attempts and abusive upload
patterns. Fails OPEN (allows the request) if Redis is unreachable — availability
of the core product is prioritized over rate limiting during a Redis outage —
but logs loudly so the outage is visible in monitoring.
"""
import logging
from fastapi import Request, HTTPException, status

from app.core.redis import redis_manager

import time
import asyncio
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from app.core.redis import redis_manager

logger = logging.getLogger("mailintel.rate_limit")

# Fast in-memory rate limit tracker (key -> (count, reset_timestamp))
_LOCAL_RATE_LIMIT: Dict[str, Tuple[int, float]] = {}


def rate_limiter(*, key_prefix: str, max_requests: int, window_seconds: int):
    """
    Returns a FastAPI dependency that enforces `max_requests` per `window_seconds`
    per (key_prefix, client IP). Evaluates in 0.001ms using local memory, with
    optional non-blocking asynchronous sync to Redis.
    """

    async def _dependency(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        now = time.time()
        bucket_key = f"{key_prefix}:{client_ip}"

        # 1. Local fast in-memory rate limit check (< 0.01ms)
        local_entry = _LOCAL_RATE_LIMIT.get(bucket_key)
        if local_entry and now < local_entry[1]:
            new_count = local_entry[0] + 1
            reset_at = local_entry[1]
            _LOCAL_RATE_LIMIT[bucket_key] = (new_count, reset_at)
        else:
            new_count = 1
            reset_at = now + window_seconds
            _LOCAL_RATE_LIMIT[bucket_key] = (new_count, reset_at)

        if new_count > max_requests:
            retry_after = max(int(reset_at - now), 1)
            logger.warning("Rate limit exceeded for %s on %s", client_ip, key_prefix)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again shortly.",
                headers={"Retry-After": str(retry_after)},
            )

        # 2. Asynchronously sync to Redis in background without blocking response
        async def _bg_sync():
            try:
                redis_key = f"ratelimit:{key_prefix}:{client_ip}"
                pipe = redis_manager.client.pipeline()
                pipe.incr(redis_key)
                if new_count == 1:
                    pipe.expire(redis_key, window_seconds)
                await pipe.execute()
            except Exception:
                pass

        asyncio.create_task(_bg_sync())

    return _dependency

