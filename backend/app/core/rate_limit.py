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

logger = logging.getLogger("mailintel.rate_limit")


def rate_limiter(*, key_prefix: str, max_requests: int, window_seconds: int):
    """
    Returns a FastAPI dependency that enforces `max_requests` per `window_seconds`
    per (key_prefix, client IP). Use per-route for sensitive endpoints
    (login, register, upload) rather than globally, to keep normal usage snappy.
    """

    async def _dependency(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        # Respect a trusted reverse-proxy header if present (set X-Forwarded-For
        # only from your own load balancer/ingress — never trust it from the public
        # internet directly without a proxy in front).
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        redis_key = f"ratelimit:{key_prefix}:{client_ip}"
        try:
            current = await redis_manager.client.incr(redis_key)
            if current == 1:
                await redis_manager.client.expire(redis_key, window_seconds)
            if current > max_requests:
                ttl = await redis_manager.client.ttl(redis_key)
                logger.warning("Rate limit exceeded for %s on %s", client_ip, key_prefix)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again shortly.",
                    headers={"Retry-After": str(max(ttl, 1))},
                )
        except HTTPException:
            raise
        except Exception as e:
            # Redis unavailable — fail open but log, so an outage is visible rather
            # than silently disabling protection forever.
            logger.error("Rate limiter backend unavailable (%s) - failing open for %s", e, key_prefix)

    return _dependency
