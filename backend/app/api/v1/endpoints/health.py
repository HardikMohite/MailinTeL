import sys
import platform
from datetime import datetime, timezone
from fastapi import APIRouter, Response, status
from app.core.config import settings
from app.db.session import check_db_connectivity, engine
from app.db.vector import check_pgvector_availability
from app.core.storage import storage, REQUIRED_BUCKETS
from app.core.redis import redis_manager

# MVP-07 fix: two routers instead of one.
#  - `public_router` is mounted with no auth dependency and must only ever
#    return the minimal "is the process up" signal — no hostnames, ports,
#    bucket names, runtime/platform info, or demo credentials.
#  - `protected_router` carries every diagnostic-rich endpoint and is mounted
#    behind `Depends(get_current_user)` in app.api.v1.api, since that detail
#    is deployment/service reconnaissance information, not something an
#    anonymous caller needs.
public_router = APIRouter()
protected_router = APIRouter()

# Kept for any code/tests that still import `router` directly.
router = public_router


@public_router.get("", summary="Basic Liveness Check")
async def health_check():
    """
    Minimal, unauthenticated liveness signal for load balancers/orchestrators.
    Deliberately returns no service topology, versions, or configuration —
    see GET /health/detailed (authenticated) for that.
    """
    return {"status": "ok"}


@protected_router.get("/db", summary="Database Health Check")
async def database_health_check(response: Response):
    """
    Returns detailed PostgreSQL connectivity status and pgvector extension state.
    Returns HTTP 200 if connected, HTTP 503 if disconnected.
    """
    db_health = await check_db_connectivity(timeout_seconds=8.0)

    if not db_health["connected"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        pgvector_status = {"available": False, "version": None, "error": db_health["error"]}
    else:
        pgvector_status = await check_pgvector_availability(engine)

    return {
        "status": "connected" if db_health["connected"] else "disconnected",
        "database": db_health["database"],
        "host": db_health["host"],
        "port": db_health["port"],
        "latency_ms": db_health["latency_ms"],
        "error": db_health["error"],
        "pgvector": pgvector_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@protected_router.get("/storage", summary="Object Storage Health Check")
async def storage_health_check(response: Response):
    """
    Returns detailed object storage connectivity and bucket presence.
    Returns HTTP 200 if connected, HTTP 503 if disconnected.
    """
    storage_health = storage.check_connectivity(timeout_seconds=8.0)

    if not storage_health["connected"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "connected" if storage_health["connected"] else "disconnected",
        "provider": settings.active_storage_provider,
        "endpoint": storage_health["endpoint"],
        "latency_ms": storage_health["latency_ms"],
        "available_buckets": storage_health["available_buckets"],
        "required_buckets": storage_health["required_buckets"],
        "error": storage_health["error"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@protected_router.get("/redis", summary="Redis Health Check")
async def redis_health_check(response: Response):
    """
    Returns detailed Redis connectivity and latency status.
    Returns HTTP 200 if connected, HTTP 503 if disconnected.
    """
    redis_health = await redis_manager.check_connectivity(timeout_seconds=3.0)

    if not redis_health["connected"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "connected" if redis_health["connected"] else "disconnected",
        "host": redis_health["host"],
        "port": redis_health["port"],
        "db": redis_health["db"],
        "latency_ms": redis_health["latency_ms"],
        "error": redis_health["error"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@protected_router.get("/ready", summary="Unified Readiness Probe")
async def readiness_check(response: Response):
    """
    Evaluates end-to-end readiness across all core MailIntel services
    (PostgreSQL, pgvector, object storage, and Redis).
    Returns HTTP 200 when ready, HTTP 503 if any essential service is degraded.
    """
    db_health = await check_db_connectivity(timeout_seconds=8.0)
    storage_health = storage.check_connectivity(timeout_seconds=8.0)
    redis_health = await redis_manager.check_connectivity(timeout_seconds=3.0)

    if db_health["connected"]:
        pgvector_status = await check_pgvector_availability(engine)
    else:
        pgvector_status = {"available": False, "version": None, "error": "Database disconnected"}

    is_ready = (
        db_health["connected"]
        and storage_health["connected"]
        and redis_health["connected"]
    )

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "ready": is_ready,
        "status": "ready" if is_ready else "not_ready",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "postgres": {
                "status": "connected" if db_health["connected"] else "disconnected",
                "latency_ms": db_health["latency_ms"],
                "pgvector": pgvector_status.get("available", False),
            },
            "storage": {
                "provider": settings.active_storage_provider,
                "status": "connected" if storage_health["connected"] else "disconnected",
                "latency_ms": storage_health["latency_ms"],
            },
            "minio": {
                "provider": settings.active_storage_provider,
                "status": "connected" if storage_health["connected"] else "disconnected",
                "latency_ms": storage_health["latency_ms"],
            },
            "redis": {
                "status": "connected" if redis_health["connected"] else "disconnected",
                "latency_ms": redis_health["latency_ms"],
            },
        },
    }


@protected_router.get("/detailed", summary="Detailed Health & Context Check")
async def detailed_health_check():
    """
    Returns application environment, system runtime, admin context, and live service statuses.
    """
    db_health = await check_db_connectivity(timeout_seconds=8.0)
    storage_health = storage.check_connectivity(timeout_seconds=8.0)
    redis_health = await redis_manager.check_connectivity(timeout_seconds=3.0)

    is_all_healthy = (
        db_health["connected"]
        and storage_health["connected"]
        and redis_health["connected"]
    )
    system_status = "healthy" if is_all_healthy else "degraded"

    if db_health["connected"]:
        pgvector_status = await check_pgvector_availability(engine)
    else:
        pgvector_status = {"available": False, "version": None, "error": "Database disconnected"}

    storage_info = {
        "provider": settings.active_storage_provider,
        "status": "connected" if storage_health["connected"] else "disconnected",
        "configured_endpoint": settings.SUPABASE_URL if settings.active_storage_provider == "supabase" else settings.MINIO_ENDPOINT,
        "latency_ms": storage_health["latency_ms"],
        "available_buckets": storage_health["available_buckets"],
        "required_buckets": storage_health["required_buckets"],
    }

    return {
        "status": system_status,
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "debug": settings.DEBUG,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "runtime": {
            "python_version": sys.version,
            "platform": platform.platform(),
        },
        "admin_context": {
            "admin_email": settings.ADMIN_EMAIL,
            "admin_name": settings.ADMIN_FULL_NAME,
            "organization_name": settings.ADMIN_ORG_NAME,
        },
        "demo_context": {
            "role": "Development Admin",
            "email": settings.ADMIN_EMAIL,
            "admin_name": settings.ADMIN_FULL_NAME,
            "organization_name": settings.ADMIN_ORG_NAME,
        },
        "services": {
            "postgres": {
                "status": "connected" if db_health["connected"] else "disconnected",
                "configured_host": settings.POSTGRES_HOST,
                "configured_port": settings.POSTGRES_PORT,
                "configured_db": settings.POSTGRES_DB,
                "latency_ms": db_health["latency_ms"],
                "error": db_health["error"],
                "pgvector": pgvector_status,
            },
            "storage": storage_info,
            "minio": storage_info,
            "redis": {
                "status": "connected" if redis_health["connected"] else "disconnected",
                "configured_host": settings.REDIS_HOST,
                "configured_port": settings.REDIS_PORT,
                "latency_ms": redis_health["latency_ms"],
                "error": redis_health["error"],
            },
        },
    }
