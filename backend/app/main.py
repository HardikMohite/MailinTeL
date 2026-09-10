import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.api.v1.api import api_router

from app.db.session import check_db_connectivity, engine

from app.core.redis import redis_manager

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mailintel")

# Fail fast on insecure production configuration (default SECRET_KEY, DEBUG=True, etc.)
settings.validate_production_safety()

# Maximum accepted request body size (defense in depth; the /emails/upload route
# also independently enforces a 25MB limit after reading the body).
MAX_REQUEST_BODY_BYTES = 30 * 1024 * 1024  # 30MB


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing %s in %s mode...", settings.APP_NAME, settings.APP_ENV)

    # Check Database Connection on startup (allow realistic latency for remote cloud pooler)
    db_status = await check_db_connectivity(timeout_seconds=8.0)
    if db_status["connected"]:
        logger.info("Database connection established (latency: %sms)", db_status["latency_ms"])
        # Auto-provision initial administrator account if configured via .env
        try:
            from app.db.init_db import init_admin_account
            await init_admin_account()
        except Exception as e:
            logger.warning("Could not verify/provision initial admin account on startup: %s", e)
    else:
        logger.warning(
            "Database connection could not be established on startup (%s). App will continue in resilient mode.",
            db_status["error"],
        )

    # Check Redis Connection on startup
    redis_status = await redis_manager.check_connectivity(timeout_seconds=5.0)
    if redis_status["connected"]:
        logger.info("Redis connection established (latency: %sms)", redis_status["latency_ms"])
    else:
        logger.warning(
            "Redis connection could not be established on startup (%s). App will continue in resilient mode.",
            redis_status["error"],
        )

    yield

    # Shutdown
    logger.info("Shutting down %s and releasing connection pools...", settings.APP_NAME)
    await engine.dispose()
    await redis_manager.close()


# Hide interactive API docs outside of development — they enumerate every
# endpoint, schema, and field name, which is unnecessary reconnaissance
# surface to expose publicly once this is a real deployment.
_docs_enabled = settings.DEBUG and not settings.is_production

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform",
    version="1.0.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
    lifespan=lifespan,
)

# CORS configuration — explicit allow-list only, driven by settings.cors_origins
# (FRONTEND_URL + ALLOWED_ORIGINS env var). Never uses "*" because
# allow_credentials=True makes a wildcard origin unsafe (browsers block it,
# and some proxies don't).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


@app.middleware("http")
async def security_headers_and_body_limit(request: Request, call_next):
    """Reject oversized requests early and stamp standard security headers on every response."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"error": "Payload Too Large", "message": "Request body exceeds the maximum allowed size."},
                )
        except ValueError:
            pass

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# Structured, non-leaky error handlers.
# These intentionally return the same generic shape whether or not DEBUG is on,
# so a misconfigured deployment can't accidentally leak stack traces or internal
# paths to a client. Full details always go to the server-side log instead.

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail if isinstance(exc.detail, str) else "Request failed", "path": request.url.path},
        headers=getattr(exc, "headers", None) or {},
    )


def _json_safe_validation_errors(exc: RequestValidationError) -> list:
    """
    Pydantic v2 populates `ctx` on a validation error with the *original*
    Python objects involved (e.g. `ctx["error"]` is the raw `ValueError`
    instance a `@field_validator` raised) rather than a string. Those are not
    JSON-serializable, so passing `exc.errors()` straight into `JSONResponse`
    raises an unrelated `TypeError` and turns a clean 422 into an opaque
    500-style failure — hit by, e.g., the password-strength validator in
    auth.register and the role validators in users.invite_user/update_member_role.
    Stringify anything in `ctx` so the handler can't crash on it.
    """
    safe_errors = []
    for error in exc.errors():
        error = dict(error)
        ctx = error.get("ctx")
        if isinstance(ctx, dict):
            error["ctx"] = {k: str(v) for k, v in ctx.items()}
        safe_errors.append(error)
    return safe_errors


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "The request could not be validated.",
            "path": request.url.path,
            "details": _json_safe_validation_errors(exc),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception for %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred. Please try again or contact support.",
            "path": request.url.path,
        },
    )


# Root Endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "app": settings.APP_NAME,
        "status": "online",
        "api_v1": settings.API_V1_PREFIX,
        "docs": "/docs" if _docs_enabled else None,
    }


# Mount API v1 Router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
