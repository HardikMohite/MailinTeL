import asyncio
import logging
import time
from typing import AsyncGenerator, Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

logger = logging.getLogger("mailintel.db")


def get_engine_connect_args() -> Dict[str, Any]:
    """
    Builds driver-level connection arguments for asyncpg.
    Enforces SSL for Supabase connections and configures pooler compatibility.
    """
    args: Dict[str, Any] = {}
    url_lower = settings.effective_database_url.lower()

    if settings.is_supabase_db or settings.POSTGRES_SSL or "ssl=" in url_lower:
        args["ssl"] = "require"

    # When connecting via Supabase transaction pooler (Supavisor / port 6543), prepared
    # statement caching must be disabled to prevent DuplicatePreparedStatementError.
    if settings.is_pooler_connection:
        args["statement_cache_size"] = 0
        args["prepared_statement_cache_size"] = 0

    return args


_engine_kwargs: Dict[str, Any] = {
    "connect_args": get_engine_connect_args(),
    "echo": False,
    "future": True,
    "pool_pre_ping": False,
    "pool_size": 5,
    "max_overflow": 5,
    "pool_timeout": 30,
    "pool_recycle": 300,
}

# Create Async Engine for PostgreSQL
engine: AsyncEngine = create_async_engine(
    settings.effective_database_url,
    **_engine_kwargs,
)

# Async Session Factory
async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async database session
    and guarantees proper session closure and rollback on exception.
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_connectivity(timeout_seconds: float = 10.0) -> Dict[str, Any]:
    """
    Checks database connection health with a configurable timeout.
    Returns connectivity status, latency in milliseconds, and error details if any.
    """
    start_time = time.perf_counter()
    try:
        async with asyncio.timeout(timeout_seconds):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "connected": True,
            "latency_ms": latency_ms,
            "database": settings.POSTGRES_DB,
            "host": settings.POSTGRES_HOST,
            "port": settings.POSTGRES_PORT,
            "error": None,
        }
    except TimeoutError:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        err_msg = f"Database connection timed out after {timeout_seconds}s (latency: {latency_ms}ms)"
        logger.warning(err_msg)
        return {
            "connected": False,
            "latency_ms": latency_ms,
            "database": settings.POSTGRES_DB,
            "host": settings.POSTGRES_HOST,
            "port": settings.POSTGRES_PORT,
            "error": err_msg,
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        err_msg = str(exc) or type(exc).__name__
        logger.warning("Database connectivity check failed: %s", err_msg)
        return {
            "connected": False,
            "latency_ms": latency_ms,
            "database": settings.POSTGRES_DB,
            "host": settings.POSTGRES_HOST,
            "port": settings.POSTGRES_PORT,
            "error": err_msg,
        }
