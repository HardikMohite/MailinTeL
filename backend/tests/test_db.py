import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection
from app.db.base import Base
from app.db.session import engine, async_session_maker, get_db, check_db_connectivity
from app.core.config import settings


def test_db_base_model():
    """Verify Base declarative class exists and has metadata."""
    assert hasattr(Base, "metadata")
    assert Base.metadata is not None


def test_engine_configuration():
    """Verify async engine is configured properly with expected database url and pool settings."""
    assert str(engine.url.drivername).startswith("postgresql+asyncpg")
    assert engine.url.database == settings.POSTGRES_DB
    assert engine.url.host == settings.POSTGRES_HOST
    assert engine.url.port == settings.POSTGRES_PORT


@pytest.mark.asyncio
async def test_get_db_session_lifecycle():
    """Verify get_db generator yields an AsyncSession and closes it."""
    generator = get_db()
    session = await anext(generator)
    assert session is not None
    # Generator should exit cleanly without error
    try:
        await anext(generator)
    except StopAsyncIteration:
        pass


@pytest.mark.asyncio
async def test_check_db_connectivity_success():
    """Verify check_db_connectivity returns connected=True when connection succeeds."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch.object(AsyncEngine, "connect", return_value=mock_ctx):
        result = await check_db_connectivity(timeout_seconds=2.0)
        
        assert result["connected"] is True
        assert result["database"] == settings.POSTGRES_DB
        assert result["host"] == settings.POSTGRES_HOST
        assert result["port"] == settings.POSTGRES_PORT
        assert result["error"] is None
        assert isinstance(result["latency_ms"], float)


@pytest.mark.asyncio
async def test_check_db_connectivity_failure():
    """Verify check_db_connectivity returns connected=False and captures error message on failure."""
    with patch.object(AsyncEngine, "connect", side_effect=ConnectionRefusedError("Connection refused test")):
        result = await check_db_connectivity(timeout_seconds=1.0)
        
        assert result["connected"] is False
        assert "Connection refused test" in result["error"]
        assert result["database"] == settings.POSTGRES_DB
        assert result["host"] == settings.POSTGRES_HOST


def test_supabase_db_detection_and_ssl():
    from app.db.session import get_engine_connect_args
    from app.core.config import Settings

    # 1. Supabase direct host detection
    s = Settings(POSTGRES_HOST="db.projectref123.supabase.co", POSTGRES_PORT=5432)
    assert s.is_supabase_db is True

    # 2. Supabase URL normalization from postgresql:// to postgresql+asyncpg://
    s_url = Settings(DATABASE_URL="postgresql://postgres:pass@db.xyz.supabase.co:5432/postgres")
    assert s_url.effective_database_url.startswith("postgresql+asyncpg://")

    # 3. Supabase connect args with SSL
    with patch.object(settings, "POSTGRES_SSL", True), \
         patch.object(settings, "DATABASE_URL", "postgresql+asyncpg://postgres:pass@db.xyz.supabase.co:5432/postgres"), \
         patch.object(settings, "POSTGRES_PORT", 5432):
        args = get_engine_connect_args()
        assert args["ssl"] == "require"

    # 4. Supabase transaction pooler (port 6543) disables prepared statement cache
    with patch.object(settings, "POSTGRES_SSL", True), \
         patch.object(settings, "DATABASE_URL", "postgresql+asyncpg://postgres.ref:pass@aws-0.pooler.supabase.com:6543/postgres"), \
         patch.object(settings, "POSTGRES_PORT", 6543):
        args_pooler = get_engine_connect_args()
        assert args_pooler["ssl"] == "require"
        assert args_pooler["statement_cache_size"] == 0
        assert args_pooler["prepared_statement_cache_size"] == 0


def test_supabase_url_sanitization_and_pooler_detection():
    from app.core.config import Settings

    # A. Stripping invalid asyncpg query params (sslmode, pgbouncer, connection_limit)
    dirty_url = "postgresql://postgres.myref:P@ss123@aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require&pgbouncer=true&connection_limit=20"
    s = Settings(DATABASE_URL=dirty_url)
    clean = s.effective_database_url

    assert clean.startswith("postgresql+asyncpg://")
    assert "sslmode" not in clean
    assert "pgbouncer" not in clean
    assert "connection_limit" not in clean
    assert "aws-0-us-east-1.pooler.supabase.com:6543/postgres" in clean
    assert s.is_supabase_db is True
    assert s.is_pooler_connection is True

    # B. Safe URL creation when individual parameters contain special characters in password
    s_params = Settings(
        POSTGRES_HOST="db.xyz.supabase.co",
        POSTGRES_PORT=5432,
        POSTGRES_USER="postgres",
        POSTGRES_PASSWORD="my#secret@pass!word/1",
        POSTGRES_DB="postgres",
        DATABASE_URL="",
    )
    url_rendered = s_params.effective_database_url
    assert url_rendered.startswith("postgresql+asyncpg://postgres:")
    assert "db.xyz.supabase.co:5432/postgres" in url_rendered
    # Check that special characters were percent-encoded rather than breaking URL structure
    assert "%23" in url_rendered or "#" not in url_rendered.split("@")[0].split(":")[2]


