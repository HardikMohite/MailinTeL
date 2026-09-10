import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.core.redis import RedisManager
from app.core.config import settings


def test_redis_manager_initialization():
    mgr = RedisManager()
    assert mgr.client is not None


@pytest.mark.asyncio
async def test_redis_check_connectivity_success():
    mgr = RedisManager()
    mock_client = AsyncMock()
    mock_client.ping.return_value = True

    with patch.object(mgr, "_client", mock_client):
        res = await mgr.check_connectivity(timeout_seconds=2.0)
        assert res["connected"] is True
        assert res["host"] == settings.REDIS_HOST
        assert res["port"] == settings.REDIS_PORT
        assert res["error"] is None
        assert isinstance(res["latency_ms"], float)


@pytest.mark.asyncio
async def test_redis_check_connectivity_failure():
    mgr = RedisManager()
    mock_client = AsyncMock()
    mock_client.ping.side_effect = ConnectionRefusedError("Redis connection refused")

    with patch.object(mgr, "_client", mock_client):
        res = await mgr.check_connectivity(timeout_seconds=1.0)
        assert res["connected"] is False
        assert "Redis connection refused" in res["error"]


@pytest.mark.asyncio
async def test_redis_set_and_get_json():
    mgr = RedisManager()
    mock_client = AsyncMock()
    stored_data = {}

    async def mock_set(key, val):
        stored_data[key] = val
        return True

    async def mock_get(key):
        return stored_data.get(key)

    mock_client.set = AsyncMock(side_effect=mock_set)
    mock_client.get = AsyncMock(side_effect=mock_get)

    with patch.object(mgr, "_client", mock_client):
        test_payload = {
            "job_id": "job-12345",
            "status": "processing",
            "findings_count": 3,
        }
        await mgr.set_json("job:job-12345", test_payload)
        retrieved = await mgr.get_json("job:job-12345")

        assert retrieved == test_payload
        assert retrieved["status"] == "processing"


@pytest.mark.asyncio
async def test_redis_set_json_with_ttl():
    mgr = RedisManager()
    mock_client = AsyncMock()
    mock_client.set = AsyncMock(return_value=True)
    mock_client.setex = AsyncMock(return_value=True)

    with patch.object(mgr, "_client", mock_client):
        await mgr.set_json("cache:whois:example.com", {"registrar": "TestReg"}, expire_seconds=300)
        if mock_client.set.called:
            assert mock_client.set.call_args[1].get("ex") == 300
        else:
            mock_client.setex.assert_called_once()
            assert mock_client.setex.call_args[0][1] == 300


@pytest.mark.asyncio
async def test_redis_delete_and_exists():
    mgr = RedisManager()
    mock_client = AsyncMock()
    mock_client.delete = AsyncMock(return_value=1)
    mock_client.exists = AsyncMock(return_value=1)

    with patch.object(mgr, "_client", mock_client):
        exists = await mgr.exists("test:key")
        assert exists is True

        deleted = await mgr.delete("test:key")
        assert deleted == 1


@pytest.mark.asyncio
async def test_redis_close():
    mgr = RedisManager()
    mock_client = AsyncMock()
    mock_client.close = AsyncMock()

    mgr._client = mock_client
    await mgr.close()

    mock_client.close.assert_called_once()
    assert mgr._client is None
