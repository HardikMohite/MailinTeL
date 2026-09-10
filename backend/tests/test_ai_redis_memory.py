import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock
from app.services.ai_memory_service import AIMemoryService, default_ai_memory_service


@pytest.mark.asyncio
async def test_ai_memory_explanation_cache():
    """Tests setting, getting, and invalidating threat reasoning explanation in Redis memory."""
    mock_redis = MagicMock()
    mock_redis.get_json = AsyncMock(return_value=None)
    mock_redis.set_json = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=True)

    svc = AIMemoryService(manager=mock_redis)
    test_id = str(uuid.uuid4())

    # 1. Cache miss
    res = await svc.get_cached_explanation(test_id)
    assert res is None
    mock_redis.get_json.assert_called_once_with(f"ai:explain:{test_id}")

    # 2. Cache set
    sample_explanation = {
        "classification": "phishing",
        "reasoning": [{"finding": "Credential Theft", "evidence": "Spoofed link", "confidence": 0.9}],
        "confidence": 0.95,
    }
    set_res = await svc.set_cached_explanation(test_id, sample_explanation)
    assert set_res is True
    mock_redis.set_json.assert_called_once()

    # 3. Cache hit
    mock_redis.get_json = AsyncMock(return_value=sample_explanation)
    hit_res = await svc.get_cached_explanation(test_id)
    assert hit_res["classification"] == "phishing"

    # 4. Invalidation
    inval_res = await svc.invalidate_cached_explanation(test_id)
    assert inval_res is True
    mock_redis.delete.assert_called_once_with(f"ai:explain:{test_id}")


@pytest.mark.asyncio
async def test_ai_memory_hot_ioc_precedent():
    """Tests storing and retrieving hot IOC ground-truth memory with defanging."""
    mock_redis = MagicMock()
    mock_redis.get_json = AsyncMock(return_value=None)
    mock_redis.set_json = AsyncMock(return_value=True)

    svc = AIMemoryService(manager=mock_redis)
    ioc = "hxxps://evil-login[.]com/account"
    clean_ioc = "https://evil-login.com/account"

    # Set hot IOC precedent
    ok = await svc.set_hot_ioc_precedent(
        ioc_value=ioc,
        verdict="CONFIRMED_PHISHING",
        notes="Known adversary credential lure",
        reviewer_name="Senior Analyst",
        email_id="email-123",
    )
    assert ok is True
    # Verify defanged ioc value was cleaned before key construction
    call_args = mock_redis.set_json.call_args[0]
    assert call_args[0] == f"ai:precedent:ioc:{clean_ioc}"
    assert call_args[1]["verdict"] == "CONFIRMED_PHISHING"

    # Get hot IOC precedent
    mock_redis.get_json = AsyncMock(return_value=call_args[1])
    retrieved = await svc.get_hot_ioc_precedent(ioc)
    assert retrieved is not None
    assert retrieved["verdict"] == "CONFIRMED_PHISHING"
    assert retrieved["reviewer_name"] == "Senior Analyst"


@pytest.mark.asyncio
async def test_ai_memory_chat_sessions():
    """Tests multi-turn assistant conversation history storage and clearing."""
    storage = {}

    async def fake_get(key):
        return storage.get(key)

    async def fake_set(key, val, expire_seconds=None):
        storage[key] = val
        return True

    async def fake_del(key):
        storage.pop(key, None)
        return True

    mock_redis = MagicMock()
    mock_redis.get_json = AsyncMock(side_effect=fake_get)
    mock_redis.set_json = AsyncMock(side_effect=fake_set)
    mock_redis.delete = AsyncMock(side_effect=fake_del)

    svc = AIMemoryService(manager=mock_redis)
    email_id = "case-777"
    user_id = "analyst-42"

    # Initially empty
    history = await svc.get_chat_session(email_id, user_id)
    assert history == []

    # Turn 1: User asks
    await svc.append_chat_message(email_id, user_id, "user", "Why was this email flagged as high risk?")
    # Turn 1: Assistant replies
    await svc.append_chat_message(email_id, user_id, "assistant", "Because SPF failed and the relay IP is in Russia.")

    # Retrieve history
    history = await svc.get_chat_session(email_id, user_id)
    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert "high risk" in history[0]["content"]
    assert history[1]["role"] == "assistant"
    assert "SPF failed" in history[1]["content"]

    # Clear session
    cleared = await svc.clear_chat_session(email_id, user_id)
    assert cleared is True
    history = await svc.get_chat_session(email_id, user_id)
    assert history == []


@pytest.mark.asyncio
async def test_ai_memory_precedents_cache():
    """Tests precedent result caching for fast sub-millisecond retrieval."""
    mock_redis = MagicMock()
    precedents_data = [
        {"precedent_email_id": "prev-1", "similarity_score": 94.5, "analyst_verdict": "CONFIRMED_PHISHING"}
    ]
    mock_redis.get_json = AsyncMock(return_value=precedents_data)
    mock_redis.set_json = AsyncMock(return_value=True)

    svc = AIMemoryService(manager=mock_redis)
    res = await svc.get_cached_precedents("email-abc")
    assert len(res) == 1
    assert res[0]["similarity_score"] == 94.5

    ok = await svc.set_cached_precedents("email-abc", precedents_data)
    assert ok is True
