import uuid
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.models.embeddings import EmailEmbedding, DEFAULT_EMBEDDING_DIM
from app.db.vector import (
    calculate_cosine_similarity,
    ensure_db_extensions,
    check_pgvector_availability,
    search_similar_embeddings,
)
from app.db.session import engine


def test_cosine_similarity_identical_vectors():
    vec_a = [1.0, 0.0, 0.0, 0.5]
    vec_b = [1.0, 0.0, 0.0, 0.5]
    sim = calculate_cosine_similarity(vec_a, vec_b)
    assert pytest.approx(sim, 0.0001) == 1.0


def test_cosine_similarity_orthogonal_vectors():
    vec_a = [1.0, 0.0]
    vec_b = [0.0, 1.0]
    sim = calculate_cosine_similarity(vec_a, vec_b)
    assert pytest.approx(sim, 0.0001) == 0.0


def test_cosine_similarity_opposite_vectors():
    vec_a = [1.0, 2.0, 3.0]
    vec_b = [-1.0, -2.0, -3.0]
    sim = calculate_cosine_similarity(vec_a, vec_b)
    assert pytest.approx(sim, 0.0001) == -1.0


def test_cosine_similarity_dimension_mismatch():
    with pytest.raises(ValueError, match="identical dimensions"):
        calculate_cosine_similarity([1.0, 2.0], [1.0])


def test_email_embedding_model_instantiation():
    test_uuid = uuid.uuid4()
    embedding_vector = [0.1] * DEFAULT_EMBEDDING_DIM
    model = EmailEmbedding(
        email_id=test_uuid,
        embedding_type="EMAIL_CONTENT",
        model_name="all-MiniLM-L6-v2",
        dimension=DEFAULT_EMBEDDING_DIM,
        embedding=embedding_vector,
        metadata_json={"source": "test_eml", "tokens": 128},
    )
    assert model.email_id == test_uuid
    assert model.embedding_type == "EMAIL_CONTENT"
    assert model.dimension == DEFAULT_EMBEDDING_DIM
    assert len(model.embedding) == DEFAULT_EMBEDDING_DIM
    assert "EmailEmbedding" in repr(model)


from sqlalchemy.ext.asyncio import AsyncEngine


@pytest.mark.asyncio
async def test_ensure_db_extensions():
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch.object(AsyncEngine, "begin", return_value=mock_ctx):
        res = await ensure_db_extensions(engine)
        assert res.get("vector") is True
        assert res.get("pgcrypto") is True
        assert mock_conn.execute.call_count == 2


@pytest.mark.asyncio
async def test_check_pgvector_availability_installed():
    mock_conn = AsyncMock()
    mock_result = MagicMock()
    mock_result.fetchone.return_value = ("vector", "0.5.0")
    mock_conn.execute = AsyncMock(return_value=mock_result)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch.object(AsyncEngine, "connect", return_value=mock_ctx):
        status = await check_pgvector_availability(engine)
        assert status["available"] is True
        assert status["extension"] == "vector"
        assert status["version"] == "0.5.0"


@pytest.mark.asyncio
async def test_check_pgvector_availability_not_installed():
    mock_conn = AsyncMock()
    mock_result = MagicMock()
    mock_result.fetchone.return_value = None
    mock_conn.execute = AsyncMock(return_value=mock_result)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch.object(AsyncEngine, "connect", return_value=mock_ctx):
        status = await check_pgvector_availability(engine)
        assert status["available"] is False
        assert status["version"] is None


@pytest.mark.asyncio
async def test_search_similar_embeddings():
    mock_session = AsyncMock()
    
    mock_item = MagicMock()
    mock_item.id = uuid.uuid4()
    mock_item.email_id = uuid.uuid4()
    mock_item.embedding_type = "EMAIL_CONTENT"
    mock_item.model_name = "all-MiniLM-L6-v2"
    mock_item.dimension = DEFAULT_EMBEDDING_DIM
    mock_item.metadata_json = {"cluster": "phishing"}
    mock_item.created_at = None

    # distance = 0.15 => similarity = 0.85
    mock_result = MagicMock()
    mock_result.all.return_value = [(mock_item, 0.15)]
    mock_session.execute = AsyncMock(return_value=mock_result)

    query_vec = [0.05] * DEFAULT_EMBEDDING_DIM
    results = await search_similar_embeddings(
        session=mock_session,
        query_vector=query_vec,
        embedding_type="EMAIL_CONTENT",
        limit=5,
    )

    assert len(results) == 1
    assert results[0]["id"] == str(mock_item.id)
    assert results[0]["email_id"] == str(mock_item.email_id)
    assert results[0]["cosine_distance"] == 0.15
    assert pytest.approx(results[0]["similarity_score"], 0.001) == 0.85
    assert results[0]["metadata"]["cluster"] == "phishing"
