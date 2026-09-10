import logging
import math
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine
from app.models.embeddings import EmailEmbedding

logger = logging.getLogger("mailintel.db.vector")


def calculate_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """
    Computes cosine similarity between two numeric vectors in Python memory.
    Similarity ranges from -1.0 to 1.0 (1.0 = identical direction).
    """
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        raise ValueError("Vectors must be non-empty and have identical dimensions")

    dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return dot_product / (norm_a * norm_b)


async def ensure_db_extensions(engine: AsyncEngine) -> Dict[str, bool]:
    """
    Ensures required PostgreSQL extensions (vector, pgcrypto, uuid-ossp) are created.
    """
    results: Dict[str, bool] = {}
    extensions = ["vector", "pgcrypto"]

    async with engine.begin() as conn:
        for ext in extensions:
            try:
                await conn.execute(text(f'CREATE EXTENSION IF NOT EXISTS "{ext}";'))
                results[ext] = True
                logger.info("Extension '%s' verified / activated successfully.", ext)
            except Exception as exc:
                results[ext] = False
                logger.warning("Could not create extension '%s': %s", ext, exc)

    return results


async def check_pgvector_availability(engine: AsyncEngine) -> Dict[str, Any]:
    """
    Checks if the 'vector' extension is installed and available in the target PostgreSQL instance.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';")
            )
            row = result.fetchone()
            if row:
                return {
                    "available": True,
                    "extension": row[0],
                    "version": row[1],
                    "error": None,
                }
            else:
                return {
                    "available": False,
                    "extension": "vector",
                    "version": None,
                    "error": "pgvector extension is not registered in pg_extension",
                }
    except Exception as exc:
        return {
            "available": False,
            "extension": "vector",
            "version": None,
            "error": str(exc),
        }


async def search_similar_embeddings(
    session: AsyncSession,
    query_vector: List[float],
    embedding_type: Optional[str] = None,
    limit: int = 10,
    max_distance: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Performs cosine similarity search using pgvector's cosine_distance (<=>) operator.
    Returns list of matched embeddings with calculated similarity score and metadata.
    """
    # Build query using pgvector's cosine_distance operator
    distance_expr = EmailEmbedding.embedding.cosine_distance(query_vector).label("distance")
    
    query = select(EmailEmbedding, distance_expr)
    
    if embedding_type:
        query = query.where(EmailEmbedding.embedding_type == embedding_type)
        
    if max_distance is not None:
        query = query.where(distance_expr <= max_distance)
        
    query = query.order_by(distance_expr).limit(limit)
    
    result = await session.execute(query)
    rows = result.all()
    
    matches: List[Dict[str, Any]] = []
    for item, dist in rows:
        # Cosine similarity = 1 - cosine distance
        sim_score = max(0.0, min(1.0, 1.0 - float(dist)))
        matches.append({
            "id": str(item.id),
            "email_id": str(item.email_id),
            "embedding_type": item.embedding_type,
            "model_name": item.model_name,
            "dimension": item.dimension,
            "cosine_distance": float(dist),
            "similarity_score": round(sim_score, 5),
            "metadata": item.metadata_json or {},
            "created_at": item.created_at.isoformat() if item.created_at else None,
        })
        
    return matches
