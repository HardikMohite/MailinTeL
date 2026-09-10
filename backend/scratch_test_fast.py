import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import asyncio
import time
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, select, func, desc
from app.core.config import settings
from app.models.emails import Email, EmailSource
from app.models.evidence import EvidenceObject
from app.models.identity import Organization

async def test_optimized():
    url = settings.effective_database_url
    connect_args = {"ssl": "require"}
    if settings.is_pooler_connection:
        connect_args["statement_cache_size"] = 0
        connect_args["prepared_statement_cache_size"] = 0

    engine = create_async_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=False,
        pool_size=5,
        max_overflow=5,
        pool_recycle=300,
    )
    Session = async_sessionmaker(bind=engine, class_=AsyncSession)

    # Warm up 1 connection
    async with Session() as session:
        await session.execute(text("SELECT 1"))

    print("\n--- Running Optimized Single-Pass Query ---")
    for i in range(3):
        t0 = time.perf_counter()
        async with Session() as session:
            query = (
                select(
                    Email,
                    EmailSource,
                    EvidenceObject,
                    Organization,
                    func.count(Email.id).over().label("total_count")
                )
                .outerjoin(EmailSource, Email.source_id == EmailSource.id)
                .outerjoin(EvidenceObject, Email.id == EvidenceObject.email_id)
                .outerjoin(Organization, EmailSource.organization_id == Organization.id)
                .order_by(desc(Email.created_at))
                .offset(0)
                .limit(100)
            )
            res = await session.execute(query)
            rows = res.all()
            total = rows[0][4] if rows else 0
            
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  Optimized Call {i+1}: {elapsed:.2f} ms (returned {len(rows)} items, total_count={total})")

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(test_optimized())
