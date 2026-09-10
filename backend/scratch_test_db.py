import asyncio
import time
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text
from sqlalchemy.pool import NullPool
from app.core.config import settings

async def test_nullpool():
    print("Testing with NullPool (current setting)...")
    url = settings.effective_database_url
    connect_args = {"ssl": "require"}
    if settings.is_pooler_connection:
        connect_args["statement_cache_size"] = 0
        connect_args["prepared_statement_cache_size"] = 0

    engine = create_async_engine(url, poolclass=NullPool, connect_args=connect_args)
    Session = async_sessionmaker(bind=engine, class_=AsyncSession)

    for i in range(3):
        t0 = time.perf_counter()
        async with Session() as session:
            res = await session.execute(text("SELECT 1"))
            res.scalar()
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  NullPool Request {i+1}: {elapsed:.2f} ms")
    await engine.dispose()

async def test_queuepool():
    print("\nTesting with QueuePool (pool_size=3)...")
    url = settings.effective_database_url
    connect_args = {"ssl": "require"}
    if settings.is_pooler_connection:
        connect_args["statement_cache_size"] = 0
        connect_args["prepared_statement_cache_size"] = 0

    engine = create_async_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_size=3,
        max_overflow=2,
        pool_recycle=300,
    )
    Session = async_sessionmaker(bind=engine, class_=AsyncSession)

    for i in range(3):
        t0 = time.perf_counter()
        async with Session() as session:
            res = await session.execute(text("SELECT 1"))
            res.scalar()
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  QueuePool Request {i+1}: {elapsed:.2f} ms")
    await engine.dispose()

async def main():
    await test_nullpool()
    await test_queuepool()

if __name__ == "__main__":
    asyncio.run(main())
