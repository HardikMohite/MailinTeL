import asyncio
import time
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text
from app.core.config import settings

async def main():
    url = settings.effective_database_url
    connect_args = {"ssl": "require"}
    if settings.is_pooler_connection:
        connect_args["statement_cache_size"] = 0
        connect_args["prepared_statement_cache_size"] = 0

    engine = create_async_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_recycle=300,
    )
    Session = async_sessionmaker(bind=engine, class_=AsyncSession)

    print("Opening connection and running 5 consecutive queries on open connection...")
    async with Session() as session:
        for i in range(5):
            t0 = time.perf_counter()
            res = await session.execute(text("SELECT count(*) FROM emails"))
            count = res.scalar()
            elapsed = (time.perf_counter() - t0) * 1000
            print(f"  Query {i+1} on active connection: {elapsed:.2f} ms (count={count})")

    print("\nRunning 5 queries across pooled sessions (returning connection to pool)...")
    for i in range(5):
        t0 = time.perf_counter()
        async with Session() as session:
            res = await session.execute(text("SELECT count(*) FROM emails"))
            count = res.scalar()
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  Session {i+1} using pool: {elapsed:.2f} ms (count={count})")

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
