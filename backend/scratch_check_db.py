import sys
sys.path.insert(0, 'backend')
import asyncio
from app.db.session import async_session_maker
from sqlalchemy import text

async def check():
    async with async_session_maker() as session:
        res = await session.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"))
        tables = [r[0] for r in res.fetchall()]
        print("Total tables in DB:", len(tables))
        for t in tables:
            try:
                c_res = await session.execute(text(f'SELECT count(*) FROM "{t}"'))
                count = c_res.scalar()
                print(f"  {t:35}: {count}")
            except Exception as e:
                print(f"  {t:35}: ERROR: {e}")

asyncio.run(check())
