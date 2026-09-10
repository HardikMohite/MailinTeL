import asyncio
from app.db.session import async_session_maker
from sqlalchemy import text

async def main():
    async with async_session_maker() as session:
        # Check users table
        cols = (await session.execute(text("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'"))).fetchall()
        print("USERS COLUMNS:")
        for c in cols:
            print(" ", c)
        
        users = (await session.execute(text("SELECT * FROM users"))).fetchall()
        print("\nUSERS:")
        for u in users:
            print(" ", u)

        # Check organizations table
        orgs = (await session.execute(text("SELECT * FROM organizations"))).fetchall()
        print("\nORGS:")
        for o in orgs:
            print(" ", o)

        # Check threat_indicators table
        threats = (await session.execute(text("SELECT indicator_type, indicator_value, threat_verdict, threat_category FROM threat_indicators"))).fetchall()
        print(f"\nTHREAT INDICATORS (count={len(threats)}):")
        for t in threats:
            print(" ", t)

        # Check email_urls
        eu = (await session.execute(text("""
            SELECT eu.email_id, eu.url_id, u.normalized_url, u.domain 
            FROM email_urls eu 
            JOIN urls u ON eu.url_id = u.id
        """))).fetchall()
        print(f"\nEMAIL_URLS (count={len(eu)}):")
        for x in eu:
            print(" ", x)

        # Check campaigns
        camps = (await session.execute(text("SELECT * FROM campaigns"))).fetchall()
        print(f"\nCAMPAIGNS (count={len(camps)}):")
        for c in camps:
            print(" ", c)

asyncio.run(main())
