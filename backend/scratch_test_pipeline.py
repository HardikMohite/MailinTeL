import asyncio
import uuid
import sys
from app.db.session import async_session_maker
from app.services.scoring_service import execute_email_analysis_and_scoring
from app.services.threat_intel_service import enrich_email_threat_intelligence
from app.services.dna_service import generate_and_persist_email_dna
from app.services.similarity_service import default_similarity_service
from app.services.campaign_service import default_campaign_service
from app.services.geo_service import default_geo_service

EMAIL_ID = uuid.UUID("e14af99d-b37b-4cfa-b5e0-c0794ed5eae3")

async def test_email_pipeline():
    print(f"Testing pipeline for email {EMAIL_ID}...")

    # 1. Threat scoring
    try:
        print("\n--- Running Threat Scoring ---")
        async with async_session_maker() as session:
            res = await execute_email_analysis_and_scoring(email_id=EMAIL_ID, db=session)
            await session.commit()
            print("Threat Scoring SUCCESS:", res)
    except Exception as e:
        print("Threat Scoring FAILED:", type(e), e)

    # 2. Threat intel
    try:
        print("\n--- Running Threat Intel Enrichment ---")
        async with async_session_maker() as session:
            res = await enrich_email_threat_intelligence(email_id=EMAIL_ID, db=session)
            await session.commit()
            print("Threat Intel SUCCESS:", res)
    except Exception as e:
        print("Threat Intel FAILED:", type(e), e)

    # 3. DNA generation
    try:
        print("\n--- Running DNA Generation ---")
        async with async_session_maker() as session:
            res = await generate_and_persist_email_dna(email_id=EMAIL_ID, db=session)
            await session.commit()
            print("DNA Generation SUCCESS:", res)
    except Exception as e:
        print("DNA Generation FAILED:", type(e), e)

    # 4. Geolocation
    try:
        print("\n--- Running Geolocation ---")
        async with async_session_maker() as session:
            res = await default_geo_service.geolocate_email_infrastructure(session, EMAIL_ID)
            await session.commit()
            print("Geolocation SUCCESS: markers=", res.get("total_markers"))
    except Exception as e:
        print("Geolocation FAILED:", type(e), e)

    # 5. Semantic similarity
    try:
        print("\n--- Running Similarity ---")
        async with async_session_maker() as session:
            res = await default_similarity_service.find_and_link_similar_emails(session=session, email_id=EMAIL_ID)
            await session.commit()
            print("Similarity SUCCESS:", res)
    except Exception as e:
        print("Similarity FAILED:", type(e), e)

    # 6. Campaign correlation
    try:
        print("\n--- Running Campaign Correlation ---")
        async with async_session_maker() as session:
            res = await default_campaign_service.correlate_email(session=session, email_id=EMAIL_ID)
            await session.commit()
            print("Campaign Correlation SUCCESS:", res)
    except Exception as e:
        print("Campaign Correlation FAILED:", type(e), e)

asyncio.run(test_email_pipeline())
