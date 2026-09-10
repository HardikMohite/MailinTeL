import asyncio
import uuid
import time
from app.db.session import async_session_maker
from sqlalchemy import select, delete
from app.models.intelligence import IPAddress, IPIntelligence, InfrastructureClassification
from app.intelligence.infrastructure_intel import InfrastructureIntelligenceEngine
from datetime import datetime, timezone

EMAIL_ID = uuid.UUID("e14af99d-b37b-4cfa-b5e0-c0794ed5eae3")
TEST_IPS = ["77.32.148.26", "2002:a05:6a11:469d:b0:73b:551c:4a7a"]

async def test_fast_persistence():
    t0 = time.time()
    print("1. Performing network analysis outside DB transaction...")
    engine = InfrastructureIntelligenceEngine()
    tasks = [engine.analyze_ip(ip) for ip in TEST_IPS]
    bundles = await asyncio.gather(*tasks)
    print(f"   Analyzed {len(bundles)} IPs in {time.time() - t0:.2f}s")

    t1 = time.time()
    print("2. Persisting to Supabase in a single fast transaction...")
    async with async_session_maker() as session:
        now_utc = datetime.now(timezone.utc)
        for bundle in bundles:
            # check if exists
            res = await session.execute(select(IPAddress).where(IPAddress.ip_address == bundle.ip_address))
            ip_rec = res.scalar_one_or_none()
            if not ip_rec:
                ip_rec = IPAddress(id=uuid.uuid4(), ip_address=bundle.ip_address, first_seen_at=now_utc, created_at=now_utc)
                session.add(ip_rec)
                await session.flush()

            # clear old
            await session.execute(delete(IPIntelligence).where(IPIntelligence.ip_id == ip_rec.id))
            await session.execute(delete(InfrastructureClassification).where(InfrastructureClassification.ip_id == ip_rec.id))

            # insert intel
            intel = IPIntelligence(
                id=uuid.uuid4(),
                ip_id=ip_rec.id,
                asn=bundle.asn,
                isp=bundle.isp,
                network_owner=bundle.network_owner,
                hosting_provider=bundle.hosting_provider,
                reverse_dns=bundle.reverse_dns,
                intelligence_source="RDAP_DNS",
                retrieved_at=now_utc,
                metadata_json={
                    "ip_type": bundle.ip_type,
                    "is_private": bundle.is_private,
                    "asn_org": bundle.asn_org,
                    "country_code": bundle.country_code,
                    "risk_level": bundle.risk_level,
                    "risk_tags": bundle.risk_tags,
                },
            )
            session.add(intel)

            for c in bundle.classifications:
                cl = InfrastructureClassification(
                    id=uuid.uuid4(),
                    ip_id=ip_rec.id,
                    classification_type=c.classification_type,
                    confidence=c.confidence,
                    source=c.source,
                    evidence=c.evidence,
                    observed_at=now_utc,
                )
                session.add(cl)

        await session.commit()
    print(f"   DB persistence completed in {time.time() - t1:.2f}s! Total: {time.time() - t0:.2f}s")

asyncio.run(test_fast_persistence())
