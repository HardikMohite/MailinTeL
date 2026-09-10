import asyncio
import uuid
from datetime import datetime, timezone
from app.db.session import async_session_maker
from app.models.campaign import Campaign, CampaignMembership, CampaignEvidence, CampaignEvent
from app.models.emails import Email
from sqlalchemy import select

EMAIL_1_ID = uuid.UUID("f5ea900d-14ea-4956-94de-d7e2c3ff4411")
EMAIL_2_ID = uuid.UUID("e14af99d-b37b-4cfa-b5e0-c0794ed5eae3")

async def seed_campaigns():
    async with async_session_maker() as session:
        # Check existing campaigns
        camps = (await session.execute(select(Campaign))).scalars().all()
        print(f"Existing campaigns: {len(camps)}")
        
        now = datetime.now(timezone.utc)

        # 1. Campaign for Email 2: Sagar Safar Travel Phishing Lure
        # Get org of Email 2
        e2 = (await session.execute(select(Email).where(Email.id == EMAIL_2_ID))).scalar_one_or_none()
        org_2 = e2.organization_id if e2 else None

        c2 = Campaign(
            id=uuid.uuid4(),
            campaign_name="PhishPulse: Alibaug Travel Getaway Lure",
            campaign_status="ACTIVE",
            campaign_confidence=85.0,
            threat_summary="Targeted travel promotion lure utilizing Sendinblue/Brevo relay infrastructure with confirmed malicious relay IP 77.32.148.26 and embedded click tracking beacons.",
            organization_id=org_2,
            first_detected_at=now,
            last_activity_at=now,
        )
        session.add(c2)
        await session.flush()

        m2 = CampaignMembership(
            id=uuid.uuid4(),
            campaign_id=c2.id,
            email_id=EMAIL_2_ID,
            membership_confidence=90.0,
            membership_status="CONFIRMED",
            evidence_summary={
                "source": "AUTOMATED_THREAT_INTEL",
                "matched_ioc": "77.32.148.26",
                "verdict": "MALICIOUS",
                "threat_score": 85.0,
                "relay_provider": "Sendinblue SAS (AS200484)",
            },
            created_at=now,
        )
        session.add(m2)

        ev2_1 = CampaignEvidence(
            id=uuid.uuid4(),
            campaign_id=c2.id,
            evidence_type="MALICIOUS_INFRASTRUCTURE",
            confidence=90.0,
            explanation="Relay hop IP 77.32.148.26 verified malicious by threat intelligence providers (score 85/100).",
            created_at=now,
        )
        ev2_2 = CampaignEvidence(
            id=uuid.uuid4(),
            campaign_id=c2.id,
            evidence_type="TELEMETRY_BEACONS",
            confidence=85.0,
            explanation="Identified 5 extracted tracking URLs connecting to phishpulse.onrender.com telemetry endpoints.",
            created_at=now,
        )
        session.add(ev2_1)
        session.add(ev2_2)

        evt2 = CampaignEvent(
            id=uuid.uuid4(),
            campaign_id=c2.id,
            event_type="CAMPAIGN_DETECTED",
            occurred_at=now,
            description="Campaign detected from automated threat intelligence on malicious relay node.",
            metadata_json={"ip": "77.32.148.26", "asn": "AS200484"},
        )
        session.add(evt2)

        # 2. Campaign for Email 1: Evil.com Credential Harvester
        e1 = (await session.execute(select(Email).where(Email.id == EMAIL_1_ID))).scalar_one_or_none()
        org_1 = e1.organization_id if e1 else None

        c1 = Campaign(
            id=uuid.uuid4(),
            campaign_name="Evil.com Credential Harvesting Operation",
            campaign_status="ACTIVE",
            campaign_confidence=80.0,
            threat_summary="Phishing campaign targeting corporate credentials via deceptive evil.com landing pages.",
            organization_id=org_1,
            first_detected_at=now,
            last_activity_at=now,
        )
        session.add(c1)
        await session.flush()

        m1 = CampaignMembership(
            id=uuid.uuid4(),
            campaign_id=c1.id,
            email_id=EMAIL_1_ID,
            membership_confidence=85.0,
            membership_status="CONFIRMED",
            evidence_summary={
                "source": "DOMAIN_INTEL",
                "matched_domain": "evil.com",
                "phish_url": "http://phishing.evil.com/login",
            },
            created_at=now,
        )
        session.add(m1)

        ev1 = CampaignEvidence(
            id=uuid.uuid4(),
            campaign_id=c1.id,
            evidence_type="SUSPICIOUS_DOMAIN",
            confidence=80.0,
            explanation="Domain evil.com observed hosting phishing login endpoint.",
            created_at=now,
        )
        session.add(ev1)

        evt1 = CampaignEvent(
            id=uuid.uuid4(),
            campaign_id=c1.id,
            event_type="CAMPAIGN_DETECTED",
            occurred_at=now,
            description="Campaign established from suspicious domain intelligence sighting.",
            metadata_json={"domain": "evil.com"},
        )
        session.add(evt1)

        await session.commit()
        print("Successfully created 2 confirmed Threat Campaigns with memberships and evidence!")

asyncio.run(seed_campaigns())
