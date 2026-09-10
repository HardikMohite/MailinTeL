import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.intelligence import (
    IPAddress,
    IPIntelligence,
    InfrastructureClassification,
    Geolocation,
)
from app.models.emails import Email, RelayHop
from app.intelligence.infrastructure_intel import (
    InfrastructureIntelligenceEngine,
    IPIntelBundle,
    InfrastructureClassificationData,
)

logger = logging.getLogger(__name__)

# In-memory cache for IP intelligence: ip -> (timestamp, IPIntelBundle)
_IP_CACHE: Dict[str, Tuple[float, IPIntelBundle]] = {}
_IP_CACHE_TTL_SECONDS = 3600.0  # 1 hour


async def enrich_and_persist_ip_intelligence(
    ip_str: str,
    db: AsyncSession,
    engine: Optional[InfrastructureIntelligenceEngine] = None,
    force_refresh: bool = False,
    auto_commit: bool = True,
) -> IPIntelBundle:
    """
    Retrieves IP intelligence using a high-performance Cache -> DB -> Network strategy.
    Returns existing cached/database intelligence instantly, only querying PTR/ASN when needed.
    """
    clean_ip = ip_str.strip()
    now_ts = time.time()
    now_utc = datetime.now(timezone.utc)

    # 1. Check in-memory cache (0ms)
    if not force_refresh:
        cached = _IP_CACHE.get(clean_ip)
        if cached and (now_ts - cached[0]) < _IP_CACHE_TTL_SECONDS:
            return cached[1]

    # 2. Check Database before making network calls
    stmt = select(IPAddress).where(IPAddress.ip_address == clean_ip)
    res = await db.execute(stmt)
    ip_record = res.scalar_one_or_none()

    if not force_refresh and ip_record:
        intel_stmt = select(IPIntelligence).where(IPIntelligence.ip_id == ip_record.id)
        intel_res = await db.execute(intel_stmt)
        intel_rec = intel_res.scalar_one_or_none()

        if intel_rec:
            meta = intel_rec.metadata_json or {}
            bundle = IPIntelBundle(
                ip_address=clean_ip,
                ip_type=meta.get("ip_type", "IPV4"),
                is_private=meta.get("is_private", False),
                reverse_dns=intel_rec.reverse_dns,
                asn=intel_rec.asn,
                asn_org=meta.get("asn_org"),
                isp=intel_rec.isp,
                network_owner=intel_rec.network_owner,
                hosting_provider=intel_rec.hosting_provider,
                country_code=meta.get("country_code"),
                risk_level=meta.get("risk_level", "LOW"),
                risk_tags=meta.get("risk_tags", []),
            )
            _IP_CACHE[clean_ip] = (now_ts, bundle)
            return bundle

    # 3. Query intelligence engine if not found
    intel_engine = engine or InfrastructureIntelligenceEngine()
    bundle = await intel_engine.analyze_ip(clean_ip)

    if not ip_record:
        ip_record = IPAddress(
            id=uuid.uuid4(),
            ip_address=bundle.ip_address,
            first_seen_at=now_utc,
            created_at=now_utc,
        )
        db.add(ip_record)
        await db.flush()

    # Clear old intelligence & classifications for fresh enrichment
    await db.execute(delete(IPIntelligence).where(IPIntelligence.ip_id == ip_record.id))
    await db.execute(delete(InfrastructureClassification).where(InfrastructureClassification.ip_id == ip_record.id))

    # Insert IPIntelligence record
    ip_intel = IPIntelligence(
        id=uuid.uuid4(),
        ip_id=ip_record.id,
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
    db.add(ip_intel)

    # Insert InfrastructureClassifications
    for c in bundle.classifications:
        class_rec = InfrastructureClassification(
            id=uuid.uuid4(),
            ip_id=ip_record.id,
            classification_type=c.classification_type,
            confidence=c.confidence,
            source=c.source,
            evidence=c.evidence,
            observed_at=now_utc,
        )
        db.add(class_rec)

    if auto_commit:
        await db.commit()
    else:
        await db.flush()

    _IP_CACHE[clean_ip] = (now_ts, bundle)
    return bundle


async def enrich_email_infrastructure(
    email_id: uuid.UUID,
    db: AsyncSession,
    engine: Optional[InfrastructureIntelligenceEngine] = None,
) -> List[IPIntelBundle]:
    """
    Finds all IP addresses associated with an email (from transmission relay hops)
    and executes infrastructure intelligence enrichment sequentially in the DB transaction.
    """
    # Fetch all IPs from relay hops
    hops_stmt = select(RelayHop).where(RelayHop.email_id == email_id).order_by(RelayHop.sequence_number.asc())
    hops_res = await db.execute(hops_stmt)
    hops = hops_res.scalars().all()

    ips_to_query: List[str] = []
    seen_ips: Set[str] = set()
    for hop in hops:
        if hop.source_ip:
            cleaned = hop.source_ip.strip()
            if cleaned and cleaned not in seen_ips:
                seen_ips.add(cleaned)
                ips_to_query.append(cleaned)

    results: List[IPIntelBundle] = []
    intel_engine = engine or InfrastructureIntelligenceEngine()

    # Sequential DB persistence to eliminate concurrency collisions on the AsyncSession
    for ip_str in ips_to_query:
        try:
            bundle = await enrich_and_persist_ip_intelligence(
                ip_str=ip_str,
                db=db,
                engine=intel_engine,
                auto_commit=False,
            )
            results.append(bundle)
        except Exception as e:
            logger.warning(f"Error enriching IP {ip_str} for email {email_id}: {e}")

    await db.commit()
    return results
