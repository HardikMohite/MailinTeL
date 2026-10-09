import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.indicators import ThreatIndicator, IndicatorSighting
from app.models.emails import Email, RelayHop
from app.models.intelligence import Domain, URL, EmailURL, IPAddress
from app.models.evidence import EvidenceObject
from app.intelligence.threat_intel_engine import (
    ThreatIntelEngine,
    AggregatedThreatIntel,
)

logger = logging.getLogger(__name__)

# Fast in-memory cache for IOC results: key -> (timestamp, AggregatedThreatIntel)
_IOC_CACHE: Dict[str, Tuple[float, AggregatedThreatIntel]] = {}
_IOC_CACHE_TTL_SECONDS = 3600.0  # 1 hour


async def enrich_and_persist_indicator(
    indicator_type: str,
    indicator_value: str,
    db: AsyncSession,
    email_id: Optional[uuid.UUID] = None,
    engine: Optional[ThreatIntelEngine] = None,
    auto_commit: bool = True,
) -> AggregatedThreatIntel:
    """
    Enriches an indicator via ThreatIntelEngine, updates/creates ThreatIndicator record,
    and optionally records an IndicatorSighting.
    Uses memory cache and fast database lookup before querying external network adapters.
    """
    clean_type = indicator_type.strip().upper()
    clean_val = indicator_value.strip()
    cache_key = f"{clean_type}:{clean_val.lower()}"
    now_ts = time.time()
    now_utc = datetime.now(timezone.utc)

    # 1. Check in-memory cache first (0ms latency)
    cached_entry = _IOC_CACHE.get(cache_key)
    if cached_entry and (now_ts - cached_entry[0]) < _IOC_CACHE_TTL_SECONDS:
        aggregated = cached_entry[1]
    else:
        # 2. Check DB before making external network calls
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == clean_type,
            ThreatIndicator.normalized_value == clean_val,
        )
        res = await db.execute(stmt)
        indicator_rec = res.scalar_one_or_none()

        if indicator_rec and indicator_rec.last_seen_at:
            # If seen recently in DB, construct AggregatedThreatIntel directly
            aggregated = AggregatedThreatIntel(
                indicator_type=clean_type,
                indicator_value=clean_val,
                consensus_verdict=indicator_rec.reputation or "UNKNOWN",
                consensus_threat_score=85.0 if indicator_rec.reputation in ("MALICIOUS", "CRITICAL") else (50.0 if indicator_rec.reputation == "SUSPICIOUS" else 0.0),
                consensus_confidence=indicator_rec.confidence or 0.85,
                aggregated_tags=[],
                provider_reports=[],
                provider_count=1,
            )
            _IOC_CACHE[cache_key] = (now_ts, aggregated)
        else:
            # 3. Query intelligence engine
            intel_engine = engine or ThreatIntelEngine()
            aggregated = await intel_engine.query_indicator(clean_type, clean_val)
            _IOC_CACHE[cache_key] = (now_ts, aggregated)

            # Persist or update ThreatIndicator
            if not indicator_rec:
                indicator_rec = ThreatIndicator(
                    id=uuid.uuid4(),
                    indicator_type=clean_type,
                    normalized_value=clean_val,
                    reputation=aggregated.consensus_verdict,
                    confidence=aggregated.consensus_confidence,
                    status="ACTIVE",
                    first_seen_at=now_utc,
                    last_seen_at=now_utc,
                    created_at=now_utc,
                )
                db.add(indicator_rec)
                await db.flush()
            else:
                indicator_rec.reputation = aggregated.consensus_verdict
                indicator_rec.confidence = aggregated.consensus_confidence
                indicator_rec.last_seen_at = now_utc

    # 4. Record Sighting if email_id is provided
    if email_id:
        # Find indicator record id if not in scope
        stmt = select(ThreatIndicator.id).where(
            ThreatIndicator.indicator_type == clean_type,
            ThreatIndicator.normalized_value == clean_val,
        )
        ind_res = await db.execute(stmt)
        ind_id = ind_res.scalar_one_or_none()
        if ind_id:
            sighting = IndicatorSighting(
                id=uuid.uuid4(),
                indicator_id=ind_id,
                email_id=email_id,
                observed_at=now_utc,
                context={
                    "consensus_verdict": aggregated.consensus_verdict,
                    "threat_score": aggregated.consensus_threat_score,
                    "tags": aggregated.aggregated_tags,
                    "provider_count": aggregated.provider_count,
                },
            )
            db.add(sighting)

    if auto_commit:
        await db.commit()

    return aggregated


async def enrich_email_threat_intelligence(
    email_id: uuid.UUID,
    db: AsyncSession,
    engine: Optional[ThreatIntelEngine] = None,
) -> Dict[str, Any]:
    """
    Enriches all IOCs extracted from an email (sender, domains, URLs, IPs, attachments)
    concurrently using asyncio.gather and single-transaction persistence.
    """
    # 1. Fetch Email
    email_stmt = select(Email).where(Email.id == email_id)
    email_res = await db.execute(email_stmt)
    email_obj = email_res.scalar_one_or_none()

    iocs_to_enrich: List[tuple[str, str]] = []

    # Sender Domain
    if email_obj and email_obj.sender_address and "@" in email_obj.sender_address:
        sender_dom = email_obj.sender_address.split("@")[-1].strip().lower()
        iocs_to_enrich.append(("DOMAIN", sender_dom))

    # URLs
    urls_stmt = (
        select(URL.normalized_url)
        .join(EmailURL, EmailURL.url_id == URL.id)
        .where(EmailURL.email_id == email_id)
    )
    urls_res = await db.execute(urls_stmt)
    for row in urls_res.all():
        if row[0]:
            iocs_to_enrich.append(("URL", row[0]))

    # Relay Hop IPs
    hops_stmt = select(RelayHop).where(RelayHop.email_id == email_id)
    hops_res = await db.execute(hops_stmt)
    for hop in hops_res.scalars().all():
        if hop.source_ip:
            iocs_to_enrich.append(("IP", hop.source_ip.strip()))

    # Attachment Hashes
    evidence_stmt = select(EvidenceObject).where(
        EvidenceObject.email_id == email_id,
        EvidenceObject.evidence_type == "ATTACHMENT",
    )
    evidence_res = await db.execute(evidence_stmt)
    for ev in evidence_res.scalars().all():
        if ev.sha256_hash:
            iocs_to_enrich.append(("FILE_HASH", ev.sha256_hash))

    # Deduplicate IOCs
    deduped_iocs = list(dict.fromkeys(iocs_to_enrich))

    results: List[AggregatedThreatIntel] = []
    intel_engine = engine or ThreatIntelEngine()
    now_ts = time.time()
    now_utc = datetime.now(timezone.utc)

    # 1. Fast in-memory cache check (0ms)
    uncached_iocs: List[Tuple[str, str]] = []
    for i_type, i_val in deduped_iocs:
        cache_key = f"{i_type.strip().upper()}:{i_val.strip().lower()}"
        cached = _IOC_CACHE.get(cache_key)
        if cached and (now_ts - cached[0]) < _IOC_CACHE_TTL_SECONDS:
            results.append(cached[1])
        else:
            uncached_iocs.append((i_type, i_val))

    if uncached_iocs:
        # 2. Concurrently resolve uncached IOCs using asyncio.gather with semaphore
        sem = asyncio.Semaphore(6)

        async def _query_ioc_safe(item: Tuple[str, str]) -> Tuple[str, str, Optional[AggregatedThreatIntel]]:
            t, v = item
            async with sem:
                try:
                    agg = await asyncio.wait_for(
                        intel_engine.query_indicator(t, v),
                        timeout=3.0,
                    )
                    return (t, v, agg)
                except Exception as exc:
                    logger.debug(f"Threat intel query timed out for {t} {v}: {exc}")
                    return (t, v, None)

        query_tasks = [_query_ioc_safe(item) for item in uncached_iocs]
        query_results = await asyncio.gather(*query_tasks)

        for i_type, i_val, agg in query_results:
            if not agg:
                continue
            clean_type = i_type.strip().upper()
            clean_val = i_val.strip()
            cache_key = f"{clean_type}:{clean_val.lower()}"
            results.append(agg)
            _IOC_CACHE[cache_key] = (now_ts, agg)

            try:
                # Find or create indicator in DB
                stmt = select(ThreatIndicator).where(
                    ThreatIndicator.indicator_type == clean_type,
                    ThreatIndicator.normalized_value == clean_val,
                )
                res = await db.execute(stmt)
                indicator_rec = res.scalar_one_or_none()

                if not indicator_rec:
                    indicator_rec = ThreatIndicator(
                        id=uuid.uuid4(),
                        indicator_type=clean_type,
                        normalized_value=clean_val,
                        reputation=agg.consensus_verdict,
                        confidence=agg.consensus_confidence,
                        status="ACTIVE",
                        first_seen_at=now_utc,
                        last_seen_at=now_utc,
                        created_at=now_utc,
                    )
                    db.add(indicator_rec)
                    await db.flush()
                else:
                    indicator_rec.reputation = agg.consensus_verdict
                    indicator_rec.confidence = agg.consensus_confidence
                    indicator_rec.last_seen_at = now_utc

                if email_id and indicator_rec:
                    sighting = IndicatorSighting(
                        id=uuid.uuid4(),
                        indicator_id=indicator_rec.id,
                        email_id=email_id,
                        observed_at=now_utc,
                        context={
                            "consensus_verdict": agg.consensus_verdict,
                            "threat_score": agg.consensus_threat_score,
                            "tags": agg.aggregated_tags,
                            "provider_count": agg.provider_count,
                        },
                    )
                    db.add(sighting)
            except Exception as e:
                logger.debug(f"Error persisting indicator {clean_val}: {e}")

    # Commit all sightings and indicator records in a single fast transaction
    await db.commit()

    malicious_iocs = [r for r in results if r.consensus_verdict == "MALICIOUS"]
    suspicious_iocs = [r for r in results if r.consensus_verdict == "SUSPICIOUS"]

    return {
        "email_id": str(email_id),
        "total_iocs_analyzed": len(results),
        "malicious_ioc_count": len(malicious_iocs),
        "suspicious_ioc_count": len(suspicious_iocs),
        "overall_threat_level": (
            "CRITICAL" if len(malicious_iocs) >= 2
            else "HIGH" if len(malicious_iocs) == 1
            else "MEDIUM" if len(suspicious_iocs) >= 1
            else "LOW"
        ),
        "indicators": [r.to_dict() for r in results],
    }
