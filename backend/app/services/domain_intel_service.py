import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.intelligence import Domain, DomainDNSRecord, DomainRegistrationIntel, URL, EmailURL
from app.models.emails import Email
from app.intelligence.domain_intel import (
    DomainIntelligenceEngine,
    DomainIntelBundle,
    DNSRecordData,
    RegistrationIntelData,
)

logger = logging.getLogger(__name__)

# In-memory cache for fast domain intelligence lookups: domain -> (timestamp, DomainIntelBundle)
_DOMAIN_CACHE: Dict[str, Tuple[float, DomainIntelBundle]] = {}
_DOMAIN_CACHE_TTL_SECONDS = 3600.0  # 1 hour


async def enrich_and_persist_domain_intelligence(
    domain_name: str,
    db: AsyncSession,
    engine: Optional[DomainIntelligenceEngine] = None,
    force_refresh: bool = False,
    auto_commit: bool = True,
) -> DomainIntelBundle:
    """
    Retrieves domain intelligence using a high-performance Cache -> DB -> Network strategy.
    Returns existing cached/database intelligence instantly, only querying DNS/RDAP when needed.
    """
    clean_domain = domain_name.strip(".").strip().lower()
    now_ts = time.time()
    now_utc = datetime.now(timezone.utc)

    # 1. Check in-memory cache (0ms)
    if not force_refresh:
        cached = _DOMAIN_CACHE.get(clean_domain)
        if cached and (now_ts - cached[0]) < _DOMAIN_CACHE_TTL_SECONDS:
            return cached[1]

    # 2. Check Database before making network calls
    stmt = select(Domain).where(Domain.normalized_domain == clean_domain)
    res = await db.execute(stmt)
    domain_record = res.scalar_one_or_none()

    if not force_refresh and domain_record:
        # Load associated DNS records and registration intel
        dns_stmt = select(DomainDNSRecord).where(DomainDNSRecord.domain_id == domain_record.id)
        dns_res = await db.execute(dns_stmt)
        dns_rows = dns_res.scalars().all()

        reg_stmt = select(DomainRegistrationIntel).where(DomainRegistrationIntel.domain_id == domain_record.id)
        reg_res = await db.execute(reg_stmt)
        reg_row = reg_res.scalar_one_or_none()

        if dns_rows or reg_row:
            # Construct bundle from existing DB records
            dns_data = [
                DNSRecordData(
                    record_type=r.record_type,
                    record_value=r.record_value,
                    ttl=None,
                )
                for r in dns_rows
            ]
            reg_data = None
            if reg_row:
                reg_data = RegistrationIntelData(
                    source=reg_row.source or "RDAP",
                    registrar=reg_row.registrar,
                    registered_at=reg_row.registered_at,
                    expires_at=reg_row.expires_at,
                    nameservers=reg_row.nameservers.get("nameservers", []) if reg_row.nameservers else [],
                    raw_summary=reg_row.raw_summary or {},
                )

            mx_hosts = [r.record_value for r in dns_data if r.record_type == "MX"]
            a_records = [r.record_value for r in dns_data if r.record_type == "A"]
            txt_records = [r.record_value for r in dns_data if r.record_type == "TXT"]
            ns_records = [r.record_value for r in dns_data if r.record_type == "NS"]

            bundle = DomainIntelBundle(
                domain=clean_domain,
                root_domain=domain_record.root_domain or clean_domain,
                dns_records=dns_data,
                registration_intel=reg_data,
                mx_hosts=mx_hosts,
                a_records=a_records,
                txt_records=txt_records,
                ns_records=ns_records,
                is_nrd=False,
                is_dynamic_dns=False,
                is_punycode=clean_domain.startswith("xn--") or ".xn--" in clean_domain,
                risk_tags=[],
                risk_level="LOW" if dns_data else "UNKNOWN",
            )
            _DOMAIN_CACHE[clean_domain] = (now_ts, bundle)
            return bundle

    # 3. If missing from DB, query DNS/RDAP network adapters
    intel_engine = engine or DomainIntelligenceEngine()
    bundle = await intel_engine.analyze_domain(clean_domain)

    if not domain_record:
        domain_record = Domain(
            id=uuid.uuid4(),
            normalized_domain=bundle.domain,
            root_domain=bundle.root_domain,
            first_seen_at=now_utc,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(domain_record)
        await db.flush()
    else:
        domain_record.updated_at = now_utc

    # Clear previous DNS records and Registration Intel for this domain to update with fresh intelligence
    await db.execute(delete(DomainDNSRecord).where(DomainDNSRecord.domain_id == domain_record.id))
    await db.execute(delete(DomainRegistrationIntel).where(DomainRegistrationIntel.domain_id == domain_record.id))

    # Insert DNS Records
    for r in bundle.dns_records:
        dns_rec = DomainDNSRecord(
            id=uuid.uuid4(),
            domain_id=domain_record.id,
            record_type=r.record_type,
            record_value=r.record_value,
            observed_at=now_utc,
            source="DNS_QUERY",
        )
        db.add(dns_rec)

    # Insert Registration Intel
    if bundle.registration_intel:
        reg = bundle.registration_intel
        reg_rec = DomainRegistrationIntel(
            id=uuid.uuid4(),
            domain_id=domain_record.id,
            source=reg.source,
            registrar=reg.registrar,
            registered_at=reg.registered_at,
            expires_at=reg.expires_at,
            nameservers={"nameservers": reg.nameservers},
            raw_summary=reg.raw_summary,
            retrieved_at=now_utc,
            created_at=now_utc,
        )
        db.add(reg_rec)

    if auto_commit:
        await db.commit()
    else:
        await db.flush()

    _DOMAIN_CACHE[clean_domain] = (now_ts, bundle)
    return bundle


async def enrich_email_domains(
    email_id: uuid.UUID,
    db: AsyncSession,
    engine: Optional[DomainIntelligenceEngine] = None,
) -> List[DomainIntelBundle]:
    """
    Finds all domains associated with an email (sender domain, URL domains)
    and executes domain intelligence enrichment sequentially within the DB transaction.
    """
    # Fetch email sender address
    email_stmt = select(Email).where(Email.id == email_id)
    email_res = await db.execute(email_stmt)
    email_obj = email_res.scalar_one_or_none()

    domains_to_query = []
    seen_domains = set()
    if email_obj and email_obj.sender_address:
        if "@" in email_obj.sender_address:
            sender_d = email_obj.sender_address.split("@")[-1].strip().lower()
            if sender_d and sender_d not in seen_domains:
                seen_domains.add(sender_d)
                domains_to_query.append(sender_d)

    # Fetch associated URL domains
    urls_stmt = (
        select(Domain.normalized_domain)
        .join(URL, URL.domain_id == Domain.id)
        .join(EmailURL, EmailURL.url_id == URL.id)
        .where(EmailURL.email_id == email_id)
    )
    urls_res = await db.execute(urls_stmt)
    for row in urls_res.all():
        if row[0]:
            clean_d = row[0].strip().lower()
            if clean_d and clean_d not in seen_domains:
                seen_domains.add(clean_d)
                domains_to_query.append(clean_d)

    results: List[DomainIntelBundle] = []
    intel_engine = engine or DomainIntelligenceEngine()

    for d_name in domains_to_query:
        try:
            bundle = await enrich_and_persist_domain_intelligence(
                domain_name=d_name,
                db=db,
                engine=intel_engine,
                auto_commit=False,
            )
            results.append(bundle)
        except Exception as e:
            logger.warning(f"Error enriching domain {d_name} for email {email_id}: {e}")

    await db.commit()
    return results
