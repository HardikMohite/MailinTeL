import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.models.intelligence import (
    IPAddress,
    Geolocation,
    EntityGeolocation,
    Domain,
    DomainDNSRecord,
)
from app.models.emails import Email, EmailSource, RelayHop, EmailHeader
from app.models.campaign import Campaign, CampaignMembership
from app.intelligence.origin_deducer import human_origin_deducer
from app.intelligence.geo_resolver import (
    AsyncGeoIPResolver,
    GeoIPResult,
    default_geoip_resolver,
    ATTRIBUTION_DISCLAIMER,
)

import time
from app.core.redis import redis_manager

logger = logging.getLogger("mailintel.services.geo")

# High-speed in-memory caches for geo queries
_GEO_IP_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_GEO_EMAIL_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_GEO_CAMPAIGN_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_GEO_GLOBAL_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_GEO_CACHE_TTL: float = 1800.0
_GEO_IP_TTL: float = 86400.0  # 24 hours for IP location


class GeolocationService:
    """
    Forensic Infrastructure Geolocation Service.
    Resolves, maps, and persists geographic coordinates of observable network infrastructure
    (transmission hops, originating servers, MX hosts, domain servers).
    Maintains strict attribution integrity disclaimers.
    """

    @staticmethod
    async def invalidate_geo_cache(email_id: Optional[uuid.UUID] = None, campaign_id: Optional[uuid.UUID] = None) -> None:
        """Invalidates geo infrastructure caches."""
        try:
            _GEO_GLOBAL_CACHE.clear()
            if email_id:
                _GEO_EMAIL_CACHE.pop(str(email_id), None)
                await redis_manager.delete(f"cache:geo:email:{email_id}")
            if campaign_id:
                _GEO_CAMPAIGN_CACHE.pop(str(campaign_id), None)
                await redis_manager.delete(f"cache:geo:campaign:{campaign_id}")
        except Exception as e:
            logger.warning(f"Geo cache invalidation notice: {e}")

    def __init__(self, resolver: Optional[AsyncGeoIPResolver] = None):
        self.resolver = resolver or default_geoip_resolver

    async def geolocate_ip(
        self,
        session: AsyncSession,
        ip_address: str,
        entity_id: Optional[uuid.UUID] = None,
        relationship_type: str = "IP_ORIGIN",
        host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolves an IP address to geolocation metadata and connection classification,
        persisting Geolocation & EntityGeolocation records.
        """
        clean_ip = ip_address.strip()
        now = time.time()
        # Fast path if IP already resolved and no entity linkage requested
        if not entity_id and clean_ip in _GEO_IP_CACHE:
            ts, data = _GEO_IP_CACHE[clean_ip]
            if now - ts < _GEO_IP_TTL:
                return data
        if not entity_id:
            try:
                r_data = await redis_manager.get_json(f"cache:geo:ip:{clean_ip}")
                if r_data:
                    _GEO_IP_CACHE[clean_ip] = (now, r_data)
                    return r_data
            except Exception:
                pass

        geo_result = await self.resolver.resolve_ip_geolocation(clean_ip, host=host)

        now_utc = datetime.now(timezone.utc)

        # 1. Look up or create IPAddress record
        ip_stmt = select(IPAddress).where(IPAddress.ip_address == clean_ip)
        ip_res = await session.execute(ip_stmt)
        ip_record = ip_res.scalar_one_or_none()
        if not ip_record:
            ip_record = IPAddress(
                id=uuid.uuid4(),
                ip_address=clean_ip,
                first_seen_at=now_utc,
                created_at=now_utc,
            )
            session.add(ip_record)
            await session.flush()

        # 2. Persist Geolocation record if non-private coordinates or valid country
        geo_record = None
        if geo_result.country_code != "UNKNOWN":
            geo_stmt = select(Geolocation).where(
                Geolocation.country_code == geo_result.country_code,
                Geolocation.city_name == geo_result.city_name,
                Geolocation.region_name == geo_result.region_name,
            )
            geo_res = await session.execute(geo_stmt)
            geo_record = geo_res.scalar_one_or_none()

            if not geo_record:
                geo_record = Geolocation(
                    id=uuid.uuid4(),
                    country_code=geo_result.country_code,
                    country_name=geo_result.country_name,
                    region_name=geo_result.region_name,
                    city_name=geo_result.city_name,
                    latitude=geo_result.latitude,
                    longitude=geo_result.longitude,
                    accuracy_radius_km=geo_result.accuracy_radius_km,
                    source=geo_result.source,
                    confidence=geo_result.confidence,
                    created_at=now_utc,
                )
                session.add(geo_record)
                await session.flush()

            # 3. Connect EntityGeolocation link if entity_id or ip_record.id is available
            target_entity_id = entity_id or ip_record.id
            link_stmt = select(EntityGeolocation).where(
                EntityGeolocation.entity_id == target_entity_id,
                EntityGeolocation.geolocation_id == geo_record.id,
                EntityGeolocation.relationship_type == relationship_type,
            )
            link_res = await session.execute(link_stmt)
            existing_link = link_res.scalar_one_or_none()

            if not existing_link:
                new_link = EntityGeolocation(
                    id=uuid.uuid4(),
                    entity_id=target_entity_id,
                    geolocation_id=geo_record.id,
                    relationship_type=relationship_type,
                    confidence=geo_result.confidence,
                    evidence={
                        "ip_address": clean_ip,
                        "is_private": geo_result.is_private,
                        "source": geo_result.source,
                        "connection_type": geo_result.connection_type,
                        "provider": geo_result.provider,
                    },
                    created_at=now_utc,
                )
                session.add(new_link)
                await session.flush()

        await session.commit()

        res_dict = {
            "ip_address": clean_ip,
            "is_private": geo_result.is_private,
            "country_code": geo_result.country_code,
            "country_name": geo_result.country_name,
            "region_name": geo_result.region_name,
            "city_name": geo_result.city_name,
            "latitude": geo_result.latitude,
            "longitude": geo_result.longitude,
            "accuracy_radius_km": geo_result.accuracy_radius_km,
            "source": geo_result.source,
            "confidence": geo_result.confidence,
            "attribution_statement": geo_result.attribution_statement,
            "connection_type": geo_result.connection_type,
            "provider": geo_result.provider,
            "is_tor": geo_result.is_tor,
            "is_vpn": geo_result.is_vpn,
            "is_datacenter": geo_result.is_datacenter,
            "is_cloud": geo_result.is_cloud,
            "is_personal_mail": geo_result.is_personal_mail,
            "asn": geo_result.asn,
            "asn_org": geo_result.asn_org,
            "classification_badges": geo_result.classification_badges,
        }
        _GEO_IP_CACHE[clean_ip] = (now, res_dict)
        try:
            await redis_manager.set_json(f"cache:geo:ip:{clean_ip}", res_dict, expire_seconds=86400)
        except Exception:
            pass
        return res_dict

    async def geolocate_email_infrastructure(
        self, session: AsyncSession, email_id: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Extracts and geolocates all relay hops and infrastructure nodes for an email,
        constructing ordered transmission paths and geographic markers.
        """
        now = time.time()
        key = str(email_id)
        if key in _GEO_EMAIL_CACHE:
            ts, data = _GEO_EMAIL_CACHE[key]
            if now - ts < _GEO_CACHE_TTL:
                return data
        try:
            r_data = await redis_manager.get_json(f"cache:geo:email:{key}")
            if r_data:
                _GEO_EMAIL_CACHE[key] = (now, r_data)
                return r_data
        except Exception:
            pass

        # Fetch email
        email_stmt = select(Email).where(Email.id == email_id)
        email_res = await session.execute(email_stmt)
        email = email_res.scalar_one_or_none()
        if not email:
            return {
                "email_id": str(email_id),
                "total_markers": 0,
                "markers": [],
                "paths": [],
                "country_distribution": {},
                "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
            }

        # Fetch relay hops ordered by sequence_number
        hops_stmt = (
            select(RelayHop)
            .where(RelayHop.email_id == email_id)
            .order_by(RelayHop.sequence_number.asc())
        )
        hops_res = await session.execute(hops_stmt)
        hops = hops_res.scalars().all()

        markers: List[Dict[str, Any]] = []
        hop_nodes: List[Dict[str, Any]] = []
        seen_marker_coords: Set[str] = set()
        country_counts: Dict[str, int] = {}

        for hop in hops:
            if not hop.source_ip:
                continue
            
            geo_info = await self.geolocate_ip(
                session,
                hop.source_ip,
                entity_id=hop.id,
                relationship_type="HOP_LOCATION",
                host=hop.source_host,
            )

            hop_item = {
                "sequence_number": hop.sequence_number,
                "source_host": hop.source_host,
                "source_ip": hop.source_ip,
                "destination_host": hop.destination_host,
                "reliability": hop.reliability,
                "geolocation": geo_info,
                "connection_type": geo_info.get("connection_type", "RELAY"),
                "provider": geo_info.get("provider"),
                "is_tor": geo_info.get("is_tor", False),
                "is_vpn": geo_info.get("is_vpn", False),
                "is_datacenter": geo_info.get("is_datacenter", False),
                "is_cloud": geo_info.get("is_cloud", False),
                "is_personal_mail": geo_info.get("is_personal_mail", False),
                "asn": geo_info.get("asn"),
                "asn_org": geo_info.get("asn_org"),
                "classification_badges": geo_info.get("classification_badges", []),
            }
            hop_nodes.append(hop_item)

            if geo_info.get("latitude") is not None and geo_info.get("longitude") is not None:
                cc = geo_info.get("country_code", "UNKNOWN")
                country_counts[cc] = country_counts.get(cc, 0) + 1

                coord_key = f"{geo_info['latitude']},{geo_info['longitude']}"
                if coord_key not in seen_marker_coords:
                    seen_marker_coords.add(coord_key)
                    markers.append({
                        "id": f"marker-hop-{hop.sequence_number}-{hop.source_ip}",
                        "entity_type": "RELAY_HOP",
                        "sequence_number": hop.sequence_number,
                        "ip_address": hop.source_ip,
                        "host": hop.source_host or hop.source_ip,
                        "latitude": geo_info["latitude"],
                        "longitude": geo_info["longitude"],
                        "country_code": geo_info["country_code"],
                        "country_name": geo_info["country_name"],
                        "region_name": geo_info["region_name"],
                        "city_name": geo_info["city_name"],
                        "accuracy_radius_km": geo_info["accuracy_radius_km"],
                        "confidence": geo_info["confidence"],
                        "role": "ORIGIN_HOP" if hop.sequence_number == 1 else "RELAY_INTERMEDIARY",
                        "connection_type": geo_info.get("connection_type", "RELAY"),
                        "provider": geo_info.get("provider"),
                        "is_tor": geo_info.get("is_tor", False),
                        "is_vpn": geo_info.get("is_vpn", False),
                        "is_datacenter": geo_info.get("is_datacenter", False),
                        "is_cloud": geo_info.get("is_cloud", False),
                        "is_personal_mail": geo_info.get("is_personal_mail", False),
                        "asn": geo_info.get("asn"),
                        "asn_org": geo_info.get("asn_org"),
                        "classification_badges": geo_info.get("classification_badges", []),
                    })

        # Build transmission path lines
        paths: List[Dict[str, Any]] = []
        valid_coords_hops = [
            h for h in hop_nodes
            if h["geolocation"].get("latitude") is not None and h["geolocation"].get("longitude") is not None
        ]

        for i in range(len(valid_coords_hops) - 1):
            src_hop = valid_coords_hops[i]
            dst_hop = valid_coords_hops[i + 1]
            paths.append({
                "from_hop": src_hop["sequence_number"],
                "to_hop": dst_hop["sequence_number"],
                "from_ip": src_hop["source_ip"],
                "to_ip": dst_hop["source_ip"],
                "from_coords": [src_hop["geolocation"]["latitude"], src_hop["geolocation"]["longitude"]],
                "to_coords": [dst_hop["geolocation"]["latitude"], dst_hop["geolocation"]["longitude"]],
                "label": f"Hop {src_hop['sequence_number']} → Hop {dst_hop['sequence_number']}",
            })

        # 4. Multi-Artifact Human Origin Location Deduction
        headers_stmt = select(EmailHeader).where(EmailHeader.email_id == email_id)
        headers_res = await session.execute(headers_stmt)
        headers_list = [{"header_name": h.header_name, "header_value": h.header_value} for h in headers_res.scalars().all()]

        deduced_verdict = human_origin_deducer.deduce_origin(
            raw_headers=headers_list,
            body_text=None,
            hops=hop_nodes,
        )

        if deduced_verdict.deduced_country and deduced_verdict.latitude is not None and deduced_verdict.longitude is not None:
            first_hop_lat = valid_coords_hops[0]["geolocation"]["latitude"] if valid_coords_hops else None
            first_hop_lon = valid_coords_hops[0]["geolocation"]["longitude"] if valid_coords_hops else None

            is_distinct_from_mta = True
            if first_hop_lat is not None and first_hop_lon is not None:
                is_distinct_from_mta = abs(deduced_verdict.latitude - first_hop_lat) > 0.5 or abs(deduced_verdict.longitude - first_hop_lon) > 0.5

            if is_distinct_from_mta and deduced_verdict.is_redacted_by_provider:
                origin_marker = {
                    "id": "marker-deduced-human-origin",
                    "entity_type": "DEDUCED_HUMAN_ORIGIN",
                    "sequence_number": 0,
                    "ip_address": "Redacted (Privacy Shield)",
                    "host": f"Human Composer ({deduced_verdict.deduced_city})",
                    "latitude": deduced_verdict.latitude,
                    "longitude": deduced_verdict.longitude,
                    "country_code": deduced_verdict.deduced_country_code,
                    "country_name": deduced_verdict.deduced_country,
                    "region_name": deduced_verdict.deduced_region,
                    "city_name": deduced_verdict.deduced_city,
                    "accuracy_radius_km": deduced_verdict.accuracy_radius_km,
                    "confidence": deduced_verdict.confidence_score,
                    "role": "DEDUCED_HUMAN_ORIGIN",
                    "connection_type": "PERSONAL_MAIL",
                    "provider": f"Forensic Artifact Triangulation ({deduced_verdict.confidence_level} Confidence)",
                    "is_tor": False,
                    "is_vpn": False,
                    "is_datacenter": False,
                    "is_cloud": False,
                    "is_personal_mail": True,
                    "classification_badges": ["HUMAN_ORIGIN_DEDUCED", f"CONFIDENCE_{deduced_verdict.confidence_level}"],
                    "evidence_signals": [s.to_dict() for s in deduced_verdict.evidence_signals],
                    "forensic_explanation": deduced_verdict.forensic_explanation,
                }
                markers.insert(0, origin_marker)

                if valid_coords_hops:
                    first_relay = valid_coords_hops[0]
                    paths.insert(0, {
                        "from_hop": 0,
                        "to_hop": first_relay["sequence_number"],
                        "from_ip": "Client Device",
                        "to_ip": first_relay["source_ip"],
                        "from_coords": [deduced_verdict.latitude, deduced_verdict.longitude],
                        "to_coords": [first_relay["geolocation"]["latitude"], first_relay["geolocation"]["longitude"]],
                        "label": f"Human Author ({deduced_verdict.deduced_city}) -> Ingest Relay ({first_relay['source_ip']})",
                        "is_inferred": True,
                    })

        tor_count = sum(1 for m in markers if m.get("is_tor"))
        vpn_count = sum(1 for m in markers if m.get("is_vpn"))
        cloud_count = sum(1 for m in markers if m.get("is_cloud") or m.get("is_datacenter"))
        personal_count = sum(1 for m in markers if m.get("is_personal_mail"))

        res_dict = {
            "email_id": str(email_id),
            "subject": email.subject,
            "total_hops": len(hops),
            "total_markers": len(markers),
            "tor_node_count": tor_count,
            "vpn_node_count": vpn_count,
            "cloud_node_count": cloud_count,
            "personal_mail_node_count": personal_count,
            "hops": hop_nodes,
            "markers": markers,
            "paths": paths,
            "country_distribution": country_counts,
            "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
            "deduced_human_origin": deduced_verdict.to_dict(),
        }
        _GEO_EMAIL_CACHE[key] = (now, res_dict)
        try:
            await redis_manager.set_json(f"cache:geo:email:{key}", res_dict, expire_seconds=1800)
        except Exception:
            pass
        return res_dict

    async def geolocate_campaign_infrastructure(
        self, session: AsyncSession, campaign_id: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Geolocates all observable infrastructure across all emails belonging to a threat campaign.
        """
        now = time.time()
        key = str(campaign_id)
        if key in _GEO_CAMPAIGN_CACHE:
            ts, data = _GEO_CAMPAIGN_CACHE[key]
            if now - ts < _GEO_CACHE_TTL:
                return data
        try:
            r_data = await redis_manager.get_json(f"cache:geo:campaign:{key}")
            if r_data:
                _GEO_CAMPAIGN_CACHE[key] = (now, r_data)
                return r_data
        except Exception:
            pass

        camp_stmt = select(Campaign).where(Campaign.id == campaign_id)
        camp_res = await session.execute(camp_stmt)
        campaign = camp_res.scalar_one_or_none()
        if not campaign:
            return {
                "campaign_id": str(campaign_id),
                "campaign_name": "Unknown",
                "total_markers": 0,
                "markers": [],
                "country_distribution": {},
                "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
            }

        # Fetch emails in campaign
        ce_stmt = select(CampaignMembership.email_id).where(CampaignMembership.campaign_id == campaign_id)
        ce_res = await session.execute(ce_stmt)
        email_ids = ce_res.scalars().all()

        if not email_ids:
            return {
                "campaign_id": str(campaign_id),
                "campaign_name": campaign.campaign_name or "Unnamed Campaign",
                "campaign_status": campaign.campaign_status,
                "total_emails": 0,
                "total_markers": 0,
                "tor_node_count": 0,
                "vpn_node_count": 0,
                "cloud_node_count": 0,
                "personal_mail_node_count": 0,
                "markers": [],
                "country_distribution": {},
                "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
            }

        # Get all relay hops for member emails
        hops_stmt = (
            select(RelayHop)
            .where(RelayHop.email_id.in_(email_ids))
            .order_by(RelayHop.email_id, RelayHop.sequence_number.asc())
        )
        hops_res = await session.execute(hops_stmt)
        all_hops = hops_res.scalars().all()

        unique_ips: Set[str] = set()
        ip_to_host: Dict[str, str] = {}
        for hop in all_hops:
            if hop.source_ip:
                clean_h_ip = hop.source_ip.strip()
                unique_ips.add(clean_h_ip)
                if hop.source_host and clean_h_ip not in ip_to_host:
                    ip_to_host[clean_h_ip] = hop.source_host

        markers: List[Dict[str, Any]] = []
        country_counts: Dict[str, int] = {}
        ip_to_emails: Dict[str, List[str]] = {}

        for hop in all_hops:
            if hop.source_ip:
                clean_ip = hop.source_ip.strip()
                if clean_ip not in ip_to_emails:
                    ip_to_emails[clean_ip] = []
                eid_str = str(hop.email_id)
                if eid_str not in ip_to_emails[clean_ip]:
                    ip_to_emails[clean_ip].append(eid_str)

        for ip in unique_ips:
            geo_info = await self.geolocate_ip(
                session,
                ip,
                entity_id=campaign.id,
                relationship_type="CAMPAIGN_INFRASTRUCTURE",
                host=ip_to_host.get(ip),
            )
            if geo_info.get("latitude") is not None and geo_info.get("longitude") is not None:
                cc = geo_info.get("country_code", "UNKNOWN")
                country_counts[cc] = country_counts.get(cc, 0) + 1

                associated_emails = ip_to_emails.get(ip, [])
                markers.append({
                    "id": f"marker-camp-ip-{ip}",
                    "entity_type": "IP_INFRASTRUCTURE",
                    "ip_address": ip,
                    "host": ip_to_host.get(ip),
                    "latitude": geo_info["latitude"],
                    "longitude": geo_info["longitude"],
                    "country_code": geo_info["country_code"],
                    "country_name": geo_info["country_name"],
                    "region_name": geo_info["region_name"],
                    "city_name": geo_info["city_name"],
                    "accuracy_radius_km": geo_info["accuracy_radius_km"],
                    "confidence": geo_info["confidence"],
                    "associated_email_count": len(associated_emails),
                    "associated_email_ids": associated_emails,
                    "connection_type": geo_info.get("connection_type", "RELAY"),
                    "provider": geo_info.get("provider"),
                    "is_tor": geo_info.get("is_tor", False),
                    "is_vpn": geo_info.get("is_vpn", False),
                    "is_datacenter": geo_info.get("is_datacenter", False),
                    "is_cloud": geo_info.get("is_cloud", False),
                    "is_personal_mail": geo_info.get("is_personal_mail", False),
                    "asn": geo_info.get("asn"),
                    "asn_org": geo_info.get("asn_org"),
                    "classification_badges": geo_info.get("classification_badges", []),
                })

        tor_count = sum(1 for m in markers if m.get("is_tor"))
        vpn_count = sum(1 for m in markers if m.get("is_vpn"))
        cloud_count = sum(1 for m in markers if m.get("is_cloud") or m.get("is_datacenter"))
        personal_count = sum(1 for m in markers if m.get("is_personal_mail"))

        res_dict = {
            "campaign_id": str(campaign_id),
            "campaign_name": campaign.campaign_name or "Unnamed Campaign",
            "campaign_status": campaign.campaign_status,
            "total_emails": len(email_ids),
            "total_unique_ips": len(unique_ips),
            "total_markers": len(markers),
            "tor_node_count": tor_count,
            "vpn_node_count": vpn_count,
            "cloud_node_count": cloud_count,
            "personal_mail_node_count": personal_count,
            "markers": markers,
            "country_distribution": country_counts,
            "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
        }
        _GEO_CAMPAIGN_CACHE[key] = (now, res_dict)
        try:
            await redis_manager.set_json(f"cache:geo:campaign:{key}", res_dict, expire_seconds=1800)
        except Exception:
            pass
        return res_dict

    async def get_global_geo_infrastructure(
        self, session: AsyncSession, limit_emails: int = 50, organization_id: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """
        Global overview of observable infrastructure across recent emails.
        """
        now = time.time()
        key = f"{organization_id or 'all'}:{limit_emails}"
        if key in _GEO_GLOBAL_CACHE:
            ts, data = _GEO_GLOBAL_CACHE[key]
            if now - ts < 600.0:
                return data
        try:
            r_data = await redis_manager.get_json(f"cache:geo:global:{key}")
            if r_data:
                _GEO_GLOBAL_CACHE[key] = (now, r_data)
                return r_data
        except Exception:
            pass

        recent_emails_stmt = select(Email.id).order_by(Email.created_at.desc()).limit(limit_emails)
        if organization_id is not None:
            recent_emails_stmt = recent_emails_stmt.join(
                EmailSource, EmailSource.id == Email.source_id
            ).where(EmailSource.organization_id == organization_id)
        recent_emails_res = await session.execute(recent_emails_stmt)
        email_ids = recent_emails_res.scalars().all()

        if not email_ids:
            empty_res = {
                "total_emails_scanned": 0,
                "total_markers": 0,
                "tor_node_count": 0,
                "vpn_node_count": 0,
                "cloud_node_count": 0,
                "personal_mail_node_count": 0,
                "markers": [],
                "country_distribution": {},
                "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
            }
            _GEO_GLOBAL_CACHE[key] = (now, empty_res)
            try:
                await redis_manager.set_json(f"cache:geo:global:{key}", empty_res, expire_seconds=600)
            except Exception:
                pass
            return empty_res

        hops_stmt = select(RelayHop).where(RelayHop.email_id.in_(email_ids))
        hops_res = await session.execute(hops_stmt)
        all_hops = hops_res.scalars().all()

        unique_ips: Set[str] = set()
        ip_to_host: Dict[str, str] = {}
        for hop in all_hops:
            if hop.source_ip:
                clean_ip_g = hop.source_ip.strip()
                unique_ips.add(clean_ip_g)
                if hop.source_host and clean_ip_g not in ip_to_host:
                    ip_to_host[clean_ip_g] = hop.source_host

        markers: List[Dict[str, Any]] = []
        country_counts: Dict[str, int] = {}

        for ip in unique_ips:
            geo_info = await self.geolocate_ip(session, ip, host=ip_to_host.get(ip))
            if geo_info.get("latitude") is not None and geo_info.get("longitude") is not None:
                cc = geo_info.get("country_code", "UNKNOWN")
                country_counts[cc] = country_counts.get(cc, 0) + 1
                markers.append({
                    "id": f"marker-global-{ip}",
                    "ip_address": ip,
                    "host": ip_to_host.get(ip),
                    "latitude": geo_info["latitude"],
                    "longitude": geo_info["longitude"],
                    "country_code": geo_info["country_code"],
                    "country_name": geo_info["country_name"],
                    "city_name": geo_info["city_name"],
                    "confidence": geo_info["confidence"],
                    "connection_type": geo_info.get("connection_type", "RELAY"),
                    "provider": geo_info.get("provider"),
                    "is_tor": geo_info.get("is_tor", False),
                    "is_vpn": geo_info.get("is_vpn", False),
                    "is_datacenter": geo_info.get("is_datacenter", False),
                    "is_cloud": geo_info.get("is_cloud", False),
                    "is_personal_mail": geo_info.get("is_personal_mail", False),
                    "asn": geo_info.get("asn"),
                    "asn_org": geo_info.get("asn_org"),
                    "classification_badges": geo_info.get("classification_badges", []),
                })

        tor_count = sum(1 for m in markers if m.get("is_tor"))
        vpn_count = sum(1 for m in markers if m.get("is_vpn"))
        cloud_count = sum(1 for m in markers if m.get("is_cloud") or m.get("is_datacenter"))
        personal_count = sum(1 for m in markers if m.get("is_personal_mail"))

        res_dict = {
            "total_emails_scanned": len(email_ids),
            "total_unique_ips": len(unique_ips),
            "total_markers": len(markers),
            "tor_node_count": tor_count,
            "vpn_node_count": vpn_count,
            "cloud_node_count": cloud_count,
            "personal_mail_node_count": personal_count,
            "markers": markers,
            "country_distribution": country_counts,
            "attribution_disclaimer": ATTRIBUTION_DISCLAIMER,
        }
        _GEO_GLOBAL_CACHE[key] = (now, res_dict)
        try:
            await redis_manager.set_json(f"cache:geo:global:{key}", res_dict, expire_seconds=600)
        except Exception:
            pass
        return res_dict


default_geo_service = GeolocationService()
