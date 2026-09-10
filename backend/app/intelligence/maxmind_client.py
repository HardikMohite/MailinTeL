import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
import ipaddress

from app.core.config import settings

logger = logging.getLogger("mailintel.intelligence.maxmind")

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    geoip2 = None


class MaxMindIntelligenceClient:
    """
    High-performance, thread-safe client for MaxMind GeoIP2 and GeoLite2 databases (.mmdb).
    Supports GeoLite2-ASN (Autonomous System Number & Organization) and
    GeoLite2-City / GeoLite2-Country databases with sub-millisecond local lookups.
    """

    def __init__(self):
        self._asn_reader: Optional[Any] = None
        self._city_reader: Optional[Any] = None
        self._initialized: bool = False
        self._loaded_paths: List[str] = []

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        if not GEOIP2_AVAILABLE:
            logger.info("MaxMind libraries (geoip2 / maxminddb) are not installed. Using offline heuristic fallbacks.")
            return

        db_paths = settings.resolved_maxmind_paths
        if not db_paths:
            logger.info("No MaxMind .mmdb database files found in configured paths.")
            return

        for path in db_paths:
            try:
                reader = geoip2.database.Reader(str(path))
                db_type = getattr(reader.metadata(), "database_type", "")
                self._loaded_paths.append(f"{path.name} ({db_type})")

                if "ASN" in db_type:
                    self._asn_reader = reader
                    logger.info("Loaded MaxMind ASN database: %s", path)
                elif "City" in db_type or "Country" in db_type:
                    self._city_reader = reader
                    logger.info("Loaded MaxMind City/Country database: %s", path)
                else:
                    # Generic fallback: inspect methods or try both
                    if not self._asn_reader and hasattr(reader, "asn"):
                        self._asn_reader = reader
                    if not self._city_reader and hasattr(reader, "city"):
                        self._city_reader = reader
            except Exception as e:
                logger.warning("Failed to initialize MaxMind reader for %s: %s", path, e)

    def lookup_asn(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """
        Looks up Autonomous System Number (ASN) and Organization for an IP address.
        Returns None if private, invalid, not found, or database is unavailable.
        """
        self._ensure_initialized()
        if not self._asn_reader:
            return None

        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return None

            res = self._asn_reader.asn(clean_ip)
            asn_val = f"AS{res.autonomous_system_number}" if res.autonomous_system_number else None
            org_val = res.autonomous_system_organization or None

            return {
                "asn": asn_val,
                "asn_number": res.autonomous_system_number,
                "asn_org": org_val,
                "network": str(res.network) if res.network else None,
                "source": "MAXMIND_ASN",
            }
        except Exception:
            # AddressNotFoundError or invalid address
            return None

    def lookup_city(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """
        Looks up Geographic location (Country, Region, City, Coordinates) for an IP address.
        Returns None if private, invalid, not found, or City database is unavailable.
        """
        self._ensure_initialized()
        if not self._city_reader:
            return None

        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return None

            res = self._city_reader.city(clean_ip)
            region = res.subdivisions.most_specific.name if res.subdivisions else None
            return {
                "country_code": res.country.iso_code,
                "country_name": res.country.name,
                "region_name": region,
                "city_name": res.city.name,
                "latitude": float(res.location.latitude) if res.location.latitude is not None else None,
                "longitude": float(res.location.longitude) if res.location.longitude is not None else None,
                "accuracy_radius_km": res.location.accuracy_radius,
                "source": "MAXMIND_CITY",
            }
        except Exception:
            return None

    def get_status(self) -> Dict[str, Any]:
        """Returns the operational status of the MaxMind intelligence engine."""
        self._ensure_initialized()
        return {
            "library_installed": GEOIP2_AVAILABLE,
            "asn_database_loaded": self._asn_reader is not None,
            "city_database_loaded": self._city_reader is not None,
            "loaded_databases": self._loaded_paths,
            "configured_path": settings.MAXMIND_GEOIP_DB_PATH,
        }

    def close(self) -> None:
        """Closes any open reader file handles."""
        if self._asn_reader:
            try:
                self._asn_reader.close()
            except Exception:
                pass
            self._asn_reader = None
        if self._city_reader:
            try:
                self._city_reader.close()
            except Exception:
                pass
            self._city_reader = None
        self._initialized = False


maxmind_client = MaxMindIntelligenceClient()
