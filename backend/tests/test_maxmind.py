import pytest
from pathlib import Path
from unittest.mock import patch

from app.core.config import settings, Settings
from app.intelligence.maxmind_client import MaxMindIntelligenceClient
from app.intelligence.infrastructure_intel import AsyncASNResolver


def test_maxmind_config_path_resolution():
    """Verify resolved_maxmind_paths discovers GeoLite2-ASN.mmdb across various path styles."""
    # 1. Relative path
    s1 = Settings(MAXMIND_GEOIP_DB_PATH="data/GeoLite2-ASN.mmdb")
    paths1 = s1.resolved_maxmind_paths
    assert len(paths1) > 0
    assert any("GeoLite2-ASN.mmdb" in str(p) for p in paths1)

    # 2. Directory path
    s2 = Settings(MAXMIND_GEOIP_DB_PATH="data")
    paths2 = s2.resolved_maxmind_paths
    assert len(paths2) > 0
    assert any("GeoLite2-ASN.mmdb" in str(p) for p in paths2)

    # 3. Default fallback when None / empty
    s3 = Settings(MAXMIND_GEOIP_DB_PATH="")
    paths3 = s3.resolved_maxmind_paths
    assert len(paths3) > 0
    assert any("GeoLite2-ASN.mmdb" in str(p) for p in paths3)


def test_maxmind_client_asn_lookup():
    """Verify MaxMind client resolves ASN and Organization accurately for public IPs."""
    client = MaxMindIntelligenceClient()
    status = client.get_status()
    assert status["library_installed"] is True
    assert status["asn_database_loaded"] is True

    # Public Google DNS
    google_res = client.lookup_asn("8.8.8.8")
    assert google_res is not None
    assert google_res["asn"] == "AS15169"
    assert "Google" in google_res["asn_org"]
    assert google_res["source"] == "MAXMIND_ASN"

    # Public Cloudflare DNS
    cf_res = client.lookup_asn("1.1.1.1")
    assert cf_res is not None
    assert cf_res["asn"] == "AS13335"
    assert "Cloudflare" in cf_res["asn_org"]

    # Private IP should return None
    assert client.lookup_asn("192.168.1.1") is None
    assert client.lookup_asn("127.0.0.1") is None
    assert client.lookup_asn("10.0.0.1") is None
    client.close()


@pytest.mark.asyncio
async def test_async_asn_resolver_with_maxmind():
    """Verify AsyncASNResolver integrates MaxMind lookup directly and fast-paths resolution."""
    resolver = AsyncASNResolver()
    meta = await resolver.query_ip_metadata("8.8.8.8")

    assert meta["asn"] == "AS15169"
    assert "Google" in meta["asn_org"]
    assert "Google" in meta["isp"]
    assert "maxmind_asn" in meta["raw"]
