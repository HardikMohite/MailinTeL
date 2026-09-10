from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.api.deps import get_current_user
from tests.auth_helpers import TEST_USER

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["app"] == "MailinteL"


def test_health_liveness_endpoint_is_public_and_minimal():
    """GET /health (MVP-07): unauthenticated, and must leak no topology/config."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok"}


def test_health_detailed_endpoint_requires_auth():
    """MVP-07: the diagnostic-rich routes must reject anonymous callers."""
    response = client.get("/api/v1/health/detailed")
    assert response.status_code == 401


def test_health_db_endpoint_requires_auth():
    response = client.get("/api/v1/health/db")
    assert response.status_code == 401


def test_health_storage_endpoint_requires_auth():
    response = client.get("/api/v1/health/storage")
    assert response.status_code == 401


def test_health_redis_endpoint_requires_auth():
    response = client.get("/api/v1/health/redis")
    assert response.status_code == 401


def test_health_ready_endpoint_requires_auth():
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 401


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
@patch("app.api.v1.endpoints.health.storage.check_connectivity")
@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_detailed_health_endpoint_healthy(mock_db_check, mock_storage_check, mock_redis_check):
    mock_db_check.return_value = {
        "connected": True,
        "latency_ms": 1.25,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": None,
    }
    mock_storage_check.return_value = {
        "connected": True,
        "latency_ms": 1.5,
        "endpoint": "localhost:9000",
        "available_buckets": ["mailintel-evidence"],
        "required_buckets": ["mailintel-evidence"],
        "error": None,
    }
    mock_redis_check.return_value = {
        "connected": True,
        "latency_ms": 0.5,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/detailed")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "MailinteL"
    assert data["services"]["postgres"]["status"] == "connected"
    assert data["services"]["minio"]["status"] == "connected"
    assert data["services"]["redis"]["status"] == "connected"
    assert data["demo_context"]["role"] == "Development Admin"


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
@patch("app.api.v1.endpoints.health.storage.check_connectivity")
@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_detailed_health_endpoint_degraded(mock_db_check, mock_storage_check, mock_redis_check):
    mock_db_check.return_value = {
        "connected": False,
        "latency_ms": 5.0,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": "Connection refused",
    }
    mock_storage_check.return_value = {
        "connected": True,
        "latency_ms": 1.5,
        "endpoint": "localhost:9000",
        "available_buckets": [],
        "required_buckets": [],
        "error": None,
    }
    mock_redis_check.return_value = {
        "connected": True,
        "latency_ms": 0.5,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/detailed")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["services"]["postgres"]["status"] == "disconnected"


@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_db_health_endpoint_connected(mock_db_check):
    mock_db_check.return_value = {
        "connected": True,
        "latency_ms": 0.85,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/db")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "connected"
    assert data["database"] == "mailintel"
    assert data["error"] is None


@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_db_health_endpoint_disconnected(mock_db_check):
    mock_db_check.return_value = {
        "connected": False,
        "latency_ms": 2.1,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": "Connection timed out",
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/db")
    app.dependency_overrides.clear()

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "disconnected"
    assert data["error"] == "Connection timed out"


@patch("app.api.v1.endpoints.health.storage.check_connectivity")
def test_storage_health_endpoint_connected(mock_storage_check):
    mock_storage_check.return_value = {
        "connected": True,
        "latency_ms": 1.1,
        "endpoint": "localhost:9000",
        "available_buckets": ["mailintel-evidence", "mailintel-derived"],
        "required_buckets": ["mailintel-evidence"],
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/storage")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "connected"
    assert "mailintel-evidence" in data["available_buckets"]


@patch("app.api.v1.endpoints.health.storage.check_connectivity")
def test_storage_health_endpoint_disconnected(mock_storage_check):
    mock_storage_check.return_value = {
        "connected": False,
        "latency_ms": 3.4,
        "endpoint": "localhost:9000",
        "available_buckets": [],
        "required_buckets": ["mailintel-evidence"],
        "error": "MinIO offline",
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/storage")
    app.dependency_overrides.clear()

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "disconnected"
    assert data["error"] == "MinIO offline"


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
def test_redis_health_endpoint_connected(mock_redis_check):
    mock_redis_check.return_value = {
        "connected": True,
        "latency_ms": 0.45,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/redis")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "connected"
    assert data["port"] == 6379
    assert data["error"] is None


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
def test_redis_health_endpoint_disconnected(mock_redis_check):
    mock_redis_check.return_value = {
        "connected": False,
        "latency_ms": 2.0,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": "Connection refused",
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/redis")
    app.dependency_overrides.clear()

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "disconnected"
    assert data["error"] == "Connection refused"


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
@patch("app.api.v1.endpoints.health.storage.check_connectivity")
@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_readiness_endpoint_ready(mock_db_check, mock_storage_check, mock_redis_check):
    mock_db_check.return_value = {
        "connected": True,
        "latency_ms": 1.0,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": None,
    }
    mock_storage_check.return_value = {
        "connected": True,
        "latency_ms": 1.0,
        "endpoint": "localhost:9000",
        "available_buckets": ["mailintel-evidence"],
        "required_buckets": ["mailintel-evidence"],
        "error": None,
    }
    mock_redis_check.return_value = {
        "connected": True,
        "latency_ms": 0.5,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/ready")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["status"] == "ready"
    assert data["services"]["postgres"]["status"] == "connected"
    assert data["services"]["minio"]["status"] == "connected"
    assert data["services"]["redis"]["status"] == "connected"


@patch("app.api.v1.endpoints.health.redis_manager.check_connectivity", new_callable=AsyncMock)
@patch("app.api.v1.endpoints.health.storage.check_connectivity")
@patch("app.api.v1.endpoints.health.check_db_connectivity", new_callable=AsyncMock)
def test_readiness_endpoint_not_ready(mock_db_check, mock_storage_check, mock_redis_check):
    mock_db_check.return_value = {
        "connected": True,
        "latency_ms": 1.0,
        "database": "mailintel",
        "host": "localhost",
        "port": 5432,
        "error": None,
    }
    # Storage is down
    mock_storage_check.return_value = {
        "connected": False,
        "latency_ms": 3.0,
        "endpoint": "localhost:9000",
        "available_buckets": [],
        "required_buckets": ["mailintel-evidence"],
        "error": "MinIO offline",
    }
    mock_redis_check.return_value = {
        "connected": True,
        "latency_ms": 0.5,
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "error": None,
    }
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/health/ready")
    app.dependency_overrides.clear()

    assert response.status_code == 503
    data = response.json()
    assert data["ready"] is False
    assert data["status"] == "not_ready"
    assert data["services"]["minio"]["status"] == "disconnected"
