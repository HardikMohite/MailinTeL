import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_get_notifications_rest():
    client = TestClient(app)
    response = client.get("/api/v1/notifications")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1

def test_trigger_test_notification():
    client = TestClient(app)
    payload = {
        "title": "Unit Test Phishing Ping",
        "message": "Testing real-time broadcast engine",
        "severity": "critical",
        "type": "PHISHING_ALERT",
        "data": {"test_key": "val123"}
    }
    response = client.post("/api/v1/notifications/test", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "broadcast_sent"
    assert data["notification"]["title"] == "Unit Test Phishing Ping"

def test_websocket_notifications_connection():
    client = TestClient(app)
    with client.websocket_connect("/ws/notifications") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "CONNECTED"
        assert "notifications" in data
        assert isinstance(data["notifications"], list)
        
        # Test ping/pong
        websocket.send_json({"type": "PING"})
        pong = websocket.receive_json()
        assert pong["event"] == "PONG"
