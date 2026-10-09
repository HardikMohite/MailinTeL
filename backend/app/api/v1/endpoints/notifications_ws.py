import uuid
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import deque
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger("mailintel.notifications.ws")

router = APIRouter()

# Default initial notifications to seed the stream so the SOC view is immediately useful
DEFAULT_INITIAL_NOTIFICATIONS: List[Dict[str, Any]] = [
    {
        "id": "notif-init-1",
        "type": "PHISHING_ALERT",
        "title": "Phishing Infiltration Blocked",
        "message": "AI Engine detected high-confidence credential harvester spoofing Microsoft 365 login.",
        "severity": "critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": False,
        "data": {"threat_score": 94, "verdict": "PHISHING", "category": "CREDENTIAL_PHISHING"}
    },
    {
        "id": "notif-init-2",
        "type": "CAMPAIGN_DETECTED",
        "title": "Campaign Cluster Identified",
        "message": "Cluster 'FinFraud-Spreader' correlated across 3 mail nodes sharing source relay AS13335.",
        "severity": "high",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": False,
        "data": {"campaign_id": "FinFraud-Spreader", "node_count": 3}
    },
    {
        "id": "notif-init-3",
        "type": "SYSTEM",
        "title": "Threat Feeds Synchronized",
        "message": "Global IOC feeds, Tor exit node lists, and Groq reasoning engines operational.",
        "severity": "info",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": True,
        "data": {"engine": "MailinTeL v1.0", "status": "ONLINE"}
    }
]


class NotificationConnectionManager:
    """
    Manages active WebSocket connections from SOC analysts and forensic investigators.
    Broadcasts real-time security alerts, phishing notifications, and system events.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.notification_history: deque = deque(DEFAULT_INITIAL_NOTIFICATIONS, maxlen=100)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total active connections: {len(self.active_connections)}")
        
        # Send initial batch of recent notifications + connection greeting
        try:
            welcome_payload = {
                "event": "CONNECTED",
                "message": "Connected to MailinTeL Real-Time SOC Event Stream",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "notifications": list(self.notification_history)
            }
            await websocket.send_text(json.dumps(welcome_payload))
        except Exception as e:
            logger.warning(f"Error sending welcome payload to WebSocket: {e}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total active connections: {len(self.active_connections)}")

    async def broadcast(self, notification: Dict[str, Any]):
        """
        Broadcasts a notification object to all connected clients and records in history.
        """
        if "id" not in notification:
            notification["id"] = f"notif-{uuid.uuid4().hex[:8]}"
        if "timestamp" not in notification:
            notification["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "read" not in notification:
            notification["read"] = False

        # Add to in-memory history (most recent first)
        self.notification_history.appendleft(notification)

        payload = {
            "event": "NOTIFICATION",
            "notification": notification
        }
        raw_message = json.dumps(payload)

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(raw_message)
            except Exception as e:
                logger.debug(f"Failed to send to client: {e}")
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    async def broadcast_ping(self):
        """Send heartbeat ping to all connected clients"""
        payload = json.dumps({"event": "PING", "timestamp": datetime.now(timezone.utc).isoformat()})
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)


# Global singleton instance
notification_manager = NotificationConnectionManager()


@router.websocket("/ws/notifications")
async def websocket_notifications_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat intelligence and investigation notifications.
    Clients receive instant alerts for new email scans, phishing flags, and campaign updates.
    """
    await notification_manager.connect(websocket)
    try:
        while True:
            # Listen for client messages (e.g. heartbeat ping/pong or acknowledge)
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "PONG":
                    continue
                elif message.get("type") == "PING":
                    await websocket.send_text(json.dumps({
                        "event": "PONG",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        notification_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket connection encountered exception: {e}")
        notification_manager.disconnect(websocket)


class TestNotificationRequest(BaseModel):
    title: str = Field(default="Simulated Phishing Attack Detected")
    message: str = Field(default="AI Copilot flagged suspicious domain homograph with high urgency payload.")
    severity: str = Field(default="critical", description="critical, high, medium, info, success")
    type: str = Field(default="PHISHING_ALERT")
    data: Optional[Dict[str, Any]] = None


@router.get("/notifications", response_model=List[Dict[str, Any]])
async def get_recent_notifications():
    """
    Returns recent notification history (fallback and initial fetch for REST clients).
    """
    return list(notification_manager.notification_history)


@router.post("/notifications/test", response_model=Dict[str, Any])
async def trigger_test_notification(payload: TestNotificationRequest):
    """
    Emits a test/simulated notification across the active WebSocket stream.
    Used for verifying real-time alerting integration in the SOC header.
    """
    notif = {
        "id": f"notif-{uuid.uuid4().hex[:8]}",
        "type": payload.type,
        "title": payload.title,
        "message": payload.message,
        "severity": payload.severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": False,
        "data": payload.data or {"source": "SOC_TEST_EMISSION"}
    }
    await notification_manager.broadcast(notif)
    return {
        "status": "broadcast_sent",
        "active_clients": len(notification_manager.active_connections),
        "notification": notif
    }
