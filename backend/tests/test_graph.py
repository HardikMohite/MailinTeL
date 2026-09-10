import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.graph.graph_builder import InvestigationGraphBuilder, GraphNode, GraphEdge, InvestigationGraph
from app.services.graph_service import InvestigationGraphService
from app.models.emails import Email, RelayHop
from app.models.intelligence import URL, Domain, IPAddress
from app.models.evidence import EvidenceObject
from app.models.campaign import Campaign, CampaignMembership
from tests.auth_helpers import (
    TEST_USER,
    make_authorized_email_db_mock,
    make_authorized_campaign_db_mock,
)

client = TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock async database session for graph endpoint tests."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.delete = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.flush = AsyncMock()
    return mock_session


def test_graph_builder_node_and_edge_creation():
    builder = InvestigationGraphBuilder()

    n1 = builder.add_node("email:1", "EMAIL", "Invoice Scam", risk_level="HIGH", metadata={"subject": "Invoice Scam"})
    n2 = builder.add_node("domain:evil.com", "DOMAIN", "evil.com", risk_level="CRITICAL", metadata={"nrd": True})

    assert n1.node_type == "EMAIL"
    assert n2.node_type == "DOMAIN"

    edge = builder.add_edge("email:1", "domain:evil.com", "CONTAINS_DOMAIN", confidence=90.0)
    assert edge is not None
    assert edge.source == "email:1"
    assert edge.target == "domain:evil.com"
    assert edge.relationship_type == "CONTAINS_DOMAIN"

    # Self-loop should be rejected
    self_edge = builder.add_edge("email:1", "email:1", "LOOP")
    assert self_edge is None

    graph = builder.build(focal_node_id="email:1")
    assert graph.focal_node_id == "email:1"
    assert graph.total_nodes == 2
    assert graph.total_edges == 1
    assert graph.statistics["EMAIL"] == 1
    assert graph.statistics["DOMAIN"] == 1


@pytest.mark.asyncio
async def test_build_email_investigation_graph_service():
    service = InvestigationGraphService()
    email_id = uuid.uuid4()

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Wire Transfer Urgency",
        sender_address="ceo@spoofed-target.com",
        sender_display_name="CEO Office",
        sent_at=datetime.now(timezone.utc),
    )

    mock_session = AsyncMock()

    async def mock_execute(query, *args, **kwargs):
        q_str = str(query)
        mock_res = MagicMock()
        if "FROM emails" in q_str:
            mock_res.scalar_one_or_none.return_value = mock_email
        elif "FROM email_analysis" in q_str:
            mock_res.scalar_one_or_none.return_value = None
        elif "FROM urls" in q_str or "email_urls" in q_str:
            mock_res.all.return_value = []
        elif "FROM relay_hops" in q_str:
            mock_res.scalars.return_value.all.return_value = [
                RelayHop(id=uuid.uuid4(), email_id=email_id, sequence_number=1, source_ip="198.51.100.22", reliability="HIGH")
            ]
        elif "FROM evidence_objects" in q_str:
            mock_res.scalars.return_value.all.return_value = [
                EvidenceObject(id=uuid.uuid4(), email_id=email_id, evidence_type="ATTACHMENT", original_filename="invoice.exe", sha256_hash="deadbeef", size_bytes=1024)
            ]
        elif "FROM campaign_memberships" in q_str:
            mock_res.all.return_value = []
        elif "FROM email_similarity_links" in q_str:
            mock_res.scalars.return_value.all.return_value = []
        else:
            mock_res.scalar_one_or_none.return_value = None
            mock_res.scalars.return_value.all.return_value = []
            mock_res.all.return_value = []
        return mock_res

    mock_session.execute = AsyncMock(side_effect=mock_execute)

    graph = await service.build_email_investigation_graph(mock_session, email_id)
    assert graph.focal_node_id == f"email:{email_id}"
    assert graph.total_nodes >= 4  # Email, Sender, IP, ASN, Attachment
    types = {n.node_type for n in graph.nodes}
    assert "EMAIL" in types
    assert "SENDER" in types
    assert "IP" in types
    assert "ATTACHMENT" in types


def test_api_get_email_graph_endpoint():
    email_id = uuid.uuid4()
    mock_graph_data = {
        "focal_node_id": f"email:{email_id}",
        "total_nodes": 2,
        "total_edges": 1,
        "statistics": {"EMAIL": 1, "SENDER": 1},
        "nodes": [
            {"id": f"email:{email_id}", "label": "Email: Test", "node_type": "EMAIL", "display_name": "Test", "risk_level": "HIGH", "metadata": {}},
            {"id": "sender:attacker@evil.com", "label": "Sender", "node_type": "SENDER", "display_name": "attacker@evil.com", "risk_level": "HIGH", "metadata": {}},
        ],
        "edges": [
            {"id": "e1", "source": f"email:{email_id}", "target": "sender:attacker@evil.com", "relationship_type": "SENT_BY", "label": "Sent By", "confidence": 100.0, "evidence": {}}
        ],
    }

    mock_graph = MagicMock()
    mock_graph.total_nodes = 2
    mock_graph.to_dict.return_value = mock_graph_data

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="attacker@evil.com",
    )
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.graph_service.default_graph_service.build_email_investigation_graph",
        new=AsyncMock(return_value=mock_graph),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/graph/email/{email_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["focal_node_id"] == f"email:{email_id}"
        assert data["total_nodes"] == 2
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1


def test_api_get_campaign_graph_endpoint():
    camp_id = uuid.uuid4()
    mock_graph_data = {
        "focal_node_id": f"campaign:{camp_id}",
        "total_nodes": 3,
        "total_edges": 2,
        "statistics": {"CAMPAIGN": 1, "EMAIL": 2},
        "nodes": [
            {"id": f"campaign:{camp_id}", "label": "Campaign Alpha", "node_type": "CAMPAIGN", "display_name": "Alpha", "risk_level": "CRITICAL", "metadata": {}}
        ],
        "edges": [],
    }

    mock_graph = MagicMock()
    mock_graph.to_dict.return_value = mock_graph_data

    mock_camp = Campaign(
        id=camp_id,
        campaign_name="Campaign Alpha",
        campaign_status="ACTIVE",
    )
    mock_db_session = make_authorized_campaign_db_mock(mock_camp)

    with patch(
        "app.services.graph_service.default_graph_service.build_campaign_investigation_graph",
        new=AsyncMock(return_value=mock_graph),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/graph/campaign/{camp_id}")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["focal_node_id"] == f"campaign:{camp_id}"


def test_api_get_global_graph_endpoint(mock_db_session):
    mock_graph_data = {
        "focal_node_id": None,
        "total_nodes": 5,
        "total_edges": 4,
        "statistics": {"EMAIL": 3, "CAMPAIGN": 2},
        "nodes": [],
        "edges": [],
    }

    mock_graph = MagicMock()
    mock_graph.to_dict.return_value = mock_graph_data

    with patch(
        "app.services.graph_service.default_graph_service.build_global_investigation_graph",
        new=AsyncMock(return_value=mock_graph),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get("/api/v1/graph/global?limit=20")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_nodes"] == 5
