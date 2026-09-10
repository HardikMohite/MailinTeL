import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user
from app.dna.embedding_engine import SemanticEmbeddingEngine, default_embedding_engine
from app.models.emails import Email
from app.models.embeddings import EmailEmbedding
from app.models.dna import EmailDNAProfile, EmailSimilarityLink
from app.models.analysis import EmailAnalysis, AnalysisFinding
from app.services.similarity_service import SimilarityService
from app.db.vector import calculate_cosine_similarity
from tests.auth_helpers import TEST_USER, make_authorized_email_db_mock

client = TestClient(app)


def test_embedding_engine_l2_normalization_and_dimension():
    engine = SemanticEmbeddingEngine(dimension=384)
    vec = engine.embed_text("Urgent security notification: verify your account password immediately.")
    
    assert len(vec) == 384
    # L2 norm should equal 1.0 (within float precision)
    norm = sum(x * x for x in vec)
    assert abs(norm - 1.0) < 1e-4


def test_embedding_engine_similarity_identical_and_similar():
    engine = SemanticEmbeddingEngine(dimension=384)
    
    text_a = "Your Microsoft 365 password expires today. Click here to reset your credentials."
    text_b = "Your Microsoft 365 password expires today. Click here to update your credentials."
    text_c = "Weekly newsletter: 10 tips for gardening and growing organic tomatoes."
    
    vec_a = engine.embed_text(text_a)
    vec_b = engine.embed_text(text_b)
    vec_c = engine.embed_text(text_c)
    
    sim_identical = calculate_cosine_similarity(vec_a, vec_a)
    sim_similar = calculate_cosine_similarity(vec_a, vec_b)
    sim_dissimilar = calculate_cosine_similarity(vec_a, vec_c)
    
    assert sim_identical > 0.999
    assert sim_similar > 0.80
    assert sim_dissimilar < 0.40
    assert sim_similar > sim_dissimilar


def test_embedding_engine_subject_and_content():
    engine = SemanticEmbeddingEngine(dimension=384)
    
    subj_vec = engine.embed_subject("Invoice #98234 Overdue Payment Notice")
    assert len(subj_vec) == 384
    
    content_vec = engine.embed_content(
        subject="Invoice #98234 Overdue Payment Notice",
        body_plain="Please find attached overdue invoice for $4,500. Pay immediately via wire.",
        body_html="<p>Please find attached overdue invoice for $4,500. Pay immediately via wire.</p>",
    )
    assert len(content_vec) == 384


def test_embedding_engine_dna_profile_and_threat():
    engine = SemanticEmbeddingEngine(dimension=384)
    
    dna_data = {
        "content_fingerprint": {
            "lexical_tokens": ["invoice", "wire", "urgent"],
            "attachment_extensions": [".pdf", ".exe"],
        },
        "technical_fingerprint": {
            "header_ordering_hash": "abcdef1234567890",
            "user_agent_signature": "Thunderbird/102.0",
        },
        "infrastructure_fingerprint": {
            "relay_asn_sequence": ["AS15169", "AS16509"],
            "country_sequence": ["US", "DE"],
            "infrastructure_classifications": ["TOR_EXIT_NODE"],
        },
        "behavioral_fingerprint": {
            "brand_spoofing_mismatch": True,
        },
        "temporal_fingerprint": {
            "utc_hour_of_day": 14,
            "utc_day_of_week": 2,
        },
    }
    dna_vec = engine.embed_dna_profile(dna_data)
    assert len(dna_vec) == 384
    
    threat_vec = engine.embed_threat_pattern(
        risk_score=85.5,
        findings=[{"finding_type": "TOR_RELAY_DETECTED", "severity": "CRITICAL"}],
        indicators=[{"indicator_type": "URL", "val": "http://evil-phish.ru/login"}],
    )
    assert len(threat_vec) == 384


@pytest.mark.asyncio
async def test_generate_and_persist_embeddings():
    email_id = uuid.uuid4()
    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        subject="Action Required: Confirm Identity",
        sender_address="alert@security-check.com",
    )
    
    mock_dna = EmailDNAProfile(
        id=uuid.uuid4(),
        email_id=email_id,
        dna_version="1.0.0",
        content_fingerprint={"lexical_tokens": ["unusual", "login"]},
        technical_fingerprint={"header_ordering_hash": "12345678"},
        infrastructure_fingerprint={},
        behavioral_fingerprint={},
        temporal_fingerprint={"utc_hour_of_day": 10},
    )
    
    mock_analysis = EmailAnalysis(
        id=uuid.uuid4(),
        email_id=email_id,
        analysis_run_id=uuid.uuid4(),
        threat_risk_score=75.0,
        evidence_confidence_score=90.0,
    )

    mock_session = AsyncMock()
    
    async def mock_execute(query, *args, **kwargs):
        query_str = str(query)
        mock_result = MagicMock()
        if "FROM emails" in query_str or "emails.id =" in query_str:
            mock_result.scalar_one_or_none.return_value = mock_email
        elif "FROM email_dna_profiles" in query_str:
            mock_result.scalar_one_or_none.return_value = mock_dna
        elif "FROM email_analysis" in query_str:
            mock_result.scalar_one_or_none.return_value = mock_analysis
        elif "FROM analysis_findings" in query_str:
            mock_result.scalars.return_value.all.return_value = [
                AnalysisFinding(finding_type="SPOOFING", severity="HIGH")
            ]
        elif "FROM urls" in query_str:
            mock_result.scalars.return_value.all.return_value = ["http://phishing.example.com"]
        else:
            mock_result.scalar_one_or_none.return_value = None
            mock_result.scalars.return_value.all.return_value = []
        return mock_result

    mock_session.execute = AsyncMock(side_effect=mock_execute)
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()

    service = SimilarityService()
    embeddings = await service.generate_and_persist_embeddings(mock_session, email_id)
    
    assert len(embeddings) == 4
    types = {e.embedding_type for e in embeddings}
    assert "EMAIL_CONTENT" in types
    assert "SUBJECT" in types
    assert "EMAIL_DNA" in types
    assert "THREAT_PATTERN" in types


@pytest.mark.asyncio
async def test_find_and_link_similar_emails():
    src_id = uuid.uuid4()
    tgt_id = uuid.uuid4()
    
    engine = SemanticEmbeddingEngine(dimension=384)
    src_vec = engine.embed_text("Urgent password change requested by IT security team.")
    tgt_vec = engine.embed_text("Urgent password change requested by Corporate IT team.")
    
    src_embs = [
        EmailEmbedding(email_id=src_id, embedding_type="EMAIL_CONTENT", embedding=src_vec),
        EmailEmbedding(email_id=src_id, embedding_type="SUBJECT", embedding=src_vec),
    ]
    tgt_embs = [
        EmailEmbedding(email_id=tgt_id, embedding_type="EMAIL_CONTENT", embedding=tgt_vec),
        EmailEmbedding(email_id=tgt_id, embedding_type="SUBJECT", embedding=tgt_vec),
    ]

    mock_session = AsyncMock()
    
    async def mock_execute(query, *args, **kwargs):
        query_str = str(query)
        mock_result = MagicMock()
        if "email_embeddings.email_id =" in query_str:
            mock_result.scalars.return_value.all.return_value = src_embs
        elif "email_embeddings.email_id !=" in query_str:
            mock_result.scalars.return_value.all.return_value = tgt_embs
        elif "FROM emails" in query_str:
            mock_result.scalars.return_value.all.return_value = [
                Email(id=tgt_id, source_id=uuid.uuid4(), subject="Urgent IT Update", sender_address="security@spoofed.com")
            ]
        else:
            mock_result.scalars.return_value.all.return_value = []
        return mock_result

    mock_session.execute = AsyncMock(side_effect=mock_execute)
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()

    service = SimilarityService()
    links = await service.find_and_link_similar_emails(
        mock_session,
        email_id=src_id,
        min_similarity_threshold=0.50,
        top_k=5,
    )
    
    assert len(links) == 1
    link = links[0]
    assert link.source_email_id == src_id
    assert link.related_email_id == tgt_id
    assert float(link.similarity_score) > 0.50
    assert link.evidence["target_subject"] == "Urgent IT Update"
    assert "Similarity alone does not establish campaign membership" in link.evidence["attribution_disclaimer"]


def test_api_generate_embeddings_success():
    email_id = uuid.uuid4()
    mock_embs = [
        EmailEmbedding(
            id=uuid.uuid4(),
            email_id=email_id,
            embedding_type="EMAIL_CONTENT",
            model_name="all-MiniLM-L6-v2",
            dimension=384,
            embedding=[0.1] * 384,
            metadata_json={"has_subject": True},
            created_at=datetime.now(timezone.utc),
        )
    ]

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="alert@security-check.com",
    )
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.similarity_service.default_similarity_service.generate_and_persist_embeddings",
        new=AsyncMock(return_value=mock_embs),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.post(f"/api/v1/emails/{email_id}/embeddings")
        app.dependency_overrides.clear()
        assert resp.status_code == 201
        data = resp.json()
        assert len(data) == 1
        assert data[0]["embedding_type"] == "EMAIL_CONTENT"
        assert data[0]["dimension"] == 384


def test_api_get_similar_emails_success():
    email_id = uuid.uuid4()
    related_id = uuid.uuid4()
    mock_links = [
        {
            "id": str(uuid.uuid4()),
            "source_email_id": str(email_id),
            "related_email_id": str(related_id),
            "similarity_type": "SEMANTIC",
            "similarity_score": 0.885,
            "evidence": {"target_subject": "Fake Invoice"},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]

    mock_email = Email(
        id=email_id,
        source_id=uuid.uuid4(),
        sender_address="alert@security-check.com",
    )
    mock_db_session = make_authorized_email_db_mock(mock_email)

    with patch(
        "app.services.similarity_service.default_similarity_service.get_email_similarity_links",
        new=AsyncMock(return_value=mock_links),
    ):
        app.dependency_overrides[get_db] = lambda: mock_db_session
        app.dependency_overrides[get_current_user] = lambda: TEST_USER
        resp = client.get(f"/api/v1/emails/{email_id}/similar")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["similarity_score"] == 0.885
        assert data[0]["evidence"]["target_subject"] == "Fake Invoice"
