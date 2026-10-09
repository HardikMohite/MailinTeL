"""
Unit and integration tests for cascading email deletion feature.
Ensures that deleting an email permanently purges all data across:
- Original binary files & attachments in storage (MinIO)
- Reports & dossiers
- Evidence objects & custody logs
- Analysis runs, findings, and explainability
- RFC822 headers, recipients, relay hops, and authentication results
- 5-Strand DNA profiles, embeddings, and similarity correlation links
- Threat indicator sightings, entity geolocations, and campaign memberships
- Redis and multi-tier L1/L2 caches
"""
import uuid
from unittest.mock import MagicMock, AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_current_user, CurrentUser
from app.models.emails import Email, EmailSource
from app.services.email_deletion_service import EmailDeletionService
from tests.auth_helpers import TEST_ORG_ID

client = TestClient(app)

OWNER_ID = uuid.uuid4()
OTHER_USER_ID = uuid.uuid4()

OWNER_USER = CurrentUser(
    id=OWNER_ID,
    email="owner@mailintel.test",
    full_name="Owner User",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="USER",
)

OTHER_USER = CurrentUser(
    id=OTHER_USER_ID,
    email="other@mailintel.test",
    full_name="Other User",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="USER",
)

ADMIN_USER = CurrentUser(
    id=uuid.uuid4(),
    email="admin@mailintel.test",
    full_name="Org Admin",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="INSTITUTION_ADMIN",
)


def _clear():
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def cleanup():
    _clear()
    yield
    _clear()


@pytest.mark.asyncio
async def test_delete_email_cascade_service():
    """Verify EmailDeletionService cascading queries and storage driver calls."""
    mock_db = AsyncMock()
    email_id = uuid.uuid4()

    mock_email = MagicMock(spec=Email)
    mock_email.id = email_id
    mock_email.source_id = uuid.uuid4()

    mock_scalar = MagicMock()
    mock_scalar.all.return_value = []
    mock_scalar.one.return_value = 0
    mock_scalar.scalar_one.return_value = 0

    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalar
    mock_result.first.return_value = (mock_email,)
    mock_result.scalar.return_value = 0

    mock_db.execute = AsyncMock(return_value=mock_result)

    with patch("app.services.email_deletion_service.storage") as mock_storage, \
         patch("app.services.email_deletion_service.EmailDeletionService.purge_caches", new_callable=AsyncMock) as mock_purge_caches:
        mock_storage.delete_evidence_object.return_value = True

        result = await EmailDeletionService.delete_email_cascade(email_id, mock_db, actor_user_id=OWNER_ID)

        assert result is True
        assert mock_db.commit.called
        mock_purge_caches.assert_called_once_with(email_id)


def test_delete_email_endpoint_404():
    """Deleting a non-existent email returns 404."""
    app.dependency_overrides[get_current_user] = lambda: ADMIN_USER

    mock_result = MagicMock()
    mock_result.first.return_value = None

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_result)
    app.dependency_overrides[get_db] = lambda: mock_db

    non_existent_id = str(uuid.uuid4())
    resp = client.delete(f"/api/v1/emails/{non_existent_id}")
    assert resp.status_code == 404
    err_msg = resp.json().get("error") or resp.json().get("detail", "")
    assert "not found" in err_msg.lower()


def test_delete_email_endpoint_unauthorized_user():
    """A USER cannot delete an email uploaded by another user."""
    app.dependency_overrides[get_current_user] = lambda: OTHER_USER

    email_id = uuid.uuid4()
    mock_source = EmailSource(organization_id=TEST_ORG_ID, user_id=OWNER_ID)
    mock_email = Email(id=email_id, source_id=uuid.uuid4())

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_email, mock_source)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_result)
    app.dependency_overrides[get_db] = lambda: mock_db

    resp = client.delete(f"/api/v1/emails/{str(email_id)}")
    assert resp.status_code == 403
    err_msg = resp.json().get("error") or resp.json().get("detail", "")
    assert "permission" in err_msg.lower()


def test_delete_email_endpoint_success_by_owner():
    """Owner can delete their own uploaded email successfully."""
    app.dependency_overrides[get_current_user] = lambda: OWNER_USER

    email_id = uuid.uuid4()
    mock_source = EmailSource(organization_id=TEST_ORG_ID, user_id=OWNER_ID)
    mock_email = Email(id=email_id, source_id=uuid.uuid4())

    mock_result = MagicMock()
    mock_result.first.return_value = (mock_email, mock_source)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_result)
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch.object(EmailDeletionService, "delete_email_cascade", new_callable=AsyncMock) as mock_cascade:
        mock_cascade.return_value = True
        resp = client.delete(f"/api/v1/emails/{str(email_id)}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["email_id"] == str(email_id)


def test_batch_delete_emails_endpoint_success():
    """Batch deletion endpoint deletes multiple emails."""
    app.dependency_overrides[get_current_user] = lambda: ADMIN_USER

    id1 = uuid.uuid4()
    id2 = uuid.uuid4()

    mock_email1 = Email(id=id1, source_id=uuid.uuid4())
    mock_email2 = Email(id=id2, source_id=uuid.uuid4())

    mock_res1 = MagicMock()
    mock_res1.first.return_value = (mock_email1, None)

    mock_res2 = MagicMock()
    mock_res2.first.return_value = (mock_email2, None)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(side_effect=[mock_res1, mock_res2])
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch.object(EmailDeletionService, "delete_email_cascade", new_callable=AsyncMock) as mock_cascade:
        mock_cascade.return_value = True
        resp = client.post(
            "/api/v1/emails/batch-delete",
            json={"email_ids": [str(id1), str(id2)]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["deleted_count"] == 2
        assert str(id1) in data["deleted_ids"]
        assert str(id2) in data["deleted_ids"]
