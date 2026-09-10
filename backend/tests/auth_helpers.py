"""
Shared authentication test helpers.

Every API router except /health and /auth now requires a valid bearer token
(resolved to a `CurrentUser` via `app.api.deps.get_current_user`). Tests that
exercise those routes need to override that dependency the same way they
already override `get_db`, or FastAPI rejects the request with 401 before
the route body (and the test's own mocks) ever run.

Usage in a test file:

    from app.api.deps import get_current_user
    from tests.auth_helpers import TEST_USER

    app.dependency_overrides[get_db] = lambda: mock_db_session
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(...)
    app.dependency_overrides.clear()

`TEST_USER` has a non-null `organization_id`, so it also satisfies routes
that additionally depend on `require_organization`. Endpoints that enforce
per-resource organization ownership (e.g. `emails.py`'s
`_get_authorized_email_and_evidence`) only reject when the underlying mock
row's `organization_id` is set and differs from `TEST_USER.organization_id`;
existing test fixtures that don't set `organization_id` on their mock
`EmailSource`/etc. objects are unaffected by that check.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock

from app.api.deps import CurrentUser

TEST_USER_ID = uuid.uuid4()
TEST_ORG_ID = uuid.uuid4()

TEST_USER = CurrentUser(
    id=TEST_USER_ID,
    email="test.analyst@mailintel.test",
    full_name="Test Analyst",
    organization_id=TEST_ORG_ID,
    organization_name="Test Org",
    role_code="SECURITY_ANALYST",
)


def override_auth(app) -> None:
    """Convenience helper: install the TEST_USER override on the given app."""
    from app.api.deps import get_current_user
    app.dependency_overrides[get_current_user] = lambda: TEST_USER


def make_authorized_email_db_mock(email_obj, organization_id=TEST_ORG_ID):
    """
    Build a mock AsyncSession whose first `execute()` call satisfies
    `app.api.deps.get_authorized_email`.

    That helper runs `select(Email, EmailSource).outerjoin(...)` and calls
    `.first()` on the result (NOT `.scalar_one_or_none()`) to get back a
    `(Email, EmailSource)` tuple, then fails closed unless the EmailSource's
    organization_id is present and matches the caller's. A mock that only
    configures `.scalar_one_or_none` (or doesn't configure `.first` at all)
    leaves `.first()` returning an unconfigured MagicMock, which is truthy
    but not unpackable into two values, raising ValueError as soon as the
    endpoint tries `email_obj, source_obj = row`.

    Returns a ready-to-use mock session with that one call pre-wired; further
    `.execute` calls (if any) will return a fresh MagicMock unless the caller
    overrides `.execute.side_effect`/`.return_value` afterwards.
    """
    from app.models.emails import EmailSource

    source_obj = EmailSource(id=uuid.uuid4(), organization_id=organization_id)
    mock_result = MagicMock()
    mock_result.first.return_value = (email_obj, source_obj)

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    return mock_session


def make_authorized_campaign_db_mock(campaign_obj, organization_id=TEST_ORG_ID):
    """
    Build a mock AsyncSession whose first `execute()` call satisfies
    `app.api.deps.get_authorized_campaign`.

    Unlike `get_authorized_email`, that helper queries a single table and
    calls `.scalar_one_or_none()`, so the campaign object itself just needs
    `organization_id` set to the caller's org (it fails closed on None or a
    mismatch).
    """
    campaign_obj.organization_id = organization_id
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = campaign_obj

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    return mock_session
