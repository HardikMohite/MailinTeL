import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_current_user
from app.core.tasks import (
    BackgroundJobManager,
    job_manager,
    JobStatus,
    JobStage,
    JobRecord,
)
from tests.auth_helpers import TEST_USER

client = TestClient(app)


@pytest.fixture
def local_job_manager():
    """Create a fresh isolated BackgroundJobManager instance for testing."""
    return BackgroundJobManager()


@pytest.mark.asyncio
async def test_job_manager_create_and_get_job(local_job_manager):
    """Verify job creation and retrieval with correct initial fields."""
    job = await local_job_manager.create_job(
        job_type="EMAIL_ANALYSIS",
        email_id="11111111-1111-1111-1111-111111111111",
        metadata={"filename": "suspicious.eml"},
    )

    assert job.job_id is not None
    assert job.job_type == "EMAIL_ANALYSIS"
    assert job.status == JobStatus.PENDING
    assert job.stage == JobStage.QUEUED
    assert job.progress == 0
    assert job.email_id == "11111111-1111-1111-1111-111111111111"
    assert job.metadata["filename"] == "suspicious.eml"

    fetched = await local_job_manager.get_job(job.job_id)
    assert fetched is not None
    assert fetched.job_id == job.job_id
    assert fetched.status == JobStatus.PENDING


@pytest.mark.asyncio
async def test_job_manager_update_progress(local_job_manager):
    """Verify stage transitions and progress updates from PENDING to RUNNING."""
    job = await local_job_manager.create_job(job_type="EMAIL_ANALYSIS")
    assert job.status == JobStatus.PENDING

    updated = await local_job_manager.update_progress(
        job_id=job.job_id,
        stage=JobStage.PARSING_EMAIL,
        progress=25,
        metadata={"headers_parsed": 12},
    )

    assert updated is not None
    assert updated.status == JobStatus.RUNNING
    assert updated.stage == JobStage.PARSING_EMAIL
    assert updated.progress == 25
    assert updated.started_at is not None
    assert updated.metadata["headers_parsed"] == 12


@pytest.mark.asyncio
async def test_job_manager_complete_job(local_job_manager):
    """Verify marking job as successfully COMPLETED with results."""
    job = await local_job_manager.create_job(job_type="EMAIL_ANALYSIS")
    await local_job_manager.update_progress(job.job_id, JobStage.ANALYZING_THREATS, 75)

    completed = await local_job_manager.complete_job(
        job_id=job.job_id,
        result={"threat_score": 92.5, "classification": "MALICIOUS"},
    )

    assert completed is not None
    assert completed.status == JobStatus.COMPLETED
    assert completed.stage == JobStage.COMPLETED
    assert completed.progress == 100
    assert completed.completed_at is not None
    assert completed.result["threat_score"] == 92.5


@pytest.mark.asyncio
async def test_job_manager_fail_job(local_job_manager):
    """Verify recording job failure with error explanation."""
    job = await local_job_manager.create_job(job_type="EMAIL_ANALYSIS")

    failed = await local_job_manager.fail_job(
        job_id=job.job_id,
        error_message="Invalid RFC822 format: Corrupted header block",
        error_details={"line": 42},
    )

    assert failed is not None
    assert failed.status == JobStatus.FAILED
    assert failed.stage == JobStage.FAILED
    assert failed.error == "Invalid RFC822 format: Corrupted header block"
    assert failed.completed_at is not None
    assert failed.metadata["error_details"]["line"] == 42


@pytest.mark.asyncio
async def test_job_manager_cancel_job(local_job_manager):
    """Verify cancelling an active job and rejecting cancel on finished job."""
    job = await local_job_manager.create_job(job_type="EMAIL_ANALYSIS")
    
    # Cancel pending job
    success = await local_job_manager.cancel_job(job.job_id)
    assert success is True

    cancelled = await local_job_manager.get_job(job.job_id)
    assert cancelled.status == JobStatus.CANCELLED

    # Trying to cancel again returns False
    second_attempt = await local_job_manager.cancel_job(job.job_id)
    assert second_attempt is False


@pytest.mark.asyncio
async def test_job_manager_list_jobs(local_job_manager):
    """Verify listing jobs and status filtering."""
    job1 = await local_job_manager.create_job(job_type="TYPE_A")
    job2 = await local_job_manager.create_job(job_type="TYPE_B")
    await local_job_manager.complete_job(job2.job_id)

    all_jobs = await local_job_manager.list_jobs(limit=10)
    assert len(all_jobs) == 2

    completed_jobs = await local_job_manager.list_jobs(status=JobStatus.COMPLETED)
    assert len(completed_jobs) == 1
    assert completed_jobs[0].job_id == job2.job_id


@pytest.mark.asyncio
async def test_job_manager_dispatch_background_task(local_job_manager):
    """Verify executing background coroutine via dispatch_background_task."""
    job = await local_job_manager.create_job(job_type="ASYNC_WORKER")

    async def mock_worker(job_id: str, value: int):
        await asyncio.sleep(0.01)
        await local_job_manager.update_progress(job_id, JobStage.EXTRACTING_IOCS, 50)
        return {"processed_value": value * 2}

    task = local_job_manager.dispatch_background_task(job.job_id, mock_worker, 21)
    await task

    result_job = await local_job_manager.get_job(job.job_id)
    assert result_job.status == JobStatus.COMPLETED
    assert result_job.result["processed_value"] == 42


@pytest.mark.asyncio
async def test_job_manager_dispatch_background_task_exception(local_job_manager):
    """Verify unhandled worker exception automatically marks job as FAILED."""
    job = await local_job_manager.create_job(job_type="FAULTY_WORKER")

    async def faulty_worker(job_id: str):
        raise ValueError("Simulated parsing crash")

    task = local_job_manager.dispatch_background_task(job.job_id, faulty_worker)
    await task

    result_job = await local_job_manager.get_job(job.job_id)
    assert result_job.status == JobStatus.FAILED
    assert "Simulated parsing crash" in result_job.error


def test_api_get_job_status_success():
    """Verify GET /api/v1/jobs/{job_id} returns valid job record."""
    # Pre-populate global job_manager with a test job
    job = asyncio.run(job_manager.create_job(
        job_type="EMAIL_ANALYSIS",
        email_id="22222222-2222-2222-2222-222222222222",
        organization_id=str(TEST_USER.organization_id),
    ))

    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get(f"/api/v1/jobs/{job.job_id}")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["job_id"] == job.job_id
    assert data["status"] == "PENDING"
    assert data["progress"] == 0


def test_api_get_job_status_not_found():
    """Verify GET /api/v1/jobs/{non_existent} returns 404."""
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/jobs/non-existent-uuid-999")
    app.dependency_overrides.clear()

    assert response.status_code == 404
    assert "not found" in response.json()["error"].lower()


def test_api_list_jobs():
    """Verify GET /api/v1/jobs returns array of job records."""
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.get("/api/v1/jobs")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_api_cancel_job():
    """Verify POST /api/v1/jobs/{job_id}/cancel cancels an active job."""
    job = asyncio.run(job_manager.create_job(
        job_type="EMAIL_ANALYSIS",
        organization_id=str(TEST_USER.organization_id),
    ))

    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    response = client.post(f"/api/v1/jobs/{job.job_id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "CANCELLED"

    # Subsequent check shows CANCELLED
    status_resp = client.get(f"/api/v1/jobs/{job.job_id}")
    app.dependency_overrides.clear()
    assert status_resp.json()["status"] == "CANCELLED"
