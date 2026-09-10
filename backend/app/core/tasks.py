import asyncio
import uuid
import logging
from enum import Enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Callable, Coroutine
from pydantic import BaseModel, Field

from app.core.redis import redis_manager

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStage(str, Enum):
    QUEUED = "QUEUED"
    ACQUIRING_EVIDENCE = "ACQUIRING_EVIDENCE"
    PARSING_EMAIL = "PARSING_EMAIL"
    EXTRACTING_IOCS = "EXTRACTING_IOCS"
    ANALYZING_THREATS = "ANALYZING_THREATS"
    GENERATING_DNA = "GENERATING_DNA"
    GEO_LOCATING = "GEO_LOCATING"
    CORRELATING_CAMPAIGN = "CORRELATING_CAMPAIGN"
    GENERATING_REPORT = "GENERATING_REPORT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class JobRecord(BaseModel):
    """
    Serializable job state record for tracking background task progress and outcomes.
    """
    job_id: str
    job_type: str = "EMAIL_ANALYSIS"
    status: JobStatus = JobStatus.PENDING
    stage: JobStage = JobStage.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    email_id: Optional[str] = None
    # SECURITY: authoritative tenant boundary for this job. Stamped at
    # creation time from the creating user's organization and enforced by
    # every job-scoped endpoint (get/list/cancel in app.api.v1.endpoints.jobs)
    # to reject cross-tenant access. Optional only to keep this model usable
    # by any internal/system caller that has no organization context.
    organization_id: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class BackgroundJobManager:
    """
    Manages background asynchronous processing tasks with dual-tier state persistence
    (Redis fast cache + in-memory fallback), progress telemetry, and lifecycle tracking.
    """

    def __init__(self, job_ttl_seconds: int = 86400):
        self.job_ttl_seconds = job_ttl_seconds
        # In-memory store for fallback, tests, or local non-redis operation
        self._memory_jobs: Dict[str, JobRecord] = {}
        # Active asyncio Tasks for cancellation support
        self._active_tasks: Dict[str, asyncio.Task] = {}

    def _redis_key(self, job_id: str) -> str:
        return f"mailintel:job:{job_id}"

    async def _save_record(self, record: JobRecord) -> None:
        """Persist job record to both Redis (if available) and in-memory cache."""
        self._memory_jobs[record.job_id] = record
        try:
            await redis_manager.set_json(
                self._redis_key(record.job_id),
                record.model_dump(),
                expire_seconds=self.job_ttl_seconds,
            )
        except Exception as e:
            logger.warning(f"Failed to persist job {record.job_id} to Redis: {e}")

    async def create_job(
        self,
        job_type: str = "EMAIL_ANALYSIS",
        email_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        custom_job_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> JobRecord:
        """Create a new job in PENDING status."""
        job_id = custom_job_id or str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        record = JobRecord(
            job_id=job_id,
            job_type=job_type,
            status=JobStatus.PENDING,
            stage=JobStage.QUEUED,
            progress=0,
            email_id=email_id,
            organization_id=organization_id,
            created_at=now_iso,
            metadata=metadata or {},
        )

        await self._save_record(record)
        logger.info(f"Created background job {job_id} ({job_type}) for email {email_id}")
        return record

    async def get_job(self, job_id: str) -> Optional[JobRecord]:
        """Fetch job record from Redis or memory cache."""
        try:
            data = await redis_manager.get_json(self._redis_key(job_id))
            if data:
                record = JobRecord(**data)
                self._memory_jobs[job_id] = record
                return record
        except Exception as e:
            logger.warning(f"Redis get_job failed for {job_id}: {e}")

        return self._memory_jobs.get(job_id)

    async def update_progress(
        self,
        job_id: str,
        stage: JobStage,
        progress: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[JobRecord]:
        """Update job stage and percentage progress."""
        record = await self.get_job(job_id)
        if not record:
            return None

        if record.status == JobStatus.PENDING:
            record.status = JobStatus.RUNNING
            record.started_at = datetime.now(timezone.utc).isoformat()

        record.stage = stage
        record.progress = max(0, min(100, progress))
        if metadata:
            if record.metadata is None:
                record.metadata = {}
            record.metadata.update(metadata)

        await self._save_record(record)
        logger.debug(f"Job {job_id} progress updated: {stage.value} ({progress}%)")
        return record

    async def complete_job(
        self,
        job_id: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> Optional[JobRecord]:
        """Mark job as successfully COMPLETED."""
        record = await self.get_job(job_id)
        if not record:
            return None

        record.status = JobStatus.COMPLETED
        record.stage = JobStage.COMPLETED
        record.progress = 100
        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.result = result or {}

        await self._save_record(record)
        self._active_tasks.pop(job_id, None)
        logger.info(f"Job {job_id} successfully COMPLETED")
        return record

    async def fail_job(
        self,
        job_id: str,
        error_message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> Optional[JobRecord]:
        """Mark job as FAILED with error explanation."""
        record = await self.get_job(job_id)
        if not record:
            return None

        record.status = JobStatus.FAILED
        record.stage = JobStage.FAILED
        record.completed_at = datetime.now(timezone.utc).isoformat()
        record.error = error_message
        if error_details and record.metadata is not None:
            record.metadata["error_details"] = error_details

        await self._save_record(record)
        self._active_tasks.pop(job_id, None)
        logger.error(f"Job {job_id} FAILED: {error_message}")
        return record

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running background job."""
        record = await self.get_job(job_id)
        if not record:
            return False

        if record.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            return False

        record.status = JobStatus.CANCELLED
        record.completed_at = datetime.now(timezone.utc).isoformat()
        await self._save_record(record)

        # Cancel active task if running
        task = self._active_tasks.pop(job_id, None)
        if task and not task.done():
            task.cancel()
            logger.info(f"Cancelled running task for job {job_id}")

        return True

    async def list_jobs(
        self,
        limit: int = 50,
        status: Optional[JobStatus] = None,
        organization_id: Optional[str] = None,
    ) -> List[JobRecord]:
        """
        List recently tracked jobs with optional status filter.

        SECURITY: `organization_id` restricts results to jobs created for
        that tenant. Without it every authenticated user would see every
        organization's ingestion/analysis jobs (including email_id values
        and processing metadata) platform-wide. Jobs with no
        organization_id on record (system/legacy jobs) are excluded from
        org-scoped listings rather than shown to everyone.
        """
        jobs = list(self._memory_jobs.values())
        if organization_id is not None:
            jobs = [j for j in jobs if j.organization_id == organization_id]
        if status:
            jobs = [j for j in jobs if j.status == status]
        # Sort descending by created_at
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def dispatch_background_task(
        self,
        job_id: str,
        target_coroutine_fn: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any,
    ) -> asyncio.Task:
        """
        Dispatch a worker coroutine as an asynchronous background task with
        automatic lifecycle management and error recovery.
        """
        async def _runner_wrapper():
            try:
                await self.update_progress(job_id, JobStage.ACQUIRING_EVIDENCE, 5)
                result = await target_coroutine_fn(job_id, *args, **kwargs)
                await self.complete_job(job_id, result=result if isinstance(result, dict) else {"status": "success"})
            except asyncio.CancelledError:
                logger.info(f"Task for job {job_id} was cancelled")
            except Exception as exc:
                logger.exception(f"Unhandled error in background job {job_id}: {exc}")
                await self.fail_job(job_id, str(exc))

        task = asyncio.create_task(_runner_wrapper())
        self._active_tasks[job_id] = task
        return task


# Global singleton instance
job_manager = BackgroundJobManager()
