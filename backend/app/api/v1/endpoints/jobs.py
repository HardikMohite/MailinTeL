import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.tasks import job_manager, JobRecord, JobStatus
from app.api.deps import get_current_user, require_organization_or_cross_org, require_roles, ANALYST_ROLES, CROSS_ORG_ROLES, CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter()


def _not_found(job_id: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Job with ID '{job_id}' not found",
    )


@router.get(
    "/{job_id}",
    response_model=JobRecord,
    summary="Get Background Job Status",
    description="Poll real-time execution progress, stage, and outcomes for an asynchronous analysis job.",
)
async def get_job_status(
    job_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> JobRecord:
    """
    Retrieve detailed status of an analysis job.

    SECURITY (MVP-02/03-pattern fix): jobs are stamped with the creating
    user's organization_id at creation time (see emails.py upload flow). A
    job with no organization_id on record has no provable owner and is
    therefore treated as NOT belonging to the caller — fails closed rather
    than being returned to any authenticated caller.
    """
    job = await job_manager.get_job(job_id)
    if not job:
        raise _not_found(job_id)
    if job.organization_id is None or (current_user.role_code not in CROSS_ORG_ROLES and job.organization_id != str(current_user.organization_id)):
        raise _not_found(job_id)
    return job


@router.get(
    "",
    response_model=List[JobRecord],
    summary="List Background Jobs",
    description="List recent background jobs with optional status filtering.",
)
async def list_jobs(
    limit: int = Query(default=50, ge=1, le=100, description="Maximum number of jobs to return"),
    status: Optional[JobStatus] = Query(default=None, description="Filter jobs by status"),
    organization_id: Optional[str] = Query(default=None, description="Optional organization filter for cross-org roles"),
    current_user: CurrentUser = Depends(require_organization_or_cross_org),
) -> List[JobRecord]:
    """List recent background processing jobs belonging to the caller's organization."""
    requested_org_id = organization_id if current_user.role_code in CROSS_ORG_ROLES else str(current_user.organization_id)
    return await job_manager.list_jobs(limit=limit, status=status, organization_id=requested_org_id)


@router.post(
    "/{job_id}/cancel",
    summary="Cancel Background Job",
    description="Cancel a running or queued background analysis job.",
)
async def cancel_job(
    job_id: str,
    # MVP-04: job cancellation is an analyst-and-up operation.
    current_user: CurrentUser = Depends(require_roles(*ANALYST_ROLES, *CROSS_ORG_ROLES)),
):
    """Cancel a pending or running job owned by the caller's organization."""
    job = await job_manager.get_job(job_id)
    if not job:
        raise _not_found(job_id)
    if job.organization_id is None or (current_user.role_code not in CROSS_ORG_ROLES and job.organization_id != str(current_user.organization_id)):
        raise _not_found(job_id)

    success = await job_manager.cancel_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job '{job_id}' cannot be cancelled (either not found or already completed/failed)",
        )
    return {"message": f"Job '{job_id}' cancelled successfully", "status": "CANCELLED"}
