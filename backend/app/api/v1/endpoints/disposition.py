import uuid
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.api.deps import get_current_user, CurrentUser
from app.services.disposition_service import default_disposition_service

logger = logging.getLogger("mailintel.api.disposition")

router = APIRouter()


class SubmitDispositionRequest(BaseModel):
    verdict: str = Field(
        ...,
        description="Analyst verdict: CONFIRMED_PHISHING, CONFIRMED_BEC, CONFIRMED_FRAUD, FALSE_POSITIVE, CONFIRMED_LEGITIMATE, UNDER_INVESTIGATION",
    )
    notes: str = Field(
        ...,
        description="Investigator assessment notes and rationale explaining the decision (trains AI memory)",
    )
    actions: Optional[List[str]] = Field(
        default_factory=list,
        description="Applied containment actions, e.g. BLOCK_SENDER, BLACKLIST_IP, ADD_TO_WATCHLIST",
    )
    flagged_iocs: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Observable indicators confirmed by the analyst",
    )


@router.get("/{email_id}", response_model=Dict[str, Any])
async def get_email_disposition(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Retrieves human review disposition, confidence triage tier, conflict reasons, and learned precedents.
    """
    try:
        data = await default_disposition_service.get_or_calculate_disposition(session, email_id)
        return data
    except Exception as e:
        logger.error(f"Error fetching disposition for email {email_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve disposition: {str(e)}",
        )


@router.post("/{email_id}", response_model=Dict[str, Any])
async def submit_email_disposition(
    email_id: uuid.UUID,
    payload: SubmitDispositionRequest,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Submits authoritative human analyst disposition, updates email status, logs audit event,
    and vectorizes feedback into pgvector for autonomous AI continuous learning.
    """
    try:
        result = await default_disposition_service.submit_analyst_disposition(
            session=session,
            email_id=email_id,
            user=current_user,
            verdict=payload.verdict.strip().upper(),
            notes=payload.notes.strip(),
            actions=payload.actions,
            flagged_iocs=payload.flagged_iocs,
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.error(f"Error submitting disposition for email {email_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit disposition: {str(e)}",
        )


@router.get("/{email_id}/precedents", response_model=List[Dict[str, Any]])
async def get_email_precedents(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Returns historical emails with human analyst dispositions matching the current email's DNA or IOCs.
    """
    try:
        precedents = await default_disposition_service.find_analyst_precedents(session, email_id)
        return precedents
    except Exception as e:
        logger.error(f"Error searching precedents for email {email_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to find precedents: {str(e)}",
        )
