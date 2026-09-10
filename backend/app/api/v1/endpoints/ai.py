import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.api.deps import get_current_user, get_authorized_email, CurrentUser
from app.services.ai_rag_service import default_forensic_rag_service
from app.services.llm_provider import default_groq_client
from app.core.config import settings

router = APIRouter()


class ReasoningItem(BaseModel):
    finding: str
    evidence: str
    confidence: float


class ThreatReasoningResponse(BaseModel):
    classification: str
    reasoning: List[ReasoningItem]
    social_engineering_indicators: List[str] = Field(default_factory=list)
    attack_intent: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    confidence: float


class InvestigateRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=1000, description="Question about the case")
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Recent conversation history")


class InvestigateResponse(BaseModel):
    email_id: str
    question: str
    answer: str
    grounded_sources: Dict[str, int] = Field(default_factory=dict)


class CaseSummaryResponse(BaseModel):
    email_id: str
    summary: str
    classification: str
    threat_score: float
    top_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class AIStatusResponse(BaseModel):
    provider: str
    groq_configured: bool
    model: str
    fallback_model: str
    temperature: float
    rag_pgvector_active: bool


@router.get("/status", response_model=AIStatusResponse, summary="Check AI & RAG service health")
async def get_ai_status(current_user: CurrentUser = Depends(get_current_user)):
    """Returns the operational status of the Groq LLM client and RAG subsystem."""
    return AIStatusResponse(
        provider="Groq LPUs (OpenAI-compatible) + Forensic Deterministic Engine",
        groq_configured=default_groq_client.is_configured,
        model=settings.GROQ_MODEL,
        fallback_model=settings.GROQ_FALLBACK_MODEL,
        temperature=settings.AI_TEMPERATURE,
        rag_pgvector_active=True,
    )


@router.post(
    "/{email_id}/explain",
    response_model=ThreatReasoningResponse,
    summary="AI Threat Reasoning & Forensic Explanation",
    description="Interprets already-extracted email evidence and returns a grounded threat assessment conforming strictly to WHAT? WHY? EVIDENCE? CONFIDENCE?.",
)
async def explain_email_threat(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    await get_authorized_email(email_id, current_user, session)
    try:
        result = await default_forensic_rag_service.explain_email_threat(session, email_id)
        return ThreatReasoningResponse(**result)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate threat reasoning: {str(exc)}",
        )


@router.post(
    "/{email_id}/investigate",
    response_model=InvestigateResponse,
    summary="Analyst Investigation Assistant (RAG Q&A)",
    description="Answers investigator questions grounded strictly in the case's forensic evidence, pgvector similarity, and campaign data.",
)
async def investigate_case_assistant(
    email_id: uuid.UUID,
    req: InvestigateRequest,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    await get_authorized_email(email_id, current_user, session)
    try:
        result = await default_forensic_rag_service.investigate_case_assistant(
            session=session,
            email_id=email_id,
            question=req.question,
            history=req.history,
            user_id=str(current_user.id),
        )
        return InvestigateResponse(**result)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query investigation assistant: {str(exc)}",
        )


@router.post(
    "/{email_id}/summarize",
    response_model=CaseSummaryResponse,
    summary="Executive Forensic Case Summary",
    description="Generates an executive case brief grounded in the retrieved email evidence and top forensic findings.",
)
async def summarize_case(
    email_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    await get_authorized_email(email_id, current_user, session)
    try:
        result = await default_forensic_rag_service.summarize_case(session, email_id)
        return CaseSummaryResponse(**result)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to summarize case: {str(exc)}",
        )
