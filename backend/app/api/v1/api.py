from fastapi import APIRouter, Depends
from app.api.v1.endpoints import (
    health, jobs, emails, evidence, intelligence, scoring, dna,
    similarity, campaigns, graph, geo, reports, auth, users, platform_admin, ai, disposition,
    dashboard, sandbox, notifications_ws,
)
from app.api.deps import get_current_user

api_router = APIRouter()

# --- Public endpoints (no authentication required) ---
# MVP-07: only the minimal liveness probe (GET /health) stays public. The
# detailed/db/storage/redis/ready diagnostic routes disclose deployment and
# service metadata (hosts, ports, bucket names, runtime info, demo
# credentials) and are mounted below behind auth instead.
api_router.include_router(health.public_router, prefix="/health", tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])

# --- Everything below requires a valid, active, signed-in user ---
_auth_required = [Depends(get_current_user)]

api_router.include_router(health.protected_router, prefix="/health", tags=["Health"], dependencies=_auth_required)
api_router.include_router(jobs.router, prefix="/jobs", tags=["Jobs"], dependencies=_auth_required)
api_router.include_router(emails.router, prefix="/emails", tags=["Emails"], dependencies=_auth_required)
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence"], dependencies=_auth_required)
api_router.include_router(intelligence.router, prefix="/intelligence", tags=["Intelligence"], dependencies=_auth_required)
api_router.include_router(scoring.router, prefix="/emails", tags=["Scoring & Analysis"], dependencies=_auth_required)
api_router.include_router(dna.router, prefix="/emails", tags=["Email DNA"], dependencies=_auth_required)
api_router.include_router(similarity.router, prefix="/emails", tags=["Semantic Similarity"], dependencies=_auth_required)
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Campaigns & Correlation"], dependencies=_auth_required)
api_router.include_router(graph.router, prefix="/graph", tags=["Investigation Graph"], dependencies=_auth_required)
api_router.include_router(geo.router, prefix="/geo", tags=["Geo Intelligence"], dependencies=_auth_required)
api_router.include_router(reports.router, prefix="/reports", tags=["Forensic Reports"], dependencies=_auth_required)
api_router.include_router(users.router, prefix="/users", tags=["Users & Access Management"], dependencies=_auth_required)
api_router.include_router(platform_admin.router, prefix="/platform", tags=["Platform Administration"], dependencies=_auth_required)
api_router.include_router(ai.router, prefix="/ai", tags=["AI & RAG Intelligence"], dependencies=_auth_required)
api_router.include_router(disposition.router, prefix="/disposition", tags=["Human Review & Active Learning"], dependencies=_auth_required)
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"], dependencies=_auth_required)
api_router.include_router(sandbox.router, prefix="", tags=["Sandbox Forensic Detonation"], dependencies=_auth_required)
api_router.include_router(notifications_ws.router, prefix="", tags=["WebSocket & Real-Time Alerts"])

