import logging
import uuid
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import async_session_maker
from app.models.audit import AuditLog

logger = logging.getLogger("mailintel.audit")


async def record_audit(
    db: AsyncSession,
    *,
    actor_user_id: Optional[uuid.UUID],
    organization_id: Optional[uuid.UUID],
    action: str,
    resource_type: str,
    resource_id: Optional[uuid.UUID] = None,
    metadata_json: Optional[dict[str, Any]] = None,
) -> None:
    """
    Write an audit row without ever allowing the audit write to break the
    caller's request.

    SECURITY/RELIABILITY: this deliberately does NOT use the caller's `db`
    session/transaction (the `db` parameter is accepted for call-site
    compatibility and possible future use, but is otherwise unused). The
    primary route handler has already called `db.commit()` for its actual
    mutation by the time this runs; if the audit INSERT were left to ride
    along on that same session (via `db.add()` and the caller's later
    auto-commit in `app.db.session.get_db()`), a malformed audit row -- e.g.
    a `metadata_json` value that fails to serialize, or a future FK
    constraint -- would raise out of `get_db()`'s post-request auto-commit,
    long after the primary action already succeeded, turning a successful
    invite/role-change/deactivate/org-create into a 500. Opening a fully
    separate short-lived session here (the same `async_session_maker()`
    fire-and-forget pattern used by app.services.pipeline_service) means the
    audit write has its own transaction and its own try/except: it can fail
    and be logged in complete isolation from the request that triggered it.
    """
    try:
        async with async_session_maker() as session:
            session.add(
                AuditLog(
                    actor_user_id=actor_user_id,
                    organization_id=organization_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    metadata_json=metadata_json or {},
                )
            )
            await session.commit()
    except Exception:
        logger.exception("Audit write failed for %s/%s", resource_type, action)
