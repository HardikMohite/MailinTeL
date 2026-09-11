"""
Shared FastAPI dependencies for authentication and authorization.

Every API route (except /health and /auth/register|login) requires a valid
bearer access token — see app.api.v1.api for where this is wired in at the
router level. This module resolves that token into a concrete, active
(user, organization, role) context and exposes small helpers for
per-resource ownership checks.
"""
import uuid
import logging
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.core.security import decode_access_token
from app.models.identity import User, Organization, OrganizationMember, Role

logger = logging.getLogger("mailintel.auth")

# auto_error=False lets us return a uniform 401 JSON body instead of FastAPI's default.
_bearer_scheme = HTTPBearer(auto_error=False)

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass
class CurrentUser:
    """Resolved, authenticated identity for the current request."""
    id: uuid.UUID
    email: str
    full_name: Optional[str]
    organization_id: Optional[uuid.UUID]
    organization_name: Optional[str]
    role_code: str


# High-speed in-memory TTL cache for authenticated identities.
# Eliminates redundant multi-table Supabase queries across parallel panel requests.
import time
_USER_AUTH_CACHE: dict[str, tuple[float, "CurrentUser"]] = {}
_USER_CACHE_TTL = 60.0  # 60 seconds


def cache_user_auth(user: "CurrentUser") -> None:
    """Pre-populates the fast in-memory user identity cache."""
    _USER_AUTH_CACHE[str(user.id)] = (time.time(), user)


def invalidate_user_auth(user_id: uuid.UUID) -> None:
    """Evicts a user identity from the cache on logout, deactivation, or role mutation."""
    _USER_AUTH_CACHE.pop(str(user_id), None)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """
    Validate the bearer token, then resolve the user identity using a high-speed
    in-memory cache (60s TTL) with database fallback.
    """
    if credentials is None or not credentials.credentials:
        raise _CREDENTIALS_EXCEPTION

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        raise _CREDENTIALS_EXCEPTION

    # Fast path: check in-memory cache first (0.01ms resolution)
    uid_str = str(user_id)
    now = time.time()
    if uid_str in _USER_AUTH_CACHE:
        ts, cached_user = _USER_AUTH_CACHE[uid_str]
        if now - ts < _USER_CACHE_TTL:
            return cached_user

    # Single query: fetch User and their first active membership in one round-trip.
    stmt = (
        select(User, OrganizationMember, Organization, Role)
        .outerjoin(
            OrganizationMember,
            (OrganizationMember.user_id == User.id) & (OrganizationMember.status == "ACTIVE"),
        )
        .outerjoin(Organization, OrganizationMember.organization_id == Organization.id)
        .outerjoin(Role, OrganizationMember.role_id == Role.id)
        .where(User.id == user_id)
        .order_by(OrganizationMember.created_at.asc())
        .limit(1)
    )
    result = await db.execute(stmt)
    row = result.first()

    if row is None:
        raise _CREDENTIALS_EXCEPTION

    user, membership, organization, role = row

    if user is None or user.status != "ACTIVE":
        raise _CREDENTIALS_EXCEPTION

    org_id: Optional[uuid.UUID] = None
    org_name: Optional[str] = None
    role_code = "SYSTEM_ADMIN" if getattr(user, "is_platform_admin", False) else "USER"

    if membership is not None and organization is not None and role is not None:
        if organization.status == "ACTIVE" and role_code != "SYSTEM_ADMIN":
            org_id = organization.id
            org_name = organization.name
            role_code = role.code
        elif organization.status == "ACTIVE" and role.code == "SYSTEM_ADMIN":
            org_id = organization.id
            org_name = organization.name
            role_code = "SYSTEM_ADMIN"

    current_user = CurrentUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        organization_id=org_id,
        organization_name=org_name,
        role_code=role_code,
    )
    _USER_AUTH_CACHE[uid_str] = (now, current_user)
    return current_user


def require_roles(*allowed_codes: str):
    """
    Returns a dependency that additionally requires the caller's role to be
    one of `allowed_codes` (e.g. require_roles("SYSTEM_ADMIN", "INSTITUTION_ADMIN")).
    """

    async def _dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role_code not in allowed_codes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return _dependency


# ---------------------------------------------------------------------------
# MVP-04 fix: explicit role authorization matrix
# ---------------------------------------------------------------------------
#
# Role claims (Role.code) were already issued and returned to the client, but
# no route was actually enforcing them server-side — every active org member,
# regardless of role, could reach evidence verification, job cancellation,
# campaign mutation, and report generation/export. These constants define the
# minimum role sets for those operation classes; routes apply them via
# `Depends(require_roles(*ANALYST_ROLES))` etc. The client-side role string
# must never be treated as an authorization control on its own.
#
# ADMIN_ROLES gates org/user management specifically (see
# app.api.v1.endpoints.users: inviting, role changes, and deactivating
# members are INSTITUTION_ADMIN/SYSTEM_ADMIN-only; everything else stays on
# ANALYST_ROLES so a plain analyst can still work cases end to end).
# Roles with organization-wide investigation visibility. Cross-org roles are
# deliberately separate: they must not inherit organization-only filters.
ANALYST_ROLES = ("SECURITY_ANALYST", "INSTITUTION_ADMIN", "SYSTEM_ADMIN")
# SECURITY: these roles may read resources across organization boundaries.
CROSS_ORG_ROLES = ("CYBER_CELL_INVESTIGATOR", "SYSTEM_ADMIN")
ADMIN_ROLES = ("INSTITUTION_ADMIN", "SYSTEM_ADMIN")


def require_organization(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require the caller to belong to an active organization (blocks orphaned accounts)."""
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not attached to an active organization.",
        )
    return current_user


def require_organization_or_cross_org(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require an active organization unless the role is explicitly cross-org."""
    if current_user.role_code in CROSS_ORG_ROLES:
        return current_user
    return require_organization(current_user)


# ---------------------------------------------------------------------------
# Shared cross-tenant ownership checks
# ---------------------------------------------------------------------------
#
# SECURITY: every resource below is reachable by UUID from any endpoint the
# router mounts under `_auth_required` (see app.api.v1.api) — that dependency
# only proves the caller is *some* authenticated, active user. It does NOT
# prove the resource being requested belongs to that user's organization.
# Every route that accepts a resource UUID path parameter (email_id,
# campaign_id, job_id, report_id, ...) MUST additionally resolve ownership
# through one of these helpers before touching the underlying row, or it is
# silently cross-tenant readable/writable by any authenticated user on the
# platform who guesses/enumerates the UUID. All helpers return 404 (never
# 403) for both "does not exist" and "belongs to another organization", so a
# caller can't use the distinction to enumerate which IDs exist in other
# tenants.


async def get_authorized_email(
    email_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession,
):
    """
    Resolve an Email by ID and verify it belongs to the caller's organization.

    Ownership is derived transitively via email.source_id -> email_sources.
    organization_id, matching the convention already used by the emails and
    evidence routers. Returns the ORM Email instance on success.

    SECURITY (MVP-02 fix): this fails closed. An email with no linked
    EmailSource, or whose source has a null organization_id, has no provable
    owner and is therefore treated as NOT belonging to the caller — it is
    never returned, regardless of caller. Only an email whose source
    organization_id is present and matches the caller's organization is
    authorized. Legacy/orphaned rows must be backfilled or purged before
    they become accessible again.
    """
    from app.models.emails import Email, EmailSource  # local import avoids a cycle

    stmt = (
        select(Email, EmailSource)
        .outerjoin(EmailSource, Email.source_id == EmailSource.id)
        .where(Email.id == email_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Email with ID '{email_id}' not found",
    )
    if not row:
        raise not_found

    email_obj, source_obj = row
    source_org_id = source_obj.organization_id if source_obj else None
    if source_org_id is None or (
        current_user.role_code not in CROSS_ORG_ROLES
        and source_org_id != current_user.organization_id
    ):
        raise not_found

    # SCOPING: a plain USER account (not an analyst/admin role) may only
    # reach emails it personally uploaded — see ANALYST_ROLES/ADMIN_ROLES.
    # Ownership is EmailSource.user_id, the uploader. Anyone in
    # ANALYST_ROLES (which already includes INSTITUTION_ADMIN/SYSTEM_ADMIN)
    # keeps full org-wide visibility.
    if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
        source_user_id = source_obj.user_id if source_obj else None
        if source_user_id is None or source_user_id != current_user.id:
            raise not_found

    if current_user.role_code in CROSS_ORG_ROLES and source_org_id != current_user.organization_id:
        from app.core.audit import record_audit
        await record_audit(db, actor_user_id=current_user.id, organization_id=source_org_id, action="VIEW", resource_type="EMAIL", resource_id=email_obj.id)
    return email_obj


async def get_authorized_campaign(
    campaign_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession,
):
    """
    Resolve a Campaign by ID and verify it belongs to the caller's organization.

    Campaigns are stamped with organization_id at creation time (see
    app.services.campaign_service).

    SECURITY (MVP-03 fix): this fails closed. A campaign with no
    organization_id on record (e.g. a pre-migration legacy row) has no
    provable owner and is therefore treated as NOT belonging to the
    caller — it is never returned. Only a campaign whose organization_id is
    present and matches the caller's organization is authorized.
    """
    from app.models.campaign import Campaign, CampaignMembership  # local import avoids a cycle
    from app.models.emails import Email, EmailSource

    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Campaign with ID '{campaign_id}' not found",
    )
    if not campaign:
        raise not_found

    if campaign.organization_id is not None:
        if (
            current_user.role_code not in CROSS_ORG_ROLES
            and campaign.organization_id != current_user.organization_id
        ):
            raise not_found
    else:
        # System-level, global cluster, or seeded campaign with null organization_id.
        # Allow analyst and admin roles to inspect it.
        if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
            raise not_found

    # SCOPING: a plain USER account may only reach a campaign if it
    # contains at least one email that user personally uploaded ("their
    # campaigns"). Analyst/admin roles (ANALYST_ROLES) see every campaign
    # in the organization, including the full cross-email correlation.
    if current_user.role_code not in ANALYST_ROLES and current_user.role_code not in CROSS_ORG_ROLES:
        owns_stmt = (
            select(CampaignMembership.id)
            .join(Email, Email.id == CampaignMembership.email_id)
            .join(EmailSource, EmailSource.id == Email.source_id)
            .where(
                CampaignMembership.campaign_id == campaign_id,
                EmailSource.user_id == current_user.id,
            )
            .limit(1)
        )
        owns_result = await db.execute(owns_stmt)
        if owns_result.first() is None:
            raise not_found

    if current_user.role_code in CROSS_ORG_ROLES and campaign.organization_id != current_user.organization_id:
        from app.core.audit import record_audit
        await record_audit(db, actor_user_id=current_user.id, organization_id=campaign.organization_id, action="VIEW", resource_type="CAMPAIGN", resource_id=campaign.id)
    return campaign


async def get_authorized_report(
    report_id: uuid.UUID,
    current_user: CurrentUser,
    db: AsyncSession,
):
    """
    Resolve a Report by ID and verify the email/campaign it documents belongs
    to the caller's organization.

    SECURITY (MVP-03 fix): this fails closed. A report whose ownership chain
    cannot be resolved to exactly one non-null organization (no link, a
    linked email with no/null-org source, or a linked campaign with a null
    organization_id) has no provable owner and is therefore treated as NOT
    belonging to the caller — it is never returned. Only a report that
    resolves to a non-null organization equal to the caller's organization
    is authorized.
    """
    from app.models.reports import Report
    from app.models.emails import Email, EmailSource
    from app.models.campaign import Campaign

    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Report with ID '{report_id}' not found",
    )
    if not report:
        raise not_found

    owning_org_id = None
    resolved = False

    if report.email_id is not None:
        email_stmt = (
            select(EmailSource.organization_id)
            .join(Email, Email.source_id == EmailSource.id)
            .where(Email.id == report.email_id)
        )
        email_org_res = await db.execute(email_stmt)
        row = email_org_res.first()
        if row:
            owning_org_id = row[0]
            resolved = True

    if not resolved and report.campaign_id is not None:
        camp_stmt = select(Campaign.organization_id).where(Campaign.id == report.campaign_id)
        camp_org_res = await db.execute(camp_stmt)
        row = camp_org_res.first()
        if row:
            owning_org_id = row[0]
            resolved = True

    if not resolved or owning_org_id is None or (
        current_user.role_code not in CROSS_ORG_ROLES
        and owning_org_id != current_user.organization_id
    ):
        raise not_found

    if current_user.role_code in CROSS_ORG_ROLES and owning_org_id != current_user.organization_id:
        from app.core.audit import record_audit
        await record_audit(db, actor_user_id=current_user.id, organization_id=owning_org_id, action="VIEW", resource_type="REPORT", resource_id=report.id)
    return report
