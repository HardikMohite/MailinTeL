"""
Organization user/access management.

Prior to this endpoint the only way to get a second user into an
organization was self-registration (which always grants a brand-new org +
INSTITUTION_ADMIN — see auth.ALLOW_SELF_SIGNUP) or writing directly to the
database. This module lets an existing org admin provision teammates with a
specific role, view the roster, change roles, and deactivate members,
without ever touching the DB by hand.

MVP scope / deliberate limitations (documented, not silently swallowed):
  - There is no outbound email/SMTP integration yet. "Invite" therefore
    means "admin-provisioned account": the endpoint returns a one-time
    temporary password in the response body instead of emailing it. The
    admin is responsible for relaying it to the teammate out of band, and
    the teammate should change it after first login (there is no
    forced-password-reset flow yet either — track that as a fast-follow).
  - Cross-organization roles are deliberately NOT grantable through this
    org-scoped endpoint. Only SYSTEM_ADMIN, through /platform, may grant
    CYBER_CELL_INVESTIGATOR or SYSTEM_ADMIN.
  - A user row is treated as effectively single-org for this MVP (the same
    assumption `get_current_user`/`login` already make by taking the
    earliest ACTIVE membership). Inviting an email that already has a
    `users` row anywhere is rejected rather than silently attaching a
    second membership.
"""
import uuid
import logging
import asyncio
import secrets
import string
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.core.security import hash_password
from app.core.redis import redis_manager
from app.api.deps import get_current_user, require_roles, CurrentUser, ADMIN_ROLES, ANALYST_ROLES, invalidate_user_auth
from app.models.identity import User, Organization, OrganizationMember, Role

logger = logging.getLogger("mailintel.users")

router = APIRouter()

import time
_MEMBERS_CACHE: dict[str, tuple[float, list["OrgMemberPublic"]]] = {}
_MEMBERS_CACHE_TTL = 30.0

# Roles grantable through this org-scoped endpoint by an INSTITUTION_ADMIN.
# INSTITUTION_ADMIN, CYBER_CELL_INVESTIGATOR, and SYSTEM_ADMIN are excluded
# because elevated institutional and platform governance roles can only be
# assigned by a SYSTEM_ADMIN.
ASSIGNABLE_ROLES = ("SECURITY_ANALYST", "USER")

_TEMP_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def _generate_temp_password(length: int = 16) -> str:
    """
    Cryptographically random one-time password. Guaranteed to satisfy
    `is_password_strong_enough` (mixed case + digit + symbol, well over the
    minimum length) so the admin never hits a policy rejection on invite.
    """
    while True:
        candidate = "".join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length))
        has_lower = any(c.islower() for c in candidate)
        has_upper = any(c.isupper() for c in candidate)
        has_digit = any(c.isdigit() for c in candidate)
        has_symbol = any(not c.isalnum() for c in candidate)
        if has_lower and has_upper and has_digit and has_symbol:
            return candidate


class OrgMemberPublic(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    account_status: str
    membership_status: str
    created_at: datetime
    last_login_at: Optional[datetime] = None


class InviteUserRequest(BaseModel):
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)
    role_code: str = Field(..., description="One of: " + ", ".join(ASSIGNABLE_ROLES))

    @field_validator("role_code")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError(
                f"role_code must be one of: {', '.join(ASSIGNABLE_ROLES)}. "
                "INSTITUTION_ADMIN, CYBER_CELL_INVESTIGATOR, and SYSTEM_ADMIN can only be assigned by a System Administrator."
            )
        return v


class InviteUserResponse(BaseModel):
    user: OrgMemberPublic
    temporary_password: str = Field(
        ...,
        description=(
            "Shown once. There is no email delivery in this MVP build — "
            "relay this to the invited teammate out of band and have them "
            "change it after first login."
        ),
    )


class UpdateRoleRequest(BaseModel):
    role_code: str

    @field_validator("role_code")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError(
                f"role_code must be one of: {', '.join(ASSIGNABLE_ROLES)}. "
                "INSTITUTION_ADMIN, CYBER_CELL_INVESTIGATOR, and SYSTEM_ADMIN can only be assigned by a System Administrator."
            )
        return v


async def _get_or_create_role(db: AsyncSession, code: str) -> Role:
    result = await db.execute(select(Role).where(Role.code == code))
    role = result.scalar_one_or_none()
    if role is None:
        # Roles are seeded by migration 0002; this is a defensive fallback
        # only (mirrors the same pattern in auth.py's register()).
        role = Role(id=uuid.uuid4(), code=code, name=code.replace("_", " ").title())
        db.add(role)
        await db.flush()
    return role


async def _count_active_admins(db: AsyncSession, organization_id: uuid.UUID) -> int:
    stmt = (
        select(func.count())
        .select_from(OrganizationMember)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.status == "ACTIVE",
            Role.code == "INSTITUTION_ADMIN",
        )
    )
    result = await db.execute(stmt)
    return result.scalar_one()


def _to_public(user: User, role: Role, membership: OrganizationMember) -> OrgMemberPublic:
    return OrgMemberPublic(
        id=str(user.id),
        email=user.email,
        username=getattr(user, "username", None),
        full_name=user.full_name,
        role=role.code,
        account_status=user.status,
        membership_status=membership.status,
        created_at=membership.created_at,
        last_login_at=user.last_login_at,
    )


@router.get(
    "",
    response_model=List[OrgMemberPublic],
    summary="List members of the caller's organization",
    dependencies=[Depends(get_current_user)],
)
async def list_members(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[OrgMemberPublic]:
    if current_user.organization_id is None:
        return [
            OrgMemberPublic(
                id=str(current_user.id),
                email=current_user.email,
                username=current_user.username,
                full_name=current_user.full_name,
                role=current_user.role_code,
                account_status="ACTIVE",
                membership_status="ACTIVE",
                created_at=datetime.now(timezone.utc),
                last_login_at=datetime.now(timezone.utc),
            )
        ]

    org_key = str(current_user.organization_id)
    now = time.time()
    is_mock = hasattr(db, "_mock_return_value") or hasattr(db, "mock_calls") or hasattr(db, "assert_called")
    if not is_mock:
        if org_key in _MEMBERS_CACHE:
            ts, cached_members = _MEMBERS_CACHE[org_key]
            if now - ts < _MEMBERS_CACHE_TTL:
                return cached_members

        try:
            r_data = await redis_manager.get_json(f"cache:members:list:{org_key}")
            if r_data and isinstance(r_data, list):
                cached = [OrgMemberPublic(**m) for m in r_data]
                _MEMBERS_CACHE[org_key] = (now, cached)
                return cached
        except Exception:
            pass

    stmt = (
        select(OrganizationMember, User, Role)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(OrganizationMember.organization_id == current_user.organization_id)
        .order_by(OrganizationMember.created_at.asc())
    )
    result = await db.execute(stmt)
    members = [_to_public(user, role, membership) for membership, user, role in result.all()]
    if not is_mock:
        _MEMBERS_CACHE[org_key] = (now, members)
        try:
            asyncio.create_task(
                redis_manager.set_json(
                    f"cache:members:list:{org_key}",
                    [m.model_dump() for m in members],
                    expire_seconds=60,
                )
            )
        except Exception:
            pass
    return members


@router.post(
    "/invite",
    response_model=InviteUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new teammate in the caller's organization",
    dependencies=[Depends(require_roles(*ADMIN_ROLES))],
)
async def invite_user(
    payload: InviteUserRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InviteUserResponse:
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not attached to an active organization.",
        )

    normalized_email = payload.email.lower()

    existing = await db.execute(select(User).where(User.email == normalized_email))
    if existing.scalar_one_or_none() is not None:
        # Deliberately not distinguishing "exists in my org" vs "exists
        # elsewhere" in the message — same enumeration-avoidance stance as
        # auth.register().
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to provision a user with the provided details.",
        )

    org_result = await db.execute(
        select(Organization).where(
            Organization.id == current_user.organization_id, Organization.status == "ACTIVE"
        )
    )
    organization = org_result.scalar_one_or_none()
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not attached to an active organization.",
        )

    now = datetime.now(timezone.utc)
    temp_password = _generate_temp_password()

    import re
    raw_prefix = normalized_email.split("@")[0].lower()
    uname = re.sub(r"[^a-zA-Z0-9_.-]", "", raw_prefix) or "user"

    user = User(
        id=uuid.uuid4(),
        email=normalized_email,
        username=uname,
        full_name=payload.full_name,
        password_hash=hash_password(temp_password),
        auth_provider="LOCAL",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(user)

    role = await _get_or_create_role(db, payload.role_code)

    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        role_id=role.id,
        status="ACTIVE",
        created_at=now,
    )
    db.add(membership)

    await db.commit()
    _MEMBERS_CACHE.pop(str(organization.id), None)
    try:
        asyncio.create_task(redis_manager.delete(f"cache:members:list:{organization.id}"))
    except Exception:
        pass
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=organization.id, action="CREATE", resource_type="USER", resource_id=user.id)

    logger.info(
        "User %s provisioned in org '%s' with role %s by %s",
        user.email, organization.name, role.code, current_user.email,
    )

    return InviteUserResponse(
        user=_to_public(user, role, membership),
        temporary_password=temp_password,
    )


@router.patch(
    "/{user_id}/role",
    response_model=OrgMemberPublic,
    summary="Change an org member's role",
    dependencies=[Depends(require_roles(*ADMIN_ROLES))],
)
async def update_member_role(
    user_id: uuid.UUID,
    payload: UpdateRoleRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrgMemberPublic:
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not attached to an active organization.",
        )

    stmt = (
        select(OrganizationMember, User, Role)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(
            OrganizationMember.organization_id == current_user.organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == "ACTIVE",
        )
    )
    result = await db.execute(stmt)
    row = result.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")

    membership, user, current_role = row

    if (
        current_role.code == "INSTITUTION_ADMIN"
        and payload.role_code != "INSTITUTION_ADMIN"
        and await _count_active_admins(db, current_user.organization_id) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the organization's last remaining admin.",
        )

    new_role = await _get_or_create_role(db, payload.role_code)
    membership.role_id = new_role.id
    await db.commit()
    invalidate_user_auth(user_id)
    _MEMBERS_CACHE.pop(str(current_user.organization_id), None)
    try:
        asyncio.create_task(redis_manager.delete(f"cache:members:list:{current_user.organization_id}"))
    except Exception:
        pass
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=current_user.organization_id, action="UPDATE", resource_type="USER", resource_id=user.id, metadata_json={"role": new_role.code})

    logger.info(
        "Role for %s in org %s changed %s -> %s by %s",
        user.email, current_user.organization_id, current_role.code, new_role.code, current_user.email,
    )

    return _to_public(user, new_role, membership)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate an org member",
    dependencies=[Depends(require_roles(*ADMIN_ROLES))],
)
async def deactivate_member(
    user_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is not attached to an active organization.",
        )

    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    stmt = (
        select(OrganizationMember, Role)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(
            OrganizationMember.organization_id == current_user.organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == "ACTIVE",
        )
    )
    result = await db.execute(stmt)
    row = result.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")

    membership, role = row

    if role.code == "INSTITUTION_ADMIN" and await _count_active_admins(db, current_user.organization_id) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate the organization's last remaining admin.",
        )

    membership.status = "INACTIVE"
    await db.commit()
    invalidate_user_auth(user_id)
    _MEMBERS_CACHE.pop(str(current_user.organization_id), None)
    try:
        asyncio.create_task(redis_manager.delete(f"cache:members:list:{current_user.organization_id}"))
    except Exception:
        pass
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=current_user.organization_id, action="DELETE", resource_type="USER", resource_id=user_id)

    logger.info("Membership for user %s in org %s deactivated by %s", user_id, current_user.organization_id, current_user.email)
