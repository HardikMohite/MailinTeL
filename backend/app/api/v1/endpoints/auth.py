import uuid
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple, Any

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func

from app.db.session import get_db
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    is_password_strong_enough,
    create_access_token,
)
from app.core.rate_limit import rate_limiter
from app.core.redis import redis_manager
from app.api.deps import get_current_user, CurrentUser, cache_user_auth
from app.models.identity import User, Organization, OrganizationMember, Role

logger = logging.getLogger("mailintel.auth")

router = APIRouter()

# Deliberately generic — never reveal whether the failure was "no such email/username"
# vs "wrong password". Distinguishing the two is a classic user-enumeration bug.
_INVALID_CREDENTIALS_DETAIL = "Incorrect email, username, or password."


class RegisterRequest(BaseModel):
    email: EmailStr
    username: Optional[str] = Field(None, min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=1, max_length=256)
    full_name: Optional[str] = Field(None, max_length=255)
    organization_name: Optional[str] = Field(None, max_length=255)

    @field_validator("password")
    @classmethod
    def _password_policy(cls, v: str) -> str:
        error = is_password_strong_enough(v)
        if error:
            raise ValueError(error)
        return v


class LoginRequest(BaseModel):
    email: Optional[str] = Field(None, min_length=1, max_length=256)
    username: Optional[str] = Field(None, min_length=1, max_length=256)
    identifier: Optional[str] = Field(None, min_length=1, max_length=256)
    password: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_identifier(self) -> "LoginRequest":
        val = self.identifier or self.username or self.email
        if not val or not val.strip():
            raise ValueError("Email or username is required.")
        return self

    @property
    def login_identifier(self) -> str:
        val = self.identifier or self.username or self.email or ""
        return val.strip()


class UserPublic(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserPublic


async def _get_or_create_role(db: AsyncSession, code: str, name: str) -> Role:
    result = await db.execute(select(Role).where(Role.code == code))
    role = result.scalar_one_or_none()
    if role is None:
        role = Role(id=uuid.uuid4(), code=code, name=name, description=f"Auto-provisioned role: {name}")
        db.add(role)
        await db.flush()
    return role


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account with USER access",
    dependencies=[Depends(rate_limiter(key_prefix="register", max_requests=5, window_seconds=300))],
)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    if not settings.ALLOW_SELF_SIGNUP:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-service registration is disabled. Contact your administrator for an invite.",
        )

    existing = await db.execute(select(User).where(User.email == payload.email.lower()))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in instead.",
        )

    # Determine unique username
    if payload.username:
        clean_uname = payload.username.strip().lower()
        existing_u = await db.execute(select(User).where(func.lower(User.username) == clean_uname))
        if existing_u.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This username is already taken. Please choose another username.",
            )
        assigned_username = clean_uname
    else:
        raw_prefix = payload.email.split("@")[0].lower()
        assigned_username = re.sub(r"[^a-zA-Z0-9_.-]", "", raw_prefix) or "user"

    now = datetime.now(timezone.utc)
    is_custom_org = bool(payload.organization_name and payload.organization_name.strip())
    org_name = payload.organization_name.strip() if is_custom_org else "Personal Workspace"
    organization = Organization(
        id=uuid.uuid4(),
        name=org_name,
        organization_type="ENTERPRISE" if is_custom_org else "PERSONAL",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(organization)

    user = User(
        id=uuid.uuid4(),
        email=payload.email.lower(),
        username=assigned_username,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        auth_provider="LOCAL",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(user)

    # Strictly enforce: Public self-registration only ever provisions standard USER access.
    # Elevated roles (INSTITUTION_ADMIN, CYBER_CELL_INVESTIGATOR, SYSTEM_ADMIN)
    # must be explicitly assigned by a System Administrator.
    role = await _get_or_create_role(db, "USER", "User")

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

    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=user.id,
        organization_id=organization.id,
        action="REGISTER",
        resource_type="USER",
        resource_id=user.id,
        metadata_json={"email": user.email, "workspace": organization.name},
    )

    logger.info("New user '%s' registered with role '%s' (workspace: %s)", user.email, role.code, organization.name)

    token = create_access_token(user_id=user.id, organization_id=organization.id, role_code=role.code)
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=UserPublic(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            organization_id=str(organization.id),
            organization_name=organization.name,
            role=role.code,
        ),
    )


# Fast in-memory lockout tracker to avoid blocking 1.5s Upstash Redis calls on clean logins
_LOCAL_LOCKOUT: Dict[str, Tuple[int, float]] = {}


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive an access token",
    dependencies=[Depends(rate_limiter(key_prefix="login", max_requests=10, window_seconds=300))],
)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    ident = payload.login_identifier.lower()
    now_ts = time.time()

    # 1. Fast local lockout check (<0.01ms) - only hits remote Redis if recent failures recorded
    lockout_key = f"login_lockout:{ident}"
    local_info = _LOCAL_LOCKOUT.get(ident)
    if local_info and now_ts < local_info[1] and local_info[0] >= settings.MAX_LOGIN_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.LOGIN_LOCKOUT_MINUTES} minutes.",
        )

    # 2. Single unified database query: fetches User, active OrganizationMember, Organization, and Role in 1 round-trip
    stmt = (
        select(User, OrganizationMember, Organization, Role)
        .outerjoin(
            OrganizationMember,
            (OrganizationMember.user_id == User.id) & (OrganizationMember.status == "ACTIVE"),
        )
        .outerjoin(Organization, OrganizationMember.organization_id == Organization.id)
        .outerjoin(Role, OrganizationMember.role_id == Role.id)
        .where(
            or_(
                func.lower(User.email) == ident,
                func.lower(User.username) == ident,
            )
        )
        .order_by(OrganizationMember.created_at.asc())
        .limit(1)
    )
    result = await db.execute(stmt)
    row = result.first()
    user, membership, organization, role = row if row else (None, None, None, None)

    # 3. Constant-time password verification
    dummy_hash = "$2b$12$CkP3RwqZ0e6z8G8Q1F3EEO7cQxvz5b3g8w0y8j0hVYt3aQeQmS1qO"
    password_ok = verify_password(payload.password, user.password_hash if user else dummy_hash)

    if not user or not password_ok or user.status != "ACTIVE":
        # Increment local lockout tracker
        curr_attempts = (local_info[0] + 1) if (local_info and now_ts < local_info[1]) else 1
        _LOCAL_LOCKOUT[ident] = (curr_attempts, now_ts + settings.LOGIN_LOCKOUT_MINUTES * 60)
        # Async background sync to Redis (non-blocking)
        async def _sync_lockout_incr():
            try:
                pipe = redis_manager.client.pipeline()
                pipe.incr(lockout_key)
                pipe.expire(lockout_key, settings.LOGIN_LOCKOUT_MINUTES * 60)
                await pipe.execute()
            except Exception:
                pass
        import asyncio
        asyncio.create_task(_sync_lockout_incr())
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS_DETAIL)

    # 4. Clean local lockout on success
    _LOCAL_LOCKOUT.pop(ident, None)
    import asyncio
    asyncio.create_task(redis_manager.client.delete(lockout_key))

    # Resolve organization and role
    org_id = org_name = None
    role_code = "SYSTEM_ADMIN" if getattr(user, "is_platform_admin", False) else "USER"
    if organization and role and organization.status == "ACTIVE":
        if role_code != "SYSTEM_ADMIN":
            org_id, org_name, role_code = organization.id, organization.name, role.code
        elif role.code == "SYSTEM_ADMIN":
            org_id, org_name, role_code = organization.id, organization.name, "SYSTEM_ADMIN"

    current_user_obj = CurrentUser(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        organization_id=org_id,
        organization_name=org_name,
        role_code=role_code,
    )

    # 5. Pre-populate L1 in-memory identity cache so immediate subsequent dashboard calls are 0.05ms
    cache_user_auth(current_user_obj)

    # 6. Dispatch background task for last_login_at and audit trail (non-blocking, saves ~2,000ms off response)
    async def _async_record_login(u_id: uuid.UUID, o_id: Optional[uuid.UUID], u_email: str, r_code: str):
        try:
            from app.db.session import async_session_maker
            from app.core.audit import record_audit
            async with async_session_maker() as bdb:
                u_res = await bdb.execute(select(User).where(User.id == u_id))
                u = u_res.scalar_one_or_none()
                if u:
                    u.last_login_at = datetime.now(timezone.utc)
                    await bdb.commit()
                await record_audit(
                    bdb,
                    actor_user_id=u_id,
                    organization_id=o_id,
                    action="LOGIN",
                    resource_type="AUTH",
                    resource_id=u_id,
                    metadata_json={"email": u_email, "role": r_code},
                )
        except Exception as e:
            logger.warning("Background login audit notice: %s", e)

    asyncio.create_task(_async_record_login(user.id, org_id, user.email, role_code))

    token = create_access_token(user_id=user.id, organization_id=org_id, role_code=role_code)
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=UserPublic(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            organization_id=str(org_id) if org_id else None,
            organization_name=org_name,
            role=role_code,
        ),
    )


@router.get("/me", response_model=UserPublic, summary="Get the current authenticated user")
async def read_current_user(current_user: CurrentUser = Depends(get_current_user)) -> UserPublic:
    return UserPublic(
        id=str(current_user.id),
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        organization_id=str(current_user.organization_id) if current_user.organization_id else None,
        organization_name=current_user.organization_name,
        role=current_user.role_code,
    )


class UpdateProfileRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=255)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=8, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _password_policy(cls, v: str) -> str:
        error = is_password_strong_enough(v)
        if error:
            raise ValueError(error)
        return v


@router.put("/profile", response_model=UserPublic, summary="Update current user profile")
async def update_profile(
    payload: UpdateProfileRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserPublic:
    user = await db.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found")

    user.full_name = payload.full_name.strip()
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return UserPublic(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        organization_id=str(current_user.organization_id) if current_user.organization_id else None,
        organization_name=current_user.organization_name,
        role=current_user.role_code,
    )


@router.put("/change-password", summary="Change current user password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await db.get(User, current_user.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found")

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    user.password_hash = hash_password(payload.new_password)
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()

    logger.info("User '%s' updated their password.", user.email)
    return {"status": "success", "message": "Password has been updated successfully."}

