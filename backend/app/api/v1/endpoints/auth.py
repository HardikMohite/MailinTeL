import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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
from app.api.deps import get_current_user, CurrentUser
from app.models.identity import User, Organization, OrganizationMember, Role

logger = logging.getLogger("mailintel.auth")

router = APIRouter()

# Deliberately generic — never reveal whether the failure was "no such email"
# vs "wrong password". Distinguishing the two is a classic user-enumeration bug.
_INVALID_CREDENTIALS_DETAIL = "Incorrect email or password."


class RegisterRequest(BaseModel):
    email: EmailStr
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
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)


class UserPublic(BaseModel):
    id: str
    email: str
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
        # Generic message — do not confirm the email already exists.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to register with the provided details.",
        )

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
            full_name=user.full_name,
            organization_id=str(organization.id),
            organization_name=organization.name,
            role=role.code,
        ),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive an access token",
    dependencies=[Depends(rate_limiter(key_prefix="login", max_requests=10, window_seconds=300))],
)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    normalized_email = payload.email.lower()

    # Per-account lockout (independent of the per-IP rate limiter above) so a
    # distributed attack spraying one account's password from many IPs is still
    # slowed down. Fails open if Redis is unavailable.
    lockout_key = f"login_lockout:{normalized_email}"
    try:
        attempts = int(await redis_manager.client.get(lockout_key) or 0)
    except Exception:
        attempts = 0
    if attempts >= settings.MAX_LOGIN_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.LOGIN_LOCKOUT_MINUTES} minutes.",
        )

    result = await db.execute(select(User).where(User.email == normalized_email))
    user = result.scalar_one_or_none()

    # Always run verify_password (even against a dummy hash) so response timing
    # doesn't reveal whether the email exists (basic mitigation for user enumeration
    # via timing side-channel).
    dummy_hash = "$2b$12$CkP3RwqZ0e6z8G8Q1F3EEO7cQxvz5b3g8w0y8j0hVYt3aQeQmS1qO"
    password_ok = verify_password(payload.password, user.password_hash if user else dummy_hash)

    if not user or not password_ok or user.status != "ACTIVE":
        try:
            pipe = redis_manager.client.pipeline()
            pipe.incr(lockout_key)
            pipe.expire(lockout_key, settings.LOGIN_LOCKOUT_MINUTES * 60)
            await pipe.execute()
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS_DETAIL)

    try:
        await redis_manager.client.delete(lockout_key)
    except Exception:
        pass

    membership_stmt = (
        select(OrganizationMember, Organization, Role)
        .join(Organization, OrganizationMember.organization_id == Organization.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(OrganizationMember.user_id == user.id, OrganizationMember.status == "ACTIVE")
        .order_by(OrganizationMember.created_at.asc())
    )
    membership_res = await db.execute(membership_stmt)
    row = membership_res.first()

    org_id = org_name = None
    role_code = "SYSTEM_ADMIN" if getattr(user, "is_platform_admin", False) else "USER"
    if row:
        _, organization, role = row
        if organization.status == "ACTIVE" and role_code != "SYSTEM_ADMIN":
            org_id, org_name, role_code = organization.id, organization.name, role.code
        elif organization.status == "ACTIVE" and role.code == "SYSTEM_ADMIN":
            org_id, org_name, role_code = organization.id, organization.name, "SYSTEM_ADMIN"

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=user.id,
        organization_id=org_id,
        action="LOGIN",
        resource_type="AUTH",
        resource_id=user.id,
        metadata_json={"email": user.email, "role": role_code},
    )

    token = create_access_token(user_id=user.id, organization_id=org_id, role_code=role_code)
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=UserPublic(
            id=str(user.id),
            email=user.email,
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

