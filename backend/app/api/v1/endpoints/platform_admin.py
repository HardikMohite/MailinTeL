"""Platform-level organization and user administration for SYSTEM_ADMIN only."""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, require_roles
from app.db.session import get_db
from app.core.security import hash_password
from app.api.v1.endpoints.users import (
    OrgMemberPublic,
    InviteUserResponse,
    _generate_temp_password,
    _get_or_create_role,
    _to_public,
    _count_active_admins,
)
from app.models.identity import User, Organization, OrganizationMember, Role

router = APIRouter()
PLATFORM_ROLES = ("USER", "SECURITY_ANALYST", "INSTITUTION_ADMIN", "CYBER_CELL_INVESTIGATOR", "SYSTEM_ADMIN")


class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    organization_type: str = Field("ENTERPRISE", max_length=100)


class OrganizationPublic(BaseModel):
    id: str
    name: str
    organization_type: str
    status: str
    created_at: datetime


class PlatformInviteRequest(BaseModel):
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=255)
    organization_id: uuid.UUID
    role_code: str

    @field_validator("role_code")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in PLATFORM_ROLES:
            raise ValueError(f"role_code must be one of: {', '.join(PLATFORM_ROLES)}")
        return value


class PlatformRoleRequest(BaseModel):
    role_code: str

    @field_validator("role_code")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in PLATFORM_ROLES:
            raise ValueError(f"role_code must be one of: {', '.join(PLATFORM_ROLES)}")
        return value


class PlatformMemberPublic(OrgMemberPublic):
    organization_id: str
    organization_name: str


class AuditLogPublic(BaseModel):
    id: str
    actor_user_id: Optional[str]
    organization_id: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    occurred_at: datetime
    metadata_json: Optional[dict] = None


@router.post("/organizations", response_model=OrganizationPublic, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> OrganizationPublic:
    now = datetime.now(timezone.utc)
    organization = Organization(id=uuid.uuid4(), name=payload.name.strip(), organization_type=payload.organization_type, status="ACTIVE", created_at=now, updated_at=now)
    db.add(organization)
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=organization.id, action="CREATE", resource_type="ORGANIZATION", resource_id=organization.id)
    return OrganizationPublic(id=str(organization.id), name=organization.name, organization_type=organization.organization_type, status=organization.status, created_at=organization.created_at)


@router.get("/organizations", response_model=List[OrganizationPublic])
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[OrganizationPublic]:
    result = await db.execute(select(Organization).order_by(Organization.created_at.asc()))
    return [OrganizationPublic(id=str(row.id), name=row.name, organization_type=row.organization_type, status=row.status, created_at=row.created_at) for row in result.scalars().all()]


@router.get("/users", response_model=List[PlatformMemberPublic])
async def list_platform_users(
    organization_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[PlatformMemberPublic]:
    stmt = select(OrganizationMember, User, Role, Organization).join(User, OrganizationMember.user_id == User.id).join(Role, OrganizationMember.role_id == Role.id).join(Organization, OrganizationMember.organization_id == Organization.id).order_by(OrganizationMember.created_at.asc())
    if organization_id:
        stmt = stmt.where(OrganizationMember.organization_id == organization_id)
    result = await db.execute(stmt)
    return [PlatformMemberPublic(**_to_public(user, role, membership).model_dump(), organization_id=str(org.id), organization_name=org.name) for membership, user, role, org in result.all()]


@router.post("/users/invite", response_model=InviteUserResponse, status_code=status.HTTP_201_CREATED)
async def platform_invite_user(
    payload: PlatformInviteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> InviteUserResponse:
    organization = (await db.execute(select(Organization).where(Organization.id == payload.organization_id, Organization.status == "ACTIVE"))).scalar_one_or_none()
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")
    email = payload.email.lower()
    if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to provision a user with the provided details.")
    now = datetime.now(timezone.utc)
    temporary_password = _generate_temp_password()
    user = User(id=uuid.uuid4(), email=email, full_name=payload.full_name, password_hash=hash_password(temporary_password), auth_provider="LOCAL", status="ACTIVE", created_at=now, updated_at=now, is_platform_admin=payload.role_code == "SYSTEM_ADMIN")
    role = await _get_or_create_role(db, payload.role_code)
    membership = OrganizationMember(id=uuid.uuid4(), organization_id=organization.id, user_id=user.id, role_id=role.id, status="ACTIVE", created_at=now)
    db.add_all([user, membership])
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=organization.id, action="CREATE", resource_type="USER", resource_id=user.id)
    return InviteUserResponse(user=_to_public(user, role, membership), temporary_password=temporary_password)


@router.patch("/users/{user_id}/role", response_model=PlatformMemberPublic)
async def platform_update_role(
    user_id: uuid.UUID,
    payload: PlatformRoleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> PlatformMemberPublic:
    result = await db.execute(select(OrganizationMember, User, Role, Organization).join(User, OrganizationMember.user_id == User.id).join(Role, OrganizationMember.role_id == Role.id).join(Organization, OrganizationMember.organization_id == Organization.id).where(OrganizationMember.user_id == user_id, OrganizationMember.status == "ACTIVE").order_by(OrganizationMember.created_at.asc()))
    row = result.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    membership, user, old_role, organization = row
    if old_role.code == "INSTITUTION_ADMIN" and payload.role_code != "INSTITUTION_ADMIN" and await _count_active_admins(db, organization.id) <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove the organization's last remaining admin.")
    new_role = await _get_or_create_role(db, payload.role_code)
    membership.role_id = new_role.id
    user.is_platform_admin = payload.role_code == "SYSTEM_ADMIN"
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(db, actor_user_id=current_user.id, organization_id=organization.id, action="UPDATE", resource_type="USER", resource_id=user.id, metadata_json={"role": new_role.code})
    return PlatformMemberPublic(**_to_public(user, new_role, membership).model_dump(), organization_id=str(organization.id), organization_name=organization.name)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def platform_deactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> None:
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account.")
    result = await db.execute(select(OrganizationMember, Role).join(Role, OrganizationMember.role_id == Role.id).where(OrganizationMember.user_id == user_id, OrganizationMember.status == "ACTIVE").order_by(OrganizationMember.created_at.asc()))
    rows = result.all()
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    for membership, role in rows:
        if role.code == "INSTITUTION_ADMIN" and await _count_active_admins(db, membership.organization_id) <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate the organization's last remaining admin.")
        membership.status = "INACTIVE"
    await db.commit()
    from app.core.audit import record_audit
    for membership, role in rows:
        await record_audit(db, actor_user_id=current_user.id, organization_id=membership.organization_id, action="DELETE", resource_type="USER", resource_id=user_id)


@router.get("/audit-log", response_model=List[AuditLogPublic])
async def list_audit_log(
    actor_user_id: Optional[uuid.UUID] = Query(None),
    organization_id: Optional[uuid.UUID] = Query(None),
    action: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None, description="Only include entries occurring at or after this timestamp"),
    date_to: Optional[datetime] = Query(None, description="Only include entries occurring at or before this timestamp"),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[AuditLogPublic]:
    from app.models.audit import AuditLog
    stmt = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
    if actor_user_id:
        stmt = stmt.where(
            or_(
                AuditLog.actor_user_id == actor_user_id,
                AuditLog.resource_id == actor_user_id,
            )
        )
    if organization_id:
        stmt = stmt.where(AuditLog.organization_id == organization_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if date_from:
        stmt = stmt.where(AuditLog.occurred_at >= date_from)
    if date_to:
        stmt = stmt.where(AuditLog.occurred_at <= date_to)
    result = await db.execute(stmt)
    return [AuditLogPublic(id=str(row.id), actor_user_id=str(row.actor_user_id) if row.actor_user_id else None, organization_id=str(row.organization_id) if row.organization_id else None, action=row.action, resource_type=row.resource_type, resource_id=str(row.resource_id) if row.resource_id else None, occurred_at=row.occurred_at, metadata_json=row.metadata_json) for row in result.scalars().all()]
