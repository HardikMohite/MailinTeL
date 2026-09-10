"""Platform-level organization and user administration for SYSTEM_ADMIN only."""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select
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


class CompanyAdminPublic(BaseModel):
    id: str
    full_name: Optional[str] = None
    email: str


class OrganizationPublic(BaseModel):
    id: str
    name: str
    organization_type: str
    status: str
    created_at: datetime
    company_admin: Optional[CompanyAdminPublic] = None
    member_count: int = 0


class OrganizationDetailPublic(OrganizationPublic):
    updated_at: datetime
    members: List[OrgMemberPublic] = []


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


class AssignMemberRequest(BaseModel):
    user_id: Optional[uuid.UUID] = None
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    role_code: str = Field("USER", max_length=50)

    @field_validator("role_code")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in PLATFORM_ROLES:
            raise ValueError(f"role_code must be one of: {', '.join(PLATFORM_ROLES)}")
        return value



class AssignCompanyAdminRequest(BaseModel):
    user_id: uuid.UUID


class EligibleUserPublic(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    status: str
    created_at: datetime


class UpdateOrgStatusRequest(BaseModel):
    status: str = Field(..., max_length=50)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in ("ACTIVE", "INACTIVE"):
            raise ValueError("status must be ACTIVE or INACTIVE")
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
    organization = Organization(
        id=uuid.uuid4(),
        name=payload.name.strip(),
        organization_type=payload.organization_type,
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(organization)
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=organization.id,
        action="CREATE",
        resource_type="ORGANIZATION",
        resource_id=organization.id,
    )
    return OrganizationPublic(
        id=str(organization.id),
        name=organization.name,
        organization_type=organization.organization_type,
        status=organization.status,
        created_at=organization.created_at,
        company_admin=None,
        member_count=0,
    )


@router.get("/organizations", response_model=List[OrganizationPublic])
async def list_organizations(
    include_personal: bool = Query(False, description="Whether to include personal workspaces"),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[OrganizationPublic]:
    stmt = select(Organization)
    if not include_personal:
        stmt = stmt.where(
            func.upper(Organization.organization_type) != "PERSONAL",
            func.lower(Organization.name) != "personal workspace",
        )
    stmt = stmt.order_by(Organization.created_at.asc())
    result = await db.execute(stmt)
    orgs = list(result.scalars().all())
    if not orgs:
        return []

    counts_map = {}
    try:
        counts_result = await db.execute(
            select(OrganizationMember.organization_id, func.count(OrganizationMember.id))
            .where(OrganizationMember.status == "ACTIVE")
            .group_by(OrganizationMember.organization_id)
        )
        for row in counts_result.all():
            if len(row) >= 2:
                counts_map[row[0]] = row[1]
    except Exception:
        counts_map = {}

    admins_map = {}
    try:
        admins_result = await db.execute(
            select(OrganizationMember.organization_id, User)
            .join(User, OrganizationMember.user_id == User.id)
            .join(Role, OrganizationMember.role_id == Role.id)
            .where(OrganizationMember.status == "ACTIVE", Role.code == "INSTITUTION_ADMIN")
            .order_by(OrganizationMember.created_at.asc())
        )
        for row in admins_result.all():
            if len(row) >= 2:
                org_id, user = row[0], row[1]
                if org_id not in admins_map and hasattr(user, "id"):
                    admins_map[org_id] = CompanyAdminPublic(
                        id=str(user.id),
                        full_name=user.full_name,
                        email=user.email,
                    )
    except Exception:
        admins_map = {}

    return [
        OrganizationPublic(
            id=str(row.id),
            name=row.name,
            organization_type=row.organization_type,
            status=row.status,
            created_at=row.created_at,
            company_admin=admins_map.get(row.id),
            member_count=counts_map.get(row.id, 0),
        )
        for row in orgs
    ]


@router.get("/organizations/{organization_id}", response_model=OrganizationDetailPublic)
async def get_organization_detail(
    organization_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> OrganizationDetailPublic:
    org = (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    members_stmt = (
        select(OrganizationMember, User, Role)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(OrganizationMember.organization_id == organization_id, OrganizationMember.status == "ACTIVE")
        .order_by(OrganizationMember.created_at.asc())
    )
    members_res = await db.execute(members_stmt)
    members = [
        _to_public(u, r, m)
        for m, u, r in members_res.all()
    ]

    company_admin = next(
        (CompanyAdminPublic(id=m.id, full_name=m.full_name, email=m.email) for m in members if m.role == "INSTITUTION_ADMIN"),
        None,
    )

    return OrganizationDetailPublic(
        id=str(org.id),
        name=org.name,
        organization_type=org.organization_type,
        status=org.status,
        created_at=org.created_at,
        updated_at=org.updated_at,
        company_admin=company_admin,
        member_count=len(members),
        members=members,
    )


@router.delete("/organizations/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    organization_id: uuid.UUID,
    permanent: bool = Query(False, description="If true, permanently remove organization from DB; otherwise soft-deactivate."),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> None:
    org = (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    if current_user.organization_id and org.id == current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete or deactivate the organization you are currently operating in.",
        )

    from app.core.audit import record_audit
    if not permanent:
        org.status = "INACTIVE"
        members_stmt = select(OrganizationMember).where(OrganizationMember.organization_id == organization_id)
        members_res = await db.execute(members_stmt)
        for m in members_res.scalars().all():
            m.status = "INACTIVE"
        await db.commit()
        await record_audit(
            db,
            actor_user_id=current_user.id,
            organization_id=org.id,
            action="DEACTIVATE",
            resource_type="ORGANIZATION",
            resource_id=org.id,
            metadata_json={"name": org.name},
        )
    else:
        org_name = org.name
        await db.delete(org)
        await db.commit()
        await record_audit(
            db,
            actor_user_id=current_user.id,
            organization_id=None,
            action="DELETE",
            resource_type="ORGANIZATION",
            resource_id=organization_id,
            metadata_json={"deleted_org_id": str(organization_id), "name": org_name},
        )


@router.patch("/organizations/{organization_id}/status", response_model=OrganizationPublic)
async def update_organization_status(
    organization_id: uuid.UUID,
    payload: UpdateOrgStatusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> OrganizationPublic:
    org = (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    if payload.status == "INACTIVE" and current_user.organization_id and org.id == current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate the organization you are currently operating in.",
        )

    org.status = payload.status
    members_stmt = select(OrganizationMember).where(OrganizationMember.organization_id == organization_id)
    members_res = await db.execute(members_stmt)
    for m in members_res.scalars().all():
        m.status = payload.status

    await db.commit()
    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=org.id,
        action="UPDATE_STATUS",
        resource_type="ORGANIZATION",
        resource_id=org.id,
        metadata_json={"status": payload.status},
    )
    return OrganizationPublic(
        id=str(org.id),
        name=org.name,
        organization_type=org.organization_type,
        status=org.status,
        created_at=org.created_at,
    )


@router.get("/organizations/{organization_id}/members", response_model=List[PlatformMemberPublic])
async def list_organization_members(
    organization_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[PlatformMemberPublic]:
    stmt = (
        select(OrganizationMember, User, Role, Organization)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .join(Organization, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.organization_id == organization_id, OrganizationMember.status == "ACTIVE")
        .order_by(OrganizationMember.created_at.asc())
    )
    result = await db.execute(stmt)
    return [
        PlatformMemberPublic(
            **_to_public(user, role, membership).model_dump(),
            organization_id=str(org.id),
            organization_name=org.name,
        )
        for membership, user, role, org in result.all()
    ]


@router.post("/organizations/{organization_id}/members", response_model=PlatformMemberPublic, status_code=status.HTTP_201_CREATED)
async def assign_organization_member(
    organization_id: uuid.UUID,
    payload: AssignMemberRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> PlatformMemberPublic:
    org = (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")
    if org.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign members to an inactive organization.")

    user: Optional[User] = None
    now = datetime.now(timezone.utc)

    if payload.email:
        email = payload.email.lower().strip()
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None:
            temp_password = _generate_temp_password()
            user = User(
                id=uuid.uuid4(),
                email=email,
                full_name=payload.full_name.strip() if payload.full_name else None,
                password_hash=hash_password(temp_password),
                auth_provider="LOCAL",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
                is_platform_admin=False,
            )
            db.add(user)
        else:
            if payload.full_name and not user.full_name:
                user.full_name = payload.full_name.strip()
    elif payload.user_id:
        user = (await db.execute(select(User).where(User.id == payload.user_id))).scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must provide email or user_id.")

    if user.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign an inactive user.")

    role_code = payload.role_code or "USER"
    role = await _get_or_create_role(db, role_code)

    existing_stmt = select(OrganizationMember).where(
        OrganizationMember.organization_id == org.id,
        OrganizationMember.user_id == user.id,
    )
    membership = (await db.execute(existing_stmt)).scalar_one_or_none()

    if membership is not None:
        membership.role_id = role.id
        membership.status = "ACTIVE"
    else:
        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=user.id,
            role_id=role.id,
            status="ACTIVE",
            created_at=now,
        )
        db.add(membership)

    if role_code == "SYSTEM_ADMIN":
        user.is_platform_admin = True
    elif role_code == "INSTITUTION_ADMIN" and not getattr(user, "is_platform_admin", False):
        user.is_platform_admin = False

    await db.commit()

    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=org.id,
        action="ASSIGN_MEMBER",
        resource_type="ORGANIZATION_MEMBER",
        resource_id=user.id,
        metadata_json={"role": role.code, "user_email": user.email},
    )
    return PlatformMemberPublic(
        **_to_public(user, role, membership).model_dump(),
        organization_id=str(org.id),
        organization_name=org.name,
    )


@router.post("/organizations/{organization_id}/company-admin", response_model=PlatformMemberPublic)
async def assign_company_admin(
    organization_id: uuid.UUID,
    payload: AssignCompanyAdminRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> PlatformMemberPublic:
    org = (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")
    if org.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign Company Admin to an inactive organization.")

    user = (await db.execute(select(User).where(User.id == payload.user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if user.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign an inactive user as Company Admin.")

    admin_role = await _get_or_create_role(db, "INSTITUTION_ADMIN")
    analyst_role = await _get_or_create_role(db, "SECURITY_ANALYST")
    now = datetime.now(timezone.utc)

    existing_admins = (
        await db.execute(
            select(OrganizationMember)
            .join(Role, OrganizationMember.role_id == Role.id)
            .where(
                OrganizationMember.organization_id == org.id,
                OrganizationMember.status == "ACTIVE",
                Role.code == "INSTITUTION_ADMIN",
                OrganizationMember.user_id != user.id,
            )
        )
    ).scalars().all()
    for prev_admin in existing_admins:
        prev_admin.role_id = analyst_role.id

    membership_res = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org.id,
            OrganizationMember.user_id == user.id,
        )
    )
    membership = membership_res.scalar_one_or_none()
    if membership is not None:
        membership.role_id = admin_role.id
        membership.status = "ACTIVE"
    else:
        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=user.id,
            role_id=admin_role.id,
            status="ACTIVE",
            created_at=now,
        )
        db.add(membership)

    if not getattr(user, "is_platform_admin", False):
        user.is_platform_admin = False

    await db.commit()
    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=org.id,
        action="ASSIGN_COMPANY_ADMIN",
        resource_type="ORGANIZATION",
        resource_id=org.id,
        metadata_json={"user_id": str(user.id), "user_email": user.email},
    )
    return PlatformMemberPublic(
        **_to_public(user, admin_role, membership).model_dump(),
        organization_id=str(org.id),
        organization_name=org.name,
    )


@router.delete("/organizations/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_organization_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> None:
    res = await db.execute(
        select(OrganizationMember, Role)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == "ACTIVE",
        )
    )
    row = res.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this organization.")
    membership, role = row

    if role.code == "INSTITUTION_ADMIN" and await _count_active_admins(db, organization_id) <= 1:
        total_active_members = (
            await db.execute(
                select(func.count(OrganizationMember.id)).where(
                    OrganizationMember.organization_id == organization_id,
                    OrganizationMember.status == "ACTIVE",
                )
            )
        ).scalar() or 0
        if total_active_members > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the organization's last remaining company admin while other members exist. Assign another company admin first.",
            )

    membership.status = "INACTIVE"
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=organization_id,
        action="REMOVE_MEMBER",
        resource_type="ORGANIZATION_MEMBER",
        resource_id=user_id,
    )


@router.get("/eligible-users", response_model=List[EligibleUserPublic])
async def list_eligible_users(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[EligibleUserPublic]:
    result = await db.execute(
        select(User).where(User.status == "ACTIVE").order_by(User.email.asc())
    )
    users = result.scalars().all()
    return [
        EligibleUserPublic(
            id=str(u.id),
            email=u.email,
            full_name=u.full_name,
            status=u.status,
            created_at=u.created_at,
        )
        for u in users
    ]


@router.get("/users", response_model=List[PlatformMemberPublic])
async def list_platform_users(
    organization_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> List[PlatformMemberPublic]:
    stmt = (
        select(OrganizationMember, User, Role, Organization)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .join(Organization, OrganizationMember.organization_id == Organization.id)
        .order_by(OrganizationMember.created_at.asc())
    )
    if organization_id:
        stmt = stmt.where(OrganizationMember.organization_id == organization_id)
    result = await db.execute(stmt)
    return [
        PlatformMemberPublic(
            **_to_public(user, role, membership).model_dump(),
            organization_id=str(org.id),
            organization_name=org.name,
        )
        for membership, user, role, org in result.all()
    ]


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
    user = User(
        id=uuid.uuid4(),
        email=email,
        full_name=payload.full_name,
        password_hash=hash_password(temporary_password),
        auth_provider="LOCAL",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
        is_platform_admin=payload.role_code == "SYSTEM_ADMIN",
    )
    role = await _get_or_create_role(db, payload.role_code)
    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        role_id=role.id,
        status="ACTIVE",
        created_at=now,
    )
    db.add_all([user, membership])
    await db.commit()
    from app.core.audit import record_audit
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=organization.id,
        action="CREATE",
        resource_type="USER",
        resource_id=user.id,
    )
    return InviteUserResponse(user=_to_public(user, role, membership), temporary_password=temporary_password)


@router.patch("/users/{user_id}/role", response_model=PlatformMemberPublic)
async def platform_update_role(
    user_id: uuid.UUID,
    payload: PlatformRoleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> PlatformMemberPublic:
    result = await db.execute(
        select(OrganizationMember, User, Role, Organization)
        .join(User, OrganizationMember.user_id == User.id)
        .join(Role, OrganizationMember.role_id == Role.id)
        .join(Organization, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user_id, OrganizationMember.status == "ACTIVE")
        .order_by(OrganizationMember.created_at.asc())
    )
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
    await record_audit(
        db,
        actor_user_id=current_user.id,
        organization_id=organization.id,
        action="UPDATE",
        resource_type="USER",
        resource_id=user.id,
        metadata_json={"role": new_role.code},
    )
    return PlatformMemberPublic(
        **_to_public(user, new_role, membership).model_dump(),
        organization_id=str(organization.id),
        organization_name=organization.name,
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def platform_deactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_roles("SYSTEM_ADMIN")),
) -> None:
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account.")
    result = await db.execute(
        select(OrganizationMember, Role)
        .join(Role, OrganizationMember.role_id == Role.id)
        .where(OrganizationMember.user_id == user_id, OrganizationMember.status == "ACTIVE")
        .order_by(OrganizationMember.created_at.asc())
    )
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
        await record_audit(
            db,
            actor_user_id=current_user.id,
            organization_id=membership.organization_id,
            action="DELETE",
            resource_type="USER",
            resource_id=user_id,
        )


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
        stmt = stmt.where(AuditLog.actor_user_id == actor_user_id)
    if organization_id:
        stmt = stmt.where(AuditLog.organization_id == organization_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if date_from:
        stmt = stmt.where(AuditLog.occurred_at >= date_from)
    if date_to:
        stmt = stmt.where(AuditLog.occurred_at <= date_to)
    result = await db.execute(stmt)
    return [
        AuditLogPublic(
            id=str(row.id),
            actor_user_id=str(row.actor_user_id) if row.actor_user_id else None,
            organization_id=str(row.organization_id) if row.organization_id else None,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=str(row.resource_id) if row.resource_id else None,
            occurred_at=row.occurred_at,
            metadata_json=row.metadata_json,
        )
        for row in result.scalars().all()
    ]
