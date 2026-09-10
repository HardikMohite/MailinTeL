import uuid
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.db.session import async_session_maker
from app.models.identity import User, Organization, OrganizationMember, Role

logger = logging.getLogger("mailintel.init_db")


async def init_admin_account(db: Optional[AsyncSession] = None) -> bool:
    """
    Auto-provisions the primary system administrator user and organization
    configured via ADMIN_EMAIL and ADMIN_PASSWORD in .env if not already existing.
    """
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        return False

    admin_email = settings.ADMIN_EMAIL.strip().lower()

    async def _provision(session: AsyncSession) -> bool:
        # Check if user already exists
        existing_res = await session.execute(select(User).where(User.email == admin_email))
        existing_user = existing_res.scalar_one_or_none()
        if existing_user is not None:
            return False

        now = datetime.now(timezone.utc)

        # 1. Ensure or create Role
        role_res = await session.execute(select(Role).where(Role.code == "SYSTEM_ADMIN"))
        admin_role = role_res.scalar_one_or_none()
        if admin_role is None:
            admin_role = Role(
                id=uuid.uuid4(),
                code="SYSTEM_ADMIN",
                name="System Administrator",
                description="Global platform and system administrator",
            )
            session.add(admin_role)
            await session.flush()

        # 2. Ensure or create Organization
        org_name = (settings.ADMIN_ORG_NAME or "MailIntel Security Operations").strip()
        org_res = await session.execute(select(Organization).where(Organization.name == org_name))
        organization = org_res.scalar_one_or_none()
        if organization is None:
            organization = Organization(
                id=uuid.uuid4(),
                name=org_name,
                organization_type="ENTERPRISE",
                status="ACTIVE",
                created_at=now,
                updated_at=now,
            )
            session.add(organization)
            await session.flush()

        # 3. Create Admin User
        user = User(
            id=uuid.uuid4(),
            email=admin_email,
            full_name=settings.ADMIN_FULL_NAME or "Administrator",
            password_hash=hash_password(settings.ADMIN_PASSWORD),
            auth_provider="LOCAL",
            status="ACTIVE",
            is_platform_admin=True,
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        await session.flush()

        # 4. Create Organization Membership
        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=organization.id,
            user_id=user.id,
            role_id=admin_role.id,
            status="ACTIVE",
            created_at=now,
        )
        session.add(membership)
        await session.commit()

        logger.info("Successfully provisioned initial admin account: %s", admin_email)
        return True

    if db is not None:
        return await _provision(db)

    async with async_session_maker() as session:
        return await _provision(session)
