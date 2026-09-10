"""add platform administrator flag

Revision ID: 0004_platform_admin_flag
Revises: 0003_add_campaign_organization_id
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_platform_admin_flag"
down_revision: Union[str, None] = "0003_campaign_org"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_platform_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_index("ix_users_is_platform_admin", "users", ["is_platform_admin"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_users_is_platform_admin", table_name="users")
    op.drop_column("users", "is_platform_admin")
