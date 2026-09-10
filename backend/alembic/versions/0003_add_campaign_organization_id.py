"""add_campaign_organization_id

Adds campaigns.organization_id, the authoritative tenant boundary used by
every campaign-scoped endpoint (campaigns, geo, graph, reports) to reject
cross-organization access. Backfills existing rows from the organization of
their member emails, best-effort, since campaigns previously had no
tenant column at all.

Revision ID: 0003_campaign_org
Revises: 0002_seed_roles
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0003_campaign_org'
down_revision: Union[str, None] = '0002_seed_roles'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'campaigns',
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        'fk_campaigns_organization_id',
        'campaigns', 'organizations',
        ['organization_id'], ['id'],
        ondelete='SET NULL',
    )
    op.create_index('ix_campaigns_organization_id', 'campaigns', ['organization_id'])

    # Best-effort backfill: stamp each existing campaign with the
    # organization of its member emails, when every member email agrees on
    # a single organization. Campaigns whose members span more than one
    # organization (a pre-fix cross-tenant clustering artifact) or have no
    # resolvable organization are left NULL and must be triaged manually —
    # they will simply be inaccessible to all non-admin tenants until then,
    # which is the safe default.
    op.execute(
        """
        UPDATE campaigns c
        SET organization_id = resolved.org_id
        FROM (
            SELECT cm.campaign_id, MIN(es.organization_id::text)::uuid AS org_id
            FROM campaign_memberships cm
            JOIN emails e ON e.id = cm.email_id
            JOIN email_sources es ON es.id = e.source_id
            WHERE es.organization_id IS NOT NULL
            GROUP BY cm.campaign_id
            HAVING COUNT(DISTINCT es.organization_id) = 1
        ) AS resolved
        WHERE c.id = resolved.campaign_id
        """
    )


def downgrade() -> None:
    op.drop_index('ix_campaigns_organization_id', table_name='campaigns')
    op.drop_constraint('fk_campaigns_organization_id', 'campaigns', type_='foreignkey')
    op.drop_column('campaigns', 'organization_id')
