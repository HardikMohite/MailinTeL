"""seed_rbac_roles

Revision ID: 0002_seed_roles
Revises: 0001_initial
Create Date: 2026-09-06 00:00:00.000000

Seeds the fixed set of RBAC roles used by app.api.deps.require_roles(...) and
app.api.v1.endpoints.auth. Idempotent (ON CONFLICT DO NOTHING) so it is safe
to run against a database where a role was already auto-provisioned by the
application (e.g. via self-registration before this migration ran).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0002_seed_roles'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ROLES = [
    ("SYSTEM_ADMIN", "System Administrator", "Full platform access across all organizations."),
    ("INSTITUTION_ADMIN", "Institution Administrator", "Full access within their own organization."),
    ("SECURITY_ANALYST", "Security Analyst", "Investigates and triages email threats."),
    ("CYBER_CELL_INVESTIGATOR", "Cyber Cell Investigator", "Forensic investigator with evidence access."),
    ("USER", "User", "Standard user with baseline access."),
]


def upgrade() -> None:
    roles_table = sa.table(
        "roles",
        sa.column("id", sa.dialects.postgresql.UUID(as_uuid=True)),
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )
    conn = op.get_bind()
    for code, name, description in ROLES:
        conn.execute(
            sa.text(
                """
                INSERT INTO roles (id, code, name, description)
                VALUES (gen_random_uuid(), :code, :name, :description)
                ON CONFLICT (code) DO NOTHING
                """
            ),
            {"code": code, "name": name, "description": description},
        )


def downgrade() -> None:
    conn = op.get_bind()
    codes = tuple(code for code, _, _ in ROLES)
    conn.execute(sa.text("DELETE FROM roles WHERE code = ANY(:codes)"), {"codes": list(codes)})
