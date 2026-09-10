"""add HNSW vector index for pgvector ANN similarity search

Revision ID: 0005_hnsw_index
Revises: 0004_platform_admin_flag
Create Date: 2026-09-10 16:13:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_hnsw_index"
down_revision: Union[str, None] = "0004_platform_admin_flag"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create HNSW index on the embedding column for fast approximate nearest
    # neighbor cosine similarity search.  pgvector's HNSW index supports the
    # <=> (cosine distance) operator and dramatically reduces query time for
    # similarity search from O(N) full scan to O(log N) approximate search.
    #
    # Parameters:
    #   m = 16        — number of bi-directional links per node (default 16)
    #   ef_construction = 64  — size of dynamic candidate list during build (default 64)
    #
    # The vector_cosine_ops operator class is required for cosine distance queries.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_email_embeddings_hnsw
        ON email_embeddings
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64);
        """
    )

    # Also create a composite index on (embedding_type, email_id) for
    # filtered similarity queries that restrict to a specific embedding type.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_email_embeddings_type_email
        ON email_embeddings (embedding_type, email_id);
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_email_embeddings_type_email;")
    op.execute("DROP INDEX IF EXISTS ix_email_embeddings_hnsw;")
