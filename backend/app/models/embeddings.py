import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, DateTime, JSON, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from pgvector.sqlalchemy import Vector

from app.db.base import Base

DEFAULT_EMBEDDING_DIM = 384


class EmailEmbedding(Base):
    """
    SQLAlchemy ORM model for storing dense vector embeddings of email content,
    subject lines, and Email DNA feature vectors.
    """
    __tablename__ = "email_embeddings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        index=True,
        nullable=False,
    )
    embedding_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="EMAIL_CONTENT",
        index=True,
    )  # e.g., EMAIL_CONTENT, SUBJECT, EMAIL_DNA, THREAT_PATTERN
    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="all-MiniLM-L6-v2",
    )
    dimension: Mapped[int] = mapped_column(
        default=DEFAULT_EMBEDDING_DIM,
        nullable=False,
    )
    embedding: Mapped[List[float]] = mapped_column(
        Vector(DEFAULT_EMBEDDING_DIM),
        nullable=False,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<EmailEmbedding(id={self.id}, email_id={self.email_id}, "
            f"type='{self.embedding_type}', model='{self.model_name}', dim={self.dimension})>"
        )
