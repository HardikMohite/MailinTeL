import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Text, DateTime, Numeric, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class IntelEntity(Base):
    """
    Unified intelligence entity node for the Investigation Graph (EMAIL, SENDER, URL, DOMAIN, IP, etc.).
    """
    __tablename__ = "intel_entities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    entity_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # EMAIL, SENDER, URL, DOMAIN, IP, ASN, ATTACHMENT, CAMPAIGN, ORGANIZATION
    normalized_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )
    display_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    def __repr__(self) -> str:
        return f"<IntelEntity(id={self.id}, type='{self.entity_type}', val='{self.display_value[:30]}')>"


class IntelRelationship(Base):
    """
    Directed relationship edge between two intelligence entities with confidence and evidence.
    """
    __tablename__ = "intel_relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # SENT_FROM, CONTAINS, LINKED_TO, RESOLVES_TO, HOSTED_ON, SHARED_WITH, SIMILAR_TO, RELATED_TO
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    first_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    source_entity: Mapped["IntelEntity"] = relationship("IntelEntity", foreign_keys=[source_entity_id])
    target_entity: Mapped["IntelEntity"] = relationship("IntelEntity", foreign_keys=[target_entity_id])

    def __repr__(self) -> str:
        return f"<IntelRelationship(src={self.source_entity_id}, tgt={self.target_entity_id}, type='{self.relationship_type}')>"
