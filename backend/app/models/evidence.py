import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, BigInteger, Boolean, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class EvidenceObject(Base):
    """
    Authoritative PostgreSQL record linking to MinIO object storage for forensic artifacts.
    """
    __tablename__ = "evidence_objects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    case_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    parent_evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="SET NULL"),
        nullable=True,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # ORIGINAL_EMAIL, ATTACHMENT, EXTRACTED_FILE, DERIVED_ARTIFACT, FORENSIC_REPORT
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    content_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    bucket_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    object_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    object_version_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        default="UPLOAD",
        nullable=False,
    )  # UPLOAD, OAUTH, BROWSER_EXTENSION, EXTRACTED, GENERATED
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    immutable: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    retention_status: Mapped[str] = mapped_column(
        String(50),
        default="ACTIVE",
        nullable=False,
    )  # ACTIVE, HOLD, ARCHIVED, SCHEDULED_DELETION
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    custody_events: Mapped[List["CustodyEvent"]] = relationship(
        "CustodyEvent", back_populates="evidence_object", cascade="all, delete-orphan", order_by="CustodyEvent.event_at"
    )
    derived_objects: Mapped[List["EvidenceObject"]] = relationship(
        "EvidenceObject", backref="parent_evidence", remote_side=[id]
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceObject(id={self.id}, type='{self.evidence_type}', file='{self.original_filename}', "
            f"sha256='{self.sha256_hash[:12]}...')>"
        )


class CustodyEvent(Base):
    """
    Immutable chain-of-custody audit log for evidence handling, analysis, and access.
    """
    __tablename__ = "custody_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # ACQUIRED, HASH_GENERATED, STORED, ANALYSIS_STARTED, ANALYSIS_COMPLETED, VIEWED, EXPORTED, REPORTED, VERIFIED, RETENTION_CHANGED, ACCESS_GRANTED
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    case_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    event_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    previous_event_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    event_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    evidence_object: Mapped["EvidenceObject"] = relationship("EvidenceObject", back_populates="custody_events")

    def __repr__(self) -> str:
        return f"<CustodyEvent(id={self.id}, evidence_id={self.evidence_id}, type='{self.event_type}')>"
