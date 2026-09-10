import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Text, DateTime, Integer, Boolean, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class RetentionPolicy(Base):
    """
    Configurable retention policy definitions per data category.
    """
    __tablename__ = "retention_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    data_category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # NORMAL_ANALYSIS, SUSPICIOUS_INCIDENT, MALICIOUS_INCIDENT, FORENSIC_EVIDENCE, INVESTIGATION_CASE, REPORT
    retention_days: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )  # NULL = Indefinite
    deletion_action: Mapped[str] = mapped_column(
        String(50),
        default="DELETE",
        nullable=False,
    )  # DELETE, ANONYMIZE, ARCHIVE
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<RetentionPolicy(category='{self.data_category}', days={self.retention_days})>"


class RetentionAssignment(Base):
    """
    Explicit retention overrides, legal holds, and custom expiry per evidence object or email.
    """
    __tablename__ = "retention_assignments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("retention_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    retain_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    hold_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    policy: Mapped["RetentionPolicy"] = relationship("RetentionPolicy")

    def __repr__(self) -> str:
        return f"<RetentionAssignment(policy_id={self.policy_id}, retain_until={self.retain_until})>"


class DataClassification(Base):
    """
    Data privacy classification labels applied to specific resources.
    """
    __tablename__ = "data_classifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    classification: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # NORMAL, SENSITIVE, FORENSIC_EVIDENCE, INVESTIGATION_RESTRICTED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    def __repr__(self) -> str:
        return f"<DataClassification(res={self.resource_type}, class='{self.classification}')>"


class MaskingRule(Base):
    """
    Role-specific masking rules for PII and sensitive header/content fields.
    """
    __tablename__ = "masking_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    data_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # EMAIL_ADDRESS, PII, EMAIL_CONTENT, SENSITIVE_METADATA
    role_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=True,
    )
    masking_strategy: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # REDACT, HASH, PARTIAL_MASK
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<MaskingRule(data_type='{self.data_type}', strategy='{self.masking_strategy}')>"
