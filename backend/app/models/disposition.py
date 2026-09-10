import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, Float, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class EmailDisposition(Base):
    """
    Authoritative human analyst review, verdict disposition, and active learning record.
    Tracks human triage gating, investigator rationale, containment actions, and memory vectorization.
    """
    __tablename__ = "email_dispositions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    verdict: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # CONFIRMED_PHISHING, CONFIRMED_BEC, CONFIRMED_FRAUD, FALSE_POSITIVE, CONFIRMED_LEGITIMATE, UNDER_INVESTIGATION
    triage_tier: Mapped[str] = mapped_column(
        String(50),
        default="TIER_2_HUMAN_GATED",
        nullable=False,
        index=True,
    )  # TIER_1_AUTO, TIER_2_HUMAN_GATED, TIER_3_AUTO_CLEARED, HUMAN_RESOLVED
    confidence: Mapped[float] = mapped_column(
        Float,
        default=1.0,
        nullable=False,
    )
    analyst_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    flagged_iocs: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )
    remediation_actions: Mapped[Optional[List[str]]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
    )
    reviewed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reviewed_by_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
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

    # Relationships
    email: Mapped["Email"] = relationship("Email", foreign_keys=[email_id])
    reviewed_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[reviewed_by_id])

    def __repr__(self) -> str:
        return f"<EmailDisposition(email_id={self.email_id}, verdict='{self.verdict}', tier='{self.triage_tier}')>"
