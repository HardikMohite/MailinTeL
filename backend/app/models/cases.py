import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class Case(Base):
    """
    Forensic investigation case record for Cyber Cell and analyst workflow.
    """
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    case_number: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="OPEN",
        nullable=False,
    )  # OPEN, IN_PROGRESS, CLOSED, ARCHIVED
    priority: Mapped[str] = mapped_column(
        String(50),
        default="MEDIUM",
        nullable=False,
    )  # CRITICAL, HIGH, MEDIUM, LOW
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
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
    case_emails: Mapped[List["CaseEmail"]] = relationship(
        "CaseEmail", back_populates="case", cascade="all, delete-orphan"
    )
    case_campaigns: Mapped[List["CaseCampaign"]] = relationship(
        "CaseCampaign", back_populates="case", cascade="all, delete-orphan"
    )
    actions: Mapped[List["InvestigationAction"]] = relationship(
        "InvestigationAction", back_populates="case", cascade="all, delete-orphan", order_by="InvestigationAction.action_at"
    )

    def __repr__(self) -> str:
        return f"<Case(num='{self.case_number}', title='{self.title}', status='{self.status}')>"


class CaseEmail(Base):
    """
    Associates qualifying emails with an investigation case.
    """
    __tablename__ = "case_emails"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        primary_key=True,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="case_emails")

    def __repr__(self) -> str:
        return f"<CaseEmail(case_id={self.case_id}, email_id={self.email_id})>"


class CaseCampaign(Base):
    """
    Associates campaigns with an investigation case.
    """
    __tablename__ = "case_campaigns"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        primary_key=True,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="case_campaigns")

    def __repr__(self) -> str:
        return f"<CaseCampaign(case_id={self.case_id}, campaign_id={self.campaign_id})>"


class InvestigationAction(Base):
    """
    Chronological record of actions taken by investigators on a case.
    """
    __tablename__ = "investigation_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # NOTE_ADDED, EVIDENCE_ATTACHED, STATUS_CHANGED, CAMPAIGN_LINKED, EXPORTED
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    action_at: Mapped[datetime] = mapped_column(
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

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="actions")

    def __repr__(self) -> str:
        return f"<InvestigationAction(case_id={self.case_id}, type='{self.action_type}')>"
