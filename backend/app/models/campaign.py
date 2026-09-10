import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, Numeric, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class Campaign(Base):
    """
    Identified phishing/threat campaign clustering correlated emails and infrastructure.
    """
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    # SECURITY: authoritative tenant boundary for this campaign. Stamped at
    # creation time from the creating user's organization (see
    # app.services.campaign_service.create_campaign) and used by every
    # campaign-scoped endpoint to reject cross-tenant access. Nullable only
    # to accommodate pre-existing rows from before this column existed.
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    campaign_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    campaign_status: Mapped[str] = mapped_column(
        String(50),
        default="ACTIVE",
        nullable=False,
    )  # ACTIVE, INVESTIGATING, MITIGATED, ARCHIVED
    campaign_confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        default=0.0,
        nullable=False,
    )
    threat_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
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
    memberships: Mapped[List["CampaignMembership"]] = relationship(
        "CampaignMembership", back_populates="campaign", cascade="all, delete-orphan"
    )
    evidence: Mapped[List["CampaignEvidence"]] = relationship(
        "CampaignEvidence", back_populates="campaign", cascade="all, delete-orphan"
    )
    events: Mapped[List["CampaignEvent"]] = relationship(
        "CampaignEvent", back_populates="campaign", cascade="all, delete-orphan", order_by="CampaignEvent.occurred_at"
    )

    def __repr__(self) -> str:
        return f"<Campaign(id={self.id}, name='{self.campaign_name}', status='{self.campaign_status}')>"


class CampaignMembership(Base):
    """
    Many-to-many relationship linking emails to campaigns with individual confidence scores.
    Supports overlapping campaign hypotheses and bridge entities.
    """
    __tablename__ = "campaign_memberships"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    membership_confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    membership_status: Mapped[str] = mapped_column(
        String(50),
        default="CONFIRMED",
        nullable=False,
    )  # CONFIRMED, HYPOTHETICAL, EXCLUDED
    evidence_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(
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

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="memberships")

    def __repr__(self) -> str:
        return f"<CampaignMembership(campaign_id={self.campaign_id}, email_id={self.email_id}, conf={self.membership_confidence})>"


class CampaignEvidence(Base):
    """
    Evidence links proving correlation between disparate artifacts within a campaign.
    """
    __tablename__ = "campaign_evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # SHARED_URL, RELATED_DOMAIN, SHARED_INFRASTRUCTURE, SEMANTIC_SIMILARITY, ATTACHMENT_HASH, TEMPORAL_PATTERN, HEADER_PATTERN
    source_entity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    target_entity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="evidence")

    def __repr__(self) -> str:
        return f"<CampaignEvidence(campaign_id={self.campaign_id}, type='{self.evidence_type}', conf={self.confidence})>"


class CampaignEvent(Base):
    """
    Timeline events tracing campaign progression and attack milestones.
    """
    __tablename__ = "campaign_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="events")

    def __repr__(self) -> str:
        return f"<CampaignEvent(campaign_id={self.campaign_id}, type='{self.event_type}', time={self.occurred_at})>"
