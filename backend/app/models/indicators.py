import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Text, DateTime, Numeric, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class ThreatIndicator(Base):
    """
    Threat indicators (IoCs) extracted and confirmed across campaigns (hash, domain, IP, URL).
    """
    __tablename__ = "threat_indicators"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    indicator_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # SHA256, DOMAIN, IP, URL, SENDER_EMAIL
    normalized_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )
    reputation: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        default=0.0,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="ACTIVE",
        nullable=False,
    )  # ACTIVE, DEPRECATED, WHITELISTED
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ThreatIndicator(type='{self.indicator_type}', val='{self.normalized_value[:30]}')>"


class IndicatorSighting(Base):
    """
    Sightings linking threat indicators to emails, campaigns, or evidence objects.
    """
    __tablename__ = "indicator_sightings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    context: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    # Relationships
    indicator: Mapped["ThreatIndicator"] = relationship("ThreatIndicator")

    def __repr__(self) -> str:
        return f"<IndicatorSighting(indicator_id={self.indicator_id}, time={self.observed_at})>"
