import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, DateTime, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class ExtensionEvent(Base):
    """
    Browser extension telemetry and forensic trigger events.
    """
    __tablename__ = "extension_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # GMAIL_WEB, OUTLOOK_WEB
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # EMAIL_VIEWED, SUSPICIOUS_FLAGGED, ANALYZE_TRIGGERED
    analysis_mode: Mapped[str] = mapped_column(
        String(50),
        default="VISIBLE_DATA_ONLY",
        nullable=False,
    )  # VISIBLE_DATA_ONLY, AUTHORIZED_PROVIDER_DATA
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
        return f"<ExtensionEvent(type='{self.event_type}', mode='{self.analysis_mode}')>"
