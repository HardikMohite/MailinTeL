import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, BigInteger, Integer, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class EmailSource(Base):
    """
    Identifies how an email entered MailIntel (FILE_UPLOAD, OAUTH_MAILBOX, BROWSER_EXTENSION, API).
    """
    __tablename__ = "email_sources"

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
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="FILE_UPLOAD",
    )  # FILE_UPLOAD, OAUTH_MAILBOX, BROWSER_EXTENSION, API
    source_provider: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # GMAIL, MICROSOFT, GENERIC
    source_reference: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
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

    # Relationships
    emails: Mapped[List["Email"]] = relationship(
        "Email", back_populates="source", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<EmailSource(id={self.id}, type='{self.source_type}', provider='{self.source_provider}')>"


class Email(Base):
    """
    Normalized email record storing forensic metadata, analysis status, and qualification status.
    """
    __tablename__ = "emails"

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
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("email_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    external_message_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    message_id_header: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        index=True,
    )
    subject: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    sender_address: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    sender_display_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    received_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    email_size_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    analysis_status: Mapped[str] = mapped_column(
        String(50),
        default="PENDING",
        nullable=False,
        index=True,
    )  # PENDING, PROCESSING, COMPLETED, FAILED
    qualification_status: Mapped[str] = mapped_column(
        String(50),
        default="NORMAL",
        nullable=False,
        index=True,
    )  # NORMAL, SUSPICIOUS, HIGH_RISK, MALICIOUS, CAMPAIGN_RELATED, QUALIFIED_FOR_INVESTIGATION
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
    source: Mapped["EmailSource"] = relationship("EmailSource", back_populates="emails")
    headers: Mapped[List["EmailHeader"]] = relationship(
        "EmailHeader", back_populates="email", cascade="all, delete-orphan", order_by="EmailHeader.header_order"
    )
    recipients: Mapped[List["EmailRecipient"]] = relationship(
        "EmailRecipient", back_populates="email", cascade="all, delete-orphan"
    )
    authentication_result: Mapped[Optional["EmailAuthenticationResult"]] = relationship(
        "EmailAuthenticationResult", back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    relay_hops: Mapped[List["RelayHop"]] = relationship(
        "RelayHop", back_populates="email", cascade="all, delete-orphan", order_by="RelayHop.sequence_number"
    )

    def __repr__(self) -> str:
        return f"<Email(id={self.id}, subject='{self.subject[:30] if self.subject else None}', status='{self.analysis_status}')>"


class EmailHeader(Base):
    """
    Stores all extracted headers from an email in original ordering.
    """
    __tablename__ = "email_headers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    header_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    header_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    normalized_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    header_order: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="headers")

    def __repr__(self) -> str:
        return f"<EmailHeader(id={self.id}, name='{self.header_name}', order={self.header_order})>"


class EmailRecipient(Base):
    """
    Stores parsed recipients (TO, CC, BCC) for forensic targeting analysis.
    """
    __tablename__ = "email_recipients"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recipient_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )  # TO, CC, BCC
    address: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    display_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="recipients")

    def __repr__(self) -> str:
        return f"<EmailRecipient(id={self.id}, type='{self.recipient_type}', address='{self.address}')>"


class EmailAuthenticationResult(Base):
    """
    Stores cryptographic and protocol authentication results (SPF, DKIM, DMARC, alignment).
    """
    __tablename__ = "email_authentication_results"

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
    spf_result: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, PERMERROR
    dkim_result: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # PASS, FAIL, NONE, TEMPERROR, PERMERROR
    dmarc_result: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # PASS, FAIL, NONE, TEMPERROR, PERMERROR
    from_alignment_result: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # PASS, FAIL, NONE
    return_path: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    reply_to: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
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
    email: Mapped["Email"] = relationship("Email", back_populates="authentication_result")

    def __repr__(self) -> str:
        return (
            f"<EmailAuthenticationResult(spf='{self.spf_result}', dkim='{self.dkim_result}', "
            f"dmarc='{self.dmarc_result}')>"
        )


class RelayHop(Base):
    """
    Reconstructed SMTP relay hops from parsed 'Received' headers.
    """
    __tablename__ = "relay_hops"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    source_host: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    source_ip: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    destination_host: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    reliability: Mapped[str] = mapped_column(
        String(50),
        default="UNVERIFIED",
        nullable=False,
    )  # HIGH, MEDIUM, LOW, UNVERIFIED
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
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
    email: Mapped["Email"] = relationship("Email", back_populates="relay_hops")

    def __repr__(self) -> str:
        return f"<RelayHop(seq={self.sequence_number}, src='{self.source_host}', ip='{self.source_ip}')>"
