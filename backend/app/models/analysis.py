import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, Numeric, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class AnalysisRun(Base):
    """
    Records an execution of the forensic and threat intelligence analysis pipeline for an email.
    """
    __tablename__ = "analysis_runs"

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
    analysis_type: Mapped[str] = mapped_column(
        String(50),
        default="FULL_PIPELINE",
        nullable=False,
    )  # FULL_PIPELINE, HEADER_ONLY, URL_ONLY, RE_ANALYSIS
    analysis_version: Mapped[str] = mapped_column(
        String(50),
        default="1.0",
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="RUNNING",
        nullable=False,
        index=True,
    )  # PENDING, RUNNING, COMPLETED, FAILED
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    worker_reference: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    # Relationships
    analyses: Mapped[List["EmailAnalysis"]] = relationship(
        "EmailAnalysis", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    findings: Mapped[List["AnalysisFinding"]] = relationship(
        "AnalysisFinding", back_populates="analysis_run", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<AnalysisRun(id={self.id}, email_id={self.email_id}, status='{self.status}')>"


class EmailAnalysis(Base):
    """
    Stores primary threat risk score, evidence confidence score, and likelihood indicators.
    """
    __tablename__ = "email_analysis"

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
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    threat_classification: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # BENIGN, SUSPICIOUS, MALICIOUS, PHISHING, SPOOFING
    threat_risk_score: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )  # 0.00 to 100.00
    evidence_confidence_score: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )  # 0.00 to 100.00
    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    compromised_account_likelihood: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # HIGH, MEDIUM, LOW, UNLIKELY
    spoofed_domain_likelihood: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    anonymized_infrastructure_likelihood: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    malicious_environment_likelihood: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
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
    analysis_run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="analyses")

    def __repr__(self) -> str:
        return (
            f"<EmailAnalysis(id={self.id}, threat='{self.threat_classification}', "
            f"risk={self.threat_risk_score}, confidence={self.evidence_confidence_score})>"
        )


class AnalysisFinding(Base):
    """
    Granular, explainable findings contributing to the risk calculation.
    """
    __tablename__ = "analysis_findings"

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
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )  # SPF_FAILURE, LOOKALIKE_DOMAIN, MALICIOUS_URL, SUSPICIOUS_RELAY, BRAND_IMPERSONATION, CREDENTIAL_HARVESTING
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
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
    analysis_run: Mapped["AnalysisRun"] = relationship("AnalysisRun", back_populates="findings")

    def __repr__(self) -> str:
        return f"<AnalysisFinding(type='{self.finding_type}', sev='{self.severity}', conf={self.confidence})>"
