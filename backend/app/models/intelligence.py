import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, DateTime, Integer, Numeric, ForeignKey, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.db.base import Base


class Domain(Base):
    """
    Extracted domain intelligence record.
    """
    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    normalized_domain: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    root_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
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
    urls: Mapped[List["URL"]] = relationship("URL", back_populates="domain")
    dns_records: Mapped[List["DomainDNSRecord"]] = relationship(
        "DomainDNSRecord", back_populates="domain", cascade="all, delete-orphan"
    )
    registration_intel: Mapped[List["DomainRegistrationIntel"]] = relationship(
        "DomainRegistrationIntel", back_populates="domain", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Domain(id={self.id}, domain='{self.normalized_domain}')>"


class DomainDNSRecord(Base):
    """
    DNS records (A, AAAA, MX, TXT, NS, CNAME) associated with a domain.
    """
    __tablename__ = "domain_dns_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    record_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )  # A, AAAA, MX, TXT, NS, CNAME
    record_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(50),
        default="DNS_QUERY",
        nullable=False,
    )

    # Relationships
    domain: Mapped["Domain"] = relationship("Domain", back_populates="dns_records")

    def __repr__(self) -> str:
        return f"<DomainDNSRecord(domain_id={self.domain_id}, type='{self.record_type}')>"


class DomainRegistrationIntel(Base):
    """
    RDAP and WHOIS registration metadata for domain age and registrar intelligence.
    """
    __tablename__ = "domain_registration_intel"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(50),
        default="RDAP",
        nullable=False,
    )
    registrar: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    registered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    nameservers: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    raw_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    retrieved_at: Mapped[datetime] = mapped_column(
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

    # Relationships
    domain: Mapped["Domain"] = relationship("Domain", back_populates="registration_intel")

    def __repr__(self) -> str:
        return f"<DomainRegistrationIntel(domain_id={self.domain_id}, registrar='{self.registrar}')>"


class URL(Base):
    """
    Extracted normalized URL from email body, headers, or attachments.
    """
    __tablename__ = "urls"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    normalized_url: Mapped[str] = mapped_column(
        Text,
        unique=True,
        nullable=False,
        index=True,
    )
    url_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
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
    domain: Mapped[Optional["Domain"]] = relationship("Domain", back_populates="urls")
    email_links: Mapped[List["EmailURL"]] = relationship(
        "EmailURL", back_populates="url", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<URL(id={self.id}, hash='{self.url_hash[:12]}...')>"


class EmailURL(Base):
    """
    Association between emails and extracted URLs with context location.
    """
    __tablename__ = "email_urls"

    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        primary_key=True,
    )
    url_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("urls.id", ondelete="CASCADE"),
        primary_key=True,
    )
    context: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )  # BODY_LINK, BUTTON_HREF, IMAGE_SRC, HEADER
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    url: Mapped["URL"] = relationship("URL", back_populates="email_links")

    def __repr__(self) -> str:
        return f"<EmailURL(email_id={self.email_id}, url_id={self.url_id}, ctx='{self.context}')>"


class IPAddress(Base):
    """
    Extracted IP address from relay hops, DNS records, or URLs.
    """
    __tablename__ = "ip_addresses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    ip_address: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
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
    intelligence: Mapped[List["IPIntelligence"]] = relationship(
        "IPIntelligence", back_populates="ip", cascade="all, delete-orphan"
    )
    classifications: Mapped[List["InfrastructureClassification"]] = relationship(
        "InfrastructureClassification", back_populates="ip", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<IPAddress(id={self.id}, ip='{self.ip_address}')>"


class IPIntelligence(Base):
    """
    ASN, ISP, hosting provider, and reverse DNS intelligence for an IP address.
    """
    __tablename__ = "ip_intelligence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    ip_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_addresses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asn: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        index=True,
    )
    isp: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    network_owner: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    hosting_provider: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    reverse_dns: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    intelligence_source: Mapped[str] = mapped_column(
        String(50),
        default="MAXMIND",
        nullable=False,
    )
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    # Relationships
    ip: Mapped["IPAddress"] = relationship("IPAddress", back_populates="intelligence")

    def __repr__(self) -> str:
        return f"<IPIntelligence(ip_id={self.ip_id}, asn='{self.asn}', isp='{self.isp}')>"


class InfrastructureClassification(Base):
    """
    Infrastructure indicators (TOR, VPN, PROXY, OPEN_RELAY, BOTNET_INDICATOR, CLOUD_HOSTED, etc.).
    """
    __tablename__ = "infrastructure_classifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    ip_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_addresses.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    classification_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # TOR, VPN, PROXY, OPEN_RELAY, BOTNET_INDICATOR, CLOUD_HOSTED, HOSTING_PROVIDER, RESIDENTIAL_ISP
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(50),
        default="INTERNAL",
        nullable=False,
    )
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    ip: Mapped[Optional["IPAddress"]] = relationship("IPAddress", back_populates="classifications")

    def __repr__(self) -> str:
        return f"<InfrastructureClassification(type='{self.classification_type}', conf={self.confidence})>"


class Geolocation(Base):
    """
    Standardized geographic coordinate and administrative entity record.
    """
    __tablename__ = "geolocations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    country_code: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        index=True,
    )
    country_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    region_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    city_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    latitude: Mapped[Optional[float]] = mapped_column(
        Numeric(10, 7),
        nullable=True,
    )
    longitude: Mapped[Optional[float]] = mapped_column(
        Numeric(10, 7),
        nullable=True,
    )
    accuracy_radius_km: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    source: Mapped[str] = mapped_column(
        String(50),
        default="MAXMIND_GEOIP",
        nullable=False,
    )
    confidence: Mapped[Optional[float]] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    entity_links: Mapped[List["EntityGeolocation"]] = relationship(
        "EntityGeolocation", back_populates="geolocation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Geolocation(id={self.id}, country='{self.country_code}', city='{self.city_name}')>"


class EntityGeolocation(Base):
    """
    Connects an observable intelligence entity (e.g. IP, relay hop) to a Geolocation record.
    """
    __tablename__ = "entity_geolocations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    geolocation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("geolocations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # IP_ORIGIN, HOP_LOCATION, DOMAIN_SERVER_LOCATION
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )
    confidence: Mapped[float] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    geolocation: Mapped["Geolocation"] = relationship("Geolocation", back_populates="entity_links")

    def __repr__(self) -> str:
        return f"<EntityGeolocation(entity_id={self.entity_id}, geo_id={self.geolocation_id}, type='{self.relationship_type}')>"
