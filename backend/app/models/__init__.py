"""
MailIntel SQLAlchemy ORM Models Package
Exports all domain models matching the canonical Schema.md specification.
"""

from app.db.base import Base

# 1. Identity & RBAC-ready
from app.models.identity import (
    User,
    Organization,
    Role,
    Permission,
    RolePermission,
    OrganizationMember,
)

# 2. Email & Forensics
from app.models.emails import (
    EmailSource,
    Email,
    EmailHeader,
    EmailRecipient,
    EmailAuthenticationResult,
    RelayHop,
)

# 3. Evidence & Custody
from app.models.evidence import (
    EvidenceObject,
    CustodyEvent,
)

# 4. Intelligence, Domain, URL, IP & Geolocation
from app.models.intelligence import (
    Domain,
    DomainDNSRecord,
    DomainRegistrationIntel,
    URL,
    EmailURL,
    IPAddress,
    IPIntelligence,
    InfrastructureClassification,
    Geolocation,
    EntityGeolocation,
)

# 5. Threat Analysis & Explainable Findings
from app.models.analysis import (
    AnalysisRun,
    EmailAnalysis,
    AnalysisFinding,
)

# 6. Email DNA & Embeddings
from app.models.dna import (
    EmailDNAProfile,
    EmailSimilarityLink,
)
from app.models.embeddings import (
    EmailEmbedding,
    DEFAULT_EMBEDDING_DIM,
)

# 7. Campaign Intelligence
from app.models.campaign import (
    Campaign,
    CampaignMembership,
    CampaignEvidence,
    CampaignEvent,
)

# 8. Investigation Graph
from app.models.graph import (
    IntelEntity,
    IntelRelationship,
)

# 9. Cases & Investigation Actions
from app.models.cases import (
    Case,
    CaseEmail,
    CaseCampaign,
    InvestigationAction,
)

# 10. Reports
from app.models.reports import (
    Report,
)

# 11. Audit Logs
from app.models.audit import (
    AuditLog,
)

# 12. Privacy, Retention & Masking
from app.models.retention import (
    RetentionPolicy,
    RetentionAssignment,
    DataClassification,
    MaskingRule,
)

# 13. Threat Indicators & Sightings
from app.models.indicators import (
    ThreatIndicator,
    IndicatorSighting,
)

# 14. Integrations
from app.models.oauth import (
    OAuthConnection,
)
from app.models.extension import (
    ExtensionEvent,
)

# 15. Human Dispositions & Active Learning
from app.models.disposition import (
    EmailDisposition,
)

__all__ = [
    "Base",
    # Identity
    "User",
    "Organization",
    "Role",
    "Permission",
    "RolePermission",
    "OrganizationMember",
    # Emails
    "EmailSource",
    "Email",
    "EmailHeader",
    "EmailRecipient",
    "EmailAuthenticationResult",
    "RelayHop",
    # Evidence
    "EvidenceObject",
    "CustodyEvent",
    # Intelligence
    "Domain",
    "DomainDNSRecord",
    "DomainRegistrationIntel",
    "URL",
    "EmailURL",
    "IPAddress",
    "IPIntelligence",
    "InfrastructureClassification",
    "Geolocation",
    "EntityGeolocation",
    # Analysis
    "AnalysisRun",
    "EmailAnalysis",
    "AnalysisFinding",
    # DNA & Embeddings
    "EmailDNAProfile",
    "EmailSimilarityLink",
    "EmailEmbedding",
    "DEFAULT_EMBEDDING_DIM",
    # Campaigns
    "Campaign",
    "CampaignMembership",
    "CampaignEvidence",
    "CampaignEvent",
    # Graph
    "IntelEntity",
    "IntelRelationship",
    # Cases
    "Case",
    "CaseEmail",
    "CaseCampaign",
    "InvestigationAction",
    # Reports
    "Report",
    # Audit
    "AuditLog",
    # Retention
    "RetentionPolicy",
    "RetentionAssignment",
    "DataClassification",
    "MaskingRule",
    # Indicators
    "ThreatIndicator",
    "IndicatorSighting",
    # Integrations
    "OAuthConnection",
    "ExtensionEvent",
    # Dispositions
    "EmailDisposition",
]
