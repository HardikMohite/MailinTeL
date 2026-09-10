# MailIntel — Implementation Plan

**Project:** MailIntel  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Document:** `ImplementationPlan.md`  
**Version:** 2.0  
**Implementation Strategy:** Feature-first, RBAC-ready architecture

---

# 1. Implementation Decision

MailIntel will **not implement full authentication or RBAC at the beginning**.

Instead, the project will follow this strategy:

```text
RBAC-READY ARCHITECTURE
          ↓
BUILD CORE MAILINTEL FEATURES
          ↓
COMPLETE END-TO-END INTELLIGENCE PIPELINE
          ↓
ADD AUTHENTICATION
          ↓
ENABLE RBAC ENFORCEMENT
          ↓
ADD ADVANCED INTEGRATIONS
```

This decision allows the team to focus first on MailIntel's core innovation while avoiding major architectural rework later.

---

# 2. Core Development Principle

MailIntel should be built as **one reusable intelligence pipeline with multiple future ingestion methods**.

```text
                 .eml Upload
                      │
              OAuth Integrations
                      │
              Browser Extension
                      │
                      ▼
             MAILINTEL CORE PIPELINE
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   Evidence       Forensic      Intelligence
   Preservation   Analysis      Correlation
        │             │             │
        └─────────────┼─────────────┘
                      ▼
              Campaign Intelligence
                      │
              ┌───────┴────────┐
              ▼                ▼
       Investigation Graph   Geo Map
              │                │
              └───────┬────────┘
                      ▼
                    Reports
```

The first implementation will use `.eml` upload as the primary ingestion method.

---

# 3. Authentication and RBAC Strategy

## 3.1 What Will Be Done From the Start

The architecture and database will remain ready for future multi-user access.

Important ownership and audit fields may exist where appropriate:

```text
user_id
organization_id
created_by
actor_user_id
created_at
updated_at
```

During early development, these fields may be:

- Nullable where appropriate
- Populated with a controlled demo identity
- Used for development and testing only

The database may also contain future RBAC tables:

```text
users
organizations
roles
permissions
organization_members
role_permissions
```

However, these tables will **not initially control application access**.

## 3.2 What Will Be Deferred

The following will be implemented after the core intelligence features are working:

- Registration
- Login
- Password reset
- JWT or session enforcement
- Protected frontend routes
- Permission middleware
- Role-based API enforcement
- Organization-level data isolation
- User management

## 3.3 Temporary Prototype Access

Until authentication is implemented:

```text
Application Mode: DEVELOPMENT / DEMO

Current Context:
User: MailIntel Demo User
Organization: MailIntel Demo Organization
Role Context: Development Admin
```

This is a development implementation only and must not be treated as production security.

---

# 4. Recommended Phase Order

```text
PHASE 0  → Project Foundation & RBAC-Ready Architecture
PHASE 1  → Core Database, Storage & Background Processing
PHASE 2  → .eml Upload & Evidence Preservation
PHASE 3  → Email Forensic Analysis
PHASE 4  → Threat Intelligence & Explainable Scoring
PHASE 5  → Email DNA & Semantic Similarity
PHASE 6  → Campaign Correlation & Investigation Graph
PHASE 7  → Geolocation Intelligence & Map
PHASE 8  → Investigation Workspace & Forensic Reports
PHASE 9  → Authentication
PHASE 10 → RBAC & Data Access Enforcement
PHASE 11 → OAuth Mailbox Integrations
PHASE 12 → Browser Extension
PHASE 13 → Testing, Deployment & SIH Demo
```

---

# PHASE 0 — PROJECT FOUNDATION & RBAC-READY ARCHITECTURE

## Goal

Create a stable technical foundation without spending development time on complete authentication.

## Backend Foundation

Set up:

- Python backend
- API architecture
- Environment configuration
- Dependency management
- Structured logging
- Error handling
- API versioning
- Background-task architecture

## Frontend Foundation

Set up:

- React
- TypeScript
- Vite
- Tailwind CSS
- Application routing
- API client
- Shared layouts
- Global application state where required

## Infrastructure

Prepare:

```text
PostgreSQL
pgvector
MinIO
Redis
Backend API
Frontend
```

## RBAC-Ready Decisions

Before feature development begins:

- Use UUID identifiers consistently
- Include ownership relationships where logically required
- Avoid hard-coding user assumptions into business logic
- Keep authentication logic separate from analysis logic
- Design APIs so authorization middleware can later be added
- Do not make the forensic pipeline dependent on a specific login implementation

## Deliverable

A working application foundation:

```text
Frontend
    ↓
Backend API
    ├── PostgreSQL + pgvector
    ├── MinIO
    └── Redis
```

### Phase Exit Criteria

- Frontend starts successfully
- Backend API responds successfully
- PostgreSQL connection works
- MinIO connection works
- Redis connection works
- Environment variables are correctly configured

---

# PHASE 1 — CORE DATABASE, STORAGE & BACKGROUND PROCESSING

## Goal

Prepare the infrastructure required by every major MailIntel feature.

## PostgreSQL

Implement the core schema required for:

```text
Emails
Evidence
Analysis
URLs
Domains
IP Addresses
Geolocation
Email DNA
Vectors
Campaigns
Graph Relationships
Reports
Audit Events
```

Future authentication tables may be created but remain inactive.

## MinIO

Prepare buckets:

```text
mailintel-evidence
mailintel-derived
mailintel-reports
mailintel-temp
```

## Redis

Use Redis for:

- Caching
- Temporary processing state
- Background task coordination where applicable
- Rate-limiting support where required

Redis must not be treated as the permanent source of forensic evidence.

## Background Processing

Prepare the pipeline for long-running tasks:

```text
Upload
   ↓
Processing Job Created
   ↓
Worker Processes Email
   ↓
Status Updated
   ↓
Frontend Receives Progress
```

## Deliverable

The platform has a stable data and processing foundation.

---

# PHASE 2 — .EML UPLOAD & FORENSIC EVIDENCE PRESERVATION

## Goal

Create the first complete MailIntel ingestion workflow.

This is the most important early phase because it allows the complete platform to be demonstrated without depending on OAuth approval or browser-extension distribution.

## User Flow

```text
User Uploads .eml
        ↓
File Validation
        ↓
SHA-256 Calculated
        ↓
Original Evidence Stored in MinIO
        ↓
Evidence Metadata Stored in PostgreSQL
        ↓
Chain-of-Custody Event Created
        ↓
Analysis Job Created
```

## Features

Implement:

- Drag-and-drop upload
- `.eml` validation
- MIME validation
- File-size validation
- Secure file handling
- SHA-256 calculation
- MinIO object storage
- Evidence metadata creation
- Processing status

## Evidence Rule

```text
PostgreSQL
    → Evidence metadata
    → SHA-256 hash
    → Object reference

MinIO
    → Original .eml
    → Original attachments where preserved
```

## Deliverable

A `.eml` file can enter MailIntel as preserved digital evidence.

### Phase Exit Criteria

- Original evidence remains unchanged
- SHA-256 is recorded
- MinIO object reference is correct
- Evidence metadata exists
- Initial custody events are recorded

---

# PHASE 3 — EMAIL FORENSIC ANALYSIS ENGINE

## Goal

Extract and structure the technical evidence contained in an email.

## Pipeline

```text
Original .eml
     ↓
MIME Parsing
     ↓
Header Extraction
     ↓
Metadata Extraction
     ↓
Body Analysis
     ↓
URL Extraction
     ↓
Attachment Identification
     ↓
Authentication Analysis
     ↓
Relay Path Reconstruction
```

## Features

### Email Metadata

Extract:

- Subject
- Sender
- Recipients
- Message ID
- Date
- Return-Path
- Reply-To

### Header Forensics

Analyze:

```text
From
Return-Path
Reply-To
Received
Authentication-Results
```

### Authentication Analysis

Evaluate:

```text
SPF
DKIM
DMARC
Alignment Indicators
```

### Relay Reconstruction

Extract observable SMTP hops from available `Received` headers.

Each hop may include:

```text
Host
IP
Sequence
Timestamp
Reliability
```

### URL and Attachment Extraction

Extract:

- URLs
- Domains
- Attachment names
- MIME types
- Attachment hashes where processed

## Deliverable

A structured forensic analysis view for every processed `.eml`.

---

# PHASE 4 — THREAT INTELLIGENCE & EXPLAINABLE SCORING

## Goal

Enrich extracted evidence and identify suspicious or malicious indicators.

## Domain Intelligence

Implement:

- DNS records
- MX records
- RDAP
- WHOIS where available
- Registrar intelligence
- Domain age where available
- Nameservers
- Hosting fingerprints

## IP Intelligence

Analyze:

- ASN
- ISP
- Network ownership
- Hosting provider
- Reverse DNS

## Infrastructure Classification

Support applicable indicators:

```text
TOR
VPN
PROXY
OPEN_RELAY
BOTNET_INDICATOR
CLOUD_HOSTED
```

These classifications are intelligence signals and not automatic proof of malicious activity.

## Threat Intelligence Adapter Layer

```text
MailIntel Core
      ↓
Intelligence Adapter
      ├── Provider A
      ├── Provider B
      ├── Provider C
      └── Local / Cached Intelligence
```

This keeps the platform independent of a single intelligence provider.

## Separate Scores

### Threat Risk Score

Answers:

> How risky does the email appear?

### Evidence Confidence Score

Answers:

> How reliable and strong is the supporting evidence?

These must remain separate.

## Deliverable

Every significant threat finding is explainable through evidence.

---

# PHASE 5 — EMAIL DNA & SEMANTIC SIMILARITY

## Goal

Create a multi-layer intelligence representation for each email.

## Email DNA

Generate:

```text
Content Fingerprint
Technical Fingerprint
Infrastructure Fingerprint
Behavioral Fingerprint
Temporal Fingerprint
```

## Vector Intelligence

Generate embeddings for relevant information using the selected AI embedding model.

Store vectors using:

```text
PostgreSQL + pgvector
```

## Similarity Capabilities

Support:

- Similar email content
- Similar phishing language
- Similar subjects
- Similar Email DNA patterns

## Critical Rule

```text
Vector Similarity
      ≠
Threat Score

Vector Similarity
      ≠
Automatic Campaign Membership
```

Vector similarity is one correlation signal among multiple forms of evidence.

## Deliverable

Analysts can discover and inspect related emails.

---

# PHASE 6 — CAMPAIGN CORRELATION & INVESTIGATION GRAPH

## Goal

Convert isolated suspicious emails into connected intelligence.

## Correlation Signals

```text
Shared URL
Shared Domain
Shared IP
Shared Infrastructure
Attachment Hash
Semantic Similarity
Email DNA Similarity
Header Pattern
Temporal Pattern
```

## Campaign Logic

```text
Multiple Evidence Signals
          ↓
Correlation Engine
          ↓
Campaign Confidence
          ↓
Campaign Hypothesis / Membership
```

## Overlapping Membership

MailIntel must support bridge entities.

```text
Email A ─── Shared Location ─── Email B
                                      │
                                      │ Shared URL
                                      │
                                   Email C
```

Email B may contribute evidence to more than one campaign.

```text
Email B
   ├── Campaign A
   └── Campaign B
```

## Investigation Graph

Visualize entities:

```text
Email
Sender
URL
Domain
IP
ASN
Attachment
Infrastructure
Campaign
```

Every important edge should include:

```text
Relationship Type
Confidence
Supporting Evidence
First Seen
Last Seen
```

## Deliverable

An explainable graph-based campaign intelligence system.

---

# PHASE 7 — GEOLOCATION INTELLIGENCE & MAP

## Goal

Visualize observable infrastructure and related campaign intelligence geographically.

## Pipeline

```text
IP / Infrastructure
       ↓
GeoIP Intelligence
       ↓
Country / Region / City
       ↓
Confidence + Accuracy Information
       ↓
Map Visualization
```

## MapLibre Features

- Infrastructure markers
- Campaign filtering
- Threat filtering
- Entity selection
- Geographic clustering
- Relationship paths

## Visual Relationship Paths

The map should support highlighted paths between related infrastructure points where supported by evidence.

Different visual styles may represent:

```text
High-Confidence Relationship
Suspicious Correlation
Low-Confidence Investigative Lead
```

## Critical Rule

```text
Infrastructure Geolocation
        ≠
Confirmed Attacker Location
```

## Deliverable

A connected geolocation intelligence experience.

---

# PHASE 8 — INVESTIGATION WORKSPACE & FORENSIC REPORTS

## Goal

Create the complete analyst-facing intelligence experience.

## Investigation Workspace

Support:

```text
Overview
Email Forensics
Indicators
Infrastructure
Geolocation
Relationship Graph
Campaign Intelligence
Timeline
Evidence
Reports
```

## Forensic Reports

Generate:

- Email forensic reports
- Threat intelligence reports
- Campaign intelligence reports
- Investigation summaries

## Report Integrity

For qualifying reports:

```text
Generate Report
       ↓
Store Object
       ↓
Calculate Hash
       ↓
Record Evidence Metadata
```

## Temporary Access Model

Until RBAC is implemented, these features will operate in a controlled demo environment.

The application should not claim that this temporary mode provides production-grade access control.

## Deliverable

A complete end-to-end MailIntel demonstration.

### Core MVP Is Complete After This Phase

```text
UPLOAD
   ↓
PRESERVE
   ↓
HASH
   ↓
PARSE
   ↓
ANALYZE
   ↓
ENRICH
   ↓
CORRELATE
   ↓
VISUALIZE
   ↓
INVESTIGATE
   ↓
REPORT
```

---

# PHASE 9 — AUTHENTICATION

## Goal

Introduce real user identity only after the core MailIntel pipeline is stable.

## Features

Implement:

- Registration where required
- Login
- Logout
- Secure password hashing
- JWT or secure session handling
- Token/session validation
- Password reset if included in the final product scope
- Protected frontend routes

## Security Requirements

- Passwords must be securely hashed
- Secrets must not be logged
- Authentication failures must be handled safely
- Authentication events should be auditable

## Migration Strategy

Existing development data should be migrated or associated with appropriate users and organizations where required.

## Deliverable

Real users can securely authenticate to MailIntel.

---

# PHASE 10 — RBAC & DATA ACCESS ENFORCEMENT

## Goal

Activate the RBAC-ready architecture designed during the earlier phases.

## Initial Roles

```text
USER
SECURITY_ANALYST
INSTITUTION_ADMIN
CYBER_CELL_INVESTIGATOR
SYSTEM_ADMIN
```

## Implementation

Enforce:

- Role-based API permissions
- Protected routes
- Organization boundaries
- Data-level authorization
- Evidence-access restrictions
- Investigation permissions
- Privacy and masking rules

## Example Access Model

| Role | Primary Access |
|---|---|
| User | Authorized personal email analysis and reports |
| Security Analyst | Organizational incidents and investigations |
| Institution Admin | Organization-level management and aggregated intelligence |
| Cyber Cell Investigator | Qualified investigation and campaign intelligence |
| System Admin | Platform administration |

## Important Rule

Cyber Cell investigators must not automatically receive unrestricted access to every normal email.

Access must consider:

```text
Qualification Status
Investigation Relevance
Role
Permission
Privacy Rules
Evidence Requirements
```

## Deliverable

MailIntel becomes a genuine multi-user, role-aware platform.

---

# PHASE 11 — OAUTH MAILBOX INTEGRATIONS

## Goal

Allow authorized users to connect supported email services.

## Initial Providers

```text
Gmail
Microsoft Outlook / Microsoft 365
```

## OAuth Flow

```text
Authenticated MailIntel User
          ↓
Connect Mailbox
          ↓
Provider Authorization
          ↓
User Grants Approved Permissions
          ↓
Authorization Code Returned
          ↓
Secure Backend Exchange
          ↓
Authorized Provider API Access
          ↓
Mail Data Enters MailIntel Pipeline
```

## Important Rules

- Never collect provider passwords
- Request minimum required permissions
- Protect token material
- Allow disconnection
- Record integration events

## Deliverable

Authorized mailbox data can enter the existing MailIntel analysis pipeline.

---

# PHASE 12 — BROWSER EXTENSION

## Goal

Provide supported browser-based email analysis.

## Mode A — Visible Data Analysis

```text
Supported Open Email
        ↓
Extension Reads Available Page Data
        ↓
Backend Analysis
        ↓
Limited Analysis Result
```

Possible capabilities:

- Visible sender analysis
- Subject analysis
- Visible URL analysis
- Visible content analysis

### Limitation

This mode must not claim complete raw-email forensic access.

---

## Mode B — Extension + Authorized Integration

```text
Browser Extension
        +
Authorized Mailbox Integration
        ↓
Permitted Provider Data
        ↓
MailIntel Core Pipeline
        ↓
Deep Analysis
```

This can provide deeper capabilities where technically supported.

## Existing Email Flow

```text
User Opens Email
      ↓
Extension Detects Supported Context
      ↓
Scan Requested
      ↓
MailIntel Result Displayed
```

## Incoming Email Flow

Reliable incoming-mail detection requiring mailbox-level access should use authorized provider integration rather than assuming that browser page monitoring can guarantee access to every new message's complete raw data.

The extension can display alerts and analysis results from the connected platform.

## Deliverable

A clearly defined extension experience with transparent capability limits.

---

# PHASE 13 — TESTING, DEPLOYMENT & SIH DEMO

## Testing

### Unit Tests

Test:

- Email parsing
- Hash generation
- Header extraction
- URL extraction
- Scoring logic
- Campaign correlation

### Integration Tests

```text
Upload
  ↓
Evidence Storage
  ↓
Database
  ↓
Analysis Worker
  ↓
Intelligence Enrichment
  ↓
Results
```

### Security Tests

After authentication and RBAC are implemented, test:

- Authentication
- Authorization
- Role boundaries
- Organization isolation
- File upload validation
- Sensitive-data exposure
- OAuth token handling

## SIH Demo Scenario

```text
1. Upload suspicious .eml
        ↓
2. Preserve original evidence
        ↓
3. Generate SHA-256
        ↓
4. Parse email
        ↓
5. Analyze headers and authentication
        ↓
6. Extract URLs and attachments
        ↓
7. Enrich domains and infrastructure
        ↓
8. Calculate Threat Risk Score
        ↓
9. Calculate Evidence Confidence Score
        ↓
10. Generate Email DNA
        ↓
11. Find semantic and technical relationships
        ↓
12. Correlate campaign evidence
        ↓
13. Show Investigation Graph
        ↓
14. Show Geo Intelligence Map
        ↓
15. Generate Forensic Report
```

---

# 5. Parallel Development Opportunities

Once Phase 1 is stable, work can proceed in parallel.

## Backend Team

```text
.eml Ingestion
Evidence Storage
Forensic Parsing
Threat Intelligence
Campaign Logic
```

## AI / Intelligence Team

```text
Threat Classification
Email DNA
Embeddings
Semantic Similarity
Correlation Models
```

## Frontend Team

```text
Upload Experience
Analysis Results
Investigation Workspace
Relationship Graph
Geo Intelligence Map
Reports
```

## Later Integration Team

```text
Authentication
RBAC
OAuth
Browser Extension
```

---

# 6. Why This Order Is Recommended

Building full authentication and RBAC before the core MailIntel engine would consume time on:

```text
Registration
Login
Sessions
JWT
Protected Routes
Permission Middleware
User Management
Organization Isolation
```

These are important production features, but they do not prove MailIntel's primary innovation.

The strongest development strategy is therefore:

```text
DESIGN FOR RBAC NOW
        ↓
DO NOT ENFORCE RBAC YET
        ↓
BUILD THE COMPLETE CORE PRODUCT
        ↓
ADD AUTHENTICATION
        ↓
ACTIVATE RBAC
```

---

# 7. Final Implementation Priority

The first goal is not:

> Build a complete user management system.

The first goal is:

> Prove that MailIntel can transform a suspicious email into connected, explainable and evidence-based cyber intelligence.

Therefore, the implementation priority is:

```text
EMAIL
  ↓
EVIDENCE
  ↓
FORENSICS
  ↓
INTELLIGENCE
  ↓
EMAIL DNA
  ↓
CORRELATION
  ↓
CAMPAIGN
  ↓
GRAPH
  ↓
GEOLOCATION
  ↓
REPORT
```

Authentication and RBAC are then added around a working and proven core platform.

---

# 8. Definition of Success

The MailIntel core prototype is successful when the following workflow works reliably:

```text
Upload .eml
    ↓
Preserve Original Evidence
    ↓
Generate SHA-256
    ↓
Store Object in MinIO
    ↓
Store Metadata in PostgreSQL
    ↓
Create Custody Record
    ↓
Perform Email Forensics
    ↓
Extract Indicators
    ↓
Enrich Infrastructure
    ↓
Generate Explainable Findings
    ↓
Calculate Separate Scores
    ↓
Generate Email DNA
    ↓
Find Related Emails
    ↓
Correlate Campaign Evidence
    ↓
Visualize Graph
    ↓
Visualize Geolocation
    ↓
Generate Report
```

After this workflow is proven, MailIntel can safely evolve into a multi-user platform through:

```text
Authentication
      ↓
Organizations
      ↓
Roles
      ↓
Permissions
      ↓
RBAC Enforcement
      ↓
OAuth Integrations
      ↓
Browser Extension
```

---

# Final Principle

> **Build the intelligence engine first, but never architect it in a way that prevents secure multi-user access later.**

MailIntel will therefore be developed with an **RBAC-ready schema from the beginning and full authentication/RBAC enforcement after the core forensic intelligence pipeline is operational**.
