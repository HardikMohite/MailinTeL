# MailIntel — Technical Specification

**Product:** MailIntel  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Document:** Technical Specification  
**Status:** Final Architecture Baseline

---

# 1. Technical Vision

MailIntel is an evidence-driven platform for analyzing suspicious emails, extracting forensic indicators, enriching observable infrastructure, estimating infrastructure geolocation, and correlating related emails into explainable campaign intelligence.

The system must distinguish between:

- Individual email threat detection
- Evidence reliability
- Semantic similarity
- Campaign correlation

MailIntel must **not** be positioned as a mass email surveillance system. Analysis and investigator visibility are governed by authorization, role-based access, privacy controls, masking, retention policies, and qualifying malicious-incident workflows.

---

# 2. High-Level Architecture

```text
                EMAIL INGESTION
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
   .eml Upload      OAuth API       Browser Extension
       │               │                │
       └───────────────┼────────────────┘
                       ▼
              Secure Ingestion Layer
                       ▼
              Original Evidence Storage
                       ▼
                Forensic Parsing
                       ▼
            Indicator Extraction Layer
                       ▼
     ┌─────────┬─────────┬──────────────┐
     ▼         ▼         ▼              ▼
 Authentication AI/ML  Domain/IP    Threat Intel
 Analysis       │      Intelligence       │
               └─────────┬───────────────┘
                         ▼
                  Email DNA Engine
                         ▼
              Semantic + Graph Analysis
                         ▼
             Campaign Correlation Engine
                         ▼
           Geolocation & Intelligence Layer
                         ▼
        Role-Based Results / Investigation UI
```

---

# 3. Core Technology Stack

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React + TypeScript + Vite | Web application |
| UI | Tailwind CSS | Responsive interface |
| Backend | Python + FastAPI | APIs and analysis orchestration |
| Primary Database | PostgreSQL | Structured application and intelligence data |
| Vector Search | pgvector | Semantic embeddings and similarity search |
| Queue / Cache | Redis | Background jobs, caching, temporary state |
| Worker Processing | Python worker services | Long-running analysis and enrichment |
| Evidence Storage | MinIO | Original `.eml`, artifacts and generated evidence |
| Graph Analysis | NetworkX | Relationship and campaign analysis |
| Graph Visualization | Cytoscape.js | Interactive relationship graphs |
| Maps | MapLibre GL JS | Infrastructure geolocation visualization |
| IP Geolocation | MaxMind GeoIP | Approximate observable IP enrichment |
| Browser Extension | Chrome Extension (Manifest V3) | Email-context scanning and result display |
| Authentication | Secure application authentication + OAuth 2.0 / OIDC where applicable | Identity and authorized integrations |
| Gmail Integration | Gmail API + OAuth 2.0 | Authorized Gmail data access |
| Microsoft Integration | Microsoft Graph + OAuth 2.0 | Authorized Microsoft mail access |

The stack is modular so intelligence providers can be replaced without redesigning the core platform.

---

# 4. Email Ingestion Architecture

MailIntel supports four distinct analysis modes.

## Mode 1 — `.eml` Upload

This is the primary and strongest initial forensic mode.

```text
User Uploads .eml
       ↓
Generate Evidence ID
       ↓
Calculate SHA-256
       ↓
Preserve Original
       ↓
Create Parsed Working Representation
       ↓
Run Full Forensic Pipeline
```

### Capabilities

- Full available MIME structure
- Email headers
- Authentication metadata
- Body and URL extraction
- Attachment metadata and hashes
- Received-path analysis
- Email DNA generation
- Semantic analysis
- Campaign correlation
- Infrastructure intelligence
- Geolocation

The original evidence is never treated as a mutable analysis workspace.

---

## Mode 2 — Direct OAuth Integration

The user connects a supported email account through provider-authorized OAuth.

```text
User Selects Provider
       ↓
OAuth Consent
       ↓
Authorized Access Token
       ↓
Backend Requests Permitted Email Data
       ↓
Normalize / Preserve Evidence as Allowed
       ↓
Deep Analysis
```

### Supported architecture

- Gmail API + OAuth
- Microsoft Graph + OAuth

### Required user controls

- Permission explanation
- Connected-account management
- Scope visibility
- Disconnect / revoke flow

Actual access depth depends on provider APIs, granted scopes, and the email data available through those APIs.

---

## Mode 3 — Browser Extension Without Provider OAuth

This is a limited analysis mode.

```text
User Opens Supported Email Context
       ↓
Extension Detects Available Context
       ↓
Collects Legitimately Accessible Data
       ↓
Sends Authorized Analysis Request
       ↓
Backend Performs Limited Analysis
       ↓
Result Displayed in Extension
```

### Capabilities may include

- Visible sender information
- Visible subject
- Visible body text
- Links available to the extension in the supported page context
- Contextual indicators

### Limitation

Without provider-authorized data access, the extension must not claim guaranteed access to:

- Complete raw MIME
- All original headers
- Full mailbox content
- Every incoming email's complete raw data

This mode therefore has lower forensic depth.

---

## Mode 4 — Browser Extension With Provider OAuth

The extension provides the user experience while authorized backend integration retrieves permitted email data.

```text
User Opens Email
       ↓
Extension Identifies Supported Email Context
       ↓
Authorized Backend Uses Provider Access
       ↓
Permitted Email Data Retrieved
       ↓
Deep Forensic Pipeline
       ↓
Result Returned to Extension
       ↓
Full Details Available in Dashboard
```

This can provide a richer analysis experience than non-OAuth extension mode, subject to provider permissions and available API data.

---

# 5. Incoming and Existing Email Scenarios

## Scenario A — New / Incoming Email

MailIntel should scan incoming mail only through a supported and authorized integration path capable of providing the required data.

```text
New Email Event / Authorized Retrieval
       ↓
Email Data Available Through Supported Integration
       ↓
Automated Analysis
       ↓
Threat Result
       ↓
Appropriate User / Security Workflow
```

The browser extension alone must not be represented as universally intercepting all raw incoming mail.

## Scenario B — Existing Email Opened by User

```text
User Opens Existing Email
       ↓
Extension Detects Supported Context
       ↓
Scan Triggered
       ↓
Analysis Runs
       ↓
Result Displayed
```

Without OAuth this remains context-limited. With OAuth, permitted provider data can enable deeper analysis.

---

# 6. Forensic Analysis Pipeline

```text
Acquire
   ↓
Preserve
   ↓
Parse
   ↓
Extract
   ↓
Validate
   ↓
Enrich
   ↓
Score
   ↓
Correlate
   ↓
Present
```

Key forensic activities include:

- Header parsing
- From / Reply-To / Return-Path comparison
- Received-chain analysis
- SPF evaluation
- DKIM evaluation
- DMARC evaluation
- MIME structure inspection
- URL extraction
- Attachment metadata and hash extraction
- Sender-domain analysis
- Infrastructure indicator extraction

---

# 7. Threat Detection and AI

AI is one layer of the decision system, not the entire system.

The threat assessment can combine:

- Header anomalies
- Authentication failures or inconsistencies
- Sender anomalies
- URL characteristics
- Domain intelligence
- Attachment indicators
- AI semantic understanding
- Known threat intelligence
- Infrastructure signals

The model should produce explainable supporting reasons rather than only an opaque verdict.

---

# 8. Email DNA

Email DNA is MailIntel's structured multi-layer representation of an email.

It may include:

```text
Email DNA
├── Header Features
├── Sender Features
├── Authentication Features
├── Content Features
├── Semantic Representation
├── URL Features
├── Domain Features
├── IP / Infrastructure Features
├── Attachment Features
└── Behavioral / Campaign Features
```

Email DNA is not a single fixed hash. It is a normalized evidence representation used for comparison and correlation.

---

# 9. Semantic Similarity and pgvector

pgvector stores embeddings representing semantic characteristics of email content or other selected normalized text.

Example:

```text
Email A ── semantic similarity ── Email B
```

A similarity score is a **signal**, not automatic proof that two emails belong to the same campaign.

The final similarity threshold should be evaluated using validation data and tuned during development. It must not be blindly treated as a universal fixed rule.

---

# 10. NetworkX and Campaign Correlation

NetworkX is used to model relationships among intelligence entities.

## Possible nodes

- Email
- Domain
- URL
- IP address
- Attachment hash
- Infrastructure
- Campaign

## Possible edges

```text
Email A ── uses ── Domain X
Email A ── links ── URL Y
Email B ── shares ── IP Z
Email C ── similar-to ── Email A
```

Edges should carry evidence metadata where possible:

- Evidence type
- Weight
- Confidence
- Timestamp
- Supporting indicator

---

## Bridge Email / Multi-Cluster Scenario

An email does not have to be forced into one simplistic exclusive campaign relationship.

Example:

```text
Email A ── shared location ── Email B ── shared URL ── Email C
```

Email B acts as a bridge.

The correlation engine can preserve:

- Multiple meaningful relationships
- Overlapping clusters
- Bridge entities
- Separate campaign hypotheses where evidence is insufficient for merging

Campaign grouping must be evidence-driven and explainable.

---

# 11. Three Separate Scores

MailIntel must not confuse these values.

| Score | Meaning |
|---|---|
| **Threat Risk Score** | How suspicious or malicious an individual email appears |
| **Evidence Confidence Score** | How reliable, complete and corroborated the evidence supporting a finding is |
| **Campaign Correlation Confidence** | How strongly an email or entity is linked to a particular campaign |

Semantic similarity is an additional analytical signal and is not itself the campaign confidence score.

---

# 12. Domain Intelligence

For extracted domains, MailIntel may perform:

- DNS A / AAAA lookup
- MX lookup
- NS lookup
- TXT inspection where relevant
- CNAME analysis
- RDAP lookup
- WHOIS-compatible registration intelligence where publicly available
- Registrar analysis
- Domain-age signals
- Hosting fingerprinting
- Related IP analysis

Domain age or registration information alone must never be treated as proof of malicious activity.

---

# 13. Threat Intelligence Layer

The platform should use an adapter-based enrichment architecture.

```text
MailIntel
    ↓
Threat Intelligence Adapter Layer
    ├── Provider A
    ├── Provider B
    └── Configured Intelligence Feeds
```

Indicators may include:

- URLs
- Domains
- IP addresses
- File hashes

External reputation is supporting evidence, not the sole detection mechanism.

---

# 14. Infrastructure Classification

Observable infrastructure may be classified, where supported by reliable intelligence, as:

- Residential ISP
- Corporate infrastructure
- Cloud-hosted infrastructure
- VPS / hosting provider
- VPN-associated infrastructure
- Proxy-associated infrastructure
- TOR exit infrastructure
- Known open-relay indicator
- Botnet-related infrastructure indicator
- Unknown infrastructure

The system must distinguish between an observable relay or server and the actual physical location or identity of an attacker.

---

# 15. Geolocation

## Architecture

```text
Observable IP
      ↓
MaxMind / Configured Enrichment
      ↓
Country / Region / City Estimate
      ↓
ASN / Organization Context
      ↓
MapLibre Visualization
```

The UI must use careful language such as:

> Approximate location of observable infrastructure.

It must not claim that the marker necessarily identifies the attacker's real-world location.

---

# 16. MapLibre Geolocation Experience

MapLibre renders:

- Infrastructure markers
- Campaign clusters
- Shared infrastructure
- Geographic concentration
- Timeline-aware activity where supported

Filters may include:

- Campaign
- Infrastructure classification
- Time range
- Indicator type

---

# 17. Chain of Custody and Evidence Integrity

Each evidence item should receive:

- Evidence ID
- Acquisition timestamp
- SHA-256 integrity hash
- Source / ingestion mode
- Storage reference
- Analysis version
- Relevant access and processing events

```text
Evidence Acquired
      ↓
Hash Generated
      ↓
Original Preserved
      ↓
Analysis Performed on Working Representation
      ↓
Events Recorded
```

Example event history:

```text
Uploaded
Hashed
Stored
Analysis Started
Analysis Completed
Viewed by Authorized Role
Report Generated
```

This provides an auditable evidence trail. It must not be represented as automatically guaranteeing legal admissibility in every jurisdiction.

---

# 18. Privacy, Masking and Retention

MailIntel should follow privacy-by-design principles.

## Data minimization

Only collect and expose data required for the authorized purpose.

## Role-based visibility

Different roles receive different levels of information.

## Masking

Examples:

```text
user@example.com → use***@example.com
9876543210 → 98******10
```

## Configurable retention

Retention periods should be configurable rather than hard-coded.

## Investigation visibility

```text
All Authorized Analysis
        ↓
Automated Classification
        ├── Normal / Low-Risk → Standard User Workflow
        └── Qualifying Malicious Incident
                    ↓
              Policy Evaluation
                    ↓
          Authorized Investigation Workflow
```

The Cyber Cell or investigator interface should not become a general dashboard for reading all user emails.

---

# 19. Authentication and Authorization

Authentication and authorization should include:

- Secure user authentication
- OAuth 2.0 for supported provider integrations
- Role-Based Access Control (RBAC)
- Session/token security
- Provider token protection
- Explicit account disconnect/revocation flows

Roles:

1. Individual User
2. Security Analyst
3. Organization Administrator
4. Cyber Cell Investigator
5. Super Administrator

---

# 20. Data Storage Architecture

## PostgreSQL

Stores:

- Users
- Roles
- Cases
- Incidents
- Campaign metadata
- Indicators
- Analysis summaries
- Audit metadata
- Structured intelligence

## pgvector

Stores selected embeddings for:

- Semantic similarity
- Related content discovery

## Redis

Used for:

- Job queues
- Caching
- Temporary processing state
- Rate-control support where needed

Redis is not the permanent system of record.

## MinIO

Stores:

- Original `.eml` evidence
- Analysis artifacts
- Generated reports
- Evidence-related files

---

# 21. API Architecture

FastAPI exposes versioned REST APIs for:

- Authentication
- Email ingestion
- Analysis jobs
- Results
- Indicators
- Campaigns
- Cases
- Intelligence search
- Maps
- Reports
- Integrations
- Administration

Long-running analysis should be asynchronous:

```text
API Request
    ↓
Create Job
    ↓
Redis Queue
    ↓
Worker Processing
    ↓
Persist Result
    ↓
Frontend Retrieves Status / Result
```

---

# 22. Security Principles

- Encrypt data in transit
- Protect sensitive credentials and OAuth tokens
- Validate uploaded files
- Separate original evidence from working data
- Apply RBAC
- Maintain audit trails
- Minimize exposure of sensitive communication data
- Use secure secret management in deployment
- Apply rate limiting and input validation to APIs

---

# 23. Deployment Direction

A modular service architecture is recommended.

```text
Frontend
   ↓
API Gateway / Backend
   ├── PostgreSQL + pgvector
   ├── Redis
   ├── Worker Services
   └── MinIO

External / Configured Services
   ├── Gmail API
   ├── Microsoft Graph
   ├── MaxMind
   ├── DNS / RDAP Services
   └── Threat Intelligence Providers
```

The prototype can begin with a simpler deployment while preserving service boundaries for future scaling.

---

# 24. Final Technical Principle

```text
Raw Evidence
     ↓
Forensic Extraction
     ↓
Multi-Layer Intelligence
     ↓
Email DNA
     ↓
Explainable Correlation
     ↓
Campaign Intelligence
     ↓
Role-Based Action
```

MailIntel's technical architecture prioritizes forensic depth, explainability, privacy-aware visibility and evidence-based campaign intelligence.
