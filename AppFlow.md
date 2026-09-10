# MailIntel — Application Flow and User Experience Specification

**Product:** MailIntel  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Document:** Application Flow and UX Specification  
**Status:** Final Product Architecture + MVP Implementation Baseline

---

# 1. Purpose

This document defines:

- Application pages and screens
- Navigation
- Panels and tabs
- User journeys
- Four analysis modes
- Incoming and existing-email scenarios
- Role-based experiences
- Investigation workflows
- Cyber Cell case workflows
- UX principles

MailIntel uses progressive disclosure: ordinary users receive clear security guidance first, while authorized professionals can access deeper forensic and intelligence views.

---

# 2. Product Architecture vs MVP Implementation

MailIntel's **final product architecture** supports multiple user roles and role-based experiences. However, the current implementation follows the agreed **feature-first, RBAC-ready strategy**.

## 2.1 Current MVP / Development Mode

Authentication and RBAC are intentionally deferred until the core forensic-intelligence pipeline is working.

The current prototype therefore uses a controlled development context:

```text
Application Mode: DEVELOPMENT / SIH DEMO

Current Context:
User: MailIntel Demo User
Organization: MailIntel Demo Organization
Access Context: Development Admin
```

This is only a development convenience and must not be presented as production-grade security.

### MVP navigation

```text
Dashboard
Analyze Email
Analysis History
Intelligence
Campaigns
Investigation Graph
Geo Intelligence
Evidence
Reports
Settings
```

The MVP uses one shared investigation workspace with progressive disclosure rather than building five separate dashboards immediately.

## 2.2 Future Product Roles

After authentication and RBAC are implemented, MailIntel will support:

1. Individual User
2. Security Analyst
3. Organization Administrator
4. Cyber Cell Investigator
5. Super Administrator

These roles remain part of the final product architecture. The role-specific journeys, permissions and screens defined later in this document are therefore **Future Phase / Post-RBAC Architecture** unless explicitly marked as MVP.

## 2.3 Implementation Rule

```text
RBAC-READY DATA MODEL
        ↓
CORE FEATURE DEVELOPMENT
        ↓
COMPLETE FORENSIC INTELLIGENCE MVP
        ↓
AUTHENTICATION
        ↓
RBAC ENFORCEMENT
        ↓
ROLE-SPECIFIC EXPERIENCES
```

---

# 3. Global Application Layout

```text
┌─────────────────────────────────────────────────────────────┐
│ MailIntel | Global Search | Notifications | Profile         │
├───────────────┬─────────────────────────────────────────────┤
│ MVP SIDEBAR   │ MAIN CONTENT                                │
│               │                                             │
│ Dashboard     │ Page header / actions                       │
│ Analysis      │ Panels / tabs / workspace                   │
│ Intelligence  │                                             │
│ Reports       │                                             │
│ Settings      │                                             │
└───────────────┴─────────────────────────────────────────────┘
```

During the MVP, the sidebar is shared through the controlled demo workspace. After RBAC is implemented, navigation visibility and sidebar content will adapt according to role and permission.

---

# 4. Public Pages

## 4.1 Landing Page

### Sections

- Hero
- Platform overview
- Core capabilities
- How MailIntel works
- Privacy and security
- Integration options
- Call to action

### Hero message

```text
MailIntel

AI-Powered Email Threat Detection,
Geolocation and Forensic Intelligence

[Analyze an Email] [Sign In]
```

---

## 4.2 Authentication — Future Implementation Phase

Authentication is part of the final MailIntel product but is **not an MVP prerequisite**.

During the current feature-development phase:

- No production registration flow is required
- No production login flow is required
- No password-reset workflow is required
- The controlled demo/development context is used instead

After the core intelligence pipeline is complete, this section will introduce:

- Login
- Sign Up where required
- Secure session or token handling
- Password recovery where supported

Authentication screens should remain simple and separate from investigation complexity.
---

# 5. Entry and Onboarding Strategy

## 5.1 Current MVP Entry

```text
Landing / Demo Entry
        ↓
Demo Workspace
        ↓
Choose Analysis Method
        ↓
Upload .eml
        ↓
Processing
        ↓
Analysis Results
```

## 5.2 Future Authenticated Onboarding

After authentication and RBAC are implemented:

```text
Welcome
   ↓
Choose Primary Usage
   ↓
Choose / Configure Analysis Method
   ↓
Review Privacy and Permissions
   ↓
Enter Authorized Workspace
```

Role-specific onboarding must only appear after real authentication and authorization are available.
---

# 6. Analysis Modes Page

The final product supports four analysis modes. The current MVP implements `.eml` Upload first and visually distinguishes future integrations so the interface never implies that an unimplemented capability is already available.

### Current implementation status

| Mode | Current Status | MVP Capability |
|---|---|---|
| `.eml` Upload | **Active MVP** | Full core forensic pipeline |
| Direct OAuth Connection | **Future Phase** | Designed, not yet implemented |
| Extension without OAuth | **Future Phase** | Designed, not yet implemented |
| Extension with OAuth | **Future Phase** | Designed, not yet implemented |

## Mode 1 — `.eml` Upload

### UI

```text
[ Upload .eml ]
Drag and drop or browse
```

### Features

- Deep forensic analysis
- Header and MIME analysis
- URL and attachment extraction
- Email DNA
- Campaign correlation
- Infrastructure intelligence
- Geolocation

### Limitation

Analysis quality depends on the completeness and authenticity of the supplied `.eml` file.

---

## Mode 2 — Direct OAuth Account Connection — Future Phase

### MVP display state

Show this capability as **Planned / Coming in a Later Phase**. It may be described in the architecture, but the MVP must not expose a non-functional Connect button as if OAuth is already available.


### UI

```text
Connected Email Accounts

[Gmail]     [Connect / Manage]
[Outlook]   [Connect / Manage]
```

### Flow

```text
Choose Provider
   ↓
Permission Explanation
   ↓
OAuth Consent
   ↓
Connected Account
   ↓
Authorized Analysis
```

### Account management tabs

- Connected Accounts
- Permissions
- Scan Preferences
- Activity
- Disconnect / Revoke

---

## Mode 3 — Browser Extension Without Provider OAuth — Future Phase

### MVP display state

Show the extension as **Planned / Coming in a Later Phase** until the extension is implemented and packaged.


### User flow

```text
Open Supported Email
        ↓
Extension Detects Available Context
        ↓
Scan Available Data
        ↓
Result Appears in Extension
```

### Extension panel

- Threat status
- Main reasons
- Visible indicators
- Open detailed dashboard result

### Clear limitation

This mode must not promise complete raw email, MIME or unrestricted mailbox access.

---

## Mode 4 — Browser Extension With Provider OAuth — Future Phase

### MVP display state

Show this combined mode as **Planned / Advanced Integration Phase**. It depends on both extension support and authorized provider integration.


### User flow

```text
Open Supported Email
       ↓
Extension Identifies Context
       ↓
Authorized Backend Retrieves Permitted Data
       ↓
Deep Analysis
       ↓
Result Appears in Extension
       ↓
Detailed Result Available in Dashboard
```

### Extension result panel

- Threat level
- Immediate recommendation
- Key indicators
- Campaign warning where appropriate
- View Full Analysis

---

# 7. Incoming vs Existing Email UX

## Incoming Email Scenario

The UI should only offer automated incoming-mail analysis where a supported authorized integration can obtain the necessary data.

```text
New Email Available Through Supported Integration
       ↓
Analysis Triggered
       ↓
Threat Classification
       ↓
Appropriate Notification
```

The extension alone must not be represented as universally intercepting every raw incoming email.

## Existing Email Scenario

```text
User Opens Existing Email
       ↓
Extension Scan Triggered
       ↓
Available / Authorized Data Analyzed
       ↓
Result Displayed
```

---

# 8. Individual User Dashboard

The individual user's first question is:

> Is this email dangerous, and what should I do?

## Panels

### Summary cards

- Emails Analyzed
- Threats Detected
- Safe / Low Risk
- Recent High-Risk Items

### Recent Analysis

Recent scans with simple status labels.

### Security Summary

Current threat overview and recommended attention.

### Primary action

```text
[ Analyze an Email ]
```

The dashboard should not initially overwhelm the user with ASN, graph or vector details.

---

# 9. Analysis Processing Screen

Instead of a blank loading state:

```text
Analyzing Email

✓ Evidence Preserved
✓ Email Structure Parsed
✓ Headers Extracted
✓ URLs Identified
○ Threat Analysis
○ Domain Intelligence
○ Infrastructure Analysis
○ Campaign Correlation
```

Progress must be understandable without exposing unnecessary implementation details.

---

# 10. Email Analysis Result Page

## Header

```text
EMAIL THREAT ASSESSMENT

Threat Level: HIGH RISK

[View Details] [Download Report]
```

## Tabs

### 1. Overview

- Threat level
- Main reasons
- Key indicators
- Recommended action

### 2. Threat Indicators

- URLs
- Domains
- Sender anomalies
- Attachments
- Other extracted indicators

### 3. Email Forensics

Advanced view:

- Headers
- SPF
- DKIM
- DMARC
- Received path
- Message metadata

### 4. Infrastructure

- Related IPs
- ASN / organization context
- Hosting information
- Infrastructure classification

### 5. Geolocation

Interactive map showing approximate observable infrastructure locations.

Required notice:

> Locations represent observable infrastructure intelligence and do not automatically identify an attacker's physical location.

### 6. Campaign Intelligence

- Potentially related incidents
- Shared indicators
- Campaign confidence
- Explainable relationship evidence

### 7. Evidence

- Evidence ID
- Integrity hash
- Acquisition information
- Analysis status

Visibility depends on role and authorization.

---

# 11. Security Analyst Experience

The analyst's central question is:

> Why was this email flagged, and what evidence supports the finding?

## Navigation

- Dashboard
- Incident Queue
- Investigations
- Campaigns
- Intelligence
- Reports

## Dashboard panels

- New Incidents
- High-Risk Incidents
- Active Investigations
- Emerging Campaigns
- Geographic / Infrastructure Highlights

---

# 12. Investigation Workspace

```text
┌───────────────────────────────────────────────────────────┐
│ Incident ID | Threat Status | Case Status                  │
├────────────────┬──────────────────────────────────────────┤
│ Investigation  │ Main Investigation Workspace             │
│ Navigation     │                                          │
│                │                                          │
├────────────────┴──────────────────────────────────────────┤
│ Notes | Actions | Activity Log                            │
└───────────────────────────────────────────────────────────┘
```

## Tabs

1. Overview
2. Email Forensics
3. Indicators
4. Infrastructure
5. Geolocation
6. Relationship Graph
7. Campaign
8. Timeline
9. Evidence
10. Investigation Notes

---

# 13. Campaign and Relationship Graph UX

This screen must support evidence-driven relationships rather than simplistic grouping.

## Nodes

- Email
- Domain
- URL
- IP
- Attachment hash
- Infrastructure
- Campaign

## Node interactions

- Click node
- Open details
- Highlight relationships
- Filter entity types
- View evidence supporting edges

---

## Bridge Email Scenario

The UI must support a situation such as:

```text
Email A ── shared location ── Email B ── shared URL ── Email C
```

Email B may act as a bridge between clusters.

The graph should therefore support:

- Bridge nodes
- Overlapping clusters
- Multiple meaningful relationships
- Evidence-weighted links
- Separate campaign hypotheses where appropriate

The UI must not force every email into a single exclusive campaign merely for visual simplicity.

---

# 14. Organization Administrator Experience

The organization administrator's question is:

> Is the organization being targeted, and what action is required?

## Navigation

- Dashboard
- Organization
- Users
- Incidents
- Campaigns
- Integrations
- Privacy & Retention
- Reports

## Dashboard panels

- Users Protected
- Emails Analyzed
- Threats Detected
- Active Campaigns
- Recent Qualifying Incidents
- Organization-Level Trends

Private communications should not automatically become unrestricted administrative content.

---

# 15. Organization Management Pages

## Users and Access

Tabs:

- Users
- Roles
- Permissions
- Invitations

## Integrations

Tabs:

- Gmail
- Microsoft
- Browser Extension
- Integration Activity

## Privacy and Retention

Tabs:

- Retention Rules
- Masking Rules
- Access Policies
- Data Visibility

## Reports

Tabs:

- Threat Reports
- Incident Reports
- Campaign Reports

---

# 16. Cyber Cell Investigator Experience

The Cyber Cell interface is an intelligence and investigation workspace, not a general inbox.

The investigator's central question is:

> What evidence exists, what is connected, and how does this campaign operate?

## Navigation

- Dashboard
- Cases
- Campaigns
- Intelligence Search
- Infrastructure
- Geolocation
- Relationship Graph
- Evidence
- Reports

---

# 17. Cyber Cell Dashboard

## Summary cards

- Active Cases
- High Priority Cases
- Active Campaigns
- New Infrastructure Indicators
- Affected Entities

## Main panels

### Priority Investigation Queue

Sorted by:

- Priority
- Threat severity
- Campaign impact
- Recent activity

### Active Campaigns

Shows:

- Related incidents
- Shared indicators
- Campaign confidence
- Growth / timeline

### Geolocation Intelligence

Map highlights:

- Shared infrastructure
- Geographic concentration
- Relevant campaign clusters

### Emerging Threats

New suspicious patterns requiring review.

---

# 18. Case Workspace

Each authorized investigation uses a case-based workspace.

## Main tabs

1. Case Overview
2. Incidents
3. Campaign Intelligence
4. Indicators
5. Infrastructure
6. Geolocation
7. Relationship Graph
8. Timeline
9. Evidence and Chain of Custody
10. Affected Entities
11. Reports

---

# 19. Geolocation Screen

A dedicated full-screen map is available to authorized investigation roles.

## Controls

- Search
- Zoom
- Filter by campaign
- Filter by infrastructure type
- Filter by time range
- Toggle clustering

## Highlight categories

- Shared campaign infrastructure
- High-risk infrastructure
- Cloud-hosted infrastructure
- VPN / proxy-associated indicators
- TOR-related infrastructure where applicable

Every location must be presented as observable infrastructure intelligence, not definitive attacker geolocation.

---

# 20. Evidence and Chain of Custody Screen

Displays:

- Evidence ID
- Integrity hash
- Acquisition method
- Acquisition timestamp
- Storage status
- Analysis history
- Authorized access events
- Report events

Sensitive evidence access is controlled by permissions.

---

# 21. Affected Entities Screen

Displays only authorized and necessary information regarding:

- Affected users
- Organizations
- Related incidents

Masking should be applied when full identity is unnecessary.

---

# 22. Super Administrator Experience

The Super Administrator manages the platform rather than ordinary investigations.

## Navigation

- System Dashboard
- Users
- Roles
- Integrations
- API Management
- Threat Intelligence Configuration
- Retention Policies
- Audit Logs
- System Settings

---

# 23. Global Intelligence Search

Authorized users can search:

```text
Domain
IP Address
URL
File Hash
Campaign ID
Case ID
```

The application should detect the indicator type and direct the user to the most relevant intelligence view.

---

# 24. Notification Experience

Notifications should be role-specific.

## Individual User

```text
A recently analyzed email requires your attention.
```

## Security Analyst

```text
A new high-risk incident requires review.
```

## Cyber Cell Investigator

```text
A campaign has gained new evidence-linked incidents.
```

Notifications must not expose sensitive information to unauthorized roles.

---

# 25. Role-Based Navigation Summary

## Individual User

```text
Dashboard
Analyze Email
My Analysis
Reports
Integrations
Settings
```

## Security Analyst

```text
Dashboard
Incident Queue
Investigations
Campaigns
Intelligence
Reports
```

## Organization Administrator

```text
Dashboard
Organization
Users
Incidents
Campaigns
Integrations
Privacy & Retention
Reports
```

## Cyber Cell Investigator

```text
Dashboard
Cases
Campaigns
Intelligence Search
Infrastructure
Geolocation
Relationship Graph
Evidence
Reports
```

## Super Administrator

```text
System Dashboard
Users
Roles
Integrations
API Management
Retention Policies
Audit Logs
System Settings
```

---

# 26. Core End-to-End User Journey

```text
Email Received / Existing Email Available
                  ↓
          Select Analysis Mode
                  ↓
      ┌──────────┼──────────┬──────────┐
      ▼          ▼          ▼          ▼
    .eml      OAuth      Extension   Extension
   Upload     Direct      Limited     + OAuth
      └──────────┬──────────┴──────────┘
                 ▼
          Evidence / Data Acquisition
                 ▼
            Forensic Analysis
                 ▼
            Threat Assessment
                 ▼
               Email DNA
                 ▼
          Semantic Comparison
                 ▼
        Graph-Based Correlation
                 ▼
       Campaign / Infrastructure Intelligence
                 ▼
              Geolocation
                 ▼
       Role-Based Result and Action
```

---

# 27. Progressive Disclosure Model

```text
Individual User
"Is it dangerous?"

       ↓

Security Analyst
"Why is it dangerous?"

       ↓

Organization Administrator
"Is the organization being targeted?"

       ↓

Cyber Cell Investigator
"What is connected and what evidence supports it?"
```

---

# 28. UX Principles

## Action before complexity

The most important answer is shown first.

## Explainability

Authorized users should be able to understand why a conclusion was reached.

## Privacy by default

Sensitive information is minimized and role-controlled.

## Role separation

Each role receives a purpose-built interface.

## Evidence before accusation

The UI must distinguish:

- Suspicion
- Correlation
- Confidence
- Confirmed evidence

## Progressive disclosure

Advanced technical information is available without overwhelming ordinary users.

---

# 29. Responsive Strategy

## Mobile priority

- User dashboard
- Analyze Email
- Analysis results
- Notifications
- Reports

## Desktop priority

- Investigation workspaces
- Relationship graphs
- Full geolocation maps
- Large forensic tables
- Campaign analysis

---

# 30. Critical Reusable UI Components

- Threat Risk Card
- Evidence Confidence Card
- Campaign Correlation Card
- Email Summary Card
- Indicator Table
- Domain Intelligence Card
- Infrastructure Card
- Map Marker Detail Panel
- Relationship Graph
- Graph Node Detail Panel
- Timeline
- Evidence Integrity Card
- Chain-of-Custody Log
- Analysis Progress Component

---

# 31. Final Application Vision

MailIntel must remain simple where the user needs simplicity and powerful where an authorized investigator needs depth.

```text
Email
  ↓
Forensic Evidence
  ↓
Threat Intelligence
  ↓
Email DNA
  ↓
Explainable Relationships
  ↓
Campaign Intelligence
  ↓
Role-Based Action
```

The final UX supports threat detection, forensic intelligence, infrastructure analysis and campaign investigation without presenting the platform as unrestricted surveillance of private email communications.


---

# Implementation Status Summary

## Active MVP Scope

```text
.eml Upload
    ↓
Evidence Preservation
    ↓
Forensic Analysis
    ↓
Threat Intelligence
    ↓
Email DNA
    ↓
Semantic Similarity
    ↓
Campaign Correlation
    ↓
Investigation Graph
    ↓
Geo Intelligence
    ↓
Reports
```

## Deferred Until After Core MVP

```text
Platform Authentication
RBAC Enforcement
Organization-Level Access Isolation
Role-Specific Dashboards
Gmail OAuth
Microsoft OAuth
Browser Extension
```

## UX Rule

The MVP must clearly separate:

- **Available now** — functional features
- **Processing** — features currently executing
- **Planned / Future Phase** — architecture-defined capabilities not yet implemented

No screen should visually imply that a future integration or role-based capability is already operational.
