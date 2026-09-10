# MailIntel — Design System Specification

**Project:** MailIntel  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Document:** Design.md  
**Purpose:** Define the visual design direction, single application theme, typography, layout, colours and UI design standards for MailIntel.

**Implementation Note:** The design system supports the complete MailIntel product. During the current MVP, the interface must visibly distinguish implemented capabilities from future authentication, RBAC, OAuth and browser-extension features.

---

# 1. Design Objective

MailIntel is an email threat detection, forensic analysis and cyber-intelligence platform. Its interface must support multiple user types while maintaining one consistent product identity.

The design should feel:

- Professional
- Enterprise-grade
- Security-focused
- Forensic and intelligence-driven
- Modern and clean
- Trustworthy
- Calm rather than visually aggressive
- Suitable for both ordinary users and authorized investigators

MailIntel must **not** look like a generic admin dashboard, a gaming interface or a stereotypical neon “hacker” application.

The design philosophy is:

> **Simple for the user, powerful for the investigator, and precise for forensic intelligence.**

---

# 2. Final Theme Direction

## 2.1 Single Unified Theme

MailIntel will use **one unified visual theme**.

There will not be separate Light Mode and Dark Mode interfaces.

Instead, the application combines dark and light surfaces in a controlled way:

```text
Dark Navy Navigation
        +
Soft Light Main Workspace
        +
Deep Intelligence Panels where required
        +
Professional Intelligence Blue
        +
Controlled Security Severity Colours
```

This provides a strong cybersecurity identity without making the entire application dark.

## 2.2 Important Design Rule

**Dark does not mean black.**

Avoid:

- Pure black backgrounds
- Neon green hacker aesthetics
- Excessive glowing effects
- Rainbow-coloured dashboards
- Heavy gradients
- Excessive shadows
- Oversaturated colours

Dark areas should use deep navy and blue-grey colours.

---

# 3. Colour System

## 3.1 Dark Application Surfaces

### Primary Navigation Navy

```text
#101C33
```

Used for:

- Main sidebar
- Persistent navigation
- MVP shared navigation context; role-based navigation is activated after RBAC implementation

### Deep Intelligence Navy

```text
#172641
```

Used for:

- Dark investigation areas
- Graph canvases
- Intelligence workspaces
- Dark secondary navigation surfaces

### Elevated Dark Surface

```text
#20314D
```

Used for:

- Elevated dark panels
- Graph controls
- Selected dark interface elements

---

## 3.2 Light Workspace Surfaces

### Main Workspace

```text
#F5F7FB
```

The primary workspace should use a soft cool-grey rather than pure white.

### Primary Card Surface

```text
#FFFFFF
```

Used for:

- Cards
- Forms
- Tables
- Primary information panels

### Secondary Surface

```text
#EEF2F7
```

Used for:

- Nested panels
- Quiet information blocks
- Secondary sections

### Quiet Table/Header Surface

```text
#F8FAFC
```

Used for:

- Table headers
- Subtle information sections
- Filter areas

---

## 3.3 Primary Brand Accent

### Intelligence Blue

```text
#2563B8
```

Used for:

- Primary buttons
- Active navigation
- Important actions
- Selected controls
- Interactive intelligence elements

### Hover / Active Blue

```text
#1D4E9E
```

### Soft Blue Surface

```text
#EAF2FF
```

Used for selected backgrounds and informational states.

---

## 3.4 Text Colours

### Primary Text

```text
#1C2B40
```

### Secondary Text

```text
#627086
```

### Muted Text

```text
#8793A5
```

### Text on Dark Surfaces

```text
#EAF0F8
```

---

# 4. Security Status and Severity Colours

Security colours must communicate meaning and should not be used as decoration.

| Status | Primary Colour | Soft Background |
|---|---|---|
| Critical | `#C73A32` | `#FDECEA` |
| High | `#D88916` | `#FFF4DD` |
| Medium | `#7C62C8` | `#F0ECFB` |
| Low / Informational | `#3478C7` | `#EAF3FD` |
| Safe / Positive | `#2D8B68` | `#E8F6EF` |

Severity must never depend only on colour. Labels such as **CRITICAL**, **HIGH**, **MEDIUM** and **LOW** must also be displayed.

---

# 4A. Feature Implementation State

The visual system must distinguish product architecture from currently implemented functionality.

## State Labels

Use clear, consistent labels:

```text
AVAILABLE
PROCESSING
BETA / TESTING
PLANNED
COMING IN A LATER PHASE
```

### Recommended Usage

| Feature | MVP State |
|---|---|
| `.eml` Upload | Available |
| Evidence Preservation | Available |
| Forensic Analysis | Available as implemented |
| Threat Intelligence | Available as implemented |
| Email DNA / Correlation | Available as implemented |
| Authentication | Planned until implemented |
| RBAC | Planned until implemented |
| Gmail / Outlook OAuth | Coming in a Later Phase |
| Browser Extension | Coming in a Later Phase |

## Visual Treatment

Future features should:

- Remain visible only where useful for explaining the complete product vision
- Use a subtle `Planned` or `Coming Soon` badge
- Avoid primary action buttons that imply the feature already works
- Use muted secondary surfaces instead of disabled-looking clutter
- Clearly explain the future capability in one short sentence

The interface must never create a false impression that an integration is live when it is only part of the architecture.

---

# 5. Typography System

Typography is a core part of the MailIntel identity.

The application should feel clean and professional while maintaining excellent readability for both normal users and security professionals.

## 5.1 Primary Font

### Inter

**Inter** is the primary interface font for MailIntel.

Use it for:

- Navigation
- Page titles
- Buttons
- Forms
- Cards
- Tables
- Body content
- Dashboard metrics
- Reports

Why Inter:

- Highly readable on screens
- Modern and professional
- Excellent for dense enterprise interfaces
- Clear distinction between weights
- Suitable for both technical and non-technical users

Recommended CSS stack:

```css
font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont,
             "Segoe UI", sans-serif;
```

---

## 5.2 Technical and Forensic Font

### JetBrains Mono

Use **JetBrains Mono** selectively for technical data.

Examples:

- IP addresses
- Domains when technical emphasis is required
- URLs
- Hashes
- Evidence IDs
- Artifact IDs
- ASN numbers
- Timestamps in forensic timelines
- SHA-256 values
- Raw technical indicators

Recommended CSS stack:

```css
font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
```

### Important Rule

JetBrains Mono must **not** be used for normal paragraphs or general navigation.

It is a technical accent font, not the primary product font.

---

# 6. Typography Scale

| Element | Font | Size | Weight | Usage |
|---|---|---:|---:|---|
| Display / Major Page Title | Inter | 30–32px | 700 | Main page titles |
| Page Title | Inter | 26–28px | 700 | Standard page headings |
| Section Title | Inter | 20–22px | 650–700 | Major sections |
| Card Title | Inter | 16–18px | 600 | Card headings |
| Subsection | Inter | 15–16px | 600 | Internal headings |
| Body Large | Inter | 15–16px | 400–500 | Important descriptions |
| Body | Inter | 14px | 400–500 | Standard interface content |
| Metadata | Inter | 12–13px | 400–500 | Supporting information |
| Micro Label | Inter | 10–11px | 600 | Categories and labels |
| Technical Data | JetBrains Mono | 12–14px | 400–500 | Technical artifacts |

## Typography Rules

- Avoid overly small text.
- Do not use more than three major font weights on one screen.
- Use bold primarily for hierarchy, not decoration.
- Page titles should be strong but not oversized.
- Technical values should be visually distinguishable from normal content.
- Maintain comfortable line height for descriptions and reports.

---

# 7. Layout System

## Desktop Structure

```text
┌─────────────────────────────────────────────────────────────────┐
│                          TOP HEADER                             │
├───────────────┬─────────────────────────────────────────────────┤
│               │ Breadcrumb                                      │
│               ├─────────────────────────────────────────────────┤
│               │ Page Title + Description + Primary Action       │
│    SIDEBAR    ├─────────────────────────────────────────────────┤
│               │                                                 │
│   DARK NAVY   │              MAIN WORKSPACE                     │
│               │                                                 │
│               │                                                 │
└───────────────┴─────────────────────────────────────────────────┘
```

## Recommended Dimensions

- Sidebar width: approximately `232px`
- Top header height: approximately `64px`
- Desktop content padding: `24px–32px`
- Standard grid gap: `16px–20px`
- Card padding: `18px–24px`
- Border radius: generally `10px–14px`

---

# 8. Sidebar Design

The sidebar is the main permanent dark element of MailIntel.

## Sidebar Structure

```text
[ MailIntel Logo ]

● USER PORTAL
or
● SECURITY ANALYST
or
● CYBER SECURITY CELL

MAIN
  Dashboard
  Analyze Email

EMAIL INTELLIGENCE
  My Threats
  Email DNA
  Related Threats
  Geo Intelligence

REPORTING
  Reports

ACCOUNT
  Profile
```

Cyber Security Cell navigation can contain:

```text
FORENSIC OPERATIONS

  SOC Overview
  Active Campaigns
  Investigation Graph
  Email DNA Engine
  Infrastructure Intelligence
  Evidence & Chain of Custody
  Forensic Leads
  Mitigation Actions
  Case Dossiers
  Privacy & Audit
```

## Navigation States

### Default

- Transparent or dark navy background
- Muted light text
- Quiet icon

### Hover

- Slightly lighter navy surface
- Improved text contrast

### Active

- Intelligence blue background
- White text
- Clear active state
- Subtle icon emphasis

The sidebar should feel structured and premium, not overly decorative.

---

# 9. Top Header

The top header remains light and minimal.

## Left Side

```text
[Shield Icon] MailIntel  ›  Dashboard
```

or:

```text
[Shield Icon] Cyber Security Cell  ›  Active Campaigns
```

## Right Side

```text
Search Intelligence
Notifications
Profile
```

The global search placeholder should support MailIntel intelligence artifacts:

```text
Search email, domain, IP, URL, hash, campaign or case...
```

---

# 10. Buttons

## Primary Button

Used for the most important action on a page.

Example:

```text
[ Analyze Email ]
```

Design:

- Intelligence blue background
- White text
- 8px–10px radius
- Medium weight
- Optional meaningful icon

## Secondary Button

Example:

```text
[ View Details ]
```

Design:

- Light surface
- Subtle border
- Dark text

## Destructive Button

Reserved only for actions such as:

- Delete
- Revoke
- Remove access

Red should not be used for ordinary investigation actions.

---

# 11. Cards and Surfaces

Cards should create information hierarchy without making every page look like a collection of floating boxes.

## Standard Card

```text
┌──────────────────────────────────────┐
│ Card Label                      Icon │
│                                      │
│ 128                                  │
│ Supporting information               │
└──────────────────────────────────────┘
```

### Properties

- White background
- Subtle border
- Controlled radius
- Minimal shadows
- Clear internal spacing

Avoid excessive shadows and thick borders.

---

# 12. Core Dashboard Design

The dashboard should answer:

1. What is happening?
2. How serious is it?
3. What needs attention?

## Recommended Structure

```text
Page Title + Description                         [ Analyze Email ]

[ Emails Analyzed ] [ Threats Detected ] [ Critical ] [ Reports ]

┌──────────────────────────────────┬────────────────────────────┐
│ Recent Threats                   │ Threat Distribution        │
│                                  │                            │
│ Data Table                       │ Meaningful Visualization   │
├──────────────────────────────────┼────────────────────────────┤
│ Threat Activity                  │ Intelligence Summary       │
└──────────────────────────────────┴────────────────────────────┘
```

Charts should communicate intelligence, not simply fill space.

---

# 13. Analyze Email Page

The Analyze Email page must reflect the MailIntel analysis architecture.

## Four Analysis Modes

The final design supports four analysis modes. For the current feature-first MVP, `.eml` Upload is the primary active mode.

```text
ACTIVE MVP
    → .eml Upload

FUTURE INTEGRATION PHASE
    → Gmail / Outlook OAuth
    → Browser Extension without OAuth
    → Browser Extension with OAuth
```

Future modes should be displayed only as clearly labelled architecture capabilities until they are functional.

### 1. `.eml` Upload — Deep Forensic Analysis

Features:

- Original email parsing
- Header analysis
- MIME inspection
- URL extraction
- Attachment inspection
- Email DNA generation
- Infrastructure analysis
- Campaign correlation

### 2. Authorized Email Integration — Future Phase

**MVP card state:** Display as `Planned` or `Coming in a Later Phase`. Do not show a working-looking connection control until the OAuth implementation exists.

Features:

- Authorized mailbox connection
- Supported Gmail and Microsoft services
- Deeper supported email analysis
- Existing and incoming email workflows

### 3. Browser Extension — Limited Analysis — Future Phase

**MVP card state:** Display the intended extension workflow, but use a clear future-phase badge and avoid suggesting that installation or scanning is currently available.

Features:

- Analysis of information available from the currently opened supported email
- Limited visible-data analysis without deeper authorized mailbox access

The UI must clearly communicate data limitations.

### 4. Browser Extension + Authorized Integration — Future Phase

**MVP card state:** Present this as an advanced future integration that depends on both the extension and authorized provider access.

Features:

- Extension-based workflow
- Authorized data access
- Deeper supported analysis
- Better integration with the user's email environment

---

# 14. Analysis Processing Experience

Do not use only a generic loading spinner.

Use a step-based analysis timeline:

```text
✓ Evidence Received
✓ Email Parsed
✓ Indicators Extracted
✓ Threat Intelligence Checked
◌ Email DNA Generated
◌ Infrastructure Analysed
◌ Campaign Correlation Completed
```

For ordinary users, technical details can remain collapsed.

---

# 15. Analysis Results

The result screen must clearly separate three concepts.

## Threat Risk Score

Answers:

> How risky or malicious does this email appear?

## Evidence Confidence

Answers:

> How strongly is the result supported by available evidence?

## Campaign Correlation Confidence

Answers:

> How confidently is this email associated with a related campaign or cluster?

These scores must never be visually merged into one generic “AI Score”.

---

# 16. Recommended Result Layout

```text
┌──────────────────────────────────────────────────────────────┐
│ HIGH RISK                                                    │
│ Credential Phishing Detected                                 │
│                                                              │
│ Threat Risk: 94/100                                          │
│ Evidence Confidence: High                                    │
│                                                              │
│ [ Recommended Action ]   [ View Full Intelligence ]          │
└──────────────────────────────────────────────────────────────┘
```

Below the summary, use tabs:

```text
Overview
Indicators
Forensics
Infrastructure
Geolocation
Campaign
Evidence
```

Use progressive disclosure. Do not expose every technical detail immediately.

---

# 17. Email DNA Design

Email DNA should become a distinctive MailIntel intelligence concept.

It represents the structured characteristics extracted from an email.

Suggested categories:

```text
Sender
Authentication
Content
Semantic Features
URLs
Domains
Infrastructure
Attachments
```

The visualization should help users understand relationships and evidence rather than being purely decorative.

Each category should support deeper drill-down.

---

# 18. Investigation Graph

The Investigation Graph is a signature intelligence feature.

Use a darker dedicated graph canvas within the otherwise light application.

```text
┌──────────────────────────────────────────────────────────────┐
│ Investigation Graph       Filters   Search   Layout Controls │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│     [Email A]──[Domain]──[IP]                                │
│         │                  │                                 │
│       [URL]              [Email B]──[URL]──[Email C]         │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ Node Details / Evidence / Relationship Explanation           │
└──────────────────────────────────────────────────────────────┘
```

## Entity Types

Consistent visual types may represent:

- Email
- Domain
- URL
- IP
- Attachment
- Campaign
- Infrastructure

Do not use too many colours.

## Relationship Strength

Represent confidence through:

- Edge thickness
- Opacity
- Solid or dashed edges
- Evidence indicators

---

# 19. Bridge Entity Design

MailIntel must support overlapping relationships.

Example:

```text
Campaign A ─── Email B ─── Campaign C
```

Email B may be a **Bridge Entity** because it shares relevant evidence with more than one cluster.

The interface must:

- Identify the bridge relationship
- Explain the evidence
- Avoid automatically merging all related clusters
- Clearly distinguish correlation from confirmed attribution

---

# 20. Geolocation Intelligence

The geolocation interface should use a professional map.

## Layout

```text
┌───────────────────────────────────────┬──────────────────────┐
│                                       │ Location Intelligence│
│                                       │                      │
│              MAP                      │ Frankfurt            │
│                                       │ AS12345              │
│        ●          ●                   │ Related Campaigns: 4 │
│               ●                       │                      │
│                                       │ [ View Infrastructure]│
└───────────────────────────────────────┴──────────────────────┘
```

Use a dark or muted map style that matches the intelligence environment.

The map must include a clear contextual disclaimer:

> Infrastructure geolocation represents the approximate location of observable network infrastructure and does not necessarily identify the physical location of an attacker.

---

# 21. Campaign Intelligence

Campaign cards should communicate the most relevant information quickly.

Example:

```text
Campaign #247                               CRITICAL

Microsoft Credential Harvesting Campaign

100 affected accounts · 12 organizations

[ 4 Domains ] [ 3 IPs ] [ Shared URLs ]

Campaign Correlation Confidence: 94%

First Observed: 10:14 AM
Status: Active Investigation

[ Investigate Campaign → ]
```

The label **Campaign Correlation Confidence** is preferred over simply **Confidence**.

---

# 22. Cyber Security Cell Interface

The Cyber Security Cell interface should feel operational and intelligence-focused.

## Dashboard Metrics

- Active Campaigns
- Affected Users
- Affected Organizations
- Critical Campaigns
- Suspicious Domains
- Associated Infrastructure

## Main Workspace

```text
┌───────────────────────────────────┬──────────────────────────┐
│ Campaign / Threat Activity        │ Infrastructure Location  │
├───────────────────────────────────┼──────────────────────────┤
│ Priority Investigation Queue      │ Emerging Patterns        │
└───────────────────────────────────┴──────────────────────────┘
```

The Cyber Security Cell interface should expose deeper intelligence only to authorized roles.

---

# 23. Evidence and Processing History

The evidence interface must focus on integrity and traceability.

Example:

```text
10:14:22  Evidence Received
10:14:23  SHA-256 Generated
10:14:25  Original Artifact Preserved
10:14:31  Analysis Started
10:15:08  Analysis Completed
```

Each event can show:

- Timestamp
- Action
- Authorized actor or system
- Artifact reference
- Integrity information where available

The interface should avoid making unsupported legal claims.

---

# 24. Privacy and Audit Design

Privacy controls must be visible as part of the platform architecture.

Recommended sections:

- Data Retention
- Sensitive Data Masking
- Future Role-Based Access after authentication and RBAC implementation
- Investigation Visibility
- Audit Events

Example:

```text
Sensitive Communication Content

Masked outside authorized investigation workflows.

[ Enabled ]
```

The UI should communicate privacy clearly without overwhelming ordinary users with legal terminology.

---

# 25. Reports

Report cards should provide a clean hierarchy.

```text
REF-2026-01                              Today, 10:14

Microsoft Security Alert:
Immediate Action Required

Threat Type: Credential Phishing
Threat Risk Score: 94

[ View Report ]              [ Download PDF ]
```

The primary report card itself should support navigation to detailed results.

---

# 26. Search Experience

Global search should support intelligence artifacts.

Searchable objects:

- Emails
- Domains
- URLs
- IP addresses
- Hashes
- Campaigns
- Cases

Results should be grouped by entity type.

---

# 27. Loading and Empty States

## Loading

Use:

- Skeleton cards
- Skeleton tables
- Progressive analysis timelines

Avoid excessive spinning indicators.

## Empty State

Example:

```text
No Active Threats

No high-risk emails currently require your attention.

[ Analyze an Email ]
```

Do not use generic messages such as “No Data Available” where a useful explanation can be provided.

---

# 28. Interaction and Motion

Motion should be subtle and functional.

Recommended:

- 150–220ms transitions
- Small hover feedback
- Graph node focus transitions
- Map cluster expansion
- Button state transitions

Avoid:

- Constant pulsing
- Neon glow animations
- Long page transitions
- Unnecessary movement

---

# 29. Accessibility

MailIntel must support:

- Strong colour contrast
- Keyboard navigation
- Visible focus states
- Tooltips for complex icons
- Colour-independent severity labels
- Readable typography
- Responsive layouts

Security status must never depend solely on colour.

---

# 30. Responsive Design

## Desktop

Primary environment for:

- Investigation Graph
- Geolocation
- Campaign analysis
- Forensic tables
- Cyber Security Cell workflows

## Tablet

Use:

- Collapsible sidebar
- Adaptive grids
- Simplified investigation panels

## Mobile

Prioritize:

- Dashboard overview
- Analyze Email
- Threat results
- Reports
- Notifications

Complex graph and investigation workflows should use simplified mobile experiences rather than forcing desktop layouts onto a small screen.

---

# 31. Reusable UI Components

The frontend should use a consistent component system.

Core components:

```text
AppSidebar
TopHeader
PageHeader
StatCard
ThreatBadge
ScoreCard
IntelligenceCard
DataTable
FilterBar
AnalysisProgress
EvidenceTimeline
MapPanel
GraphCanvas
NodeDetailPanel
ReportCard
EmptyState
```

The design system should ensure consistent:

- Typography
- Spacing
- Border radius
- Button behaviour
- Status indicators
- Hover states

---

# 32. Final Visual Rules

Every major page should follow this information hierarchy:

```text
1. What happened?
2. How serious is it?
3. What should the user do?
4. Why does the system believe this?
5. What deeper intelligence is available?
```

This is especially important because MailIntel serves users with different levels of technical knowledge.

---

# 32A. MVP and Future-Feature Design Principle

The current MailIntel prototype must feel complete without pretending that every final-product integration already exists.

## MVP Interface Focus

The strongest visual journey is:

```text
Upload .eml
    ↓
Evidence Preserved
    ↓
Analysis Processing
    ↓
Threat Findings
    ↓
Email DNA
    ↓
Related Evidence
    ↓
Campaign Intelligence
    ↓
Graph + Geo Intelligence
    ↓
Forensic Report
```

## Future Features in the UI

Authentication, RBAC, OAuth integrations and the browser extension should be represented only when useful to communicate the complete product roadmap.

When shown, they must use:

- A subtle future-phase badge
- Clear capability descriptions
- No deceptive active state
- No fake live data
- No primary CTA that performs no real action

This preserves the professional credibility of the SIH demonstration.

---

# 33. Final Design Identity

MailIntel should visually sit between:

```text
Enterprise Security Platform
        +
Digital Forensics Workspace
        +
Modern Threat Intelligence System
```

It should not resemble:

```text
Generic Admin Template       ✗
Neon Hacker Interface        ✗
Gaming Dashboard             ✗
Overly Minimal Consumer App  ✗
```

The final identity is:

```text
DEEP NAVY
+
SOFT LIGHT WORKSPACE
+
INTELLIGENCE BLUE
+
INTER TYPOGRAPHY
+
JETBRAINS MONO FOR TECHNICAL ARTIFACTS
+
CONTROLLED SECURITY COLOURS
+
EVIDENCE-FIRST INFORMATION DESIGN
```

---

# 34. Final Design Principle

> **MailIntel should feel calm enough for daily use, precise enough for forensic work, and powerful enough for campaign-level cyber intelligence.**

The interface should progressively move from:

```text
Simple User Experience
        ↓
Clear Threat Understanding
        ↓
Explainable Evidence
        ↓
Deep Intelligence
        ↓
Professional Investigation
```

This design system is the final visual direction for the MailIntel platform.


---

# 35. Attack Path and Geolocation Flow Visualization

The MailIntel geolocation interface must not behave like a simple map containing unrelated location pins.

It should visually communicate the **observable relationship and potential flow between malicious infrastructure, infrastructure hops and affected targets**.

The design inspiration is a relationship graph: entities are connected through clear lines so that an investigator can understand the path of an attack visually.

## 35.1 Core Visual Concept

The map should support a visual intelligence flow such as:

```text
[ Suspected Source Infrastructure ]
                │
                │ Attack / Communication Path
                ▼
[ Intermediate Infrastructure ]
                │
                │ Related Infrastructure / Redirect Path
                ▼
[ Affected User or Organization ]
```

On the geographical map, these relationships should be represented by:

- Source markers
- Infrastructure markers
- Destination or affected-entity markers
- Curved relationship lines between locations
- Direction indicators where a direction is technically supported
- Different visual treatment for confirmed, correlated and uncertain relationships

The goal is to make an investigation understandable at a glance.

---

## 35.2 Relationship Lines on the Map

The map should display highlighted connection paths between relevant entities rather than simply placing multiple pins on different countries.

Example concept:

```text
       ● Suspicious Infrastructure
        \
         \═══════════════►
          \
           ● Relay / Hosting Infrastructure
                    \
                     \──────────────►
                                      ● Affected Organization
```

Use elegant curved lines instead of harsh straight lines where appropriate.

### Important Design Rule

A line on the map must represent a meaningful observed or correlated relationship.

It must not imply that the physical attacker travelled from one location to another.

Possible relationship labels include:

- Shared Infrastructure
- Redirect Path
- Related Hosting
- Observed Email Infrastructure
- Campaign Correlation
- Network Relationship

---

## 35.3 Visual Hierarchy of Attack Paths

### High-Confidence / Critical Relationship

Use:

- Stronger line visibility
- More prominent path
- Critical colour used carefully
- Clear relationship label
- Optional directional indicator

Example:

```text
Critical Infrastructure Path
════════════════════════════►
```

### Suspicious or Correlated Relationship

Use:

- Intelligence blue or amber
- Medium line weight
- Dashed or partially transparent path where useful

Example:

```text
Correlation Path
- - - - - - - - - - - - - ►
```

### Low-Confidence or Investigative Lead

Use:

- Muted blue-grey
- Thin dashed line
- Lower opacity

Example:

```text
Potential Relationship
· · · · · · · · · · · · · ►
```

This distinction helps investigators understand the difference between evidence, correlation and a hypothesis.

---

## 35.4 Recommended Map Entity Types

The map should use distinct markers for different types of geolocated intelligence.

### Source / Suspicious Infrastructure

Represents observable suspicious infrastructure such as:

- Malicious hosting
- Suspicious IP infrastructure
- Related network infrastructure
- Campaign-associated infrastructure

### Infrastructure Hop

Represents observable infrastructure associated with the analysis, such as:

- Hosting infrastructure
- Redirect infrastructure
- Intermediate network infrastructure

### Affected Entity

Represents the authorized or known affected organization or reporting context.

The UI must not reveal precise personal location data unnecessarily.

---

## 35.5 Source-to-Victim Visualization

A major visual feature of MailIntel should be the ability to inspect an **infrastructure-to-target relationship path**.

Example:

```text
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│       [●] Frankfurt                                         │
│        Suspicious Infrastructure                            │
│              ╲                                              │
│               ╲  Shared Infrastructure                      │
│                ╲═══════════════►                            │
│                         [●] Amsterdam                       │
│                          Redirect / Hosting                 │
│                                  ╲                          │
│                                   ╲ Campaign Relationship   │
│                                    ╲──────────────►         │
│                                             [●] India        │
│                                              Affected Org    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The actual visual implementation should be more polished than this conceptual diagram.

The design must feel like a professional threat-intelligence system, not a military attack animation or a movie-style cyber map.

---

## 35.6 Map Interaction

When an investigator selects a marker or connection line:

### Selecting a Node

Show:

- Location or approximate region
- IP or infrastructure identifier where authorized
- ASN
- Related domain or artifact
- Associated campaigns
- Evidence summary
- Confidence level

### Selecting a Relationship Line

Show a relationship panel such as:

```text
Relationship: Shared Infrastructure

Source:
185.xxx.xxx.xxx

Related Entity:
Suspicious Domain

Evidence:
Shared ASN + infrastructure fingerprint

Relationship Confidence:
89%
```

This ensures that the visualization remains explainable.

---

## 35.7 Animated Flow

Subtle animation may be used to help communicate an active path.

For example:

- A small directional particle moving along a selected path
- Gentle path highlighting on hover
- Progressive path reveal when an investigation is opened

Animation must be optional or restrained.

Avoid:

- Constant moving red lines
- Flashing attack animations
- Aggressive pulsing effects
- Overly dramatic “live cyber attack” visuals

The interface must remain professional and suitable for long investigative sessions.

---

## 35.8 Map Filters

The geolocation workspace should provide practical filters.

Recommended filters:

```text
[ Campaign ▼ ]
[ Time Range ▼ ]
[ Infrastructure Type ▼ ]
[ Relationship Confidence ▼ ]
[ Threat Severity ▼ ]
```

Additional toggle controls:

```text
☑ Show Relationship Paths
☑ Show Campaign Clusters
☑ Show Infrastructure Nodes
☐ Show Low-Confidence Leads
```

---

## 35.9 Combined Map and Relationship Intelligence

The best design should combine geographic intelligence with relationship intelligence.

Recommended workspace:

```text
┌──────────────────────────────────────────────────────────────┐
│ Geo Intelligence                                             │
│ Campaign #247  |  Last 30 Days  |  Confidence > 70%          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│                     GEOGRAPHICAL MAP                         │
│                                                              │
│      ● Frankfurt ═════════► ● Amsterdam                      │
│            ╲                         ╲                       │
│             ╲                         ╲══════► ● Mumbai      │
│              ╲                                               │
│               ═════► ● Singapore                             │
│                                                              │
├───────────────────────────────┬──────────────────────────────┤
│ Relationship Timeline         │ Selected Intelligence       │
│                               │                              │
│ Source → Infrastructure       │ Entity Details              │
│ Infrastructure → Target       │ Evidence                    │
│ Campaign Correlation          │ Confidence                  │
└───────────────────────────────┴──────────────────────────────┘
```

This is the preferred direction because it makes the map an active investigative tool rather than a decorative dashboard widget.

---

## 35.10 Connection with Investigation Graph

The **Investigation Graph** and **Geo Intelligence Map** should use a related visual language but serve different purposes.

### Investigation Graph

Answers:

> Which digital entities are connected?

Examples:

- Email → URL
- URL → Domain
- Domain → IP
- IP → Campaign
- Email → Related Email

### Geo Intelligence Map

Answers:

> Where is observable infrastructure geographically associated, and how are those geolocated entities related?

The two interfaces should complement each other.

A user should be able to:

```text
Select Graph Entity
        ↓
Open Geo Context
        ↓
View Related Geographic Infrastructure
        ↓
Inspect Relationship Path
```

---

## 35.11 Privacy and Attribution Disclaimer

The interface must clearly distinguish infrastructure geolocation from attacker attribution.

Recommended information notice:

> Geographic indicators represent approximate locations associated with observable network infrastructure. They do not independently establish the physical location or identity of an attacker.

Similarly, a source-to-target visual path represents an observed, inferred or correlated infrastructure relationship based on available evidence and must not automatically be presented as confirmed attacker attribution.

---

## 35.12 Final Geolocation Design Principle

The MailIntel map should feel like:

```text
THREAT INTELLIGENCE MAP
        +
RELATIONSHIP VISUALIZER
        +
FORENSIC EVIDENCE EXPLORER
```

It should not feel like:

```text
Generic Location Map          ✗
Decorative Pin Map            ✗
Movie-Style Cyber Attack Map  ✗
Unexplained Red Attack Lines  ✗
```

Every highlighted path must provide a clear explanation of:

1. What is connected?
2. Why is it connected?
3. What evidence supports the relationship?
4. How confident is the relationship?

---

# 36. Brand Assets (Final)

These are the only approved brand source files. Never regenerate, redraw, or
approximate the logo with CSS/SVG/styled text — always render these images.

```text
/frontend/public/logo-icon.png        Shield + envelope + fingerprint mark, transparent
/frontend/public/wordmark-dark.png    "MailinteL" wordmark, navy/black — for light surfaces
/frontend/public/wordmark-white.png   "MailinteL" wordmark, white — for dark/navy surfaces
/frontend/public/tagline-dark.png     "Intelligence behind each Inbox", dark text — light surfaces
/frontend/public/tagline-white.png    "Intelligence behind each Inbox", white text — dark surfaces
/frontend/public/favicon.png          32x32 icon
/frontend/public/favicon-192.png      192x192 icon
/frontend/public/favicon-512.png      512x512 icon
```

## Usage Rule

Every placement picks the wordmark/tagline pair that matches the surface it sits
on — white-text assets on navy/dark surfaces (sidebar, hero), dark-text assets on
light surfaces (top header, light cards). Use `components/common/BrandLogo.tsx`
(`variant` + `surface` props) rather than re-implementing logo markup elsewhere.

---

# 37. No Technology / Architecture Flex

Product screens show what the platform found for the user, not what the platform
is built from. This is a hard rule, not a style preference.

## Banned on product screens (Dashboard, Analyze, History, Intelligence,
## Campaigns, Graph, Geo, Evidence, Reports)

```text
Backend framework name-drops       (FastAPI, Uvicorn, Node...)          ✗
Database/infra brand cards         (PostgreSQL, pgvector, MinIO, Redis) ✗
"$TECH Ready" / "$TECH Enabled" badges                                 ✗
Architecture / pipeline step diagrams as page content                  ✗
Version numbers, build badges, "Powered by" chrome                     ✗
Latency/uptime numbers outside Settings                                ✗
```

## Where system/technology information belongs

**Settings only.** `SettingsView` is the single legitimate place for backend
health, service latency, environment, and infrastructure status. If it isn't
something a security analyst is investigating, it does not belong outside
Settings.

## The test before adding anything to a screen

> "Is this a finding about an email/domain/IP/campaign, or is it a fact about
> our own server?" If it's a fact about our own server, it goes in Settings or
> it doesn't go in the UI at all.

Technical vocabulary that IS the finding is not flex and stays: a SHA-256 hash
in the Evidence Vault, an SPF/DKIM result in Analyze, a relay-hop IP in the
Graph. The rule targets bragging about our own stack, not the forensic
technical detail that is the product.

---

# 38. Per-Screen Data Source Specification (MVP)

Every screen must be backed by real data from these endpoints — never static
or invented numbers, never a placeholder chart with made-up values. If an
endpoint has no data yet, use the Empty State pattern from §27, not a fake
sample.

| Screen | Purpose | Real Data Source | Primary Showcase | Empty State |
|---|---|---|---|---|
| **Dashboard** | Answer "what's happening, how bad, what needs attention" | `GET /emails` (stats + recent), `GET /campaigns`, `GET /reports` | Metric strip (analyzed/threats/critical/reports), Recent Activity table, Threat Distribution bars, Active Campaigns list | "No emails analyzed yet — upload a .eml to get started" + CTA |
| **Analyze Email** | Deep forensic breakdown of one email | `POST /emails/upload`, `GET /emails/{id}/structure|headers|hops|auth|artifacts`, `GET /emails/{id}/analysis`, `GET /emails/{id}/findings`, `GET /emails/{id}/dna`, `GET /emails/{id}/similar`, `GET /jobs/{id}` | Step-based analysis timeline (§14), header/MIME/relay breakdown, DNA fingerprint, similarity matches | Upload dropzone as the initial state, not a blank page |
| **Analysis History** | Browse/filter every analyzed email | `GET /emails` (paginated, filterable) | Sortable/filterable table: subject, sender, qualification, analyzed date | "No results for this filter" with a clear-filters action |
| **Threat Intel** | On-demand domain/IP reputation lookup | `GET /intelligence/domains/{domain_name}`, `GET /intelligence/ips/{ip_address}`, `POST /intelligence/threat/lookup` | Search-driven result card: reputation, WHOIS/ASN signals, related findings | Empty search state with example query format, not fake results |
| **Campaigns** | Correlated groups of related emails | `GET /campaigns`, `GET /campaigns/{id}`, `POST /campaigns/auto-cluster` | Campaign cards (name, confidence, member count, first/last seen), member email list | "No campaigns detected yet — run auto-clustering" |
| **Investigation Graph** | Visual entity relationships | `GET /graph/global`, `GET /graph/email/{id}`, `GET /graph/campaign/{id}` | Node/edge graph of emails-domains-IPs-campaigns with a legend, click-to-inspect | "Not enough correlated evidence yet to draw a graph" |
| **Geo Intelligence** | Observable infrastructure geolocation | `GET /geo/global`, `GET /geo/email/{id}`, `GET /geo/campaign/{id}`, `GET /geo/ip/{ip_address}` | Map of infrastructure points with confidence, no decorative attack lines (§35) | "No geolocated infrastructure yet" |
| **Evidence Vault** | Chain-of-custody for preserved originals | `GET /emails`, `GET /evidence/{id}`, `GET /evidence/{id}/custody`, `POST /evidence/{id}/verify` | Evidence table with hash, custody trail, integrity verification tool | "No evidence preserved yet" |
| **Reports** | Generated forensic/campaign reports | `GET /reports`, `POST /reports/email/{id}`, `POST /reports/campaign/{id}`, `GET /reports/{report_id}` | Report list (type, generated date, linked email/campaign), report preview/export | "No reports generated yet" + CTA from an analyzed email |
| **Settings** | Platform config + system health | `GET /health`, `GET /health/detailed` | The *only* screen allowed backend/infra status (§37) | N/A |

This table is the source of truth for what "data showcase" means on each
screen — build to it, don't invent metrics that aren't backed by a real
endpoint above.
