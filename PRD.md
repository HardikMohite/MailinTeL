# MailIntel
## Product Requirements Document (PRD)

**Product Name:** MailIntel

**Official SIH Problem Statement:**  
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

---

# 1. Product Overview

MailIntel is an AI-powered Email Threat Detection, Geolocation and Forensic Intelligence Platform designed to transform suspicious emails into actionable, evidence-based cyber intelligence.

Instead of only answering **"Is this email malicious?"**, MailIntel aims to answer:

- Why is this email suspicious?
- What forensic evidence supports the conclusion?
- How was the email transmitted?
- What infrastructure was involved?
- What domains, IP addresses, URLs and entities are connected?
- What is the probable geolocation of observable infrastructure?
- Is the sender potentially spoofed or compromised?
- Is anonymized infrastructure involved?
- Have other users received related attacks?
- Are multiple emails part of the same phishing campaign?
- What evidence can be preserved for further investigation?

### Intelligence Pipeline

```text
Email Ingestion
      ↓
Threat Detection
      ↓
Forensic Evidence Extraction
      ↓
Email Header & Protocol Analysis
      ↓
Domain & Infrastructure Intelligence
      ↓
Origin Traceability & Geolocation
      ↓
Email DNA Generation
      ↓
Cross-Email Correlation
      ↓
Campaign Intelligence
      ↓
Evidence-Based Investigation
```

---

# 2. Problem Statement

Email remains one of the most commonly exploited attack vectors for cybercrime.

Attackers use techniques such as:

- Phishing
- Email spoofing
- Sender impersonation
- Business Email Compromise
- Credential harvesting
- Fake invoices
- Payment diversion
- Malicious URLs and attachments
- Social engineering
- Compromised email accounts
- Lookalike domains
- Open relays
- VPNs and proxies
- TOR infrastructure
- Cloud-hosted malicious infrastructure
- Botnet infrastructure

Traditional tools often focus on filtering, blocking or classifying individual emails. Investigators may still need answers regarding the technical transmission path, observable infrastructure, potentially forged information, compromised accounts, spoofed domains, anonymized infrastructure, related incidents and large-scale campaigns.

MailIntel addresses this problem by combining AI-powered detection, deep email forensics, infrastructure intelligence, geolocation and graph-based campaign correlation.

---

# 3. Product Vision

> MailIntel transforms isolated suspicious emails into connected forensic intelligence.

The platform should enable investigators to move from:

```text
"This email is suspicious."
```

to:

```text
Why is it suspicious?
        ↓
What technical evidence exists?
        ↓
How was it transmitted?
        ↓
What infrastructure is associated with it?
        ↓
Where is that observable infrastructure probably located?
        ↓
Is it related to other attacks?
        ↓
Is it part of a larger campaign?
        ↓
What evidence can support further investigation?
```

---

# 4. Target Users

## 4.1 Individual Email Users

Users who receive suspicious emails and require simple security intelligence.

### Primary Needs

- Threat identification
- Easy-to-understand warnings
- Explanation of suspicious indicators
- Link and sender analysis
- Safe forensic analysis without advanced cybersecurity expertise

## 4.2 Security Analysts

Cybersecurity professionals investigating suspicious emails.

### Primary Needs

- Deep forensic analysis
- Header inspection
- Authentication analysis
- Domain intelligence
- Infrastructure intelligence
- Geolocation
- Evidence correlation

## 4.3 Institutional Administrators

Organizations managing multiple users and email security incidents.

### Primary Needs

- Centralized threat visibility
- Incident analysis
- Threat intelligence
- Campaign detection
- Forensic reporting

## 4.4 Authorized Cyber Cell Investigators

Authorized investigators responsible for analyzing qualifying cybercrime incidents.

### Primary Needs

- Centralized malicious email intelligence
- Cross-user campaign visibility
- Infrastructure relationships
- Geolocation intelligence
- Graph-based investigation
- Campaign timelines
- Evidence preservation
- Chain of custody

### Critical Privacy Rule

Cyber Cell investigators must not receive unrestricted access to normal user emails.

Only qualifying:

- Malicious emails
- High-risk incidents
- Campaign-related incidents
- Relevant forensic evidence

should enter the authorized investigation workflow according to defined policies.

---

# 5. Core Product Principles

## 5.1 Evidence Before Attribution

MailIntel must distinguish between:

- Confirmed technical evidence
- Investigative inference
- Confidence-based assessment

The platform must not claim an attacker's identity without sufficient evidence.

## 5.2 Probable Infrastructure Location, Not Attacker Location

IP geolocation identifies the probable location of observable infrastructure.

It must not automatically be represented as:

> "The attacker is located here."

Instead:

> "Relevant observable infrastructure is associated with this approximate location."

## 5.3 Privacy by Design

Normal and non-malicious emails should not unnecessarily enter centralized investigation systems.

MailIntel must support:

- Data minimization
- Role-based access
- Data masking
- Configurable retention
- Controlled evidence sharing

## 5.4 Explainable Intelligence

Important results should explain:

- Why an email was classified as malicious
- Which evidence supports campaign correlation
- Why infrastructure is considered suspicious
- How confidence levels were calculated

## 5.5 Correlation Over Isolation

A malicious email should not always be treated as an isolated incident.

MailIntel should identify meaningful relationships across multiple incidents.

---

# 6. Core Features

MailIntel consists of nine primary product pillars.

## 6.1 Email Ingestion and Integration

MailIntel shall support multiple methods of email ingestion.

### Mode 1: `.eml` File Upload

Users can upload an `.eml` file for complete forensic analysis.

#### Available Features

- Full header extraction
- MIME analysis
- Email body analysis
- Attachment metadata analysis
- URL extraction
- Domain extraction
- Authentication analysis
- Relay-path reconstruction
- Email DNA generation
- Campaign correlation
- Geolocation intelligence
- Forensic reporting

#### Primary Use Cases

- Manual investigation
- Historical email analysis
- Incident reporting
- Forensic investigation

### Mode 2: OAuth-Based Gmail Integration

Users can authorize access to supported Gmail data through OAuth.

MailIntel must never request or store the user's Gmail password.

#### Features

- Authorized email retrieval
- Analysis of existing emails
- Threat detection
- Deep forensic processing
- Campaign correlation
- Integrated results

### Mode 3: OAuth-Based Microsoft Outlook Integration

Users can authorize supported Outlook access through OAuth and approved provider APIs.

#### Features

- Authorized email retrieval
- Existing email analysis
- Threat detection
- Forensic analysis
- Campaign intelligence

### Mode 4: Browser Extension

A browser extension may integrate MailIntel intelligence into supported Gmail and Outlook web environments.

#### Without OAuth

The extension can perform preliminary analysis of information legitimately accessible within the web interface.

**Limitations:**

- Full raw email data may not be available
- Complete header analysis may be limited
- Deep forensic capabilities may be restricted

#### With OAuth

The extension can trigger deeper analysis using authorized provider data.

This enables:

- Complete email retrieval where authorized
- Forensic analysis
- Email DNA generation
- Campaign correlation
- Integrated threat results

---

## 6.2 AI-Powered Email Threat Detection

MailIntel shall use AI, NLP and machine-learning techniques to analyze emails.

The system shall detect potential:

- Phishing
- Spoofing
- Impersonation
- Business Email Compromise
- Credential theft
- Financial fraud
- Fake invoices
- Payment diversion
- Social engineering
- Suspicious URLs
- Suspicious attachments

The system should provide an explainable threat assessment.

### Threat Risk Score

Each analyzed email may receive a Threat Risk Score representing:

> How likely the email is to be malicious.

Possible inputs include:

- Content analysis
- Social engineering indicators
- Header anomalies
- Authentication failures
- Malicious URLs
- Domain reputation
- Infrastructure indicators
- Attachment indicators

### Evidence Confidence Score

MailIntel shall maintain a separate Evidence Confidence Score representing:

> How reliable and complete the supporting forensic evidence is.

This must remain separate from the Threat Risk Score.

Example:

```text
Email A

Threat Risk: High
Evidence Confidence: Medium
```

This means the email appears highly suspicious, but the available forensic evidence may be incomplete.

---

## 6.3 Email Header and Protocol Forensics

MailIntel shall analyze available email headers and authentication mechanisms.

### Header Fields

- From
- Reply-To
- Return-Path
- Message-ID
- Received headers

### Authentication

- SPF
- DKIM
- DMARC

### Forensic Objectives

The system shall identify:

- Sender inconsistencies
- Authentication failures
- Spoofing indicators
- Routing anomalies
- Suspicious relay infrastructure
- Forged or unreliable header information

---

## 6.4 SMTP Relay Path Reconstruction

MailIntel shall analyze available `Received` headers and reconstruct the observable transmission path.

The system should:

- Identify mail servers
- Analyze relay sequences
- Identify suspicious nodes
- Detect unusual routing
- Identify the earliest reliable observable infrastructure

The system must not blindly trust every header. Each relay indicator should be assessed according to available evidence.

---

## 6.5 Domain and Infrastructure Intelligence

MailIntel shall perform domain intelligence analysis for domains associated with suspicious emails.

### Domain Analysis

- WHOIS data where available
- DNS records
- MX records
- Registrar information
- Hosting information
- Hosting fingerprints
- Domain age where available
- Domain relationships
- Lookalike domains

### Objectives

The analysis should help identify:

- Suspicious sender infrastructure
- Newly created infrastructure
- Spoofed or deceptive domains
- Infrastructure relationships
- Unusual domain configurations

---

## 6.6 Anonymized and Suspicious Infrastructure Detection

MailIntel shall correlate infrastructure indicators with available intelligence regarding:

- VPN infrastructure
- TOR nodes
- Proxy services
- Open relays
- Botnets
- Cloud-hosted infrastructure
- Hosting services
- Other anonymized infrastructure indicators

The presence of such infrastructure alone must not prove malicious activity.

```text
Infrastructure Indicator
          ↓
Infrastructure Classification
          ↓
Additional Forensic Evidence
          ↓
Threat Correlation
          ↓
Confidence-Based Assessment
```

---

## 6.7 Origin Traceability and Geolocation

MailIntel shall extract relevant observable infrastructure indicators.

Analysis may include:

- IP address
- ASN
- ISP
- Hosting provider
- Country
- Region
- Approximate city

Geolocation must be displayed through an interactive map.

The map may also highlight:

- High-risk infrastructure
- Campaign hotspots
- Related infrastructure clusters
- Multiple incident locations

---

## 6.8 Email DNA Intelligence Engine

Email DNA is MailIntel's internal multi-layer intelligence methodology.

Each suspicious email is represented through multiple evidence dimensions.

```text
                    EMAIL DNA
                         │
 ┌───────────────────────┼────────────────────────┐
 │                       │                        │
Content              Technical              Infrastructure
 │                       │                        │
Semantic Patterns     Headers                IPs
Language              Authentication         ASN
Intent                Relay Path             Hosting
 │                       │                        │
URLs                  Domains                Attachments
 │                       │                        │
Behavioral            Temporal
Patterns              Patterns
```

Email DNA may include:

- Semantic similarity
- Content patterns
- URLs and URL structures
- Domains
- Infrastructure
- Headers
- Sender behavior
- Attachments
- Temporal patterns

The objective is to identify relationships even when attackers modify individual indicators.

---

## 6.9 Semantic Intelligence

AI-generated semantic representations may be used to understand the meaning and intent of email content.

Semantic similarity should not independently determine campaign membership. It acts as one evidence signal.

Example:

```text
Email A
Content Similarity with B: High

But:

Domain Similarity: Low
Infrastructure Similarity: Low

Result:
Requires additional evidence before campaign grouping.
```

---

## 6.10 Campaign Intelligence and Correlation

MailIntel shall identify potentially coordinated campaigns affecting multiple users.

```text
User A → Email A
User B → Email B
User C → Email C
User D → Email D

         ↓

    MailIntel Correlation

         ↓

Potential Phishing Campaign
```

Campaign correlation may analyze:

- Shared URLs
- Related domains
- Shared infrastructure
- Similar infrastructure patterns
- Semantic similarities
- Attachment hashes
- Sender aliases
- Reply chains
- Header characteristics
- Temporal patterns

### Multi-Campaign Relationships

An email may contain evidence connected to more than one cluster.

```text
Email A ─── Same Infrastructure ─── Email B
                                         │
                                         │ Same URL
                                         │
                                      Email C
```

Email B may act as a connecting node between two groups.

Therefore, MailIntel should not force every email into only one campaign at the earliest stage.

The system should support:

- Campaign overlap
- Shared infrastructure nodes
- Evidence-level relationships
- Confidence-based campaign membership

Final campaign decisions should depend on the overall evidence graph.

---

## 6.11 Graph-Based Threat Intelligence

MailIntel shall represent relationships through an intelligence graph.

Potential nodes include:

- Emails
- Users
- Sender addresses
- Domains
- URLs
- IP addresses
- ASN
- Infrastructure
- Attachments
- Campaigns

Relationships may include:

- Sent from
- Linked to
- Resolves to
- Hosted on
- Shared with
- Similar to
- Appeared before
- Belongs to campaign

The graph should help analysts discover hidden relationships.

---

## 6.12 Campaign Timeline and Attack Progression

MailIntel should maintain temporal intelligence regarding related attacks.

```text
Initial Incident
      ↓
Similar Email
      ↓
New Domain
      ↓
Infrastructure Change
      ↓
Campaign Expansion
      ↓
Multiple Users Targeted
```

This helps investigators understand how a campaign evolves over time.

---

## 6.13 Threat Intelligence Feedback Loop

Confirmed or high-confidence malicious indicators may contribute to future detection.

```text
New Malicious Email
        ↓
Evidence Extraction
        ↓
Confirmed Indicators
        ↓
Threat Intelligence Database
        ↓
Future Detection & Correlation
```

Only appropriate threat indicators and authorized evidence should be shared or retained.

The system should avoid unnecessary sharing of private email content.

---

## 6.14 Cyber Cell Intelligence Dashboard

MailIntel shall provide a centralized dashboard for authorized investigators.

The dashboard should display:

- High-risk incidents
- Confirmed malicious indicators
- Campaign clusters
- Affected users
- Threat scores
- Evidence confidence
- Relationship graphs
- Infrastructure intelligence
- Geolocation maps
- Domain intelligence
- Campaign timelines
- Investigation records

### Critical Access Rule

Normal email traffic must not automatically become visible to the Cyber Cell.

The dashboard should focus on:

- Qualifying malicious incidents
- High-confidence suspicious incidents
- Campaign-related evidence

---

## 6.15 User Security Dashboard

Users should receive a simplified view of their email analysis.

The user interface should display:

- Threat level
- Major risk indicators
- Suspicious URLs
- Spoofing indicators
- Recommended actions

Highly technical forensic details may be available based on user role.

---

## 6.16 Forensic Reporting

MailIntel shall generate structured forensic reports.

Reports may include:

- Email identification
- Threat classification
- Threat Risk Score
- Evidence Confidence Score
- Header analysis
- Authentication results
- Relay path
- URLs
- Domains
- Infrastructure intelligence
- Geolocation
- Campaign relationships
- Timeline
- Forensic findings

Reports should support authorized:

- Incident response
- Institutional investigation
- Fraud investigation
- Cyber Cell investigation

---

## 6.17 Evidence Preservation and Chain of Custody

MailIntel shall support forensic evidence preservation.

For qualifying incidents, the system should maintain:

- Evidence identifier
- Evidence source
- Ingestion timestamp
- Original file hash where applicable
- Analysis timestamp
- Analysis version
- Authorized access history
- Investigation actions
- Report generation history

The chain of custody should provide an auditable evidence trail.

```text
Evidence Acquired
        ↓
Evidence Identified
        ↓
Integrity Preserved
        ↓
Evidence Analyzed
        ↓
Authorized Access
        ↓
Investigation Activity
        ↓
Report Generation
```

---

## 6.18 Privacy, Data Retention and Masking

MailIntel shall follow privacy-by-design principles.

### Configurable Data Retention

Retention policies should be configurable based on:

- Organization policy
- Investigation requirements
- Legal requirements
- Evidence requirements

### Sensitive Data Masking

The platform should support masking of:

- Email addresses
- Personally identifiable information
- Sensitive email content
- Sensitive metadata

Data visibility should depend on user authorization.

### Data Minimization

The system should prioritize processing only what is required for:

- Threat detection
- Forensic analysis
- Campaign correlation
- Authorized investigation

Normal emails should not unnecessarily enter centralized investigation storage.

---

# 7. Key User Workflows

## Workflow 1: `.eml` Analysis

```text
User Uploads .eml
        ↓
Integrity Hash Generated
        ↓
Email Parsing
        ↓
Threat Analysis
        ↓
Forensic Analysis
        ↓
Infrastructure & Domain Intelligence
        ↓
Geolocation
        ↓
Email DNA Generation
        ↓
Campaign Correlation
        ↓
Result & Report
```

## Workflow 2: OAuth Integration

```text
User Connects Gmail / Outlook
        ↓
OAuth Authorization
        ↓
Authorized API Access
        ↓
Email Data Retrieved
        ↓
MailIntel Analysis
        ↓
Threat Intelligence Result
```

## Workflow 3: Campaign Detection

```text
Multiple Suspicious Emails
            ↓
Evidence Extraction
            ↓
Email DNA Generation
            ↓
Entity Graph Construction
            ↓
Evidence Correlation
            ↓
Campaign Confidence Assessment
            ↓
Campaign Cluster
```

---

# 8. Success Criteria

## 8.1 Threat Detection

- Detect phishing indicators
- Identify spoofing indicators
- Detect impersonation patterns
- Detect fraud-related content
- Provide explainable findings

## 8.2 Email Forensics

- Parse email headers
- Analyze SPF, DKIM and DMARC
- Reconstruct available relay paths
- Extract relevant technical indicators

## 8.3 Domain Intelligence

- Analyze DNS records
- Analyze MX records
- Retrieve WHOIS information where available
- Analyze registrar and hosting information
- Detect suspicious domain relationships

## 8.4 Infrastructure Intelligence

- Identify observable IP infrastructure
- Analyze ASN and ISP information
- Identify VPN/TOR/proxy indicators where applicable
- Detect cloud-hosted infrastructure indicators
- Correlate infrastructure evidence

## 8.5 Geolocation

- Display probable infrastructure locations
- Visualize findings on a map
- Clearly communicate geolocation limitations

## 8.6 Campaign Intelligence

- Correlate related suspicious emails
- Identify evidence-based relationships
- Support overlapping evidence clusters
- Visualize relationships using graphs
- Display campaign progression over time

## 8.7 Evidence Integrity

- Generate evidence hashes where applicable
- Preserve evidence records
- Maintain chain-of-custody logs
- Maintain authorized access records

## 8.8 Privacy

- Prevent unnecessary exposure of normal emails
- Support configurable retention
- Support sensitive-data masking
- Support role-based access

---

# 9. Product Scope

## In Scope

- `.eml` analysis
- Gmail OAuth integration
- Outlook OAuth integration
- Browser extension
- AI-powered threat detection
- NLP analysis
- Header forensics
- SPF/DKIM/DMARC analysis
- Relay path reconstruction
- Domain intelligence
- WHOIS/DNS/MX analysis
- Hosting and registrar intelligence
- IP intelligence
- Geolocation
- VPN/TOR/proxy indicators
- Cloud infrastructure indicators
- Open relay indicators
- Botnet indicators where applicable
- Email DNA
- Semantic analysis
- Graph correlation
- Campaign intelligence
- Campaign timeline
- Threat intelligence feedback loop
- Cyber Cell dashboard
- User dashboard
- Forensic reporting
- Evidence preservation
- Chain of custody
- Configurable retention
- Sensitive-data masking

---

# 10. Out of Scope

The initial MailIntel implementation will not:

- Build a complete email provider
- Replace Gmail or Outlook
- Build an independent SMTP service
- Store user passwords
- Guarantee identification of every malicious actor
- Claim exact attacker physical location from IP data alone
- Perform automatic law-enforcement action
- Treat every VPN, cloud server or proxy as malicious

---

# 11. Product Vision Statement

> MailIntel is an AI-powered forensic intelligence platform that detects malicious emails, analyzes their technical and infrastructure evidence, identifies probable infrastructure locations, and connects related incidents to uncover larger cybercrime campaigns.

The ultimate objective is to help authorized users move from isolated email detection toward connected, evidence-based cyber intelligence.
