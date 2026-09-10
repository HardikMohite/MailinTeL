# MailIntel — Data & Object Storage Schema

**Product:** MailIntel  
**Official SIH Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Document:** `Schema.md`  
**Version:** 1.0  
**Primary Database:** PostgreSQL + pgvector  
**Object Storage:** MinIO (S3-compatible)

---

# 1. Purpose

This document defines how MailIntel stores and connects the data required by the Product Requirements Document (PRD).

The architecture separates:

```text
PostgreSQL
    ↓
Structured intelligence, metadata, hashes, scores,
relationships, audit records and object references

MinIO
    ↓
Original evidence objects, attachments, derived files,
generated reports and other large binary artifacts
```

## Core Principle

> **PostgreSQL knows what an evidence object is, why it matters, who accessed it, its integrity hash and where it is stored. MinIO stores the actual object.**

This separation directly supports:

- Email forensic analysis
- Evidence preservation
- SHA-256 integrity verification
- Chain of custody
- Campaign intelligence
- Graph relationships
- Geolocation intelligence
- Privacy and data retention
- Controlled Cyber Cell access

---

# 2. PRD Coverage Check

This schema has been mapped against the current MailIntel PRD.

| PRD Requirement | Schema Coverage |
|---|---|
| `.eml` analysis | `emails`, `email_sources`, `evidence_objects`, MinIO |
| Gmail OAuth integration | `oauth_connections`, `emails`, encrypted token handling |
| Outlook OAuth integration | `oauth_connections`, provider-specific metadata |
| Browser extension | `email_sources`, `extension_events`, analysis references |
| AI/NLP threat detection | `email_analysis`, `analysis_findings`, `analysis_runs` |
| Threat Risk Score | `email_analysis` |
| Evidence Confidence Score | `email_analysis`, `analysis_findings` |
| Header forensics | `email_headers`, `relay_hops`, `email_authentication_results` |
| SPF/DKIM/DMARC | `email_authentication_results` |
| Relay path reconstruction | `relay_hops` |
| URL intelligence | `urls`, `email_urls`, `url_intelligence` |
| DNS/MX/WHOIS/RDAP | `domains`, `domain_dns_records`, `domain_registration_intel` |
| Hosting/registrar intelligence | `domain_intelligence`, `ip_intelligence` |
| IP intelligence | `ip_addresses`, `ip_intelligence` |
| VPN/TOR/proxy/open relay/botnet indicators | `infrastructure_classifications` |
| Geolocation | `geolocations`, `entity_geolocations` |
| Email DNA | `email_dna_profiles`, `email_embeddings` |
| Semantic similarity | `email_similarity_links`, pgvector |
| Graph correlation | `intel_entities`, `intel_relationships` |
| Campaign intelligence | `campaigns`, `campaign_memberships`, `campaign_evidence` |
| Campaign overlap | many-to-many campaign memberships |
| Campaign timeline | `campaign_events` |
| Threat intelligence feedback | `threat_indicators`, `indicator_sightings` |
| Cyber Cell dashboard | campaigns, cases, incidents, qualified evidence |
| User dashboard | user-scoped emails and analysis records |
| Forensic reports | `reports` + MinIO report objects |
| Evidence preservation | `evidence_objects` + MinIO |
| Chain of custody | `custody_events` |
| Configurable retention | `retention_policies`, `retention_assignments` |
| Sensitive-data masking | `data_classifications`, `masking_rules`, access controls |

**Conclusion:** The database and object-storage design covers the major requirements currently defined in the PRD, including the evidence integrity and privacy rules that are especially important for MailIntel.

---

# 3. Storage Responsibilities

## 3.1 PostgreSQL

PostgreSQL is the system of record for structured application and intelligence data.

It stores:

- Users and organizations
- Roles and permissions
- Email metadata
- Parsed headers and recipients
- Threat analysis results
- Threat Risk and Evidence Confidence scores
- Email DNA metadata
- Vector embeddings through pgvector
- URLs, domains and IP addresses
- Domain and infrastructure intelligence
- Geolocation records
- Campaigns and memberships
- Intelligence graph relationships
- Cases and investigation records
- Evidence metadata
- SHA-256 hashes
- MinIO bucket and object keys
- Chain-of-custody events
- Reports and report metadata
- Retention policies
- Audit and access records
- OAuth connection metadata

PostgreSQL does **not** act as the primary storage location for original `.eml` evidence files or other large binary artifacts.

---

## 3.2 MinIO

MinIO stores the actual binary or original evidence objects.

Examples:

- Original `.eml` files
- Authorized raw email exports where retention is permitted
- Attachments
- Extracted files
- Derived forensic artifacts
- Generated PDF reports
- Investigation exports

MinIO object access should be controlled through backend-issued, time-limited access mechanisms rather than public object URLs.

---

# 4. High-Level Data Architecture

```text
                    EMAIL INGESTION
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
      .eml Upload       OAuth API      Browser Extension
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                   Secure Ingestion
                           │
                    SHA-256 Created
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
         PostgreSQL                    MinIO
              │                         │
      Evidence metadata           Original object
      SHA-256 hash                Attachments
      Object reference            Reports
      Analysis state              Derived artifacts
              │                         │
              └────────────┬────────────┘
                           ▼
                    Analysis Pipeline
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   Threat Analysis    Intelligence      Email DNA
                      Enrichment        + Vectors
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                  Campaign Correlation
                           │
                           ▼
              Cases / Reports / Investigation
```

---

# 5. PostgreSQL Extensions

Recommended extensions:

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";
```

Optional:

```sql
CREATE EXTENSION IF NOT EXISTS "postgis";
```

## `pgcrypto`

Can support database-side cryptographic functions where required.

## `pgvector`

Stores semantic embeddings and supports similarity search.

Examples:

- Similar email content
- Similar phishing language
- Email DNA similarity signals
- Related campaign discovery

A vector is **not** a threat score and must not independently decide campaign membership.

## PostGIS — Optional

Recommended only if advanced geographic queries become necessary, such as:

- Geographic campaign clustering
- Infrastructure hotspots
- Regional aggregation

---

# 6. Common PostgreSQL Conventions

## 6.1 IDs

Use UUID primary keys.

```text
user_id
email_id
evidence_id
campaign_id
case_id
report_id
```

## 6.2 Timestamps

Use:

```sql
TIMESTAMPTZ
```

Store system timestamps in UTC.

## 6.3 Sensitive Data

Sensitive fields should not automatically be duplicated across multiple tables.

Where possible:

```text
Raw evidence → MinIO
Structured intelligence → PostgreSQL
Masked view → Application layer / authorized access policy
```

---

# 7. Identity and Access Schema

## 7.1 `users`

```text
users
├── id UUID PK
├── email VARCHAR UNIQUE
├── full_name VARCHAR
├── password_hash TEXT NULL
├── auth_provider VARCHAR
├── status VARCHAR
├── last_login_at TIMESTAMPTZ NULL
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

### Important

The `password_hash` field is only for a MailIntel local authentication method if one exists.

MailIntel must never store Gmail or Outlook passwords.

---

## 7.2 `organizations`

```text
organizations
├── id UUID PK
├── name VARCHAR
├── organization_type VARCHAR
├── status VARCHAR
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

---

## 7.3 `roles`

```text
roles
├── id UUID PK
├── code VARCHAR UNIQUE
├── name VARCHAR
└── description TEXT
```

Examples:

```text
USER
SECURITY_ANALYST
INSTITUTION_ADMIN
CYBER_CELL_INVESTIGATOR
SYSTEM_ADMIN
```

---

## 7.4 `organization_members`

```text
organization_members
├── id UUID PK
├── organization_id UUID FK
├── user_id UUID FK
├── role_id UUID FK
├── status VARCHAR
└── created_at TIMESTAMPTZ
```

---

## 7.5 `permissions`

```text
permissions
├── id UUID PK
├── code VARCHAR UNIQUE
├── name VARCHAR
└── description TEXT
```

## 7.6 `role_permissions`

```text
role_permissions
├── role_id UUID FK
└── permission_id UUID FK
```

Primary key:

```text
(role_id, permission_id)
```

---

# 8. Email Ingestion Schema

## 8.1 `email_sources`

Identifies how an email entered MailIntel.

```text
email_sources
├── id UUID PK
├── organization_id UUID FK NULL
├── user_id UUID FK NULL
├── source_type VARCHAR
├── source_provider VARCHAR NULL
├── source_reference VARCHAR NULL
├── created_at TIMESTAMPTZ
└── metadata JSONB
```

### `source_type`

```text
FILE_UPLOAD
OAUTH_MAILBOX
BROWSER_EXTENSION
API
```

### `source_provider`

```text
GMAIL
MICROSOFT
GENERIC
```

---

## 8.2 `emails`

Stores normalized email metadata.

```text
emails
├── id UUID PK
├── organization_id UUID FK NULL
├── source_id UUID FK
├── external_message_id VARCHAR NULL
├── message_id_header VARCHAR NULL
├── subject TEXT NULL
├── sender_address VARCHAR NULL
├── sender_display_name VARCHAR NULL
├── sent_at TIMESTAMPTZ NULL
├── received_at TIMESTAMPTZ NULL
├── email_size_bytes BIGINT NULL
├── analysis_status VARCHAR
├── qualification_status VARCHAR
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

### `qualification_status`

Supports the PRD's critical privacy rule.

Examples:

```text
NORMAL
SUSPICIOUS
HIGH_RISK
MALICIOUS
CAMPAIGN_RELATED
QUALIFIED_FOR_INVESTIGATION
```

A Cyber Cell workflow should not automatically expose all `NORMAL` emails.

---

# 9. Email Forensic Schema

## 9.1 `email_headers`

```text
email_headers
├── id UUID PK
├── email_id UUID FK
├── header_name VARCHAR
├── header_value TEXT
├── normalized_value TEXT NULL
├── header_order INTEGER
└── created_at TIMESTAMPTZ
```

---

## 9.2 `email_recipients`

```text
email_recipients
├── id UUID PK
├── email_id UUID FK
├── recipient_type VARCHAR
├── address VARCHAR
├── display_name VARCHAR NULL
└── created_at TIMESTAMPTZ
```

`recipient_type`:

```text
TO
CC
BCC
```

---

## 9.3 `email_authentication_results`

```text
email_authentication_results
├── id UUID PK
├── email_id UUID FK UNIQUE
├── spf_result VARCHAR NULL
├── dkim_result VARCHAR NULL
├── dmarc_result VARCHAR NULL
├── from_alignment_result VARCHAR NULL
├── return_path VARCHAR NULL
├── reply_to VARCHAR NULL
├── evidence JSONB
└── created_at TIMESTAMPTZ
```

---

## 9.4 `relay_hops`

Stores the observable SMTP relay path reconstructed from available `Received` headers.

```text
relay_hops
├── id UUID PK
├── email_id UUID FK
├── sequence_number INTEGER
├── source_host VARCHAR NULL
├── source_ip INET NULL
├── destination_host VARCHAR NULL
├── observed_at TIMESTAMPTZ NULL
├── reliability VARCHAR
├── evidence JSONB
└── created_at TIMESTAMPTZ
```

### Reliability

```text
HIGH
MEDIUM
LOW
UNVERIFIED
```

This supports the PRD rule that headers must not be blindly trusted.

---

# 10. Evidence Object Schema — PostgreSQL

This is the central connection between PostgreSQL and MinIO.

## 10.1 `evidence_objects`

```text
evidence_objects
├── id UUID PK
├── email_id UUID FK NULL
├── case_id UUID FK NULL
├── parent_evidence_id UUID FK NULL
├── evidence_type VARCHAR
├── original_filename VARCHAR
├── content_type VARCHAR
├── size_bytes BIGINT
├── sha256_hash CHAR(64)
├── bucket_name VARCHAR
├── object_key TEXT
├── object_version_id VARCHAR NULL
├── source_type VARCHAR
├── acquired_at TIMESTAMPTZ
├── stored_at TIMESTAMPTZ
├── immutable BOOLEAN
├── retention_status VARCHAR
├── created_by UUID FK NULL
└── created_at TIMESTAMPTZ
```

### Example

```text
Evidence ID: EV-001
Evidence Type: ORIGINAL_EMAIL
Filename: suspicious_email.eml
SHA-256: 9f86d081884c7d659a2feaa0c55ad015...
Bucket: mailintel-evidence
Object Key: originals/emails/2026/09/EV-001.eml
Immutable: true
```

The actual `.eml` file exists in MinIO.

PostgreSQL stores the metadata and reference.

---

# 11. Evidence Integrity and Hashing

For every qualifying original evidence object:

```text
Original File Received
        ↓
SHA-256 Calculated
        ↓
Evidence Metadata Created in PostgreSQL
        ↓
Original Object Stored in MinIO
        ↓
Bucket + Object Key Recorded
        ↓
Chain-of-Custody Event Created
```

## Integrity Verification

```text
Stored SHA-256 in PostgreSQL
            │
            ▼
Retrieve Object from MinIO
            │
            ▼
Calculate SHA-256 Again
            │
            ▼
Compare Hashes
      ┌─────┴─────┐
      │           │
    MATCH      MISMATCH
      │           │
 Integrity    Investigation
 Verified       Required
```

---

# 12. Chain-of-Custody Schema

## 12.1 `custody_events`

```text
custody_events
├── id UUID PK
├── evidence_id UUID FK
├── event_type VARCHAR
├── actor_user_id UUID FK NULL
├── case_id UUID FK NULL
├── event_at TIMESTAMPTZ
├── event_metadata JSONB
├── previous_event_hash CHAR(64) NULL
├── event_hash CHAR(64) NULL
└── created_at TIMESTAMPTZ
```

### Event Types

```text
ACQUIRED
HASH_GENERATED
STORED
ANALYSIS_STARTED
ANALYSIS_COMPLETED
VIEWED
EXPORTED
REPORTED
VERIFIED
RETENTION_CHANGED
ACCESS_GRANTED
```

`previous_event_hash` and `event_hash` may optionally provide tamper-evident chaining for custody records.

---

# 13. Analysis Schema

## 13.1 `analysis_runs`

Every major analysis execution should be recorded.

```text
analysis_runs
├── id UUID PK
├── email_id UUID FK
├── analysis_type VARCHAR
├── analysis_version VARCHAR
├── status VARCHAR
├── started_at TIMESTAMPTZ
├── completed_at TIMESTAMPTZ NULL
├── worker_reference VARCHAR NULL
└── metadata JSONB
```

---

## 13.2 `email_analysis`

Stores the primary analysis outcome.

```text
email_analysis
├── id UUID PK
├── email_id UUID FK
├── analysis_run_id UUID FK
├── threat_classification VARCHAR
├── threat_risk_score NUMERIC(5,2)
├── evidence_confidence_score NUMERIC(5,2)
├── summary TEXT
├── compromised_account_likelihood VARCHAR NULL
├── spoofed_domain_likelihood VARCHAR NULL
├── anonymized_infrastructure_likelihood VARCHAR NULL
├── malicious_environment_likelihood VARCHAR NULL
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

## Important Score Separation

```text
Threat Risk Score
        ≠
Evidence Confidence Score
        ≠
Campaign Correlation Confidence
```

These scores must remain separate because they answer different questions.

---

## 13.3 `analysis_findings`

Stores explainable findings.

```text
analysis_findings
├── id UUID PK
├── email_id UUID FK
├── analysis_run_id UUID FK
├── finding_type VARCHAR
├── severity VARCHAR
├── confidence NUMERIC(5,2)
├── title VARCHAR
├── description TEXT
├── evidence JSONB
└── created_at TIMESTAMPTZ
```

Examples:

```text
SPF_FAILURE
LOOKALIKE_DOMAIN
MALICIOUS_URL
SUSPICIOUS_RELAY
BRAND_IMPERSONATION
CREDENTIAL_HARVESTING
```

---

# 14. Email DNA and Semantic Intelligence

## 14.1 `email_dna_profiles`

```text
email_dna_profiles
├── id UUID PK
├── email_id UUID FK UNIQUE
├── content_fingerprint JSONB
├── technical_fingerprint JSONB
├── infrastructure_fingerprint JSONB
├── behavioral_fingerprint JSONB
├── temporal_fingerprint JSONB
├── dna_version VARCHAR
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

This represents the PRD's multi-layer Email DNA methodology.

---

## 14.2 `email_embeddings`

```text
email_embeddings
├── id UUID PK
├── email_id UUID FK
├── embedding_type VARCHAR
├── model_name VARCHAR
├── embedding VECTOR(n)
└── created_at TIMESTAMPTZ
```

`n` depends on the chosen embedding model.

Examples:

```text
EMAIL_CONTENT
SUBJECT
EMAIL_DNA
```

---

## 14.3 `email_similarity_links`

```text
email_similarity_links
├── id UUID PK
├── source_email_id UUID FK
├── related_email_id UUID FK
├── similarity_type VARCHAR
├── similarity_score NUMERIC(6,5)
├── evidence JSONB
└── created_at TIMESTAMPTZ
```

Similarity types:

```text
SEMANTIC
CONTENT
STRUCTURAL
EMAIL_DNA
```

A similarity link is an evidence signal, not automatic proof of campaign membership.

---

# 15. URL and Domain Intelligence

## 15.1 `urls`

```text
urls
├── id UUID PK
├── normalized_url TEXT UNIQUE
├── url_hash CHAR(64)
├── domain_id UUID FK NULL
├── first_seen_at TIMESTAMPTZ NULL
└── created_at TIMESTAMPTZ
```

## 15.2 `email_urls`

```text
email_urls
├── email_id UUID FK
├── url_id UUID FK
├── context VARCHAR NULL
└── created_at TIMESTAMPTZ
```

---

## 15.3 `domains`

```text
domains
├── id UUID PK
├── normalized_domain VARCHAR UNIQUE
├── root_domain VARCHAR
├── first_seen_at TIMESTAMPTZ NULL
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

---

## 15.4 `domain_dns_records`

```text
domain_dns_records
├── id UUID PK
├── domain_id UUID FK
├── record_type VARCHAR
├── record_value TEXT
├── observed_at TIMESTAMPTZ
└── source VARCHAR
```

Supported records can include:

```text
A
AAAA
MX
TXT
NS
CNAME
```

---

## 15.5 `domain_registration_intel`

Supports RDAP and WHOIS-derived intelligence where available.

```text
domain_registration_intel
├── id UUID PK
├── domain_id UUID FK
├── source VARCHAR
├── registrar VARCHAR NULL
├── registered_at TIMESTAMPTZ NULL
├── expires_at TIMESTAMPTZ NULL
├── nameservers JSONB NULL
├── raw_summary JSONB
├── retrieved_at TIMESTAMPTZ
└── created_at TIMESTAMPTZ
```

---

# 16. IP and Infrastructure Intelligence

## 16.1 `ip_addresses`

```text
ip_addresses
├── id UUID PK
├── ip_address INET UNIQUE
├── first_seen_at TIMESTAMPTZ NULL
└── created_at TIMESTAMPTZ
```

---

## 16.2 `ip_intelligence`

```text
ip_intelligence
├── id UUID PK
├── ip_id UUID FK
├── asn VARCHAR NULL
├── isp VARCHAR NULL
├── network_owner VARCHAR NULL
├── hosting_provider VARCHAR NULL
├── reverse_dns VARCHAR NULL
├── intelligence_source VARCHAR
├── retrieved_at TIMESTAMPTZ
└── metadata JSONB
```

---

## 16.3 `infrastructure_classifications`

```text
infrastructure_classifications
├── id UUID PK
├── ip_id UUID FK NULL
├── domain_id UUID FK NULL
├── classification_type VARCHAR
├── confidence NUMERIC(5,2)
├── source VARCHAR
├── evidence JSONB
└── observed_at TIMESTAMPTZ
```

Examples:

```text
TOR
VPN
PROXY
OPEN_RELAY
BOTNET_INDICATOR
CLOUD_HOSTED
HOSTING_PROVIDER
RESIDENTIAL_ISP
```

A classification is an intelligence signal and does not independently prove malicious activity.

---

# 17. Geolocation Schema

## 17.1 `geolocations`

```text
geolocations
├── id UUID PK
├── country_code VARCHAR
├── country_name VARCHAR
├── region_name VARCHAR NULL
├── city_name VARCHAR NULL
├── latitude NUMERIC NULL
├── longitude NUMERIC NULL
├── accuracy_radius_km INTEGER NULL
├── source VARCHAR
├── confidence NUMERIC(5,2) NULL
└── created_at TIMESTAMPTZ
```

---

## 17.2 `entity_geolocations`

Connects intelligence entities to geographic observations.

```text
entity_geolocations
├── id UUID PK
├── entity_id UUID FK
├── geolocation_id UUID FK
├── relationship_type VARCHAR
├── evidence JSONB
├── confidence NUMERIC(5,2)
└── created_at TIMESTAMPTZ
```

This can support map relationship paths while preserving the distinction between:

```text
Observable Infrastructure Location
        ≠
Confirmed Physical Attacker Location
```

---

# 18. Unified Intelligence Graph Schema

A relational graph model is recommended for the SIH prototype.

## 18.1 `intel_entities`

```text
intel_entities
├── id UUID PK
├── entity_type VARCHAR
├── normalized_value TEXT
├── display_value TEXT
├── first_seen_at TIMESTAMPTZ NULL
├── last_seen_at TIMESTAMPTZ NULL
└── metadata JSONB
```

Examples:

```text
EMAIL
SENDER
URL
DOMAIN
IP
ASN
ATTACHMENT
CAMPAIGN
ORGANIZATION
```

---

## 18.2 `intel_relationships`

```text
intel_relationships
├── id UUID PK
├── source_entity_id UUID FK
├── target_entity_id UUID FK
├── relationship_type VARCHAR
├── confidence NUMERIC(5,2)
├── evidence JSONB
├── first_observed_at TIMESTAMPTZ NULL
├── last_observed_at TIMESTAMPTZ NULL
└── created_at TIMESTAMPTZ
```

Examples:

```text
SENT_FROM
CONTAINS
LINKED_TO
RESOLVES_TO
HOSTED_ON
SHARED_WITH
SIMILAR_TO
RELATED_TO
```

This structure supports the Investigation Graph and explainable relationship edges.

---

# 19. Campaign Intelligence Schema

## 19.1 `campaigns`

```text
campaigns
├── id UUID PK
├── campaign_name VARCHAR NULL
├── campaign_status VARCHAR
├── campaign_confidence NUMERIC(5,2)
├── threat_summary TEXT
├── first_detected_at TIMESTAMPTZ
├── last_activity_at TIMESTAMPTZ
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

---

## 19.2 `campaign_memberships`

This table is intentionally many-to-many.

```text
campaign_memberships
├── id UUID PK
├── campaign_id UUID FK
├── email_id UUID FK
├── membership_confidence NUMERIC(5,2)
├── membership_status VARCHAR
├── evidence_summary JSONB
└── created_at TIMESTAMPTZ
```

An email can therefore belong to or be linked with more than one campaign hypothesis.

This supports the PRD's bridge-entity concept.

---

## 19.3 `campaign_evidence`

```text
campaign_evidence
├── id UUID PK
├── campaign_id UUID FK
├── evidence_type VARCHAR
├── source_entity_id UUID FK NULL
├── target_entity_id UUID FK NULL
├── confidence NUMERIC(5,2)
├── explanation TEXT
└── created_at TIMESTAMPTZ
```

Examples:

```text
SHARED_URL
RELATED_DOMAIN
SHARED_INFRASTRUCTURE
SEMANTIC_SIMILARITY
ATTACHMENT_HASH
TEMPORAL_PATTERN
HEADER_PATTERN
```

---

## 19.4 `campaign_events`

```text
campaign_events
├── id UUID PK
├── campaign_id UUID FK
├── event_type VARCHAR
├── occurred_at TIMESTAMPTZ
├── description TEXT
└── metadata JSONB
```

Supports campaign timelines and progression.

---

# 20. Threat Intelligence Feedback Schema

## 20.1 `threat_indicators`

```text
threat_indicators
├── id UUID PK
├── indicator_type VARCHAR
├── normalized_value TEXT
├── reputation VARCHAR NULL
├── confidence NUMERIC(5,2)
├── status VARCHAR
├── first_seen_at TIMESTAMPTZ NULL
├── last_seen_at TIMESTAMPTZ NULL
└── created_at TIMESTAMPTZ
```

---

## 20.2 `indicator_sightings`

```text
indicator_sightings
├── id UUID PK
├── indicator_id UUID FK
├── email_id UUID FK NULL
├── campaign_id UUID FK NULL
├── evidence_id UUID FK NULL
├── observed_at TIMESTAMPTZ
└── context JSONB
```

This allows confirmed or high-confidence indicators to support future correlation without unnecessarily sharing entire private emails.

---

# 21. Case and Investigation Schema

## 21.1 `cases`

```text
cases
├── id UUID PK
├── organization_id UUID FK NULL
├── case_number VARCHAR UNIQUE
├── title VARCHAR
├── status VARCHAR
├── priority VARCHAR
├── created_by UUID FK
├── opened_at TIMESTAMPTZ
├── closed_at TIMESTAMPTZ NULL
└── created_at TIMESTAMPTZ
```

---

## 21.2 `case_emails`

```text
case_emails
├── case_id UUID FK
├── email_id UUID FK
└── added_at TIMESTAMPTZ
```

---

## 21.3 `case_campaigns`

```text
case_campaigns
├── case_id UUID FK
├── campaign_id UUID FK
└── added_at TIMESTAMPTZ
```

---

## 21.4 `investigation_actions`

```text
investigation_actions
├── id UUID PK
├── case_id UUID FK
├── actor_user_id UUID FK
├── action_type VARCHAR
├── description TEXT
├── action_at TIMESTAMPTZ
└── metadata JSONB
```

---

# 22. Reports Schema

## `reports`

```text
reports
├── id UUID PK
├── report_type VARCHAR
├── email_id UUID FK NULL
├── campaign_id UUID FK NULL
├── case_id UUID FK NULL
├── evidence_id UUID FK NULL
├── evidence_object_id UUID FK NULL
├── report_version VARCHAR
├── generated_by UUID FK
├── generated_at TIMESTAMPTZ
└── summary JSONB
```

The actual PDF or generated report file should be stored in MinIO and referenced through `evidence_objects`.

---

# 23. OAuth Integration Schema

## 23.1 `oauth_connections`

```text
oauth_connections
├── id UUID PK
├── user_id UUID FK
├── provider VARCHAR
├── provider_account_id VARCHAR
├── granted_scopes JSONB
├── token_reference TEXT
├── token_expires_at TIMESTAMPTZ NULL
├── status VARCHAR
├── connected_at TIMESTAMPTZ
├── last_sync_at TIMESTAMPTZ NULL
└── metadata JSONB
```

### Security Rule

The schema should not store provider passwords.

OAuth access and refresh tokens should be protected through an approved encryption or secret-management approach.

For a production architecture, the preferred design is to store encrypted token material outside normal application logs and expose only a secure reference where practical.

---

# 24. Browser Extension Schema

## `extension_events`

```text
extension_events
├── id UUID PK
├── user_id UUID FK NULL
├── email_id UUID FK NULL
├── provider VARCHAR NULL
├── event_type VARCHAR
├── analysis_mode VARCHAR
├── created_at TIMESTAMPTZ
└── metadata JSONB
```

### `analysis_mode`

```text
VISIBLE_DATA_ONLY
AUTHORIZED_PROVIDER_DATA
```

This preserves the distinction between limited browser-visible analysis and deeper OAuth-authorized analysis.

---

# 25. Privacy, Retention and Masking Schema

## 25.1 `retention_policies`

```text
retention_policies
├── id UUID PK
├── organization_id UUID FK NULL
├── data_category VARCHAR
├── retention_days INTEGER NULL
├── deletion_action VARCHAR
├── active BOOLEAN
├── created_at TIMESTAMPTZ
└── updated_at TIMESTAMPTZ
```

Examples of data categories:

```text
NORMAL_ANALYSIS
SUSPICIOUS_INCIDENT
MALICIOUS_INCIDENT
FORENSIC_EVIDENCE
INVESTIGATION_CASE
REPORT
```

---

## 25.2 `retention_assignments`

```text
retention_assignments
├── id UUID PK
├── evidence_id UUID FK NULL
├── email_id UUID FK NULL
├── policy_id UUID FK
├── retain_until TIMESTAMPTZ NULL
├── hold_reason TEXT NULL
└── created_at TIMESTAMPTZ
```

This supports cases where evidence must be retained beyond the standard policy.

---

## 25.3 `data_classifications`

```text
data_classifications
├── id UUID PK
├── resource_type VARCHAR
├── resource_id UUID
├── classification VARCHAR
├── created_at TIMESTAMPTZ
└── metadata JSONB
```

Examples:

```text
NORMAL
SENSITIVE
FORENSIC_EVIDENCE
INVESTIGATION_RESTRICTED
```

---

## 25.4 `masking_rules`

```text
masking_rules
├── id UUID PK
├── organization_id UUID FK NULL
├── data_type VARCHAR
├── role_id UUID FK NULL
├── masking_strategy VARCHAR
└── created_at TIMESTAMPTZ
```

Examples:

```text
EMAIL_ADDRESS
PII
EMAIL_CONTENT
SENSITIVE_METADATA
```

---

# 26. Audit and Authorized Access

## 26.1 `audit_logs`

```text
audit_logs
├── id UUID PK
├── actor_user_id UUID FK NULL
├── organization_id UUID FK NULL
├── action VARCHAR
├── resource_type VARCHAR
├── resource_id UUID NULL
├── occurred_at TIMESTAMPTZ
├── ip_address INET NULL
└── metadata JSONB
```

Actions may include:

```text
VIEW
CREATE
UPDATE
DELETE
EXPORT
DOWNLOAD
REPORT_GENERATE
EVIDENCE_ACCESS
```

This table supports the PRD requirement for authorized access records.

---

# 27. MinIO Bucket Architecture

Recommended buckets:

```text
mailintel-evidence
mailintel-derived
mailintel-reports
mailintel-temp
```

## 27.1 `mailintel-evidence`

For original or qualifying forensic evidence.

```text
mailintel-evidence
└── originals/
    └── emails/
        └── {year}/
            └── {month}/
                └── {evidence_id}.eml
```

Examples:

```text
originals/emails/2026/09/EV-001.eml
originals/attachments/EV-001/ATT-001.pdf
```

Original evidence should be treated as immutable.

---

## 27.2 `mailintel-derived`

For derived analysis artifacts.

Examples:

```text
parsed/
extracted/
normalized/
analysis-artifacts/
```

Example:

```text
parsed/EV-001/headers.json
extracted/EV-001/urls.json
analysis-artifacts/EV-001/forensic-summary.json
```

A derived object should reference its parent evidence through `parent_evidence_id` or metadata.

---

## 27.3 `mailintel-reports`

For generated reports.

```text
mailintel-reports/
└── {case_or_report_id}/
    └── report-v1.pdf
```

The report itself should also have a SHA-256 record if it becomes qualifying evidence.

---

## 27.4 `mailintel-temp`

For temporary processing objects.

Examples:

- Temporary upload staging
- Short-lived processing artifacts

These objects should have lifecycle rules and should not be treated as permanent evidence.

---

# 28. MinIO Object Metadata

Every important object should include or be associated with metadata such as:

```text
evidence_id
sha256
original_filename
content_type
source_type
acquired_at
parent_evidence_id
```

However, PostgreSQL remains the authoritative structured record for evidence metadata and chain-of-custody relationships.

---

# 29. PostgreSQL ↔ MinIO Example

## PostgreSQL Record

```text
evidence_objects
────────────────────────────────────────────
id: EV-001
email_id: EM-001
evidence_type: ORIGINAL_EMAIL
original_filename: suspicious_email.eml
sha256_hash: 9f86d081884c7d659a...
bucket_name: mailintel-evidence
object_key: originals/emails/2026/09/EV-001.eml
size_bytes: 245678
immutable: true
```

## MinIO

```text
Bucket: mailintel-evidence

originals/
└── emails/
    └── 2026/
        └── 09/
            └── EV-001.eml
```

The connection is:

```text
PostgreSQL Evidence Record
          │
          ├── SHA-256 Integrity Hash
          │
          ├── Bucket Name
          │
          └── Object Key
                    │
                    ▼
              MinIO Object
                    │
                    ▼
            Actual .eml File
```

---

# 30. Core Entity Relationship Overview

```text
Organization
    │
    ├── Users
    │
    └── Emails
          │
          ├── Email Source
          ├── Headers
          ├── Recipients
          ├── Authentication Results
          ├── Relay Hops
          ├── Evidence Objects ───────────────► MinIO
          ├── Analysis Runs
          ├── Analysis Findings
          ├── Email DNA
          ├── Embeddings
          ├── URLs ──► Domains ──► IPs
          ├── Intelligence Graph Entities
          └── Campaign Memberships
                    │
                    ▼
                 Campaigns
                    │
                    ├── Campaign Evidence
                    └── Campaign Events

Evidence Objects
    │
    ├── SHA-256
    ├── Custody Events
    ├── Access Logs
    └── Reports
```

---

# 31. Important Indexes

Recommended indexes include:

```text
users(email)
emails(message_id_header)
emails(external_message_id)
emails(analysis_status)
evidence_objects(sha256_hash)
evidence_objects(email_id)
email_headers(email_id)
relay_hops(email_id, sequence_number)
domains(normalized_domain)
urls(normalized_url)
ip_addresses(ip_address)
campaign_memberships(email_id)
campaign_memberships(campaign_id)
intel_relationships(source_entity_id)
intel_relationships(target_entity_id)
custody_events(evidence_id, event_at)
audit_logs(resource_type, resource_id)
```

For vectors, create the appropriate pgvector index according to the selected distance metric and production dataset size.

---

# 32. Final Architecture Rules

## Rule 1 — Original Evidence

```text
Original .eml
→ SHA-256
→ MinIO
→ PostgreSQL Evidence Reference
```

## Rule 2 — Do Not Duplicate Large Objects

Large files should not be repeatedly stored inside PostgreSQL.

Use:

```text
PostgreSQL → Metadata + Hash + Object Reference
MinIO      → Actual Object
```

## Rule 3 — Scores Remain Separate

```text
Threat Risk Score
Evidence Confidence Score
Campaign Correlation Confidence
```

These are different measurements and must not be merged into one field.

## Rule 4 — Semantic Similarity Is One Signal

```text
Vector Similarity
      +
URLs
      +
Domains
      +
Infrastructure
      +
Headers
      +
Temporal Evidence
      ↓
Campaign Correlation
```

A vector score alone must not automatically assign campaign membership.

## Rule 5 — Campaign Membership Can Overlap

```text
Email B
   │
   ├── Campaign A
   │
   └── Campaign B
```

This is required for bridge entities and overlapping evidence clusters.

## Rule 6 — Geolocation Is Infrastructure Intelligence

The database should model:

> Approximate location associated with observable infrastructure.

It must not convert an IP geolocation record into a claim about the attacker's physical identity or exact location.

## Rule 7 — Cyber Cell Access Is Qualified

Normal email traffic must not automatically enter the centralized Cyber Cell investigation view.

Access should be governed by:

- Qualification status
- Role and permission
- Investigation relevance
- Privacy policy
- Evidence requirements

---

# 33. Final Summary

MailIntel uses a hybrid storage architecture:

```text
                    MAILINTEL
                        │
        ┌───────────────┴────────────────┐
        │                                │
        ▼                                ▼
   PostgreSQL                           MinIO
        │                                │
   Structured Data                  Actual Objects
        │                                │
   Users                             .eml Files
   Emails                            Attachments
   Hashes                            Evidence Files
   Scores                            Derived Artifacts
   Intelligence                      Reports
   Campaigns
   Relationships
   Custody Events
   Audit Logs
   Object References
        │                                │
        └───────────────┬────────────────┘
                        ▼
             Evidence-Based Intelligence
```

### The simplest explanation for MailIntel

> **PostgreSQL stores the intelligence, metadata, relationships and SHA-256 hashes. MinIO stores the actual evidence objects. The database references the MinIO object, while the hash allows MailIntel to verify that the evidence has not been altered.**

This design directly supports MailIntel's PRD requirement to transform suspicious emails into connected, evidence-based cyber intelligence while maintaining forensic integrity, privacy controls and explainable campaign correlation.
