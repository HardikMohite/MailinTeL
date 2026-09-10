# MailIntel — AI Agent Project Tracker

> **Purpose:** This is a living project-state file for MailIntel.  
> AI agents must read this file before starting development and update it after meaningful work.

---

## 1. CURRENT PROJECT STATE

**Project:** MailIntel  
**Problem Statement:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

**Current Phase:** Phase 2 — .eml Upload and Evidence Preservation  
**Current Task:** TASK-010 — Preserve Original Evidence (COMPLETED)  
**Overall Status:** IN_PROGRESS  
**Last Updated:** 2026-09-06

### Current Goal

Tasks 1 through 10 fully implemented, tested, and reviewed. Ready to proceed with TASK-011 (Verify Evidence Integrity).

---

# 2. CURRENT TASK

> Only one major task should normally be marked as `IN_PROGRESS`.

## TASK-010 — Preserve Original Evidence

**Status:** COMPLETED  
**Priority:** HIGH

### Objective

Preserve the raw binary `.eml` artifact in MinIO (`mailintel-evidence` bucket) with immutable metadata, create corresponding `EvidenceObject` records in PostgreSQL, and log the formal `ACQUIRED` chain-of-custody event.

### Requirements

- [x] Calculate SHA-256 hash immediately upon ingest
- [x] Store original `.eml` in MinIO (`mailintel-evidence/originals/emails/{year}/{month}/{evidence_id}.eml`)
- [x] Store evidence metadata in PostgreSQL (`evidence_objects` table)
- [x] Link database record to object storage with immutability flag
- [x] Record evidence acquisition custody event in `custody_events` table
- [x] Evidence metadata, download presigning, and custody API endpoints (`/api/v1/evidence/*`)

### Completion Criteria

Evidence objects are permanently preserved, verified against their SHA-256 hash, and traced through chain-of-custody.

### Notes

Tasks 1 through 10 (Phase 0, Phase 1, and Phase 2 inception) are 100% completed with all 70 backend tests passing.

---

# 3. ACTIVE TASKS

Tasks currently being worked on.

| Task ID | Task | Status | Notes |
|---|---|---|---|
| TASK-010 | Preserve Original Evidence | COMPLETED | MinIO object preservation, SHA-256 hashing, custody event logging, evidence endpoints |

---

# 4. UPCOMING TASKS

Complete tasks in logical order. The AI agent may add implementation subtasks when necessary.

## Phase 0 — Foundation

### TASK-001 — Initialize Project Structure

**Status:** COMPLETED

Requirements:

- [x] Backend project structure created
- [x] Frontend project structure created
- [x] Environment configuration created (.env.example, .env)
- [x] `.gitignore` configured
- [x] Basic README available
- [x] Local development setup documented
- [x] Both backend and frontend verified running and communicating

---

### TASK-002 — Configure PostgreSQL
 
**Status:** COMPLETED
 
Requirements:
 
- [x] PostgreSQL connection configured
- [x] Connection tested
- [x] Basic database health check available

---

### TASK-003 — Enable pgvector

**Status:** COMPLETED

Requirements:

- [x] pgvector enabled
- [x] Vector storage tested
- [x] Similarity query tested

---

### TASK-004 — Configure MinIO

**Status:** COMPLETED

Requirements:

- [x] MinIO connection configured
- [x] Evidence bucket created
- [x] Test object upload successful
- [x] Test object retrieval successful

---

### TASK-005 — Configure Redis

**Status:** COMPLETED

Requirements:

- [x] Redis connection configured
- [x] Read/write test successful
- [x] Redis purpose documented

Redis must be used for:

- Caching
- Temporary processing support
- Background job support where required

Redis must **not** be treated as permanent forensic evidence storage.

---

### TASK-006 — Create Core Health Checks

**Status:** COMPLETED

Verify:

- [x] Backend
- [x] PostgreSQL
- [x] pgvector
- [x] MinIO
- [x] Redis

---

## Phase 1 — Database and Processing
 
### TASK-007 — Implement Core Database Schema
 
**Status:** COMPLETED
 
Implement the approved schema from `Schema.md`.
 
Requirements:
- [x] Users and Organizations tables (RBAC-ready)
- [x] Email and forensic tables (`emails`, `email_sources`, `email_headers`, `email_recipients`, `email_authentication_results`, `relay_hops`)
- [x] Evidence and custody tables (`evidence_objects`, `custody_events`)
- [x] Threat intelligence and finding tables (`analysis_runs`, `email_analysis`, `analysis_findings`)
- [x] URL, Domain, and IP intelligence tables (`urls`, `domains`, `ip_addresses`, `ip_intelligence`, `infrastructure_classifications`)
- [x] Geolocation tables (`geolocations`, `entity_geolocations`)
- [x] Email DNA and Vector tables (`email_dna_profiles`, `email_embeddings`, `email_similarity_links`)
- [x] Alembic migration generated and verified
 
Core principles:
 
- PostgreSQL stores structured metadata
- MinIO stores original and large evidence objects
- SHA-256 hashes support evidence integrity verification
- The schema remains RBAC-ready
- Authentication and RBAC enforcement are implemented later

---

### TASK-008 — Implement Background Processing Architecture

**Status:** COMPLETED

Requirements:

- [x] Analysis jobs can be created
- [x] Processing status can be tracked
- [x] Failed jobs are recorded
- [x] Long-running analysis does not unnecessarily block the main API
- [x] Dual-layer persistence (Redis ephemeral cache + in-memory fallback)
- [x] Task polling endpoints (`GET /api/v1/jobs/{job_id}`, `GET /api/v1/jobs`, `POST /api/v1/jobs/{job_id}/cancel`)

---

## Phase 2 — `.eml` Upload and Evidence Preservation

### TASK-009 — Build `.eml` Upload API

**Status:** COMPLETED

Requirements:

- [x] Accept valid `.eml` and `message/rfc822` multipart files
- [x] Reject invalid file extensions and MIME types with HTTP 400
- [x] Validate file size limits (max 25MB)
- [x] Create `Email`, `EmailSource`, and background analysis job record
- [x] Return immediate job receipt containing `job_id`, `email_id`, and status
- [x] Query endpoints (`GET /api/v1/emails/{email_id}`, `GET /api/v1/emails`)

---

### TASK-010 — Preserve Original Evidence

**Status:** COMPLETED

Requirements:

- [x] Calculate SHA-256 hash upon ingestion
- [x] Store original `.eml` in MinIO (`mailintel-evidence` bucket)
- [x] Store evidence metadata in PostgreSQL (`evidence_objects` table)
- [x] Link database record to object storage with immutable flag
- [x] Record evidence acquisition custody event in `custody_events` table
- [x] Dedicated endpoints (`GET /api/v1/evidence/{id}`, `/download`, `/custody`)

**Important:** Original evidence must never be modified.

---

### TASK-011 — Verify Evidence Integrity

**Status:** COMPLETED

Requirements:

- [x] Original file hash recorded
- [x] Stored object can be retrieved
- [x] Retrieved object hash matches original
- [x] Integrity mismatch is detected
- [x] Chain of custody logging for verification events (`VERIFIED`, `VERIFICATION_FAILED`)
- [x] Verification endpoint (`POST /api/v1/evidence/{evidence_id}/verify`)

---

## Phase 3 — Email Forensic Analysis

### TASK-012 — Parse Email Structure

**Status:** COMPLETED

Extract:

- [x] Subject (with RFC 2047 safe decoding)
- [x] Sender (display name + clean email address)
- [x] Recipients (To, Cc, Bcc display names + email addresses into `email_recipients`)
- [x] Date (normalized UTC datetime `sent_at` + raw string)
- [x] Message-ID (sanitized `message_id_header`)
- [x] Return-Path (envelope return address)
- [x] Reply-To (reply address and display name)
- [x] MIME structure (recursive MIME tree, part types, charsets, transfer encodings, attachments)
- [x] Decoded plain text and HTML bodies with safe size truncation
- [x] Extracted ordered RFC822 headers into `email_headers`
- [x] Dedicated endpoints (`GET /api/v1/emails/{id}/structure`, `GET /api/v1/emails/{id}/headers`, `POST /api/v1/emails/{id}/parse`)
- [x] Security protections (null-byte stripping, MIME recursion depth limits, memory bounding, safe charset fallbacks)

---

### TASK-013 — Analyze Email Headers

**Status:** COMPLETED

Analyze:

- [x] Received headers (parsed from RFC822 messages in chronological sequence)
- [x] Routing hops (extracted sequence, source host, IPv4/IPv6, destination host, queue ID, envelope to, TLS parameters, and inter-hop transit delays)
- [x] Hop reliability classification (`HIGH`, `MEDIUM`, `LOW`, `UNVERIFIED`) based on RFC 1918 LAN vs public internet relays
- [x] SPF (extracted from `Authentication-Results` and `Received-SPF` headers)
- [x] DKIM (extracted verdicts, signing domain `d=`, selector `s=`, algorithm `a=`, body hash `bh=`, and signature previews from `DKIM-Signature` headers)
- [x] DMARC (extracted verdicts and alignment policies)
- [x] From-domain alignment calculation (`PASS`, `FAIL`, `NONE`) with strict and relaxed organizational domain matching
- [x] Persistence in PostgreSQL (`relay_hops`, `email_authentication_results` tables)
- [x] Dedicated endpoints (`GET /api/v1/emails/{id}/hops`, `GET /api/v1/emails/{id}/auth`, `POST /api/v1/emails/{id}/analyze-headers`)

---

### TASK-014 — Extract Email Artifacts

**Status:** COMPLETED

Extract and normalize:

- [x] URLs (extracted from HTML `<a>` tags, `<img src>`, plain text bodies, and headers; normalized, SHA-256 hashed, defanged, and tracked by context)
- [x] Domains (extracted from URLs, headers, bodies, deduplicated, normalized, with root organizational domain calculation, suspicious TLD flagging, and punycode detection)
- [x] IP addresses (extracted from headers and bodies, categorized into `PUBLIC`, `PRIVATE_RFC1918`, `LOOPBACK`, `LINK_LOCAL`, `RESERVED`)
- [x] Attachments (extracted binary payloads from MIME parts, filename, content type, size, SHA-256 and MD5 cryptographic hashes, dangerous extension and double-extension detection)
- [x] Evidence preservation for attachments in MinIO (`derived/attachments/{year}/{month}/{id}_{filename}`) and database records (`evidence_objects`, `custody_events`)
- [x] Relational persistence in PostgreSQL (`urls`, `email_urls`, `domains`, `ip_addresses`, `evidence_objects`)
- [x] Dedicated endpoints (`GET /api/v1/emails/{id}/artifacts`, `POST /api/v1/emails/{id}/extract-artifacts`)

---

## Phase 4 — Threat Intelligence and Scoring

### TASK-015 — Domain Intelligence

**Status:** COMPLETED

Analyze:

- [x] DNS (concurrent resolution for A, AAAA, MX, TXT, NS, CNAME records via `AsyncDNSResolver` using `dnspython`)
- [x] MX records (extracted preference, exchange hosts, and mail server reachability indicators)
- [x] RDAP / WHOIS (async ICANN RDAP registry querying via `AsyncRDAPClient` with graceful failure handling)
- [x] Registrar information (registrar name extraction from vcards/handles, nameservers, registration dates, expiration dates, update dates)
- [x] Domain age and Newly Registered Domain (NRD) calculation (`NEWLY_REGISTERED_DOMAIN_30D`, `NEWLY_REGISTERED_DOMAIN_90D`, `EMERGING_DOMAIN_UNDER_1YR`)
- [x] Suspicious domain indicator evaluation (`DYNAMIC_DNS_PROVIDER`, `PUNYCODE_HOMOGLYPH`, `NO_MX_RECORDS`, `NO_DNS_RECORDS_RESOLVED`)
- [x] Database persistence in PostgreSQL (`domains`, `domain_dns_records`, `domain_registration_intel` tables)
- [x] Dedicated REST endpoints (`GET /api/v1/intelligence/domains/{domain_name}`, `GET /api/v1/intelligence/emails/{email_id}/domains`)
- [x] Frontend TypeScript API client types and services (`getDomainIntelligence`, `getEmailDomainIntelligence`)

---

### TASK-016 — Infrastructure Intelligence

**Status:** COMPLETED

Classify infrastructure where evidence and available intelligence permit:

- [x] VPN (commercial VPN provider and datacenter proxy detection via keywords, ASN, and reverse DNS heuristics)
- [x] TOR (Tor exit node identification against known exit relay lists and `.tor`/`tor-exit` PTR patterns)
- [x] Proxy (commercial scraping/proxy networks including BrightData, Luminati, Oxylabs, Smartproxy)
- [x] Open relay & DNSBL indicators
- [x] Cloud-hosted infrastructure (AWS, Microsoft Azure, Google Cloud, Oracle Cloud, Cloudflare, DigitalOcean, Linode, Hetzner, OVH, Vultr)
- [x] Reverse DNS (async PTR resolution via `AsyncReverseDNSResolver` with bounded timeouts)
- [x] ASN & ISP resolution (via `AsyncASNResolver` with RDAP network metadata parsing)
- [x] Residential broadband detection (Comcast, AT&T, Verizon, Charter, Deutsche Telekom, etc.)
- [x] RFC 1918 Private IP / Loopback isolation
- [x] Relational persistence in PostgreSQL (`ip_addresses`, `ip_intelligence`, `infrastructure_classifications` tables)
- [x] Dedicated REST endpoints (`GET /api/v1/intelligence/ips/{ip_address}`, `GET /api/v1/intelligence/emails/{email_id}/infrastructure`)
- [x] Frontend TypeScript API client types and services (`getIPIntelligence`, `getEmailInfrastructureIntelligence`)

---

### TASK-017 — Threat Intelligence Enrichment

**Status:** COMPLETED

Integrate approved intelligence providers through a modular adapter approach:

- [x] Abstract adapter interface (`BaseThreatIntelAdapter` & `ThreatIntelReport` standardized schema)
- [x] VirusTotal v3 Adapter (`VirusTotalAdapter` for IP, domain, URL, file hash analysis via API v3)
- [x] AbuseIPDB v2 Adapter (`AbuseIPDBAdapter` for IP abuse confidence scoring and report counts)
- [x] URLHaus / Abuse.ch Adapter (`URLHausAdapter` for free open malware URLs and payload SHA-256 signatures)
- [x] Internal Reputation & Heuristics Adapter (`InternalReputationAdapter` for offline zero-API-key phishing domain/URL heuristics, suspicious TLD detection, Shannon entropy DGA scoring, and disposable email domain analysis)
- [x] Multi-Provider Threat Consensus Engine (`ThreatIntelEngine` aggregating concurrent provider reports, calculating weighted consensus threat scores, boosted consensus confidence, and deduplicated threat tags)
- [x] Record source/provider attribution and timestamps
- [x] Handle provider failures gracefully with resilient timeouts and fallback detection
- [x] Relational persistence in PostgreSQL (`threat_indicators`, `indicator_sightings` tables)
- [x] Dedicated REST endpoints (`GET /api/v1/intelligence/threat/lookup`, `GET /api/v1/intelligence/emails/{email_id}/threat-intel`, `POST /api/v1/intelligence/emails/{email_id}/enrich`)
- [x] Frontend TypeScript API client types and services (`lookupThreatIndicator`, `getEmailThreatIntelligence`, `enrichEmailThreatIntelligence`)

---

### TASK-018 — Implement Explainable Scoring

**Status:** COMPLETED

Maintain separate concepts:

- [x] **Threat Risk Score** (0.00–100.00) — Multi-signal risk assessment based on authentication failures, spoofing indicators, NRD domain age, DynDNS, Tor/VPN relays, malicious URLs, and dangerous payloads.
- [x] **Evidence Confidence Score** (0.00–100.00) — How strongly the available evidence supports the conclusion (evaluating EML structure integrity, cryptographic verification, routing hops completeness, and threat intelligence provider consensus).
- [x] **Campaign Confidence** — Preserved for campaign clustering and graph correlation (Phase 6).
- [x] **Compromise & Spoofing Likelihood Indicators** (`compromised_account_likelihood`, `spoofed_domain_likelihood`, `anonymized_infrastructure_likelihood`, `malicious_environment_likelihood` with discrete `HIGH`, `MEDIUM`, `LOW`, `UNLIKELY` values).
- [x] **Granular Explainable Findings** (`AnalysisFinding` with `finding_type`, `severity`, `confidence`, `title`, `description`, `evidence`).
- [x] Human-readable forensic summary explanation synthesized for each analyzed email.
- [x] Full-pipeline execution service (`execute_email_analysis_and_scoring`) persisting `AnalysisRun`, `EmailAnalysis`, and `AnalysisFinding` records in PostgreSQL.
- [x] Dedicated REST endpoints (`GET /api/v1/emails/{email_id}/analysis`, `POST /api/v1/emails/{email_id}/analyze`, `GET /api/v1/emails/{email_id}/findings`).
- [x] Frontend TypeScript API client types and services (`getEmailAnalysis`, `triggerEmailAnalysis`, `getEmailFindings`).

---

## Phase 5 — Email DNA and Similarity

### TASK-019 — Build Email DNA

**Status:** COMPLETED

Create a structured multi-layer forensic fingerprint:

- [x] Content fingerprint (`content_fingerprint` with subject hash, lexical tokens, DOM tag sequence pattern, attachment hashes/extensions, urgency markers)
- [x] Technical fingerprint (`technical_fingerprint` with header ordering hash, X-Mailer/User-Agent signatures, Message-ID domain, DKIM selector/domain/algo signatures, MIME topology, auth verdicts)
- [x] Infrastructure fingerprint (`infrastructure_fingerprint` with originating IP, relay IP chain, ASN sequence, country hops, classification flags like TOR/VPN/Cloud, DynDNS, NRD)
- [x] Behavioral fingerprint (`behavioral_fingerprint` with recipient count/domain diversity, URL domain diversity, From-domain alignment, display name brand spoofing mismatch detection)
- [x] Temporal fingerprint (`temporal_fingerprint` with UTC hour of day, day of week, timezone offset, inter-hop transit latency metrics)
- [x] Deterministic SHA-256 composite DNA hash (`overall_dna_hash`) via canonical sorted JSON hashing
- [x] PostgreSQL persistence (`email_dna_profiles` table)
- [x] Dedicated REST endpoints (`GET /api/v1/emails/{email_id}/dna`, `POST /api/v1/emails/{email_id}/dna`)
- [x] Frontend TypeScript API client types and services (`getEmailDNA`, `generateEmailDNA`)


---

### TASK-020 — Implement Semantic Similarity

**Status:** COMPLETED

Requirements:

- [x] Generate dense 384-dimensional normalized vector embeddings (`SemanticEmbeddingEngine` for `EMAIL_CONTENT`, `SUBJECT`, `EMAIL_DNA`, and `THREAT_PATTERN` vector spaces)
- [x] Store vectors using pgvector (`EmailEmbedding` table with L2 normalization and metadata)
- [x] Search for similar emails (`SimilarityService.find_and_link_similar_emails` with multi-channel cosine distance weighting)
- [x] Return and persist similarity evidence (`EmailSimilarityLink` table with granular channel breakdown, weighted score, target details, and strict attribution disclaimer)
- [x] Dedicated REST endpoints (`POST /api/v1/emails/{id}/embeddings`, `GET /api/v1/emails/{id}/embeddings`, `POST /api/v1/emails/{id}/similar`, `GET /api/v1/emails/{id}/similar`)
- [x] Frontend TypeScript API client types and services (`getEmailEmbeddings`, `generateEmailEmbeddings`, `getSimilarEmails`, `computeSimilarEmails`)

**Rule:** Similarity alone must not automatically establish campaign membership.


---

## Phase 6 — Campaign Correlation

### TASK-021 — Implement Correlation Signals

**Status:** COMPLETED

Potential evidence relationships:

- [x] Shared URLs (`SHARED_URL` exact normalized URL and url_hash discovery)
- [x] Shared domains (`SHARED_DOMAIN` organizational root domain correlation, excluding benign public services)
- [x] Shared IPs (`SHARED_IP` public originating and relay hop IP discovery)
- [x] Shared infrastructure (`SHARED_INFRASTRUCTURE` matching ASN, hosting network, and Tor/VPN exit relay usage)
- [x] Shared attachment hashes (`SHARED_ATTACHMENT_HASH` exact cryptographic SHA-256 / MD5 matching)
- [x] Email DNA similarity (`EMAIL_DNA_SIMILARITY` header ordering hash, DKIM selector & domain matching)
- [x] Semantic similarity (`SEMANTIC_SIMILARITY` vector cosine similarity >= 70%)
- [x] Temporal patterns (`TEMPORAL_PATTERN` coordinated dispatch clustering within attack burst windows <= 4 hours)
- [x] Weighted multi-signal synergy scoring and composite confidence calculation (`CorrelationEngine`)
- [x] Dedicated REST endpoints (`POST /api/v1/campaigns/correlate/{email_id}`, `GET /api/v1/campaigns/correlations/{email_id}`)
- [x] Frontend TypeScript API client types and services (`computeEmailCorrelations`, `getEmailCorrelations`)


---

### TASK-022 — Support Overlapping Campaign Relationships

**Status:** COMPLETED

Example:

```text
Email A
   │
   │ Shared infrastructure
   │
Email B (Bridge Entity)
   │
   │ Shared URL
   │
Email C
```

- [x] Multi-campaign membership model allowing an email to be linked to multiple campaigns simultaneously (`CampaignMembership` many-to-many schema)
- [x] Bridge entity detection identifying emails connecting multiple distinct campaign clusters (`is_bridge_entity`, `total_campaigns`)
- [x] Campaign lifecycle management (`Campaign`, `CampaignMembership`, `CampaignEvidence`, `CampaignEvent` with creation, activity tracking, confidence scoring)
- [x] Automated cluster discovery (`auto_cluster_campaigns`) preserving multi-hypothesis bridge entities without forced single-assignment
- [x] Dedicated REST endpoints (`POST /api/v1/campaigns`, `GET /api/v1/campaigns`, `GET /api/v1/campaigns/{id}`, `POST /api/v1/campaigns/{id}/emails/{eid}`, `DELETE /api/v1/campaigns/{id}/emails/{eid}`, `GET /api/v1/campaigns/emails/{eid}/memberships`, `POST /api/v1/campaigns/auto-cluster`)
- [x] Frontend TypeScript API client types and services (`createCampaign`, `listCampaigns`, `getCampaign`, `addEmailToCampaign`, `removeEmailFromCampaign`, `getEmailCampaignMemberships`, `autoClusterCampaigns`)

**Rule:** The system must preserve evidence rather than forcing an unsupported single campaign assignment.


---

### TASK-023 — Build Investigation Graph

**Status:** COMPLETED

Interactive multi-hop investigation graph:

- [x] Email nodes (`EMAIL` with subject, sender, sent timestamp, threat risk score, qualification status)
- [x] URL nodes (`URL` with normalized URL, defanged representation, and URL hash)
- [x] Domain nodes (`DOMAIN` with root domain, registration metadata, NRD and DynDNS risk flags)
- [x] IP nodes (`IP` with public IP address, relay hop sequence, reverse DNS, and reliability classification)
- [x] Infrastructure / ASN nodes (`ASN` with Autonomous System Number and ISP network provider)
- [x] Attachment nodes (`ATTACHMENT` with filename, SHA-256 cryptographic hash, size, and danger status)
- [x] Campaign relationship nodes & edges (`CAMPAIGN` with status, confidence, and `MEMBER_OF_CAMPAIGN` edges)
- [x] Evidence-supported edges (`SENT_BY`, `CONTAINS_URL`, `HOSTED_ON_DOMAIN`, `ROUTED_THROUGH_IP`, `LOCATED_IN_ASN`, `CONTAINS_ATTACHMENT`, `SIMILAR_TO`, `MEMBER_OF_CAMPAIGN` with confidence and evidence payloads)
- [x] Dedicated REST endpoints (`GET /api/v1/graph/email/{id}`, `GET /api/v1/graph/campaign/{id}`, `GET /api/v1/graph/global`)
- [x] Frontend TypeScript API client types and services (`getInvestigationGraphForEmail`, `getInvestigationGraphForCampaign`, `getGlobalInvestigationGraph`)

Every meaningful relationship is fully inspectable with evidence.


---

## Phase 7 — Geo Intelligence

### TASK-024 — Implement Infrastructure Geolocation

**Status:** COMPLETED

Map available infrastructure observations.

Important language rule adhered to:
- Strict Attribution Disclaimer enforced: *"This observable infrastructure is geolocated at the indicated coordinates. Infrastructure geolocation indicates the routing/hosting location of intermediate or originating servers and does NOT prove the physical location of the human threat actor."*
- `AsyncGeoIPResolver` with deterministic RFC 1918 private IP handling and public subnet mapping.
- `GeolocationService` with `geolocate_ip`, `geolocate_email_infrastructure`, `geolocate_campaign_infrastructure`, and `get_global_geo_infrastructure`.
- Full persistence into `geolocations` and `entity_geolocations` database tables.
- REST API endpoints:
  - `GET /api/v1/geo/ip/{ip_address}`
  - `GET /api/v1/geo/email/{email_id}`
  - `GET /api/v1/geo/campaign/{campaign_id}`
  - `GET /api/v1/geo/global`
- Test suite: `backend/tests/test_geo.py` (10/10 tests passing).
- Frontend client methods in `frontend/src/services/api.ts`.

---

### TASK-025 — Build Geo Intelligence Map

**Status:** COMPLETED

Requirements:

- [x] Infrastructure markers
- [x] Evidence-linked relationships
- [x] Source-to-related-observable paths where justified
- [x] Campaign filtering
- [x] Confidence context

Implementation details:
- Created interactive component `frontend/src/components/geo/GeoIntelligenceMap.tsx`.
- Dark cyber-grid SVG world map with equirectangular projection, latitude/longitude guide lines, and continent landmasses.
- Animated pulsing infrastructure markers color-coded by role (Origin Hop, Transit Relay, Destination MX, Campaign Infrastructure).
- Curved bezier animated flight path lines connecting transmission hops chronologically.
- Multi-mode support: Single Email Hop Path, Campaign Footprint clustering, Global Overview, and Live IP Query.
- Integrated node inspection card, accuracy radius display, confidence context percentages, and dynamic country distribution breakdown.
- Rendered in `frontend/src/App.tsx` under the `geo` navigation tab.
- Production build passing cleanly with 0 errors.

---

## Phase 8 — Investigation Workspace and Reports

### TASK-026 — Build Analysis Workspace

**Status:** COMPLETED

The primary investigation journey:

```text
Upload .eml
    ↓
Evidence Preservation
    ↓
Forensic Analysis
    ↓
Threat Intelligence
    ↓
Email DNA
    ↓
Related Evidence
    ↓
Campaign Intelligence
    ↓
Graph Intelligence
    ↓
Geo Intelligence
    ↓
Report
```

Implementation details:
- Created [`frontend/src/components/workspace/AnalysisWorkspace.tsx`](file:///c:/Dev/MailinteL/frontend/src/components/workspace/AnalysisWorkspace.tsx) implementing the complete 10-step unified investigation journey:
  1. Executive Triage (Threat risk score, evidence confidence, compromised account / spoofing / anonymized likelihoods, key findings).
  2. Evidence Preservation (SHA-256 copy, file size, immutable status, RFC 822 format).
  3. Headers & Cryptographic Authentication (SPF/DKIM/DMARC/From-alignment badges, complete raw RFC 822 table).
  4. SMTP Relay Hops (Reconstructed transit timeline with delay metrics and reliability ratings).
  5. MIME & Payload Inspection (Sanitized HTML body, plain text payload, structure).
  6. IOC Threat Intelligence (Aggregated multi-provider reputation, NRD/punycode domains, defanged links, TOR/VPN indicators).
  7. Email DNA Fingerprints (5 structural layers: Content, Technical, Infrastructure, Behavioral, Temporal, and overall DNA hash).
  8. Semantic Similarity (384-dimensional cosine matching against historical lure corpus).
  9. Campaign Graph & Multi-Vector Correlations (Pairwise correlation signals, bridge entity detection, graph node statistics).
  10. Geo Intelligence (Integrated world map with hop flight paths and country distribution).
- Rendered in [`frontend/src/App.tsx`](file:///c:/Dev/MailinteL/frontend/src/App.tsx) under the `analyze` navigation tab with live .eml ingestion.
- Frontend build compiled cleanly with 0 errors.

---

### TASK-027 — Generate Forensic Reports

**Status:** COMPLETED

Reports summarize:

- [x] Evidence & Custody Information (SHA-256 hash, file size, timestamps, immutable status)
- [x] Integrity information (MinIO storage status, verification result, cryptographic hash validation)
- [x] Forensic Findings (SPF/DKIM/DMARC auth results, From domain alignment, raw RFC 822 headers, SMTP relay hop sequence)
- [x] Threat Intelligence (Enriched domains, URLs, IPs, multi-provider consensus verdicts)
- [x] Explainable Scores (Threat Risk Score 0–100, Evidence Confidence Score %, hypotheses likelihoods: compromised account, spoofed domain, anonymized infrastructure, malicious environment)
- [x] Email DNA & Similar Lures (Overall DNA hash, 5 structural fingerprints, semantically similar lure matches)
- [x] Correlations & Campaign Associations (Active campaigns, bridge entity status, pairwise correlation signals)
- [x] Infrastructure Geolocation (IPs, transit hops, country/city distribution, ASN/ISP metadata)
- [x] Limitations & Mandatory Attribution Disclaimer (Strict distinction between routing/hosting servers and physical threat actor identity; heuristic limitations)
- [x] Formats supported: Structured JSON, GitHub Flavored Markdown, and standalone print-ready HTML dossier
- [x] MinIO artifact preservation: Reports saved to `mailintel-reports` bucket with SHA-256 hash and PostgreSQL `Report` & `EvidenceObject` records
- [x] Dedicated REST endpoints (`POST /api/v1/reports/email/{id}`, `GET /api/v1/reports/email/{id}`, `GET /api/v1/reports/email/{id}/export`, `POST /api/v1/reports/campaign/{id}`, `GET /api/v1/reports/campaign/{id}`, `GET /api/v1/reports`, `GET /api/v1/reports/{id}`)
- [x] Frontend `ForensicReportView` with interactive executive dossier, printable HTML iframe preview, markdown editor, JSON schema inspector, and historical reports archive
- [x] Integrated into `AnalysisWorkspace.tsx` Step 11 ("11. Forensic Report") and `App.tsx` reports tab
- [x] Backend automated test suite passing (7/7 in `test_reports.py`, 199/199 across all 14 test suites)
- [x] Frontend production bundle verified (`npm run build`, 0 errors)

---

# 5. POST-MVP / FUTURE TASKS

These tasks are intentionally deferred until the core forensic intelligence pipeline is stable.

## TASK-028 — Authentication

**Status:** DEFERRED

---

## TASK-029 — RBAC Enforcement

**Status:** DEFERRED

The data model should remain ready for future RBAC, but permission enforcement is implemented after authentication.

---

## TASK-030 — OAuth Mailbox Integrations

**Status:** DEFERRED

Potential providers include:

- Gmail
- Microsoft / Outlook

OAuth-based ingestion must use authorized access and feed data into the existing analysis pipeline.

---

## TASK-031 — Browser Extension

**Status:** DEFERRED

Planned modes:

### Without OAuth

Analyze only data legitimately available through the supported browser context.

### With OAuth

Use authorized provider access where available to support deeper analysis.

The extension must reuse the proven backend analysis pipeline rather than duplicating core forensic logic.

---

# 6. COMPLETED WORK

> Move tasks here only after implementation and meaningful testing.

### TASK-001 — Initialize Project Structure

**Completed Date:** 2026-09-05  
**Result:** VERIFIED COMPLETED  
**Details:**
- Initialized FastAPI backend with Python 3.13, Pydantic settings loading from `.env`, CORS middleware, structured logging, and health check endpoints (`/api/v1/health`, `/api/v1/health/detailed`).
- Initialized React + TypeScript + Vite frontend with Tailwind CSS configured to the approved single forensic theme (`#101C33` navy sidebar, `#F5F7FB` workspace, `#2563B8` intelligence blue, Inter typography).
- Created root configurations: `.gitignore`, `.env.example`, `.env`, `docker-compose.yml`, and comprehensive `README.md`.
- Automated backend unit testing passed (`pytest backend/tests -v`, 3 passed).
- Frontend production bundle build verified (`npm run build`, 0 errors).
- Live integration verified with backend running on port 8000 and frontend on port 5173 via browser subagent.

---

### TASK-002 — Configure PostgreSQL

**Completed Date:** 2026-09-06  
**Result:** VERIFIED COMPLETED  
**Details:**
- Configured async SQLAlchemy engine (`create_async_engine`) and async session maker (`async_sessionmaker`) with connection pooling in `backend/app/db/session.py`.
- Created declarative ORM Base model in `backend/app/db/base.py`.
- Implemented `get_db()` async session dependency generator with automatic commit/rollback lifecycle.
- Implemented `check_db_connectivity()` with latency calculation and resilient non-blocking timeout handling.
- Enhanced health endpoints: `/api/v1/health` reports system degradation gracefully, `/api/v1/health/detailed` includes live DB status, and `/api/v1/health/db` provides a dedicated probe endpoint.
- Updated frontend API client and header UI to display live PostgreSQL connection status and latency.
- Comprehensive automated test coverage passed (11 unit/integration tests passed in `backend/tests`).
- Frontend production build verified (`npm run build`, 0 errors).

---

### TASK-003 — Enable pgvector

**Completed Date:** 2026-09-06  
**Result:** VERIFIED COMPLETED  
**Details:**
- Created `EmailEmbedding` ORM model in `backend/app/models/embeddings.py` supporting `Vector(384)` embeddings with metadata and UUID primary keys.
- Implemented pgvector extension activation helper `ensure_db_extensions` in `backend/app/db/vector.py`.
- Implemented `check_pgvector_availability` and cosine similarity search helper `search_similar_embeddings` utilizing SQLAlchemy pgvector `<=>` cosine distance expressions.
- Enhanced health telemetry endpoints to report pgvector extension presence and version.
- Added comprehensive unit tests for vector math, ORM mappings, extension initialization, and similarity querying.
- Backend automated testing passed (`pytest backend/tests -v`, 20 passed).
- Frontend production bundle build verified (`npm run build`, 0 errors).

---

### TASK-004 — Configure MinIO

**Completed Date:** 2026-09-06  
**Result:** VERIFIED COMPLETED  
**Details:**
- Configured official MinIO S3 client and `StorageManager` in `backend/app/core/storage.py`.
- Implemented automatic bucket provisioning for required buckets (`mailintel-evidence`, `mailintel-derived`, `mailintel-reports`, `mailintel-temp`).
- Implemented SHA-256 evidence hashing during object upload (`upload_evidence_object`).
- Implemented evidence object retrieval and tamper-evident SHA-256 integrity verification (`verify_evidence_integrity`).
- Implemented time-limited presigned URL generation for investigator evidence downloads.
- Added `/api/v1/health/storage` dedicated health probe and updated `/api/v1/health/detailed` and `/api/v1/health` with storage state.
- Updated frontend header telemetry strip and dashboard evidence vault indicators.
- Comprehensive automated test coverage passed (29 unit/integration tests passed in `backend/tests`).
- Frontend production bundle build verified (`npm run build`, 0 errors).

---

### TASK-005 — Configure Redis

**Completed Date:** 2026-09-06  
**Result:** VERIFIED COMPLETED  
**Details:**
- Configured async `redis.asyncio` client and `RedisManager` in `backend/app/core/redis.py`.
- Implemented JSON serialization and deserialization cache helpers (`set_json`, `get_json`) with TTL expiration support.
- Implemented cache lifecycle operations (`delete`, `exists`, `close`).
- Documented architectural purpose (DEC-005): Caching, pub/sub coordination, and rate-limiting support — explicitly not permanent evidence storage.
- Added `/api/v1/health/redis` probe endpoint and integrated Redis health into `/api/v1/health` and `/api/v1/health/detailed`.
- Updated frontend header telemetry strip with Redis latency status.
- Added comprehensive unit tests for cache operations, connection errors, and lifecycle management.
- Backend automated testing passed (`pytest backend/tests -v`, 38 passed).
- Frontend production bundle build verified (`npm run build`, 0 errors).

---

### TASK-006 — Create Core Health Checks

**Completed Date:** 2026-09-06  
**Result:** VERIFIED COMPLETED  
**Details:**
- Implemented unified readiness probe `GET /api/v1/health/ready` aggregating PostgreSQL, pgvector, MinIO, and Redis.
- Implemented individual component diagnostic routes: `/health`, `/health/detailed`, `/health/db`, `/health/storage`, `/health/redis`.
- Built resilient degradation handling: services report `degraded` without crashing the FastAPI process.
- Updated frontend API client and header telemetry pill with real-time multi-service status indicators.
- Added automated unit and integration tests covering readiness success and failure degradation.
- Backend automated testing passed (`pytest backend/tests -v`, 40 passed).
- Frontend production bundle build verified (`npm run build`, 0 errors).
- **Phase 0 (Project Foundation) officially exited and completed.**

---

# 7. CURRENT BLOCKERS

> Record problems that genuinely prevent progress.

_No current blockers._

---

# 8. KNOWN ISSUES

> Record known bugs, limitations or technical debt that do not completely block development.

_No known issues yet._

---

# 9. TESTING RECORD

Record meaningful tests here.

## Test Template

### TEST-001 — Project Structure & Health Verification

**Related Task:** TASK-001  
**Date:** 2026-09-05  
**Result:** PASS

**Expected:**
- Backend API responds with 200 OK on `/` and `/api/v1/health` with `healthy` status.
- Frontend builds cleanly without TypeScript or CSS errors.
- Frontend launches on port 5173, connects to backend, renders dark navy sidebar with demo context, and navigates between tabs smoothly.

**Actual:**
- `backend/tests/test_health.py` passed (3 tests passed).
- `GET /api/v1/health` returned `{"status":"healthy","app_name":"MailIntel","environment":"development","version":"1.0.0"}`.
- `GET /api/v1/health/detailed` returned system runtime and demo context (`MailIntel Demo User`, `Development Admin`).
- `npm run build` in `frontend` succeeded in 25.2s.
- `browser_subagent` navigated to `http://localhost:5173/`, verified UI rendering, verified backend health status "Connected (v1.0)", and verified navigation to `.eml` upload workspace.

**Notes:**
- Video recording: `mailintel_init_ui_1788631572011.webp`
- Screenshots: `dashboard_initial_1788631683189.png`, `analyze_email_page_1788631701683.png`

---

### TEST-002 — PostgreSQL Configuration & Health Verification

**Related Task:** TASK-002  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- SQLAlchemy async engine and session factory initialize correctly.
- `get_db()` yields and closes sessions cleanly.
- `check_db_connectivity()` reports accurate latency and error states.
- `/api/v1/health`, `/api/v1/health/detailed`, and `/api/v1/health/db` report database connectivity dynamically.
- Backend and frontend builds pass cleanly.

**Actual:**
- `pytest backend/tests -v` passed all 11 tests in 1.05s (5 db tests + 6 health endpoint tests).
- Frontend `npm run build` transformed 1648 modules with 0 errors in 11.3s.

---

### TEST-003 — pgvector Support & Vector Similarity Verification

**Related Task:** TASK-003  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `EmailEmbedding` model initializes with `Vector(384)` column.
- In-memory and SQL cosine distance calculations compute valid similarity scores (0.0 to 1.0).
- `ensure_db_extensions` registers required extensions.
- `check_pgvector_availability` reports extension status without error.
- Health endpoints reflect `pgvector` availability.
- All backend tests and frontend build pass without errors.

**Actual:**
- `pytest backend/tests -v` passed all 20 tests in 9.36s (9 vector tests + 5 db tests + 6 health tests).
- Frontend `npm run build` passed with 0 errors in 4.28s.

---

### TEST-004 — MinIO Object Storage & Evidence Integrity Verification

**Related Task:** TASK-004  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- MinIO client initializes with configured endpoint and credentials.
- `ensure_buckets_exist` provisions required evidence, derived, reports, and temp buckets.
- `upload_evidence_object` stores objects and calculates correct SHA-256 hash.
- `verify_evidence_integrity` validates matching and detects mismatching hashes.
- `generate_presigned_download_url` produces time-limited download links.
- `/api/v1/health/storage` and `/api/v1/health/detailed` report live storage status.
- All backend tests and frontend build succeed.

**Actual:**
- `pytest backend/tests -v` passed all 29 tests in 9.44s (7 storage tests + 9 vector tests + 5 db tests + 8 health tests).
- Frontend `npm run build` succeeded in 4.00s with 0 errors.

---

### TEST-005 — Redis Async Cache & Telemetry Verification

**Related Task:** TASK-005  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- RedisManager initializes async client using `settings.REDIS_URL`.
- `check_connectivity` reports latency and connection errors gracefully.
- `set_json`, `get_json`, `setex`, `delete`, and `exists` execute as expected.
- `/api/v1/health/redis` returns connectivity details.
- Header telemetry strip displays Redis status.
- All 38 backend tests and frontend build pass without errors.

**Actual:**
- `pytest backend/tests -v` passed all 38 tests in 9.99s (7 redis tests + 7 storage tests + 9 vector tests + 5 db tests + 10 health tests).
- Frontend `npm run build` succeeded in 4.18s with 0 errors.

---

### TEST-006 — Unified Health Checks & Readiness Verification

**Related Task:** TASK-006  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `/api/v1/health/ready` validates end-to-end readiness across PostgreSQL, pgvector, MinIO, and Redis.
- Returns HTTP 200 when all services are healthy and HTTP 503 when any service is disconnected.
- All 40 unit and integration tests in backend suite pass.
- Frontend build succeeds.

**Actual:**
- `pytest backend/tests -v` passed all 40 tests in 17.83s.
- Frontend `npm run build` passed in 4.30s with 0 errors.
---

### TEST-007 — Core Database Schema & Model Verification

**Related Task:** TASK-007  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- All 28+ relational and vector models declared according to `Schema.md`.
- SQLAlchemy `Base.metadata` contains all expected tables, indexes, and foreign keys.
- Models instantiate cleanly with UUID primary keys and JSON metadata payloads.
- Alembic configured with async engine and initial migration script created.
- All 47 backend tests pass without error.

**Actual:**
- `pytest backend/tests -v` passed all 47 tests (7 model tests + 40 baseline tests) in 18.29s.
- `0001_initial_mailintel_schema.py` migration script generated and verified in `backend/alembic/versions/`.

---

### TEST-008 — Background Processing Architecture & Job Polling Verification

**Related Task:** TASK-008  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `BackgroundJobManager` creates, updates, and completes background jobs with stage tracking and percentage progress.
- Non-blocking async execution via `dispatch_background_task` with automatic error capture and failure status assignment.
- Support job cancellation and status listing.
- REST API endpoints (`GET /api/v1/jobs/{job_id}`, `GET /api/v1/jobs`, `POST /api/v1/jobs/{job_id}/cancel`) return valid serialized schemas.
- Frontend API client provides type-safe job polling interfaces.
- All backend tests and frontend build pass with 0 errors.

**Actual:**
- `pytest backend/tests -v` passed all 59 tests (12 job tests + 7 model tests + 40 baseline tests) in 18.64s.
- `npm run build` in `frontend/` succeeded with 0 TypeScript/CSS errors in 4.28s.
- **Phase 1 (Database and Processing) is 100% completed.**

---

### TEST-009 — .eml Upload API & Forensic Ingestion Verification

**Related Task:** TASK-009  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `POST /api/v1/emails/upload` accepts RFC822 `.eml` multipart uploads and calculates SHA-256 hash.
- Invalid extensions and empty files rejected with HTTP 400; oversized files (>25MB) rejected with HTTP 413.
- Database records (`EmailSource`, `Email`, `EvidenceObject`, `CustodyEvent`) persisted with correct UUID linkages.
- Immediate analysis job queued and dispatched with tracking receipt returned.
- `GET /api/v1/emails/{email_id}` and `GET /api/v1/emails` return normalized metadata.
- All backend tests and frontend build succeed with 0 errors.

**Actual:**
- `pytest backend/tests -v` passed all 66 tests (7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.59s.
- `npm run build` in `frontend/` transformed 1648 modules with 0 errors in 4.29s.

---

### TEST-010 — Evidence Preservation, MinIO Storage & Chain of Custody Verification

**Related Task:** TASK-010  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- Original binary `.eml` files stored in MinIO `mailintel-evidence` bucket with year/month partitioning.
- Evidence metadata with SHA-256 hash and immutable flag recorded in PostgreSQL `evidence_objects`.
- Chain of custody events (`ACQUIRED`, `VIEWED`) logged in `custody_events`.
- Dedicated endpoints (`GET /api/v1/evidence/{id}`, `/download`, `/custody`) return structured models.
- All backend tests and frontend build pass without errors.

**Actual:**
- `pytest backend/tests -v` passed all 70 tests (4 evidence tests + 7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.68s.
- `npm run build` in `frontend/` succeeded with 0 TypeScript/CSS errors in 4.20s.

---

### TEST-011 — Evidence Integrity Verification & Tamper Detection

**Related Task:** TASK-011  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `POST /api/v1/evidence/{evidence_id}/verify` fetches stored binary evidence from MinIO and recalculates SHA-256 hash.
- Compares computed hash against authoritative PostgreSQL `sha256_hash`.
- Returns `status: "VERIFIED"` when hashes match and records `VERIFIED` custody event with client IP/user agent.
- Returns `status: "TAMPERED"` and `is_valid: False` when byte hashes mismatch, recording `VERIFICATION_FAILED` custody event.
- Returns HTTP 404 when evidence record or underlying MinIO object is missing.
- All 73 backend tests and frontend build pass with 0 errors.

**Actual:**
- `pytest backend/tests -v` passed all 73 tests (7 evidence tests + 7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.88s.
- `npm run build` in `frontend/` transformed 1648 modules in 4.25s with 0 errors.
- **Phase 2 (.eml Upload and Evidence Preservation: TASK-009 to TASK-011) is 100% completed.**

---

### TEST-012 — Email Structure Parsing & Forensic Decomposition Verification

**Related Task:** TASK-012  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `EmailStructureParser` extracts subject, sender (name and email), recipients (`TO`, `CC`, `BCC`), UTC timestamp, Message-ID, Return-Path, Reply-To, and full MIME tree with attachments.
- Security controls: Null-byte sanitization (`\x00` stripping) protects against PostgreSQL string termination vulnerabilities; recursion depth limits (`MAX_MIME_RECURSION_DEPTH = 32`) protect against MIME bomb / stack overflow attacks; header count capping (`MAX_HEADER_COUNT = 500`) mitigates header flood DoS; text extraction bounded (`MAX_BODY_TEXT_LENGTH = 1MB`).
- `parse_and_persist_email` updates `Email` record and persists `EmailHeader` and `EmailRecipient` tables.
- Endpoints `GET /api/v1/emails/{id}/structure`, `GET /api/v1/emails/{id}/headers`, and `POST /api/v1/emails/{id}/parse` operate cleanly.
- All 84 backend tests and frontend production build pass with 0 errors.

**Actual:**
- `pytest backend/tests -v` passed all 84 tests (11 parser tests + 7 evidence tests + 7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.63s.
- `npm run build` in `frontend/` succeeded with 0 TypeScript/CSS errors in 4.17s.

---

### TEST-013 — Email Header Analysis, Relay Hop Reconstruction & Protocol Authentication Verification

**Related Task:** TASK-013  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `ReceivedHeaderParser` extracts chronological transmission sequence (Hop 1 = origin $\rightarrow$ final delivery hop), source host, IPv4/IPv6, destination host, queue ID, envelope to, TLS cipher, and inter-hop transit delays.
- Hop reliability classified correctly distinguishing LAN (RFC 1918) and external public relays.
- `AuthenticationResultsParser` extracts SPF, DKIM, and DMARC verdicts from `Authentication-Results` (RFC 8601) and `Received-SPF`.
- `DKIM-Signature` tag parser extracts signing domain `d=`, selector `s=`, algorithm `a=`, body hash `bh=`, and signature preview `b=`.
- Evaluates From-domain alignment (strict and relaxed organizational domain matching against SPF and DKIM domains), flagging spoofed header mismatches.
- `analyze_and_persist_headers` persists records into `relay_hops` and `email_authentication_results` PostgreSQL tables.
- REST endpoints `GET /api/v1/emails/{id}/hops`, `GET /api/v1/emails/{id}/auth`, and `POST /api/v1/emails/{id}/analyze-headers` operate cleanly.
- All 92 backend tests and frontend build pass without errors.

**Actual:**
- `pytest backend/tests -v` passed all 92 tests (8 header analysis tests + 11 parser tests + 7 evidence tests + 7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.87s.
- `npm run build` in `frontend/` transformed 1648 modules with 0 errors in 3.91s.

---

### TEST-014 — Forensic Artifact Extraction, Normalization & Evidence Linking Verification

**Related Task:** TASK-014  
**Date:** 2026-09-06  
**Result:** PASS

**Expected:**
- `EmailArtifactExtractor` extracts URLs from HTML `<a>`, `<img>`, plain text, and headers; normalizes URLs, refangs defanged formats, and computes SHA-256 hashes.
- Extracted domains deduplicated and analyzed for root domains, suspicious TLDs, and IDN/punycode flags.
- Extracted IPs categorized into public vs private RFC 1918, loopback, and link-local.
- Binary attachments extracted with SHA-256 and MD5 hashes, dangerous extension flagging (`.exe`, `.scr`, double extensions), and stored in MinIO `mailintel-derived` bucket with `evidence_objects` linkage.
- Relational persistence in PostgreSQL across `urls`, `email_urls`, `domains`, `ip_addresses`, `evidence_objects`, and `custody_events`.
- REST endpoints `GET /api/v1/emails/{id}/artifacts` and `POST /api/v1/emails/{id}/extract-artifacts` operate cleanly.
- All 100 backend tests and frontend production build pass with 0 errors.

**Actual:**
- `pytest backend/tests -v` passed all 100 tests (8 artifact tests + 8 header analysis tests + 11 parser tests + 7 evidence tests + 7 upload tests + 12 job tests + 7 model tests + 40 baseline tests) in 18.83s.
- `npm run build` in `frontend/` succeeded with 0 TypeScript/CSS errors in 4.43s.
- **Phase 3 (Email Forensic Analysis: TASK-012 to TASK-014) is 100% completed.**

---

---

# 10. PROJECT DECISIONS

These decisions should not be changed without a documented reason.

## DEC-001 — `.eml` First

The first ingestion method is `.eml` upload.

**Reason:** It allows the core forensic pipeline to be developed and demonstrated without OAuth approval or mailbox integration dependencies.

**Status:** ACCEPTED

---

## DEC-002 — PostgreSQL for Structured Data

PostgreSQL stores:

- Metadata
- Relationships
- Findings
- Analysis records
- Intelligence references
- Hashes and integrity metadata
- Vector-related records where defined by the schema

**Status:** ACCEPTED

---

## DEC-003 — MinIO for Evidence Objects

MinIO stores:

- Original `.eml` files
- Large evidence objects
- Other approved binary artifacts

**Status:** ACCEPTED

---

## DEC-004 — SHA-256 for Evidence Integrity

Evidence integrity is verified through reproducible hashing.

**Status:** ACCEPTED

---

## DEC-005 — Redis Is Supporting Infrastructure

Redis supports:

- Caching
- Temporary data
- Background processing support

Redis is not permanent forensic evidence storage.

**Status:** ACCEPTED

---

## DEC-006 — Separate Scoring Concepts

MailIntel must not merge all intelligence into one unexplained score.

Maintain separate concepts where applicable:

- Threat Risk
- Evidence Confidence
- Campaign Confidence

**Status:** ACCEPTED

---

## DEC-007 — Similarity Is Not Campaign Membership

Semantic similarity and Email DNA similarity are correlation signals.

They are not, by themselves, proof that two emails belong to the same malicious campaign.

**Status:** ACCEPTED

---

## DEC-008 — Support Overlapping Relationships

An email can share different evidence with different groups of emails.

The system should preserve these relationships rather than forcing a simplistic one-campaign-only model.

**Status:** ACCEPTED

---

## DEC-009 — Authentication After Core MVP

Core forensic and intelligence functionality is developed first.

Authentication follows after the core pipeline is stable.

**Status:** ACCEPTED

---

## DEC-010 — RBAC-Ready From the Beginning

The architecture and schema should support future user, organization and permission relationships without requiring immediate RBAC implementation.

**Status:** ACCEPTED

---

## DEC-011 — OAuth After Core Pipeline

OAuth integration should not block development of the core product.

The same core analysis pipeline should later process authorized mailbox data.

**Status:** ACCEPTED

---

## DEC-012 — Browser Extension After Core Pipeline

The browser extension is built after the core backend pipeline is proven.

**Status:** ACCEPTED

---

# 11. NEXT ACTION

> This section must always contain the single most important next action.

## CURRENT NEXT ACTION
 
```text
TASK-006 — Create Core Health Checks
```
 
### Immediate Checklist
 
- [ ] Verify comprehensive health check endpoints (`/api/v1/health`, `/api/v1/health/detailed`, `/api/v1/health/db`, `/api/v1/health/storage`, `/api/v1/health/redis`)
- [ ] Run full automated test suite covering all services (PostgreSQL, pgvector, MinIO, Redis)
- [ ] Update frontend dashboard and header live status indicators
- [ ] Complete Phase 0 exit criteria and prepare Phase 1 (Core Database Schema)


---

# 12. AI AGENT OPERATING RULES

Every AI coding agent working on MailIntel should follow this process.

## Before Starting Work

1. Read `Tracker.md`
2. Check `CURRENT PROJECT STATE`
3. Read the `CURRENT TASK`
4. Review relevant project documentation
5. Inspect the existing codebase
6. Confirm that the task is not already completed
7. Check blockers and known issues

---

## During Development

The AI agent should:

- Focus primarily on the current task
- Avoid unrelated refactoring
- Preserve existing working functionality
- Follow the approved architecture
- Add implementation notes when a significant decision is made
- Record blockers instead of silently abandoning work

---

## After Development

The AI agent must:

1. Test the implemented work
2. Record the result
3. Update the task status
4. Add completed details to `COMPLETED WORK`
5. Record any known limitations
6. Add blockers if necessary
7. Update `CURRENT TASK`
8. Update `NEXT ACTION`

### Task Status Rule

Use:

```text
PENDING
    ↓
IN_PROGRESS
    ↓
TESTING
    ↓
COMPLETED
```

Or:

```text
PENDING
    ↓
BLOCKED
```

A task must not be marked `COMPLETED` merely because code was written.

---

# 13. AGENT UPDATE TEMPLATE

After meaningful work, the agent should update the tracker in a format similar to:

```markdown
## TASK-XXX — Task Name

**Status:** COMPLETED

### Implemented

- Feature A
- Feature B
- Feature C

### Testing

- Test A: PASS
- Test B: PASS

### Limitations

- Limitation if any

### Files Changed

- `example/file.py`
- `example/file.ts`

### Next Task

TASK-XXX — Next Task Name
```

---

# 14. QUICK PROJECT SNAPSHOT

```text
PROJECT: MailIntel

CURRENT PHASE:
Phase 0 — Project Foundation

CURRENT TASK:
TASK-001 — Initialize Project Structure

CORE MVP:
NOT STARTED

POST-MVP FEATURES:
Authentication → Deferred
RBAC → Deferred
OAuth → Deferred
Browser Extension → Deferred

CURRENT BLOCKERS:
None

NEXT ACTION:
Initialize project structure
```

---

# FINAL RULE

> **Tracker.md represents the actual current state of the project, not the planned state.**

Planned work belongs in the task queue.

Implemented and tested work belongs in `COMPLETED WORK`.

Problems belong in `CURRENT BLOCKERS` or `KNOWN ISSUES`.

After every meaningful development session, the AI agent should update this file so the next AI agent or developer can immediately understand exactly where MailIntel stands.


---

## RBAC v2: cross-org investigator/admin roles

**Status:** COMPLETED

Phases 1–6 completed in this implementation pass, plus a follow-up cleanup
pass (patches 3.5, 4.5, 5.5, 5.6a–e, 6.5) closing gaps found in review:

- Backend authorization core and org-less SYSTEM_ADMIN identity support.
- Platform organization and user management with role-assignment restrictions.
- Cross-org list/detail scoping across the main investigation resources,
  including the `geo.py` `/global` overview endpoint (missed in the initial
  pass, fixed in the cleanup pass).
- Audit logging for sensitive cross-org reads and administration, wired into
  all four `platform_admin.py` mutations, on its own fail-safe DB session so
  an audit-write failure can never block or fail the primary request.
- Full platform-administration frontend (organization creation, cross-org
  user listing/invite/role-change/deactivate, audit log viewer with
  actor/org/action/date-range filters), gated to `SYSTEM_ADMIN` only, added
  in the cleanup pass — this did not exist in the initial implementation
  pass despite the API client already being wired up.
- Full verification and documentation close-out, including a correction to
  a now-stale finding in `SECURITY_REVIEW.md`'s original IDOR table.

**Files touched (cumulative, initial pass + cleanup pass):**

Backend:
- `backend/app/api/deps.py`
- `backend/app/api/v1/endpoints/users.py`
- `backend/app/api/v1/endpoints/platform_admin.py`
- `backend/app/api/v1/endpoints/campaigns.py`
- `backend/app/api/v1/endpoints/emails.py`
- `backend/app/api/v1/endpoints/evidence.py`
- `backend/app/api/v1/endpoints/reports.py`
- `backend/app/api/v1/endpoints/jobs.py`
- `backend/app/api/v1/endpoints/graph.py`
- `backend/app/api/v1/endpoints/similarity.py`
- `backend/app/api/v1/endpoints/geo.py`
- `backend/app/services/geo_service.py`
- `backend/app/core/audit.py`
- `backend/app/models/identity.py`
- `backend/app/models/audit.py`
- `backend/alembic/` — `0004_platform_admin_flag` migration
- `backend/tests/test_rbac_scoping.py`
- `backend/tests/test_users.py`
- `backend/tests/test_platform_admin.py` (new)

Frontend:
- `frontend/src/context/AuthContext.tsx`
- `frontend/src/constants/rbac.ts`
- `frontend/src/services/api.ts`
- `frontend/src/components/settings/TeamView.tsx`
- `frontend/src/components/settings/TeamView.test.tsx` (new)
- `frontend/src/components/layout/OrganizationSwitcher.tsx`
- `frontend/src/components/layout/Sidebar.tsx`
- `frontend/src/components/layout/Sidebar.test.tsx` (new)
- `frontend/src/pages/PlatformAdminView.tsx` (new)
- `frontend/src/pages/PlatformAdminView.test.tsx` (new)
- `frontend/src/App.tsx`

Docs:
- `docs/RBAC_MATRIX.md`
- `SECURITY_REVIEW.md` — added an "Update — RBAC v2" section

**Verification (re-run in full, this session):** `286 passed` backend
tests (`pytest tests/`, no failures/errors — includes 6 new tests added
this session to `test_rbac_scoping.py`, see below); `10 passed` frontend
tests across 3 files (`npm run test -- --run`:
`PlatformAdminView.test.tsx`, `Sidebar.test.tsx`, `TeamView.test.tsx`);
frontend production build (`npm run build`) succeeded cleanly
(`tsc && vite build`, one benign chunk-size-over-500kB advisory, unrelated
to this work).

**Residual test gaps closed this session:** added 6 tests to
`test_rbac_scoping.py` directly exercising
`get_authorized_email`/`get_authorized_campaign`/`get_authorized_report`
(rather than only indirectly via the `geo.py` tests): an org-less
`SYSTEM_ADMIN` can reach a resource in any organization (3 tests, one per
helper), and `SECURITY_ANALYST`/`INSTITUTION_ADMIN` are still denied `404`
when the resource belongs to a different organization than their own
(3 tests, one per helper). `SECURITY_REVIEW.md`'s RBAC v2 update section
has been corrected to reflect this — no known gaps remain in this area as
of this session.
