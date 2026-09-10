# Prompt: Per-Screen Data Showcase & Design Pass

Paste this into your AI coding agent (Claude Code or similar), one phase at a
time. Do not run all phases in one shot — review each screen before moving on.

---

## Phase Tracker

| Phase | Screen | Status |
|---|---|---|
| 1 | Analysis History | ✅ Complete |
| 2 | Threat Intel | ✅ Complete |
| 3 | Campaigns | ✅ Complete |
| 4 | Investigation Graph | ✅ Complete |
| 5 | Geo Intelligence | ✅ Complete |
| 6 | Evidence Vault | ✅ Complete |
| 7 | Reports | ✅ Complete |
| 8 | Analyze Email workspace | ✅ Complete |
| 9 | Settings (verify only) | ✅ Complete |

Update this table's Status column as each phase is finished/verified.
"Not verified" means the component wasn't checked against §38 in this
pass — it may already be done, just unconfirmed here.

Note (Phase 6/7 pass): EmailDetailResponse from `GET /emails` and
`GET /emails/{id}` was missing `evidence_id`, so EvidenceVaultView's
verify/custody actions had no evidence object to target. Fixed by
adding `evidence_id` to the backend response model and both
construction sites (`backend/app/api/v1/endpoints/emails.py`) and to
the frontend `EmailDetailResponse` type (`frontend/src/services/api.ts`).

Note (Phase 8 pass): Rebuilt `components/workspace/AnalysisWorkspace.tsx`
around §13–§17 and §38. Replaced the gradient/glow "11-step journey"
stepper and the `PHASE 8 CORE MVP` badge (banned per §37/§2.2) and every
hardcoded fallback value (fake SHA-256, fake risk/confidence numbers,
fake SPF/DKIM defaults, fake executive summary) with real-data-only
rendering and proper empty states per §27. Upload now drives a real
step-based processing timeline (§14) by polling `GET /jobs/{id}` and
mapping `JobStage` to the timeline steps, instead of a spinner. Results
are organized into the exact §16 tab set (Overview, Indicators,
Forensics, Infrastructure, Geolocation, Campaign, Evidence), with
Threat Risk / Evidence Confidence / Campaign Correlation kept as three
visually distinct scores per §15. Email DNA (§17) is rendered as
drill-down categories over the real DNA fingerprint fields. The four
analysis modes (§13) are shown in the upload empty state, with only
`.eml` Upload marked available and the other three shown as
planned/coming-soon — no working-looking controls for unbuilt modes.
Added an optional `onOpenReport` prop (wired in `App.tsx`, same pattern
already used by `AnalysisHistoryView`) so the Overview tab's
"View Full Report" action can hand off to the Reports screen; this is
new UI wiring, not a change to any existing data-fetching contract.

The Infrastructure tab was enriched with `GET /intelligence/emails/{id}/domains`
and `GET /intelligence/emails/{id}/infrastructure` (IP/hosting risk,
Tor/VPN/cloud relay flags, registrar/NRD signals) above the relay-hop
transmission chain — these are real per-email endpoints already
defined in `services/api.ts`, distinct from the raw extracted-domain
list in Indicators and from the routing-focused hop chain.

`npx tsc --noEmit` and `npx vite build` both pass.

Note (Phase 9 pass): Verified `components/settings/SettingsView.tsx` against
§6/§7/§10/§11 and found it out of line with the rest of the app, not just
unconfirmed. Page title was `text-xl` inside a bordered card instead of the
`text-2xl` title-outside-a-card pattern every other screen uses (see
EvidenceVaultView/CampaignView), and status pills used ad hoc
emerald/indigo/amber Tailwind colors instead of the design system's
severity tokens — replaced with the shared `StatusBadge` component.

Also found several invented values that §38's "never invented values" rule
covers regardless of screen: "28 REST Routes", a hardcoded "384 Dimensions"
/ "HNSW/IVFFlat" vector-index description, and hardcoded MinIO bucket names
were not backed by any field in `HealthResponse`/`DetailedHealthResponse` —
replaced with the real fields that were already typed in `services/api.ts`
but unused (`services.postgres.pgvector.{available,version}`,
`services.minio.{configured_endpoint,available_buckets,required_buckets}`,
`runtime.{python_version,platform}`, `demo_context`). The three Threat
Intelligence Provider cards claimed a live "ACTIVE" status with no backing
endpoint (`/health` and `/health/detailed` don't report per-provider
connectivity) — reworded to describe them as configured correlation-engine
sources without an unverifiable status claim.

The "Forensic Engine Parameters" form let the user drag similarity/
clustering sliders and showed a "Forensic parameters updated successfully"
toast on submit, but nothing was persisted — no settings-write endpoint
exists, and no other screen read the two pieces of local state it set.
Replaced with a read-only "Correlation Engine Defaults" card showing the
real default threshold values the backend already applies
(`similarity_service.py`'s 65%, and `campaigns.py`'s 60%/40%
auto-cluster/live-correlation defaults), labeled as not yet independently
configurable, instead of a control that silently did nothing.

Added a `loading` prop to `SettingsView` (wired from `App.tsx`'s existing
`loadingHealth` state, already used by `Header`) so the screen has a real
loading state instead of always rendering as if data had arrived — this is
new UI wiring using state `App.tsx` already had, not a new data-fetching
contract.

`npx tsc --noEmit` and `npx vite build` both pass.

---

## Context to give the agent first

```
Read Design.md in full before touching any UI code, especially the new:
  - Section 36: Brand Assets (Final)
  - Section 37: No Technology / Architecture Flex
  - Section 38: Per-Screen Data Source Specification (MVP)

These three sections are non-negotiable rules, not suggestions. Section 37
in particular: do not add backend/infra/stack information to any screen
except Settings, even if it seems informative.

The Dashboard (App.tsx + components/dashboard/DashboardView.tsx) was already
redesigned to follow this spec — use it as the reference pattern for what
"real data showcase" and "no tech flex" look like in this codebase before
you start on the next screen.
```

---

## Phase-by-phase (run one at a time)

### Phase 1 — Analysis History
```
Redesign components/history/AnalysisHistoryView.tsx per Design.md §38's
Analysis History row and §11/§27 (cards, loading/empty states). It already
calls listEmails — audit the actual rendered UI against Design.md's
Typography Scale (§6) and Layout System (§7): fix any oversized/undersized
text, inconsistent spacing, or leftover glow/gradient styling that doesn't
match the calm, professional direction in §2.2. Keep all existing
filtering/search logic working. Do not add any content outside what §38
lists for this screen.
```

### Phase 2 — Threat Intel
```
Redesign components/intelligence/ThreatIntelView.tsx per Design.md §38's
Threat Intel row. This is a search-driven tool, not a list — the empty
state before a search should clearly explain what it does and show an
example query, not an empty table. Results must render every real field
the domain/IP intelligence endpoints return; do not truncate to "looks
nice" at the cost of dropping real findings.
```

### Phase 3 — Campaigns
```
Redesign components/campaigns/CampaignView.tsx per Design.md §38's
Campaigns row and §21 (Campaign Intelligence). Campaign cards must show
real member_count, campaign_confidence, first_detected_at/last_activity_at
from the API — no placeholder numbers. If campaigns list is empty, surface
the auto-cluster action per §38's empty state, not a blank page.
```

### Phase 4 — Investigation Graph
```
Redesign components/graph/InvestigationGraphView.tsx per Design.md §18
(Investigation Graph) and §38. Every node/edge must trace to a real
entity/relationship from the graph endpoints — no illustrative/sample
graph data. Follow §19 (Bridge Entity Design) for shared-infrastructure
nodes and §35's rule: every highlighted path needs a visible reason
(what's connected, why, what evidence, what confidence) — never an
unexplained line.
```

### Phase 5 — Geo Intelligence
```
Redesign components/geo/GeoIntelligenceMap.tsx per Design.md §20
(Geolocation Intelligence) and §35. Remove any decorative attack-line or
movie-style effects per §35's explicit "should not feel like" list. Every
mapped point must be a real geolocated IP/infrastructure record with a
confidence indicator, not a generic pin.
```

### Phase 6 — Evidence Vault
```
Redesign components/evidence/EvidenceVaultView.tsx per Design.md §38's
Evidence Vault row and §24 (Privacy and Audit Design) where relevant. Keep
the SHA-256/custody-chain content — that's real forensic data, not tech
flex (§37 explicitly carves this out). Focus the pass on layout/typography
consistency and clear loading/empty states.
```

### Phase 7 — Reports
```
Redesign components/reports/ForensicReportView.tsx per Design.md §25
(Reports) and §38. Report list and preview must come from real
GET /reports and GET /reports/{id} data. Keep MinIO bucket references out
of primary UI copy per §37 — that detail can stay in an expandable
"storage details" area but should not be a headline element.
```

### Phase 8 — Analyze Email workspace
```
Redesign components/workspace/AnalysisWorkspace.tsx per Design.md §13
(Analyze Email Page), §14 (Analysis Processing Experience), §15/§16
(Analysis Results), and §17 (Email DNA Design). This is the most complex
screen — do it last, in sub-passes if needed (upload → processing timeline
→ results sections). Every section must reflect a real field from the
corresponding endpoint in §38; do not leave any hardcoded example values
that were there for early scaffolding.
```

### Phase 9 — Settings (verify, don't redesign from scratch)
```
Settings is the one screen where backend/infra/system health status is
correct to show (§37). Just verify components/settings/SettingsView.tsx
against §6/§7/§10/§11 for visual consistency with the rest of the app —
don't strip its system content, that's its actual job.
```

---

## After each phase

```
Run `npx tsc --noEmit` and `npx vite build` in frontend/ and fix any
errors before moving to the next phase. Confirm the screen still compiles
and the existing API calls are unchanged (i.e. you redesigned the
presentation, not the data-fetching contract), unless Design.md §38
requires calling an endpoint the screen wasn't using yet.
```
