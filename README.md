# MailIntel

> **AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**

MailIntel is an evidence-driven platform designed to transform suspicious emails into actionable cyber intelligence. It moves beyond simple binary classification by analyzing transmission paths, reconstructing SMTP relay hops, assessing domain and infrastructure signals, estimating observable infrastructure geolocation, generating multi-layer Email DNA fingerprints, and correlating isolated emails into explainable campaign intelligence.

---

## Architecture Overview

```text
                 EMAIL INGESTION (.eml First)
                             │
                             ▼
                    Evidence Preservation
                             │
                             ▼
                    Forensic Parsing
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Authentication    AI/NLP        Domain/IP
        Forensics         Threat        Intelligence
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                      Email DNA Engine
                             │
                             ▼
                 Campaign Correlation & Graph
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
       Investigation Graph             Geo Map
              │                             │
              └──────────────┬──────────────┘
                             ▼
                      Forensic Reports
```

---

## Technology Stack

- **Backend:** Python 3.13 + FastAPI + Uvicorn
- **Database:** PostgreSQL + pgvector (semantic similarity & vectors)
- **Object Storage:** MinIO (immutable original `.eml` and report storage)
- **Queue / Cache:** Redis (background task execution & caching)
- **Frontend:** React + TypeScript + Vite + Tailwind CSS (Single unified forensic theme)
- **Analysis:** NetworkX (graph modeling), MapLibre GL (geolocation visualization)

---

## Local Development Setup

### Prerequisites

- **Python:** 3.11+ (Python 3.13 recommended)
- **Node.js:** v18+ (Node.js v24 recommended)
- **PostgreSQL / MinIO / Redis:** Local services or Docker Compose

### 1. Environment Setup

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv

# Windows:
.\venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend API will be accessible at:
- **API Root:** [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Endpoint:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend application will be accessible at:
- **Web App:** [http://localhost:5173](http://localhost:5173)

---

## Development Status & Roadmap

Progress is tracked in [`Tracker.md`](Tracker.md) following [`Rules.md`](Rules.md) and [`ImplementationPlan.md`](ImplementationPlan.md).

- [x] **Phase 0 — Project Foundation**
  - [x] TASK-001: Initialize Project Structure
  - [ ] TASK-002: Configure PostgreSQL
  - [ ] TASK-003: Enable pgvector
  - [ ] TASK-004: Configure MinIO
  - [ ] TASK-005: Configure Redis
  - [ ] TASK-006: Create Core Health Checks
- [ ] **Phase 1 — Core Database, Storage & Background Processing**
- [ ] **Phase 2 — .eml Upload & Forensic Evidence Preservation**
- [ ] **Phase 3 — Email Forensic Analysis Engine**
- [ ] **Phase 4 — Threat Intelligence & Explainable Scoring**
- [ ] **Phase 5 — Email DNA & Semantic Similarity**
- [ ] **Phase 6 — Campaign Correlation & Investigation Graph**
- [ ] **Phase 7 — Geolocation Intelligence & Map**
- [ ] **Phase 8 — Investigation Workspace & Forensic Reports**
- [ ] **Phase 9 — Authentication** (Deferred Post-MVP)
- [ ] **Phase 10 — RBAC Enforcement** (Deferred Post-MVP)
