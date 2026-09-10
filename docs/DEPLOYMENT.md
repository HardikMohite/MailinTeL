# MailinteL Production Deployment Guide

This guide walks you through deploying the **MailinteL** platform into production using **Render** (Backend API) and **Vercel** (Frontend UI), with **Supabase** for PostgreSQL database and object storage.

---

## Architecture Overview

```text
┌──────────────────────────────────────┐
│          Vercel (Frontend)           │
│   React + TypeScript + Tailwind CSS  │
│   https://mailintel.vercel.app       │
└──────────────────┬───────────────────┘
                   │
         HTTPS API Requests (/api/v1)
                   │
                   ▼
┌──────────────────────────────────────┐
│           Render (Backend)           │
│         FastAPI + Python 3.12        │
│  https://mailintel-backend.onrender  │
└──────────┬────────────────┬──────────┘
           │                │
     PostgreSQL + pgvector  │ Object Storage
           │                │ (.eml & reports)
           ▼                ▼
┌──────────────────────────────────────┐
│               Supabase               │
│     PostgreSQL 15+ & S3 Storage      │
└──────────────────────────────────────┘
```

---

## Part 1: Backend Deployment on Render

### Option A: 1-Click Blueprint Deployment (Recommended)

1. Log into your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** and select **Blueprint**.
3. Connect your GitHub repository `HardikMohite/MailinTeL`.
4. Render will automatically detect [`render.yaml`](file:///c:/Dev/MailinteL/render.yaml) and configure the `mailintel-backend` service.
5. In the Environment Variables section, fill in your Supabase connection strings:
   - `DATABASE_URL` (Supabase Connection Pooler or Direct string)
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_KEY`
   - `ADMIN_EMAIL` & `ADMIN_PASSWORD` (Initial admin account)
6. Click **Apply**. Render will automatically run the build, apply schema migrations, and launch your API.

---

### Option B: Manual Web Service Setup

1. Click **New +** -> **Web Service**.
2. Connect `HardikMohite/MailinTeL`.
3. Configure the following fields:
   - **Name**: `mailintel-backend`
   - **Language**: `Python 3`
   - **Branch**: `main`
   - **Region**: Oregon (or closest to your Supabase project)
   - **Build Command**: `./render-build.sh`
   - **Start Command**: `./render-start.sh`
   - **Health Check Path**: `/`
4. Add the following **Environment Variables**:

| Variable | Recommended Value | Notes |
|---|---|---|
| `PYTHON_VERSION` | `3.12.8` | Ensures consistent package builds |
| `APP_ENV` | `production` | Enables strict security checks |
| `DEBUG` | `false` | Disables debug stack traces |
| `BACKEND_HOST` | `0.0.0.0` | Binds to all network interfaces |
| `SECRET_KEY` | *(Generate 32+ chars)* | Or click "Generate" in Render |
| `ALLOW_SELF_SIGNUP` | `true` | Allows analyst registration |
| `STORAGE_PROVIDER` | `supabase` | Enables cloud object storage |
| `SUPABASE_URL` | `https://<ref>.supabase.co` | From Supabase Project Settings |
| `SUPABASE_SERVICE_KEY` | `eyJhb...` | Supabase `service_role` key |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Supabase PostgreSQL URI |
| `ALLOWED_ORIGINS` | `https://your-frontend.vercel.app` | Your Vercel domain |
| `CORS_ORIGIN_REGEX` | `https://.*\.vercel\.app` | Permits all Vercel preview deploys |
| `ADMIN_EMAIL` | `admin@yourdomain.com` | Initial admin login |
| `ADMIN_PASSWORD` | *(Strong password)* | Initial admin password |
| `GROQ_API_KEY` | `gsk_...` | (Optional) LLM forensic insights |
| `VIRUSTOTAL_API_KEY` | *(Key)* | (Optional) Threat intelligence |
| `ABUSEIPDB_API_KEY` | *(Key)* | (Optional) IP reputation checks |

5. Click **Deploy Web Service**.
6. Once deployed, copy your Render URL (e.g., `https://mailintel-backend.onrender.com`).

---

## Part 2: Frontend Deployment on Vercel

1. Log into your [Vercel Dashboard](https://vercel.com/dashboard).
2. Click **Add New...** -> **Project**.
3. Import `HardikMohite/MailinTeL`.
4. Configure Project Settings:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click `Edit` and select `frontend` *(or leave as `./` — both are supported via `vercel.json`)*.
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Expand **Environment Variables** and add:

| Variable | Value | Notes |
|---|---|---|
| `VITE_API_URL` | `https://mailintel-backend.onrender.com` | Your Render backend URL |

> [!TIP]
> You do **not** need to add `/api/v1` to `VITE_API_URL`. The client normalizes the URL automatically.

6. Click **Deploy**.
7. Once finished, visit your Vercel deployment URL (e.g. `https://mailintel.vercel.app`).

---

## Part 3: Verification Checklist

1. **Backend Health Check**:
   - Navigate to `https://mailintel-backend.onrender.com/` -> Should return `{"app": "MailinteL", "status": "online"}`.
   - Navigate to `https://mailintel-backend.onrender.com/api/v1/health` -> Should return `{"status": "ok"}`.
2. **Frontend Connectivity**:
   - Open your Vercel URL.
   - Log in using your `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
   - Upload a test `.eml` sample in the Analysis Workspace to verify parser, DNA generation, and report rendering.
