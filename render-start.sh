#!/usr/bin/env bash
# Render Startup Script for MailinteL Backend
set -o errexit

PORT="${PORT:-8000}"

echo "====================================================="
echo "==> [Step 1/2] Applying database migrations & checks..."
echo "====================================================="
if [ -n "$DATABASE_URL" ] || [ -n "$POSTGRES_HOST" ]; then
    python backend/scripts/setup_supabase_db.py || {
        echo "[-] Database pre-flight warning: Continuing in resilient mode..."
    }
else
    echo "[!] No DATABASE_URL or POSTGRES_HOST specified. Continuing in resilient mode..."
fi

echo "====================================================="
echo "==> [Step 2/2] Launching Uvicorn on 0.0.0.0:${PORT}..."
echo "====================================================="
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --app-dir backend --workers 2
