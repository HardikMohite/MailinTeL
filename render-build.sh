#!/usr/bin/env bash
# Render Build Script for MailinteL Backend
# Exit on any failure
set -o errexit

echo "====================================================="
echo "==> [1/3] Upgrading pip, setuptools, and wheel..."
echo "====================================================="
python -m pip install --upgrade pip setuptools wheel

echo "====================================================="
echo "==> [2/3] Installing backend dependencies..."
echo "====================================================="
pip install -r backend/requirements.txt

echo "====================================================="
echo "==> [3/3] Checking MaxMind GeoIP/ASN intelligence..."
echo "====================================================="
python backend/scripts/setup_maxmind.py || true

echo "====================================================="
echo "==> Render build finished successfully!"
echo "====================================================="
