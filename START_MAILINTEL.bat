@echo off
title MailinTeL - AI Email Threat Intelligence Platform
cd /d "%~dp0"

echo =================================================================
echo             MailinTeL -- One-Click Application Launcher
echo =================================================================
echo.
echo [*] Initializing Backend (FastAPI :8000) and Frontend (Vite :5173)...
echo [*] Your default web browser will open automatically once ready.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_server.ps1" -WithFrontend -OpenBrowser %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Server manager exited with code %ERRORLEVEL%.
    pause
)
