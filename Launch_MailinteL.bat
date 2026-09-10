@echo off
title MailinteL Launcher
cd /d "%~dp0"

echo =================================================================
echo             Launching MailinteL Full Stack Application           
echo =================================================================
echo.

:: 1. Launch FastAPI Backend in a dedicated window
echo [*] Starting Backend Server (FastAPI on http://127.0.0.1:8000)...
start "MailinteL Backend (Port 8000)" cmd /k "cd /d "%~dp0" && "%~dp0backend\venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"

:: 2. Launch Vite Frontend in a dedicated window
echo [*] Starting Frontend Server (Vite on http://localhost:5173)...
start "MailinteL Frontend (Port 5173)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: 3. Wait for servers to initialize
echo [*] Initializing services (3 seconds)...
timeout /t 3 /nobreak >nul

:: 4. Open default browser
echo [*] Opening MailinteL in your default browser...
start http://localhost:5173

echo.
echo =================================================================
echo   MailinteL is successfully running!
echo   ---------------------------------------------------------------
echo   * Web Frontend UI:     http://localhost:5173
echo   * Backend API:         http://127.0.0.1:8000
echo   * Interactive Docs:    http://127.0.0.1:8000/docs
echo   * Health Check:        http://127.0.0.1:8000/api/v1/health
echo =================================================================
echo.
echo You can keep this window open or close it.
echo To stop the application, simply close the Backend and Frontend windows.
echo.
pause
