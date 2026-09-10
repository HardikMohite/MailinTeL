@echo off
title MailinteL Server Manager
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_server.ps1" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Server exited with code %ERRORLEVEL%
    pause
)
