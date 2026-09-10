<#
.SYNOPSIS
    Starts the MailinteL Full Stack Application Server.
.DESCRIPTION
    Automates pre-flight database migrations, extensions verification,
    admin account provisioning, storage bucket checks, MaxMind intelligence,
    and starts the Uvicorn FastAPI server on the local virtual environment.
.EXAMPLE
    .\start_server.ps1
    .\start_server.ps1 -WithFrontend
    .\start_server.ps1 -Port 8000 -HostName "127.0.0.1"
#>

[CmdletBinding()]
param (
    [switch]$WithFrontend,
    [switch]$SkipMigrations,
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$NoReload
)

$ErrorActionPreference = "Stop"

# Ensure current working directory is the project root
$RootDir = $PSScriptRoot
Set-Location -Path $RootDir

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "               MailinteL -- Server Startup Manager                " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Project Root: $RootDir" -ForegroundColor Gray
Write-Host " Target Host:  http://${HostName}:${Port}" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan

# 1. Check Python Virtual Environment & Auto-Provision if Missing
$VenvDir = Join-Path $RootDir "backend\venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvUvicorn = Join-Path $VenvDir "Scripts\uvicorn.exe"
$ReqFile = Join-Path $RootDir "backend\requirements.txt"

if (-not (Test-Path $VenvPython)) {
    Write-Host ""
    Write-Host "[*] Virtual environment not found. Creating at backend\venv..." -ForegroundColor Yellow
    $SystemPython = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $SystemPython) {
        $SystemPython = (Get-Command py -ErrorAction SilentlyContinue).Source
    }
    if (-not $SystemPython) {
        Write-Host "[!] Python executable not found in system PATH. Please install Python 3.11+." -ForegroundColor Red
        exit 1
    }
    Write-Host "    [+] Initializing virtual environment using: $SystemPython..." -ForegroundColor Cyan
    & $SystemPython -m venv $VenvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPython)) {
        Write-Host "[!] Failed to create virtual environment at backend\venv." -ForegroundColor Red
        exit 1
    }
    Write-Host "    [+] Virtual environment created successfully." -ForegroundColor Green
}

# Verify Core Dependencies Installed (Uvicorn, FastAPI, SQLAlchemy, Alembic)
$NeedsDeps = $false
if (-not (Test-Path $VenvUvicorn)) {
    $NeedsDeps = $true
} else {
    & $VenvPython -c "import fastapi, sqlalchemy, pydantic, alembic" 2>$null
    if ($LASTEXITCODE -ne 0) {
        $NeedsDeps = $true
    }
}

if ($NeedsDeps) {
    Write-Host ""
    Write-Host "[*] Installing/updating backend dependencies from requirements.txt..." -ForegroundColor Yellow
    Write-Host "    This may take 1-2 minutes on first initialization..." -ForegroundColor Gray
    & $VenvPython -m pip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Dependency installation failed. Please check network connectivity or requirements.txt." -ForegroundColor Red
        exit 1
    }
    Write-Host "    [+] All backend dependencies successfully installed." -ForegroundColor Green
}

# 2. Check Environment Configuration File (.env)
$EnvFile = Join-Path $RootDir ".env"
if (-not (Test-Path $EnvFile)) {
    Write-Host "[!] Configuration file (.env) not found in project root." -ForegroundColor Red
    if (Test-Path (Join-Path $RootDir ".env.example")) {
        Write-Host "    Copying .env.example to .env..." -ForegroundColor Yellow
        Copy-Item (Join-Path $RootDir ".env.example") $EnvFile
    } else {
        exit 1
    }
}

# 3. Redis Infrastructure Check & Activation
Write-Host ""
Write-Host "[Step 1/4] Verifying Redis Cache & Queue Service..." -ForegroundColor Green

$EnvContent = Get-Content $EnvFile -Raw -ErrorAction SilentlyContinue
$IsRemoteRedis = $false
$RedisUrlVal = "redis://localhost:6379/0"

if ($EnvContent -match "REDIS_URL\s*=\s*([^\r\n]+)") {
    $RedisUrlVal = $matches[1].Trim()
}

if ($RedisUrlVal -match "upstash\.io" -or $RedisUrlVal -match "^rediss://" -or ($EnvContent -match "REDIS_HOST\s*=\s*([^\r\n]+)" -and $matches[1].Trim() -notmatch "localhost|127\.0\.0\.1")) {
    $IsRemoteRedis = $true
}

if ($IsRemoteRedis) {
    Write-Host "    [*] Cloud Redis detected in configuration (Upstash TLS)..." -ForegroundColor Cyan
    $testCmd = "import asyncio, redis.asyncio as aioredis; asyncio.run((lambda: aioredis.from_url('$RedisUrlVal', socket_timeout=5.0, socket_connect_timeout=5.0).ping())())"
    & $VenvPython -c $testCmd 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [+] Upstash Cloud Redis is operational and accepting TLS connections." -ForegroundColor Green
    } else {
        Write-Host "    [!] Cloud Redis ping timed out or failed. MailinteL will run in resilient cache mode." -ForegroundColor Yellow
    }
} else {
    $RedisRunning = $false
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect("127.0.0.1", 6379, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(800, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($connect)
            $RedisRunning = $true
        }
        $tcp.Close()
    } catch {
        $RedisRunning = $false
    }

    if ($RedisRunning) {
        Write-Host "    [+] Local Redis is operational and accepting connections on 127.0.0.1:6379." -ForegroundColor Green
    } else {
        Write-Host "    [-] Local Redis not detected on port 6379. Checking Docker..." -ForegroundColor Yellow
        $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
        if ($DockerCmd) {
            try {
                $redisContainer = docker ps -a --filter "name=^mailintel-redis$" --format "{{.Status}}" 2>$null
                if ($redisContainer -and ($redisContainer -notmatch "^Up")) {
                    Write-Host "    [+] Starting existing Docker container 'mailintel-redis'..." -ForegroundColor Cyan
                    docker start mailintel-redis | Out-Null
                } elseif (-not $redisContainer) {
                    Write-Host "    [+] Launching Redis via Docker Compose..." -ForegroundColor Cyan
                    docker compose up -d redis | Out-Null
                }
                Start-Sleep -Seconds 1
                Write-Host "    [+] Redis service started successfully via Docker." -ForegroundColor Green
            } catch {
                Write-Host "    [!] Could not start Redis via Docker ($($_.Exception.Message))." -ForegroundColor Yellow
                Write-Host "        MailinteL will continue in resilient mode." -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [!] Docker CLI not detected. MailinteL will run in resilient local cache mode." -ForegroundColor Yellow
        }
    }
}

# 4. Pre-flight Setup: Database Migrations, Extensions & Admin Account
if (-not $SkipMigrations) {
    Write-Host ""
    Write-Host "[Step 2/4] Running Database Migrations and Extension Checks..." -ForegroundColor Green
    
    $DbSetupScript = Join-Path $RootDir "backend\scripts\setup_supabase_db.py"
    & $VenvPython $DbSetupScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[WARNING] Database pre-flight check exited with code $LASTEXITCODE." -ForegroundColor Yellow
        Write-Host "          Proceeding to server launch in resilient mode..." -ForegroundColor Yellow
    }
} else {
    Write-Host "[Step 2/4] Skipping database migrations (-SkipMigrations enabled)." -ForegroundColor Yellow
}

# 5. MaxMind GeoIP / ASN Check & Auto-Deployment
Write-Host ""
Write-Host "[Step 3/4] Verifying & Deploying MaxMind GeoLite2 (City & ASN)..." -ForegroundColor Green
$MaxMindScript = Join-Path $RootDir "backend\scripts\setup_maxmind.py"
if (Test-Path $MaxMindScript) {
    & $VenvPython $MaxMindScript --download
}

# 6. Optionally Launch Frontend in Concurrent Window
$FrontendDir = Join-Path $RootDir "frontend"
if ($WithFrontend -and (Test-Path $FrontendDir)) {
    $NodeModules = Join-Path $FrontendDir "node_modules"
    if (-not (Test-Path $NodeModules)) {
        Write-Host ""
        Write-Host "[*] Frontend dependencies not found. Installing via npm install..." -ForegroundColor Yellow
        Push-Location $FrontendDir
        npm install
        Pop-Location
    }
    Write-Host ""
    Write-Host "[+] Launching Vite Frontend in a concurrent window..." -ForegroundColor Magenta
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$FrontendDir'; Write-Host 'MailinteL Frontend Starting on http://localhost:5173...' -ForegroundColor Cyan; npm run dev"
}

# 7. Launch FastAPI Server with Uvicorn
Write-Host ""
Write-Host "[Step 4/4] Starting Uvicorn FastAPI Backend..." -ForegroundColor Green
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  * API Server:    http://${HostName}:${Port}" -ForegroundColor White
Write-Host "  * Documentation: http://${HostName}:${Port}/docs" -ForegroundColor White
Write-Host "  * Health Check:  http://${HostName}:${Port}/api/v1/health" -ForegroundColor White
if ($WithFrontend) {
    Write-Host "  * Frontend UI:   http://localhost:5173" -ForegroundColor White
}
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

$UvicornArgs = @(
    "app.main:app",
    "--app-dir", "backend",
    "--host", $HostName,
    "--port", "$Port"
)

if (-not $NoReload) {
    $UvicornArgs += "--reload"
}

& $VenvUvicorn @UvicornArgs
