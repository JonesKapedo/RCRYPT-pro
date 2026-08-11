# RockyCrypt — Docker + ngrok local pilot on Windows
# ===================================================
# 1) Builds & starts the app in Docker (host port 8080 -> container 8000)
# 2) Waits for the container healthcheck to pass
# 3) Starts an ngrok tunnel to expose it publicly
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\start_docker_ngrok.ps1
#
# Requires: Docker Desktop running, ngrok on PATH (or set $NgrokPath below).
# First run: paste your ngrok authtoken (https://dashboard.ngrok.com/get-started/your-authtoken)
#   ngrok config add-authtoken YOUR_TOKEN

$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$NgrokPath = 'C:\Users\User\ngrok\ngrok.exe'   # fallback if not on PATH
$HostPort = 8080
$ContainerPort = 8000

Set-Location $ProjectDir

Write-Host "`n[1/4] Building and starting containers..." -ForegroundColor Cyan
docker compose -f docker-compose.local.yml up -d --build

Write-Host "[2/4] Waiting for the app to become healthy..." -ForegroundColor Cyan
$healthy = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    $state = (docker inspect --format '{{.State.Health.Status}}' rockycrypt-app 2>$null)
    if ($state -eq 'healthy') { $healthy = $true; break }
}
if (-not $healthy) {
    Write-Host "Container is not healthy. Recent logs:" -ForegroundColor Red
    docker logs rockycrypt-app --tail 30
    exit 1
}
Write-Host "[OK] App is healthy at http://localhost:$HostPort" -ForegroundColor Green

Write-Host "[3/4] Testing local endpoint..." -ForegroundColor Cyan
curl.exe -s -o NUL -w "  GET / -> %{http_code} (%{size_download} bytes)`n" http://localhost:$HostPort/

Write-Host "[4/4] Starting ngrok tunnel (terminal stays attached; press Ctrl+C to stop)..." -ForegroundColor Cyan
if (Get-Command ngrok -ErrorAction SilentlyContinue) {
    ngrok http $HostPort
} else {
    & $NgrokPath http $HostPort
}