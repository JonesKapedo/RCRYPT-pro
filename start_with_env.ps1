# RockyCrypt — load .env into the current PowerShell session and start the server.
#   powershell -ExecutionPolicy Bypass -File .\start_with_env.ps1
#
# Secrets live in .env (git-ignored). Copy .env.example to .env and fill it in.

$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $ProjectDir '.env'

if (-not (Test-Path $EnvFile)) {
    Write-Host "[ERROR] .env not found. Copy .env.example to .env and fill in the values." -ForegroundColor Red
    exit 1
}

Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { return }
    $idx = $line.IndexOf('=')
    if ($idx -lt 1) { return }
    $name = $line.Substring(0, $idx).Trim()
    $value = $line.Substring($idx + 1).Trim().Trim('"').Trim("'")
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    Write-Host "  set $name"
}

Write-Host "`nEnvironment loaded. Starting server..." -ForegroundColor Green
Set-Location $ProjectDir
python rockycrypt_server.py
