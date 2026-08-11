@echo off
title RockyCrypt — NSE Kenya Server (Production)
color 0A

echo.
echo   ╔══════════════════════════════════════════════╗
echo   ║        RockyCrypt — NSE Kenya Server         ║
echo   ║               by great turbinez              ║
echo   ║          Launching Trading Intelligence...   ║
echo   ╚══════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

:: --- Check Python ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

:: --- Virtual Environment Setup ---
echo [*] Setting up virtual environment...
if not exist "venv" (
    echo [*] Creating virtual environment 'venv'...
    python -m venv venv
)

:: Activate virtual environment
call "venv\Scripts\activate"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)
echo [*] Virtual environment activated.

:: --- Install dependencies ---
echo [*] Installing/Updating dependencies from requirements.txt...
python -m pip install -q -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [*] Dependencies installed.

:: --- Create data directory if missing ---
if not exist "data" mkdir data

:: --- Determine production port from .env.production (default 8000) ---
set "RC_PORT=8000"
if exist ".env.production" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env.production") do (
        if "%%A"=="ROCKYCRYPT_PORT" set "RC_PORT=%%B"
    )
)

:: --- Free the production port (kill stale server process) ---
echo [*] Checking port %RC_PORT% for stale processes...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r "^[ ]*TCP[ ]*0.0.0.0:%RC_PORT%[ ]*.*LISTENING"') do (
    echo [*] Killing stale process PID %%p on port %RC_PORT%...
    taskkill /f /pid %%p >nul 2>&1
)
timeout /t 2 /nobreak >nul

:: --- Load production environment variables from .env.production ---
echo [*] Loading production environment variables...
if exist ".env.production" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env.production") do (
        if not "%%A"=="" (
            if not "%%A"=="REM" (
                set "%%A=%%B"
            )
        )
    )
    echo [*] Production environment loaded.
) else (
    echo [WARNING] .env.production not found. Using defaults.
)

:: --- Launch server in production mode ---
echo.
echo [*] Starting RockyCrypt server in PRODUCTION mode.
echo [*] Local URL : http://localhost:%RC_PORT%
echo [*] Network URL: http://192.168.12.3:%RC_PORT%
echo [*] Press Ctrl+C to stop the server
echo.

:: Open browser after a short delay
start /b "" cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:%RC_PORT%"

:: Run the FastAPI server (reads ROCKYCRYPT_PRODUCTION=true, host & port from env)
python rockycrypt_server.py

echo.
echo [*] Server stopped.
pause
