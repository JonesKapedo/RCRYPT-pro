@echo off
REM RockyCrypt Startup Script - Windows

echo.
echo Starting RockyCrypt...
echo Network: http://192.168.12.3:8000
echo Local: http://localhost:8000
echo.

REM Load env vars
for /f "tokens=*" %%i in (.env.production) do set "%%i"

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
python -m pip install -q -r requirements.txt

REM Start server
echo.
echo Starting FastAPI server...
python rockycrypt_server.py

pause
