@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CyberTrace - Network Monitoring ^& Security Analyzer

echo.
echo ============================================================
echo   CyberTrace - Network Monitoring ^& Security Analyzer
echo ============================================================
echo.

:: ------------------------------------------------------------
:: 1. Privilege Check & Auto-Elevation
:: ------------------------------------------------------------
fltmc >nul 2>&1
if not errorlevel 1 goto :IS_ADMIN

echo ============================================================
echo   [PRIVILEGE] Requesting Administrator Privileges...
echo   (Required for live Npcap packet capture on Windows)
echo ============================================================
echo.
powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0start.bat\"\"' -Verb RunAs"
if not errorlevel 1 exit /b 0

echo [WARNING] Elevation was declined or unavailable.
echo Running in Standard User mode (Live Telemetry & Demo Mode ready).
goto :AFTER_PRIV

:IS_ADMIN
echo [PRIVILEGE] Administrator mode: YES (Full live packet capture ready)

:AFTER_PRIV
echo.

:: ------------------------------------------------------------
:: 2. Python Detection
:: ------------------------------------------------------------
set "PY_EXE="
if exist "%~dp0venv\Scripts\python.exe" set "PY_EXE=%~dp0venv\Scripts\python.exe"
if not defined PY_EXE if exist "%~dp0.venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if not defined PY_EXE if exist "C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe" set "PY_EXE=C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if not defined PY_EXE (
    where python.exe >nul 2>&1
    if not errorlevel 1 set "PY_EXE=python.exe"
)

if defined PY_EXE goto :PYTHON_FOUND

echo [ERROR] Python was not found on your system!
echo Please install Python from python.org and check 'Add Python to PATH'.
echo.
pause
exit /b 1

:PYTHON_FOUND
echo [PYTHON] Using: %PY_EXE%
"%PY_EXE%" --version
echo.

:: ------------------------------------------------------------
:: 3. Port 5000 Check
:: ------------------------------------------------------------
set "PORT_PID="
for /f "tokens=5" %%a in ('netstat -ano -p tcp ^| findstr LISTENING ^| findstr :5000') do (
    set "PORT_PID=%%a"
)

if not defined PORT_PID goto :START_SERVER

echo [INFO] Detected existing process on port 5000 (PID: %PORT_PID%).
echo [INFO] Stopping previous server to ensure clean, elevated start...
taskkill /F /PID %PORT_PID% >nul 2>&1
ping 127.0.0.1 -n 2 >nul
echo [OK] Port 5000 cleared.
echo.

:START_SERVER
:: ------------------------------------------------------------
:: 4. Start Server
:: ------------------------------------------------------------
echo ============================================================
echo   Starting CyberTrace Server at http://127.0.0.1:5000
echo ============================================================
echo [INFO] Press Ctrl+C in this window to stop the server.
echo [INFO] Browser will open automatically in 5 seconds...
echo.

:: Open the Live Capture Guide page after 5 seconds (gives Flask time to fully start)
start "" cmd /c "timeout /t 5 /nobreak >nul & start http://127.0.0.1:5000/guide"

"%PY_EXE%" app.py
set "APP_ERR=%errorlevel%"

if not "%APP_ERR%"=="0" (
    echo.
    echo [ERROR] CyberTrace server exited with code %APP_ERR%.
    pause
)

