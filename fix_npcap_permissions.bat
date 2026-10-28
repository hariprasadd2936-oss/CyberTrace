@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CyberTrace - Fix Npcap Capture Permissions

echo ============================================================
echo   CyberTrace - Npcap Permission Configurator
echo ============================================================
echo.

:: Check for Administrator elevation & auto-request UAC
fltmc >nul 2>&1
if not errorlevel 1 goto :ADMIN_OK

echo ============================================================
echo   Requesting Administrator Privileges to configure Npcap...
echo ============================================================
powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0fix_npcap_permissions.bat\"\"' -Verb RunAs"
if not errorlevel 1 exit /b 0

echo [ERROR] Administrator privileges are required to configure Npcap.
pause
exit /b 1

:ADMIN_OK
echo [OK] Running with Administrator privileges.
echo.
echo Configuring Npcap to allow standard non-admin users to capture packets...

:: Set AdminOnly = 0
reg add "HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters" /v AdminOnly /t REG_DWORD /d 0 /f
if errorlevel 1 (
    echo [ERROR] Failed to update Npcap registry settings.
    pause
    exit /b 1
)

echo.
echo Restarting Npcap kernel driver service...
net stop npcap >nul 2>&1
net start npcap >nul 2>&1

echo.
echo ============================================================
echo  [SUCCESS] Npcap Admin-Only restriction has been REMOVED!
echo ============================================================
echo.
echo Standard users and applications can now capture live network packets
echo without needing to run as Administrator.
echo.

:: Stop existing server on port 5000 so the updated driver takes effect
set "OLD_PID="
for /f "tokens=5" %%a in ('netstat -ano -p tcp ^| findstr LISTENING ^| findstr :5000') do (
    set "OLD_PID=%%a"
)

if defined OLD_PID (
    echo [INFO] Stopping previous CyberTrace server PID %OLD_PID% to reload Npcap driver...
    taskkill /F /PID %OLD_PID% >nul 2>&1
    ping 127.0.0.1 -n 2 >nul
    echo [OK] Port 5000 cleared.
)

echo.
echo Starting CyberTrace with live packet capture enabled...
start "" "%~dp0start.bat"

echo.
echo [DONE] CyberTrace has been launched.
ping 127.0.0.1 -n 3 >nul
exit /b 0
