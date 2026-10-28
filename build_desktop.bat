@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CyberTrace - Standalone Desktop Application Builder

echo.
echo ============================================================
echo   CyberTrace - Standalone Desktop Packaging Tool
echo ============================================================
echo.

:: 1. Privilege Check
fltmc >nul 2>&1
if not errorlevel 1 goto :IS_ADMIN

echo ============================================================
echo   [PRIVILEGE] Requesting Administrator Elevation...
echo ============================================================
powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0build_desktop.bat\"\"' -Verb RunAs"
if not errorlevel 1 exit /b 0

:IS_ADMIN
echo [OK] Running with elevated privileges.
echo.

:: 2. Python Detection
set "PY_EXE="
if exist "%~dp0venv\Scripts\python.exe" set "PY_EXE=%~dp0venv\Scripts\python.exe"
if not defined PY_EXE if exist "%~dp0.venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if not defined PY_EXE if exist "C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe" set "PY_EXE=C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe"
if not defined PY_EXE set "PY_EXE=python.exe"

echo [PYTHON] Using: %PY_EXE%
"%PY_EXE%" --version
echo.

:: 3. Run Quality Test Suite before building
echo ============================================================
echo   Running automated test suite (Pytest)...
echo ============================================================
"%PY_EXE%" -m pytest
if errorlevel 1 (
    echo.
    echo [ERROR] Test suite failed! Aborting build to ensure release stability.
    pause
    exit /b 1
)
echo.
echo [OK] All tests passed! Proceeding to desktop build...
echo.

:: 4. Check / Install PyInstaller
"%PY_EXE%" -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    "%PY_EXE%" -m pip install pyinstaller
)

:: 5. Create Standalone Bundle
echo ============================================================
echo   Building standalone CyberTrace executable...
echo ============================================================
"%PY_EXE%" -m PyInstaller --noconfirm --clean CyberTrace.spec

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  [SUCCESS] CyberTrace Standalone Executable Created!
echo ============================================================
echo.
echo Your compiled application is located at:
echo   %~dp0dist\CyberTrace.exe
echo.
echo You can run CyberTrace.exe directly on any Windows PC without
echo needing Python installed.
echo.
pause
