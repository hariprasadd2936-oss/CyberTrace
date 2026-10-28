@echo off
title CyberTrace - Environment Setup
echo ============================================================
echo   CyberTrace - Environment Setup & Dependencies
echo ============================================================
echo.

set "PY_EXE=python"
if exist "C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe" (
    set "PY_EXE=C:\Users\HARIPRASADD\AppData\Local\Python\pythoncore-3.14-64\python.exe"
) else if exist "venv\Scripts\python.exe" (
    set "PY_EXE=venv\Scripts\python.exe"
)

echo [OK] Using Python: %PY_EXE%
echo.
echo [1/3] Installing Python dependencies...
"%PY_EXE%" -m pip install --upgrade pip
"%PY_EXE%" -m pip install -r requirements.txt
echo.
echo [2/3] Initializing SQLite database...
"%PY_EXE%" -c "import database as db; db.init_db(); print('Database ready.')"
echo.
echo [3/3] Running automated unit test suite...
"%PY_EXE%" -m unittest discover tests
echo.
echo ============================================================
echo   Setup Complete!
echo   Double-click npcap-1.90.exe to install driver (if not yet installed).
echo   Run start.bat to launch CyberTrace on http://127.0.0.1:5000
echo ============================================================
pause
