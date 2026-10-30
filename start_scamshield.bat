@echo off
title ScamShield - Advanced Scam Detection & Digital Forensics
cd /d "%~dp0"

echo ============================================================
echo      ScamShield Launcher (AI Detection & Digital Forensics)
echo ============================================================
echo.

set PYTHON_BIN=
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON_BIN=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_BIN=python"
    )
)

if "%PYTHON_BIN%"=="" (
    echo ERROR: Working Python installation was not found.
    echo Please ensure Python 3.11 is installed and available in PATH.
    pause
    exit /b 1
)

echo Using Python interpreter: "%PYTHON_BIN%"
"%PYTHON_BIN%" --version
echo.

echo Checking and validating dependencies...
"%PYTHON_BIN%" check_backend.py
if errorlevel 1 (
    echo.
    echo ERROR: Dependency or backend check failed.
    echo Attempting pip install...
    "%PYTHON_BIN%" -m pip install -r requirements.txt
)

echo.
echo ============================================================
echo Starting ScamShield Flask Web Application...
echo Browser will open at: http://127.0.0.1:5000
echo Press CTRL+C in this console window to stop the server.
echo ============================================================
echo.
"%PYTHON_BIN%" app.py

echo.
echo ScamShield has stopped.
pause
