@echo off
title Binary Security Scanner - Launcher
color 0A

echo ===================================================
echo    BINARY TRANSPARENCY & SECURITY ANALYZER
echo ===================================================
echo.
echo [1/3] Checking dependencies...
pip install -r backend\requirements.txt > nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Warning: Could not install dependencies automatically.
    echo     Please ensure Python and pip are installed and in your PATH.
) else (
    echo [OK] Dependencies verified.
)

echo.
echo [2/3] Starting Backend API Server (Port 5000)...
start "Security Scanner Backend" /min cmd /c "cd backend && python app.py"

echo.
echo [3/3] Starting Frontend Interface (Port 8080)...
start "Security Scanner Frontend" /min cmd /c "cd frontend && python -m http.server 8080"

echo.
echo [SUCCESS] System Online.
echo.
echo Opening Secure Dashboard...
timeout /t 3 > nul
start http://localhost:8080

echo.
echo ===================================================
echo    SCANNER IS RUNNING
echo ===================================================
echo.
echo - Backend: http://localhost:5000
echo - Frontend: http://localhost:8080
echo.
echo To stop the scanner, close the opened command windows.
pause
