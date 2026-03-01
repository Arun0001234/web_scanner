@echo off
echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║     VulnScanner Web Interface Launcher               ║
echo ╚════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed!
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if Flask is installed
python -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing required packages...
    pip install -r requirements_web.txt
    echo.
)

REM Start the web server
echo [*] Starting VulnScanner Web Interface...
echo [*] Access the scanner at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.

python web_scanner_app.py

pause
