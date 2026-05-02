@echo off
echo ==========================================
echo    SOC Level 2 Advanced Dashboard
echo ==========================================
echo.

REM Check admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Admin privileges OK
) else (
    echo [!] Warning: Not admin
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found!
    pause
    exit /b
)

REM Install deps
if not exist .deps_installed (
    echo [+] Installing dependencies...
    pip install -r requirements.txt
    echo. > .deps_installed
)

echo [+] Starting SOC Advanced Dashboard...
echo [+] Browser will open automatically
echo [+] URL: http://127.0.0.1:5000
echo.

python soc_advanced.py

pause
