@echo off
echo 🔍 AWS Security Infrastructure Analysis
echo ======================================

REM Check if Python is installed
echo.
echo 🔄 Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.7 or higher first.
    pause
    exit /b 1
)
echo ✅ Python found

REM Check if infrastructure directory exists
echo.
echo 🔄 Checking infrastructure directory...
if not exist "..\infra" (
    echo ❌ Infrastructure directory not found. Please ensure 'infra' folder exists.
    pause
    exit /b 1
)
echo ✅ Infrastructure directory found

REM Run the security analysis
echo.
echo 🔍 Running security analysis...
python security-analyzer.py ..\infra -o security-report.json -p security-report.pdf -f security-patterns.json

if %errorlevel% neq 0 (
    echo ❌ Security analysis failed.
    pause
    exit /b 1
)

echo.
echo ✅ Security analysis complete!
echo 📄 JSON report saved as: security-report.json
echo 📄 PDF report saved as: security-report.pdf
echo.
pause
