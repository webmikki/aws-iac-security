@echo off
echo 🔍 Running AWS Security Infrastructure Analysis
echo ==============================================

REM Check if Java is installed
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Java not found. Please install Java 11 or higher first.
    pause
    exit /b 1
)

REM Check if Maven is installed
mvn -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Maven not found. Please install Maven first.
    pause
    exit /b 1
)

echo.
echo 🔄 Compiling security analyzer...
mvn clean compile
if %errorlevel% neq 0 (
    echo ❌ Compilation failed.
    pause
    exit /b 1
)

echo.
echo 🔍 Running security analysis...
mvn exec:java -Dexec.mainClass="com.aws-iac-security.security.SecurityAnalyzer" -Dexec.args="../infra config/securitycheck-patterns.json"

echo.
echo ✅ Security analysis complete!
pause
