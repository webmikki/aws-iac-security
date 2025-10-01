@echo off
echo 🚀 Starting AWS Security Infrastructure Deployment (Java CDK)
echo ========================================================

REM Check if Java is installed
echo.
echo 🔄 Checking Java installation...
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Java not found. Please install Java 11 or higher first.
    pause
    exit /b 1
)
echo ✅ Java found

REM Check if Maven is installed
echo.
echo 🔄 Checking Maven installation...
mvn -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Maven not found. Please install Maven first.
    pause
    exit /b 1
)
echo ✅ Maven found

REM Check if AWS CLI is installed
echo.
echo 🔄 Checking AWS CLI installation...
aws --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ AWS CLI not found. Please install AWS CLI first.
    pause
    exit /b 1
)
echo ✅ AWS CLI found

REM Check if CDK is installed
echo.
echo 🔄 Checking AWS CDK installation...
cdk --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ AWS CDK not found. Installing CDK...
    npm install -g aws-cdk
    if %errorlevel% neq 0 (
        echo ❌ Failed to install CDK. Please install manually.
        pause
        exit /b 1
    )
)
echo ✅ AWS CDK found

REM Compile the Java project
echo.
echo 🔄 Compiling Java project...
mvn clean compile
if %errorlevel% neq 0 (
    echo ❌ Compilation failed.
    pause
    exit /b 1
)
echo ✅ Compilation successful

REM Bootstrap CDK (if needed)
echo.
echo 🔧 Bootstrapping CDK...
cdk bootstrap
if %errorlevel% neq 0 (
    echo ⚠️  CDK bootstrap may have failed, but continuing...
)

REM Deploy the stack
echo.
echo 🏗️  Deploying infrastructure...
cdk deploy --require-approval never
if %errorlevel% neq 0 (
    echo ❌ Deployment failed.
    pause
    exit /b 1
)

echo.
echo 🎉 Deployment completed successfully!
echo.
echo 📋 Next steps:
echo 1. Check the outputs above for VPC ID, Instance ID, and Public IP
echo 2. Use SSM Session Manager to connect to your EC2 instance:
echo    aws ssm start-session --target ^<instance-id^>
echo 3. To destroy the infrastructure when done:
echo    cdk destroy
echo.
pause
