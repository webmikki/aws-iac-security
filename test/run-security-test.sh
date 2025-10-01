#!/bin/bash

echo "🔍 Running AWS Security Infrastructure Analysis"
echo "=============================================="

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install Java 11 or higher first."
    exit 1
fi

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven not found. Please install Maven first."
    exit 1
fi

echo ""
echo "🔄 Compiling security analyzer..."
mvn clean compile
if [ $? -ne 0 ]; then
    echo "❌ Compilation failed."
    exit 1
fi

echo ""
echo "🔍 Running security analysis..."
mvn exec:java -Dexec.mainClass="com.aws-iac-security.security.SecurityAnalyzer" -Dexec.args="../infra config/securitycheck-patterns.json"

echo ""
echo "✅ Security analysis complete!"
