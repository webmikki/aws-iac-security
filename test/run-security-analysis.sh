#!/bin/bash

echo "🔍 AWS Security Infrastructure Analysis"
echo "======================================"

# Check if Python is installed
echo ""
echo "🔄 Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "❌ Python not found. Please install Python 3.7 or higher first."
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi
echo "✅ Python found"

# Check if infrastructure directory exists
echo ""
echo "🔄 Checking infrastructure directory..."
if [ ! -d "../infra" ]; then
    echo "❌ Infrastructure directory not found. Please ensure 'infra' folder exists."
    exit 1
fi
echo "✅ Infrastructure directory found"

# Run the security analysis
echo ""
echo "🔍 Running security analysis..."
$PYTHON_CMD security-analyzer.py ../infra -o security-report.json -p security-report.pdf -f security-patterns.json

if [ $? -ne 0 ]; then
    echo "❌ Security analysis failed."
    exit 1
fi

echo ""
echo "✅ Security analysis complete!"
echo "📄 JSON report saved as: security-report.json"
echo "📄 PDF report saved as: security-report.pdf"
echo ""
