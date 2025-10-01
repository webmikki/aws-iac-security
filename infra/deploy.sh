#!/bin/bash

echo "🚀 Starting AWS Security Infrastructure Deployment (Java CDK)"
echo "========================================================"

# Check if Java is installed
echo ""
echo "🔄 Checking Java installation..."
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install Java 11 or higher first."
    exit 1
fi
echo "✅ Java found"

# Check if Maven is installed
echo ""
echo "🔄 Checking Maven installation..."
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven not found. Please install Maven first."
    exit 1
fi
echo "✅ Maven found"

# Check if AWS CLI is installed
echo ""
echo "🔄 Checking AWS CLI installation..."
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI first."
    exit 1
fi
echo "✅ AWS CLI found"

# Check if CDK is installed
echo ""
echo "🔄 Checking AWS CDK installation..."
if ! command -v cdk &> /dev/null; then
    echo "❌ AWS CDK not found. Installing CDK..."
    npm install -g aws-cdk
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install CDK. Please install manually."
        exit 1
    fi
fi
echo "✅ AWS CDK found"

# Compile the Java project
echo ""
echo "🔄 Compiling Java project..."
mvn clean compile
if [ $? -ne 0 ]; then
    echo "❌ Compilation failed."
    exit 1
fi
echo "✅ Compilation successful"

# Bootstrap CDK (if needed)
echo ""
echo "🔧 Bootstrapping CDK..."
cdk bootstrap
if [ $? -ne 0 ]; then
    echo "⚠️  CDK bootstrap may have failed, but continuing..."
fi

# Deploy the stack
echo ""
echo "🏗️  Deploying infrastructure..."
cdk deploy --require-approval never
if [ $? -ne 0 ]; then
    echo "❌ Deployment failed."
    exit 1
fi

echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Check the outputs above for VPC ID, Instance ID, and Public IP"
echo "2. Use SSM Session Manager to connect to your EC2 instance:"
echo "   aws ssm start-session --target <instance-id>"
echo "3. To destroy the infrastructure when done:"
echo "   cdk destroy"
