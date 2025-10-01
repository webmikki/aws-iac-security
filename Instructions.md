

## How to Run the Tests

You have **two ways** to run the security tests:

### Option 1: Using the Convenience Scripts (Recommended)

**For Windows:**
```cmd
cd test
run-security-test.bat
```

**For Linux/macOS:**
```bash
cd test
chmod +x run-security-test.sh
./run-security-test.sh
```

### Option 2: Manual Maven Execution

```bash
cd test
mvn clean compile
mvn exec:java -Dexec.mainClass="com.aws-iac-security.security.SecurityAnalyzer" -Dexec.args="../infra config/securitycheck-patterns.json"
```

## Where Results Appear

The test results appear **directly in the terminal/console** where you run the command. The output is displayed in real-time as the analysis runs.

## Output Format

The results are displayed in a **structured, human-readable format** with the following sections:

### 1. **Header Section**
```
🔍 AWS Security Infrastructure Analyzer
=====================================
Analyzing infrastructure at: ../infra
```

### 2. **File Analysis Progress**
```
📄 Analyzing: AwsIacSecurityStack.java
✅ Analysis complete. Found X security findings.
```

### 3. **Security Report Summary**
```
📊 SECURITY ANALYSIS REPORT
===========================

🚨 HIGH SEVERITY ISSUES (X)
--------------------------------------------------
📁 File: AwsIacSecurityStack.java
📍 Line: 92
🔍 Issue: Security group allows all outbound traffic
💡 Recommendation: Consider restricting outbound access to specific ports and destinations

🚨 MEDIUM SEVERITY ISSUES (X)
--------------------------------------------------
📁 File: AwsIacSecurityStack.java
📍 Line: 104
🔍 Issue: SSH port 22 is open to all IPs
💡 Recommendation: Consider using SSM Session Manager instead of direct SSH access
```

### 4. **Severity Levels**
- **🚨 HIGH**: Critical security issues requiring immediate attention
- **⚠️ MEDIUM**: Important security concerns that should be reviewed  
- **ℹ️ LOW**: Minor security improvements
- **✅ INFO**: Best practices and positive security implementations

### 5. **Categories Analyzed**
- **NETWORK_SECURITY**: Firewall and network access issues
- **ACCESS_CONTROL**: IAM and authentication issues
- **WEB_SECURITY**: HTTP/HTTPS security issues
- **MONITORING**: Logging and monitoring issues
- **RESOURCE_MANAGEMENT**: Naming, tagging, and organization

## What the Tests Analyze

The security analyzer examines your AWS CDK infrastructure code (`../infra` directory) for:

- **IAM Role Analysis**: Excessive permissions and policy attachments
- **Network Security**: Security group configurations and network access patterns
- **Access Control**: Overly permissive access rules
- **Resource Configuration**: Naming, tagging, and deployment patterns

## Prerequisites

Before running the tests, ensure you have:
- **Java 11 or higher** installed
- **Maven 3.6 or higher** installed

The scripts will check for these dependencies and show an error if they're missing.

