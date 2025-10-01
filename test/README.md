# AWS Security Infrastructure Analyzer

This directory contains security analysis tools for the AWS Infrastructure as Code (IaC) deployment.

## Overview

The security analyzer scans AWS CDK infrastructure code for common security vulnerabilities, misconfigurations, and compliance issues. It provides detailed reports with recommendations for improving security posture.

## Files

- `security-analyzer.py` - Main Python security analysis script
- `security-patterns.json` - Security patterns configuration file
- `run-security-analysis.bat` - Windows batch script to run the analysis
- `run-security-analysis.sh` - Unix/Linux shell script to run the analysis
- `security-report.json` - Generated security analysis report (created after running)
- `security-report.pdf` - Generated PDF security report (created after running)

## Prerequisites

- Python 3.7 or higher
- Access to the `../infra` directory containing the AWS CDK code

## Quick Start

### Windows
```cmd
run-security-analysis.bat
```

### Unix/Linux/macOS
```bash
./run-security-analysis.sh
```

### Manual Execution
```bash
# Basic analysis (console output only)
python security-analyzer.py ../infra

# JSON report
python security-analyzer.py ../infra -o security-report.json

# PDF report
python security-analyzer.py ../infra -p security-report.pdf

# Both JSON and PDF
python security-analyzer.py ../infra -o security-report.json -p security-report.pdf

# Custom patterns file
python security-analyzer.py ../infra -f custom-patterns.json

# All options
python security-analyzer.py ../infra -o security-report.json -p security-report.pdf -f security-patterns.json
```

## Security Patterns Configuration

The analyzer uses externalized security patterns defined in `security-patterns.json`. This allows you to:

- **Customize patterns** without modifying the Python code
- **Enable/disable** specific security checks
- **Add new patterns** for your specific environment
- **Modify severity levels** and recommendations
- **Version control** your security policies

### Pattern Structure
```json
{
  "id": "WIDE_SSH_ACCESS",
  "pattern": "Peer\\.anyIpv4\\(\\)",
  "severity": "HIGH",
  "category": "NETWORK_SECURITY",
  "title": "SSH Access from Anywhere",
  "description": "SSH port 22 is open to all IP addresses (0.0.0.0/0)",
  "recommendation": "Restrict SSH access to specific IP ranges or use SSM Session Manager",
  "standards": ["CIS-4.2", "NIST-CSF-PR.AC-5"],
  "enabled": true
}
```

### Customizing Patterns
1. **Edit** `security-patterns.json`
2. **Add new patterns** to the appropriate category
3. **Modify existing patterns** as needed
4. **Set `enabled: false`** to disable specific checks
5. **Run the analyzer** with your custom patterns

## Security Checks

The analyzer performs the following security checks:

### Network Security
- **SSH Access from Anywhere** (HIGH) - Detects SSH port 22 open to 0.0.0.0/0
- **HTTP Access from Anywhere** (MEDIUM) - Detects HTTP port 80 open to 0.0.0.0/0
- **HTTPS Access from Anywhere** (MEDIUM) - Detects HTTPS port 443 open to 0.0.0.0/0
- **Unrestricted Outbound Access** (MEDIUM) - Detects `allowAllOutbound(true)`

### Access Control
- **EC2 Service Principal** (LOW) - Detects IAM roles attached to EC2 instances
- **AWS Managed Policies** (INFO) - Identifies use of AWS managed policies

### Infrastructure Security
- **Resources in Public Subnet** (MEDIUM) - Detects EC2 instances in public subnets
- **No Encryption at Rest** (MEDIUM) - Detects missing EBS encryption
- **Limited Monitoring** (LOW) - Detects missing CloudWatch configuration

### Deployment Security
- **Automatic Deployment Approval** (HIGH) - Detects `--require-approval never`
- **Bootstrap Error Handling** (MEDIUM) - Detects ignored CDK bootstrap errors

### Configuration Security
- **CDK Security Context** (INFO) - Identifies enabled security best practices

## Output Formats

The analyzer generates **3 output formats**:

### 1. **Console Report** (Default)
- **Format:** Rich text with emojis and colors
- **Content:** Detailed findings with code snippets and recommendations
- **Usage:** Automatically displayed when running the analyzer

### 2. **JSON Report** 
- **Format:** Machine-readable JSON
- **Content:** Structured data for integration with other tools
- **Usage:** `python security-analyzer.py ../infra -o security-report.json`

### 3. **PDF Report** ⭐ **NEW!**
- **Format:** Professional PDF document
- **Content:** Formatted findings table with hardening recommendations
- **Usage:** `python security-analyzer.py ../infra -p security-report.pdf`
- **Requirements:** `pip install reportlab`

### **Combined Output**
```bash
# Generate all formats at once
python security-analyzer.py ../infra -o security-report.json -p security-report.pdf
```

### **Report Structure (JSON)**
```json
{
  "analysis_date": "2024-01-01T12:00:00",
  "infrastructure_path": "../infra",
  "total_findings": 5,
  "findings": [
    {
      "id": "WIDE_SSH_ACCESS",
      "severity": "HIGH",
      "category": "NETWORK_SECURITY",
      "title": "SSH Access from Anywhere",
      "description": "SSH port 22 is open to all IP addresses (0.0.0.0/0)",
      "recommendation": "Restrict SSH access to specific IP ranges or use SSM Session Manager",
      "file_path": "../infra/src/main/java/com/aws-iac-security/AwsIacSecurityStack.java",
      "line_number": 104,
      "code_snippet": ">>> 104: ec2SecurityGroup.addIngressRule(\n   105:         Peer.anyIpv4(),\n   106:         Port.tcp(22),",
      "standards": ["CIS-4.2", "NIST-CSF-PR.AC-5"]
    }
  ]
}
```

### **PDF Report Features**
- **Professional Layout:** Clean, corporate-ready format
- **Color-Coded Severity:** High (Red), Medium (Orange), Low (Yellow), Info (Blue)
- **Structured Tables:** Easy-to-read findings summary
- **Hardening Recommendations:** Actionable security improvements
- **Standards Compliance:** References to CIS, NIST, and AWS frameworks

## Security Standards

The analyzer checks against:

- **CIS AWS Foundations Benchmark** - Center for Internet Security benchmarks
- **NIST Cybersecurity Framework** - National Institute of Standards and Technology
- **AWS Well-Architected Security Pillar** - AWS best practices

## Hardening Recommendations

The analyzer provides comprehensive hardening recommendations for:

- 🔐 **Network Security** - VPC Flow Logs, private subnets, WAF
- 🚪 **Access Control** - Least privilege, MFA, role-based access
- 🔍 **Monitoring & Logging** - CloudTrail, CloudWatch, GuardDuty
- 🔒 **Data Protection** - Encryption, KMS, data classification
- 🏗️ **Infrastructure Hardening** - Patch management, security baselines

## Examples

### Running Analysis
```bash
# Basic analysis
python security-analyzer.py ../infra

# With JSON output
python security-analyzer.py ../infra -o my-report.json

# Verbose output
python security-analyzer.py ../infra -v
```

### Sample Output
```
🔍 AWS Security Infrastructure Analysis
=====================================

📄 Analyzing: AwsIacSecurityStack.java
📄 Analyzing: deploy.bat
📄 Analyzing: cdk.json

============================================================
🛡️  AWS SECURITY INFRASTRUCTURE ANALYSIS REPORT
============================================================
Analysis Date: 2024-01-01 12:00:00
Infrastructure Path: ../infra
Total Findings: 3

🚨 HIGH SEVERITY (1 findings)
--------------------------------------------------
📁 File: AwsIacSecurityStack.java
📍 Line: 104
🔍 Issue: SSH Access from Anywhere
📝 Description: SSH port 22 is open to all IP addresses (0.0.0.0/0)
💡 Recommendation: Restrict SSH access to specific IP ranges or use SSM Session Manager
📋 Standards: CIS-4.2, NIST-CSF-PR.AC-5
📄 Code:
>>> 104: ec2SecurityGroup.addIngressRule(
   105:         Peer.anyIpv4(),
   106:         Port.tcp(22),
```

## Contributing

To add new security checks:

1. Add patterns to the `_load_security_patterns()` method
2. Define pattern regex, severity, category, and recommendations
3. Test with sample infrastructure code
4. Update this README with new check descriptions

## License

This security analyzer is part of the AWS Security Infrastructure project.
