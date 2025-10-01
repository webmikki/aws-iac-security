# AWS Security Infrastructure Test Suite

This test suite provides automated security analysis for the AWS Security Infrastructure CDK project.

## Overview

The security analyzer examines AWS CDK infrastructure code for potential security vulnerabilities and provides hardening recommendations based on AWS security best practices. The analyzer uses external JSON configuration for security patterns, allowing easy customization without code changes.

## Features

### 🔍 **Security Analysis**
- **IAM Role Analysis**: Checks for excessive permissions and policy attachments
- **Network Security**: Analyzes security group configurations and network access patterns
- **Access Control**: Identifies overly permissive access rules
- **Resource Configuration**: Reviews resource naming, tagging, and deployment patterns

### 📊 **Vulnerability Detection**
- **High Severity**: Critical security issues requiring immediate attention
- **Medium Severity**: Security concerns that should be reviewed
- **Low Severity**: Minor security improvements
- **Info**: Best practices and positive security implementations

### 🛡️ **Hardening Recommendations**
- Network security improvements
- Access control enhancements
- Monitoring and logging setup
- Data protection measures
- Infrastructure hardening guidelines

### ⚙️ **Configuration Management**
- **External JSON Configuration**: Security patterns defined in `config/securitycheck-patterns.json`
- **No Recompilation**: Add/modify patterns without code changes
- **Easy Customization**: Enable/disable patterns, change severity levels
- **Load on Each Run**: Configuration loaded fresh on every analysis
- **Standards Compliance**: Patterns mapped to CIS, NIST, AWS, and OWASP standards

## Quick Start

### Prerequisites
- Java 11 or higher
- Maven 3.6 or higher

### Windows
```cmd
cd test
run-security-test.bat
```

### Linux/macOS
```bash
cd test
chmod +x run-security-test.sh
./run-security-test.sh
```

### Manual Execution
```bash
cd test
mvn clean compile
mvn exec:java -Dexec.mainClass="com.aws-iac-security.security.SecurityAnalyzer" -Dexec.args="../infra"
```

## Configuration

### 📁 **Configuration File**
The security patterns are defined in `config/securitycheck-patterns.json`:

```json
{
  "securityPatterns": [
    {
      "id": "EXCESSIVE_OUTBOUND_ACCESS",
      "pattern": "allowAllOutbound.*true",
      "severity": "HIGH",
      "category": "NETWORK_SECURITY",
      "description": "Security group allows all outbound traffic",
      "recommendation": "Consider restricting outbound access to specific ports and destinations",
      "standards": ["CIS-4.1", "AWS-IAM-BP"],
      "enabled": true
    }
  ]
}
```

### ⚙️ **Customizing Patterns**
- **Add New Patterns**: Edit the JSON file and add new pattern objects
- **Modify Existing**: Change severity, description, or recommendations
- **Enable/Disable**: Set `"enabled": true/false` for any pattern
- **No Recompilation**: Changes take effect on next run
- **Simple Workflow**: Edit JSON → Run analyzer → See results

## Security Checks

### 🔐 **IAM Security**
- ✅ SSM Session Manager usage (good practice)
- ✅ CloudWatch logging permissions (good practice)
- ⚠️ Excessive outbound access detection
- ⚠️ Overly permissive role policies

### 🌐 **Network Security**
- ⚠️ Wide ingress access (0.0.0.0/0) detection
- ⚠️ SSH port exposure analysis
- ⚠️ Public subnet usage warnings
- ✅ DNS configuration review

### 🏷️ **Resource Management**
- ✅ Consistent naming convention validation
- ✅ Project tagging verification
- ✅ Resource organization analysis

## Sample Output

```
🔍 AWS Security Infrastructure Analyzer
=====================================
Analyzing infrastructure at: ../infra

📄 Analyzing: AwsIacSecurityStack.java
✅ Analysis complete. Found 8 security findings.

📊 SECURITY ANALYSIS REPORT
===========================

🚨 HIGH SEVERITY ISSUES (2)
--------------------------------------------------
📁 File: AwsIacSecurityStack.java
📍 Line: 92
🔍 Issue: Security group allows all outbound traffic
💡 Recommendation: Consider restricting outbound access to specific ports and destinations

🚨 MEDIUM SEVERITY ISSUES (3)
--------------------------------------------------
📁 File: AwsIacSecurityStack.java
📍 Line: 104
🔍 Issue: SSH port 22 is open to all IPs
💡 Recommendation: Consider using SSM Session Manager instead of direct SSH access
```

## Security Patterns Detected

| Pattern | Severity | Description |
|---------|----------|-------------|
| `allowAllOutbound.*true` | HIGH | Excessive outbound access |
| `Peer\.anyIpv4\(\)` | HIGH | Wide ingress access |
| `Port\.tcp\(22\)` | MEDIUM | SSH access open |
| `SubnetType\.PUBLIC` | MEDIUM | Public subnet usage |
| `AmazonSSMManagedInstanceCore` | INFO | Good SSM practice |
| `aws-security-.*` | INFO | Consistent naming |

## Hardening Recommendations

### 1. 🔐 Network Security
- Implement VPC Flow Logs for network monitoring
- Use private subnets for sensitive resources
- Implement Network ACLs for additional security layer
- Consider AWS WAF for web application protection

### 2. 🚪 Access Control
- Replace SSH access with SSM Session Manager
- Implement least privilege IAM policies
- Use IAM roles instead of access keys
- Enable MFA for all user accounts

### 3. 🔍 Monitoring & Logging
- Enable CloudTrail for API call logging
- Implement CloudWatch alarms for security events
- Use AWS Config for compliance monitoring
- Set up GuardDuty for threat detection

### 4. 🔒 Data Protection
- Enable encryption at rest for EBS volumes
- Use AWS KMS for key management
- Implement data classification policies
- Regular security updates and patching

### 5. 🏗️ Infrastructure Hardening
- Use AWS Systems Manager for patch management
- Implement security baselines using AWS Config rules
- Regular security assessments and penetration testing
- Implement automated security scanning in CI/CD pipeline

## Integration with CI/CD

Add security analysis to your CI/CD pipeline:

```yaml
# GitHub Actions example
- name: Run Security Analysis
  run: |
    cd test
    mvn clean compile
    mvn exec:java -Dexec.mainClass="com.aws-iac-security.security.SecurityAnalyzer" -Dexec.args="../infra config/securitycheck-patterns.json"
```

## Customization

### Adding New Security Patterns

Edit `SecurityAnalyzer.java` and add patterns to the `SECURITY_PATTERNS` map:

```java
SECURITY_PATTERNS.put("your-pattern", 
    new SecurityIssue("ISSUE_ID", "SEVERITY", 
        "Description", "Recommendation"));
```

### Modifying Severity Levels

Update the severity levels in the pattern definitions:
- `HIGH`: Critical issues requiring immediate attention
- `MEDIUM`: Important issues that should be reviewed
- `LOW`: Minor improvements
- `INFO`: Best practices and positive findings

## References

- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [AWS Well-Architected Security Pillar](https://aws.amazon.com/architecture/well-architected/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS CDK Security Guidelines](https://docs.aws.amazon.com/cdk/latest/guide/security.html)
