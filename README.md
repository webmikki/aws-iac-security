# AWS Security Infrastructure Analysis

A comprehensive security analysis framework for AWS Infrastructure as Code (IaC) deployments using AWS CDK. This project provides automated security scanning, vulnerability detection, and compliance reporting for AWS infrastructure deployments.

## 🏗️ Project Structure

```
aws-iac-security/
├── infra/                    # AWS CDK Infrastructure Code
│   ├── src/main/java/       # Java CDK Stack Definitions
│   ├── cdk.json            # CDK Configuration
│   ├── deploy.bat          # Windows Deployment Script
│   └── deploy.sh           # Unix/Linux Deployment Script
├── test/                    # Security Analysis Tools
│   ├── security-analyzer.py # Main Security Analysis Script
│   ├── security-patterns.json # Security Patterns Configuration
│   ├── run-security-analysis.bat # Windows Analysis Script
│   ├── run-security-analysis.sh  # Unix/Linux Analysis Script
│   └── security-report.*   # Generated Security Reports
└── README.md               # This file
```

## 🚀 Quick Start

### 1. Deploy AWS Infrastructure
```bash
# Windows
cd infra
deploy.bat

# Unix/Linux/macOS
cd infra
./deploy.sh
```

### 2. Run Security Analysis
```bash
# Windows
cd test
run-security-analysis.bat

# Unix/Linux/macOS
cd test
./run-security-analysis.sh

# Manual execution
python security-analyzer.py ../infra -o security-report.json -p security-report.pdf
```

## 🛡️ Security Analysis Features

### **Comprehensive Security Scanning**
- **Network Security** - VPC, Security Groups, Subnet Analysis
- **Access Control** - IAM Roles, Policies, Permissions Review
- **Infrastructure Security** - Resource Placement, Configuration Analysis
- **Data Protection** - Encryption, Data Handling Practices
- **Deployment Security** - CI/CD Pipeline Security Review
- **Compliance** - CIS, NIST, AWS Well-Architected Standards

### **Multiple Output Formats**
- **Console Report** - Rich text with emojis and colors
- **JSON Report** - Machine-readable structured data
- **PDF Report** - Professional landscape format for stakeholders

### **Customizable Security Patterns**
- **Externalized Configuration** - JSON-based pattern definitions
- **Enable/Disable Checks** - Toggle specific security rules
- **Custom Patterns** - Add organization-specific security rules
- **Version Control** - Track security policy changes over time

## 📊 Security Analysis Results

The analyzer identifies security issues across multiple categories:

- **🚨 HIGH Severity** - Critical issues requiring immediate attention
- **⚠️ MEDIUM Severity** - Important issues that should be reviewed
- **📋 LOW Severity** - Minor security improvements
- **ℹ️ INFO Severity** - Best practices and positive implementations

### **Sample Findings**
- SSH access from anywhere (0.0.0.0/0)
- Unrestricted outbound security group rules
- Resources placed in public subnets
- Missing encryption at rest
- Automatic deployment approval without review

## 🔧 Prerequisites

### **For Infrastructure Deployment**
- Java 11 or higher
- Maven 3.6+
- AWS CLI configured
- AWS CDK 2.x

### **For Security Analysis**
- Python 3.7+
- reportlab (for PDF generation): `pip install reportlab`

## 📋 Installation

### **1. Clone the Repository**
```bash
git clone <repository-url>
cd aws-iac-security
```

### **2. Install Dependencies**
```bash
# Install Python dependencies for security analysis
cd test
pip install -r requirements.txt
```

### **3. Configure AWS Credentials**
```bash
aws configure
# Or use AWS SSO, IAM roles, etc.
```

## 🚀 Usage

### **Deploy Infrastructure**
```bash
cd infra
# Windows
deploy.bat

# Unix/Linux/macOS
./deploy.sh
```

### **Run Security Analysis**
```bash
cd test
# Windows
run-security-analysis.bat

# Unix/Linux/macOS
./run-security-analysis.sh

# Custom analysis
python security-analyzer.py ../infra -f custom-patterns.json -o report.json -p report.pdf
```

## 📁 Key Files

### **Infrastructure (`infra/`)**
- `AwsIacSecurityStack.java` - Main CDK stack definition
- `cdk.json` - CDK configuration with security best practices
- `deploy.bat` / `deploy.sh` - Automated deployment scripts

### **Security Analysis (`test/`)**
- `security-analyzer.py` - Main security analysis engine
- `security-patterns.json` - Configurable security patterns
- `run-security-analysis.*` - Analysis execution scripts
- `README.md` - Detailed analysis documentation

## 🔒 Security Standards

The analyzer checks against industry standards:

- **CIS AWS Foundations Benchmark** - Center for Internet Security
- **NIST Cybersecurity Framework** - National Institute of Standards
- **AWS Well-Architected Security Pillar** - AWS best practices
- **Custom Organization Standards** - Configurable via JSON patterns

## 📈 Sample Analysis Output

```
🔍 AWS Security Infrastructure Analysis
=====================================

📋 Loaded security patterns from: security-patterns.json
   Version: 1.0.0
   Last Updated: 2025-10-01

📄 Analyzing: AwsIacSecurityStack.java
📄 Analyzing: deploy.bat
📄 Analyzing: cdk.json

🛡️  AWS SECURITY INFRASTRUCTURE ANALYSIS REPORT
============================================================
Analysis Date: 2025-10-01 19:00:28
Infrastructure Path: ../infra
Total Findings: 28

🚨 HIGH SEVERITY (5 findings)
⚠️ MEDIUM SEVERITY (9 findings)
📋 LOW SEVERITY (8 findings)
ℹ️ INFO SEVERITY (6 findings)

⚠️  CRITICAL: High severity issues found - immediate attention required!
```

## 🛠️ Customization

### **Adding Custom Security Patterns**
1. Edit `test/security-patterns.json`
2. Add new patterns to appropriate categories
3. Set `enabled: true/false` to control activation
4. Run analysis with custom patterns

### **Modifying Infrastructure**
1. Edit `infra/src/main/java/com/aws-iac-security/AwsIacSecurityStack.java`
2. Update CDK configuration in `infra/cdk.json`
3. Redeploy infrastructure
4. Re-run security analysis

## 📚 Documentation

- **[Infrastructure Documentation](infra/README.md)** - AWS CDK deployment details
- **[Security Analysis Documentation](test/README.md)** - Detailed analysis tool usage
- **[Security Patterns Reference](test/security-patterns.json)** - Pattern configuration guide

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add security patterns or infrastructure improvements
4. Test with security analysis
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 📞 Support

For questions or issues:
- Create an issue in the repository
- Review the documentation in `test/README.md`
- Check the security patterns configuration

---

**⚠️ Security Notice**: This tool is designed to help identify security issues in AWS infrastructure. Always review findings carefully and implement appropriate security measures based on your organization's requirements and risk tolerance.
