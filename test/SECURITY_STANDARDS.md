# Security Standards & Framework Mapping

## 🏛️ **Standards & Frameworks Used**

### **1. AWS Security Best Practices**
- **AWS Well-Architected Security Pillar**: Core principles for secure cloud architecture
- **AWS IAM Best Practices**: Least privilege access, role-based permissions
- **AWS Security Documentation**: Official AWS security guidelines

### **2. Industry Security Standards**
- **CIS AWS Foundations Benchmark**: Center for Internet Security controls for AWS
- **NIST Cybersecurity Framework**: Risk management and security controls
- **OWASP Top 10**: Web application security risks (adapted for infrastructure)

### **3. Cloud Security Frameworks**
- **Cloud Security Alliance (CSA)**: Cloud security best practices
- **ISO 27001**: Information security management standards
- **SOC 2**: Security, availability, and confidentiality controls

## 🔍 **Security Checks Mapping**

| Check | Standard/Framework | Reference | Severity |
|-------|-------------------|-----------|----------|
| **Excessive Outbound Access** | CIS 4.1, AWS IAM Best Practices | CIS AWS 4.1.1 | HIGH |
| **Wide Ingress Access (0.0.0.0/0)** | CIS 4.2, NIST CSF PR.AC-5 | CIS AWS 4.2.1 | HIGH |
| **SSH Port Exposure** | CIS 4.3, AWS Security Best Practices | CIS AWS 4.3.1 | MEDIUM |
| **Public Subnet Usage** | AWS Well-Architected, NIST CSF PR.AC-5 | AWS WA Security | MEDIUM |
| **HTTP Access Open** | OWASP A05, NIST CSF PR.AC-5 | OWASP Top 10 2021 | LOW |
| **HTTPS Access Open** | OWASP A02, NIST CSF PR.AC-5 | OWASP Top 10 2021 | LOW |
| **SSM Usage** | AWS Security Best Practices | AWS IAM Best Practices | INFO |
| **CloudWatch Logging** | CIS 3.1, NIST CSF DE.AE-1 | CIS AWS 3.1.1 | INFO |
| **Consistent Naming** | AWS Well-Architected, NIST CSF ID.AM-1 | AWS WA Operational Excellence | INFO |
| **Project Tagging** | AWS Well-Architected, NIST CSF ID.AM-2 | AWS WA Cost Optimization | INFO |

## 📚 **Detailed Standards References**

### **CIS AWS Foundations Benchmark v1.5.0**
- **Control 4.1**: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
- **Control 4.2**: Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
- **Control 4.3**: Ensure the default security group of every VPC restricts all traffic
- **Control 3.1**: Ensure CloudTrail is enabled in all regions

### **AWS Well-Architected Security Pillar**
- **SEC-1**: How do you securely operate your workload?
- **SEC-2**: How do you manage identities and permissions?
- **SEC-3**: How do you detect and investigate security events?
- **SEC-4**: How do you protect your data?

### **NIST Cybersecurity Framework**
- **PR.AC-5**: Network integrity is protected
- **PR.AC-6**: Identities are proofed and bound to credentials
- **DE.AE-1**: A baseline of network operations is established
- **ID.AM-1**: Physical devices and systems are inventoried

### **OWASP Top 10 2021**
- **A02:2021 – Cryptographic Failures**: Insecure transmission
- **A05:2021 – Security Misconfiguration**: Insecure default configurations

## 🎯 **Risk Assessment Methodology**

### **Severity Levels**
- **HIGH**: Direct violation of CIS controls or critical AWS security practices
- **MEDIUM**: Potential security risk that should be reviewed
- **LOW**: Minor security improvement opportunity
- **INFO**: Positive security practice or informational finding

### **Risk Scoring**
- **CIS Critical**: HIGH severity
- **CIS Important**: MEDIUM severity
- **AWS Best Practice**: LOW to INFO severity
- **Industry Standard**: Based on impact and likelihood

## 🔗 **Reference Links**

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Security Pillar](https://aws.amazon.com/architecture/well-architected/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## 📊 **Compliance Mapping**

| Standard | Coverage | Key Controls |
|----------|----------|--------------|
| **CIS AWS** | 80% | Network security, IAM, logging |
| **NIST CSF** | 70% | Access control, monitoring |
| **AWS WA** | 90% | Architecture, operations |
| **SOC 2** | 60% | Access control, monitoring |
| **ISO 27001** | 50% | Information security management |
