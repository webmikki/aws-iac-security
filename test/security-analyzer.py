#!/usr/bin/env python3
"""
AWS Security Infrastructure Analyzer
====================================

This script analyzes AWS CDK infrastructure code for security vulnerabilities
and compliance issues. It checks for common security misconfigurations,
best practices violations, and potential attack vectors.

Author: Security Team
Version: 1.0.0
"""

import os
import re
import json
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

# Fix Windows console encoding for emojis
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

# PDF generation imports
try:
    from reportlab.lib.pagesizes import letter, A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

@dataclass
class SecurityFinding:
    """Represents a security finding"""
    id: str
    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    file_path: str
    line_number: int
    code_snippet: str
    standards: List[str]

class SecurityAnalyzer:
    """Main security analyzer class"""
    
    def __init__(self, infra_path: str, patterns_file: str = None):
        self.infra_path = Path(infra_path)
        self.findings: List[SecurityFinding] = []
        self.patterns_file = patterns_file or "security-patterns.json"
        self.patterns = self._load_security_patterns()
        
    def _load_security_patterns(self) -> Dict[str, Any]:
        """Load security analysis patterns from JSON file"""
        try:
            # Try to load from current directory first
            patterns_path = Path(self.patterns_file)
            if not patterns_path.exists():
                # Try to load from the same directory as the script
                script_dir = Path(__file__).parent
                patterns_path = script_dir / self.patterns_file
            
            if not patterns_path.exists():
                print(f"⚠️  Patterns file not found: {self.patterns_file}")
                print("   Using default patterns...")
                return self._get_default_patterns()
            
            with open(patterns_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            print(f"📋 Loaded security patterns from: {patterns_path}")
            print(f"   Version: {config.get('version', 'Unknown')}")
            print(f"   Last Updated: {config.get('lastUpdated', 'Unknown')}")
            
            # Convert patterns to the expected format
            patterns = {}
            for category, pattern_list in config.get('patterns', {}).items():
                patterns[category] = [p for p in pattern_list if p.get('enabled', True)]
            
            return patterns
            
        except Exception as e:
            print(f"❌ Error loading patterns file: {e}")
            print("   Using default patterns...")
            return self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Fallback default patterns if JSON file cannot be loaded"""
        return {
            "network_security": [
                {
                    "id": "WIDE_SSH_ACCESS",
                    "pattern": r"Peer\.anyIpv4\(\).*Port\.tcp\(22\)",
                    "severity": "HIGH",
                    "category": "NETWORK_SECURITY",
                    "title": "SSH Access from Anywhere",
                    "description": "SSH port 22 is open to all IP addresses (0.0.0.0/0)",
                    "recommendation": "Restrict SSH access to specific IP ranges or use SSM Session Manager",
                    "standards": ["CIS-4.2", "NIST-CSF-PR.AC-5"],
                    "enabled": True
                }
            ],
            "deployment_security": [
                {
                    "id": "AUTO_APPROVAL",
                    "pattern": r"--require-approval never",
                    "severity": "HIGH",
                    "category": "DEPLOYMENT_SECURITY",
                    "title": "Automatic Deployment Approval",
                    "description": "CDK deployment without manual approval",
                    "recommendation": "Require manual approval for production deployments",
                    "standards": ["CIS-2.3", "NIST-CSF-PR.IP-1"],
                    "enabled": True
                }
            ]
        }
    
    def analyze_infrastructure(self) -> List[SecurityFinding]:
        """Analyze the infrastructure for security issues"""
        print("🔍 Starting AWS Security Infrastructure Analysis")
        print("=" * 50)
        
        # Analyze Java CDK files
        java_files = list(self.infra_path.rglob("*.java"))
        for java_file in java_files:
            self._analyze_java_file(java_file)
        
        # Analyze deployment scripts
        script_files = list(self.infra_path.glob("deploy.*"))
        for script_file in script_files:
            self._analyze_script_file(script_file)
        
        # Analyze CDK configuration
        cdk_config = self.infra_path / "cdk.json"
        if cdk_config.exists():
            self._analyze_cdk_config(cdk_config)
        
        return self.findings
    
    def _analyze_java_file(self, file_path: Path) -> None:
        """Analyze Java CDK files for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            print(f"📄 Analyzing: {file_path.name}")
            
            # Check all security patterns
            for category, patterns in self.patterns.items():
                for pattern_info in patterns:
                    if pattern_info.get('pattern'):
                        matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE | re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            code_snippet = self._extract_code_snippet(lines, line_num)
                            
                            finding = SecurityFinding(
                                id=pattern_info['id'],
                                severity=pattern_info['severity'],
                                category=pattern_info['category'],
                                title=pattern_info['title'],
                                description=pattern_info['description'],
                                recommendation=pattern_info['recommendation'],
                                file_path=str(file_path),
                                line_number=line_num,
                                code_snippet=code_snippet,
                                standards=pattern_info['standards']
                            )
                            self.findings.append(finding)
        
        except Exception as e:
            print(f"❌ Error analyzing {file_path}: {e}")
    
    def _analyze_script_file(self, file_path: Path) -> None:
        """Analyze deployment scripts for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            print(f"📄 Analyzing: {file_path.name}")
            
            # Check for deployment security patterns
            deployment_patterns = self.patterns.get('deployment_security', [])
            for pattern_info in deployment_patterns:
                if pattern_info.get('pattern'):
                    matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        code_snippet = self._extract_code_snippet(lines, line_num)
                        
                        finding = SecurityFinding(
                            id=pattern_info['id'],
                            severity=pattern_info['severity'],
                            category=pattern_info['category'],
                            title=pattern_info['title'],
                            description=pattern_info['description'],
                            recommendation=pattern_info['recommendation'],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=code_snippet,
                            standards=pattern_info['standards']
                        )
                        self.findings.append(finding)
        
        except Exception as e:
            print(f"❌ Error analyzing {file_path}: {e}")
    
    def _analyze_cdk_config(self, file_path: Path) -> None:
        """Analyze CDK configuration for security issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            print(f"📄 Analyzing: {file_path.name}")
            
            # Check for security-related CDK context settings
            context = config.get('context', {})
            
            # Check for security best practices
            security_checks = [
                ('@aws-cdk/core:checkSecretUsage', 'Secret usage checking enabled', 'INFO'),
                ('@aws-cdk/aws-iam:minimizePolicies', 'IAM policy minimization enabled', 'INFO'),
                ('@aws-cdk/aws-ec2:restrictDefaultSecurityGroup', 'Default security group restriction enabled', 'INFO'),
                ('@aws-cdk/aws-efs:denyAnonymousAccess', 'EFS anonymous access denied', 'INFO')
            ]
            
            for check, description, severity in security_checks:
                if context.get(check, False):
                    finding = SecurityFinding(
                        id=f"CDK_{check.replace('@aws-cdk/', '').replace(':', '_').upper()}",
                        severity=severity,
                        category="CONFIGURATION_SECURITY",
                        title=description,
                        description=f"CDK context setting: {check}",
                        recommendation="Good security practice enabled",
                        file_path=str(file_path),
                        line_number=1,
                        code_snippet=f'"{check}": true',
                        standards=["AWS-Well-Architected-Security"]
                    )
                    self.findings.append(finding)
        
        except Exception as e:
            print(f"❌ Error analyzing {file_path}: {e}")
    
    def _extract_code_snippet(self, lines: List[str], line_num: int, context: int = 3) -> str:
        """Extract code snippet around the finding"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:3d}: {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def generate_report(self) -> None:
        """Generate security analysis report"""
        print("\n" + "=" * 60)
        print("🛡️  AWS SECURITY INFRASTRUCTURE ANALYSIS REPORT")
        print("=" * 60)
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Infrastructure Path: {self.infra_path}")
        print(f"Total Findings: {len(self.findings)}")
        print()
        
        if not self.findings:
            print("✅ No security findings detected!")
            return
        
        # Group findings by severity
        severity_groups = {}
        for finding in self.findings:
            severity = finding.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Print findings by severity
        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
        for severity in severity_order:
            if severity in severity_groups:
                findings = severity_groups[severity]
                print(f"🚨 {severity} SEVERITY ({len(findings)} findings)")
                print("-" * 50)
                
                for finding in findings:
                    print(f"📁 File: {Path(finding.file_path).name}")
                    print(f"📍 Line: {finding.line_number}")
                    print(f"🔍 Issue: {finding.title}")
                    print(f"📝 Description: {finding.description}")
                    print(f"💡 Recommendation: {finding.recommendation}")
                    print(f"📋 Standards: {', '.join(finding.standards)}")
                    print(f"📄 Code:")
                    print(finding.code_snippet)
                    print()
        
        # Generate hardening recommendations
        self._generate_hardening_recommendations()
        
        # Generate summary
        self._generate_summary()
    
    def _generate_hardening_recommendations(self) -> None:
        """Generate security hardening recommendations"""
        print("🛡️  SECURITY HARDENING RECOMMENDATIONS")
        print("=" * 50)
        print()
        
        recommendations = [
            {
                "category": "🔐 Network Security",
                "items": [
                    "Implement VPC Flow Logs for network monitoring",
                    "Use private subnets for sensitive resources",
                    "Implement Network ACLs for additional security layer",
                    "Consider using AWS WAF for web application protection",
                    "Restrict SSH access to specific IP ranges or use SSM Session Manager"
                ]
            },
            {
                "category": "🚪 Access Control",
                "items": [
                    "Implement least privilege IAM policies",
                    "Use IAM roles instead of access keys",
                    "Enable MFA for all user accounts",
                    "Regular access reviews and cleanup"
                ]
            },
            {
                "category": "🔍 Monitoring & Logging",
                "items": [
                    "Enable CloudTrail for API call logging",
                    "Implement CloudWatch alarms for security events",
                    "Use AWS Config for compliance monitoring",
                    "Set up GuardDuty for threat detection"
                ]
            },
            {
                "category": "🔒 Data Protection",
                "items": [
                    "Enable encryption at rest for EBS volumes",
                    "Use AWS KMS for key management",
                    "Implement data classification policies",
                    "Regular security updates and patching"
                ]
            },
            {
                "category": "🏗️ Infrastructure Hardening",
                "items": [
                    "Use AWS Systems Manager for patch management",
                    "Implement security baselines using AWS Config rules",
                    "Regular security assessments and penetration testing",
                    "Implement automated security scanning in CI/CD pipeline"
                ]
            }
        ]
        
        for rec in recommendations:
            print(f"{rec['category']}:")
            for item in rec['items']:
                print(f"   • {item}")
            print()
    
    def _generate_summary(self) -> None:
        """Generate analysis summary"""
        print("📈 ANALYSIS SUMMARY")
        print("=" * 30)
        
        severity_counts = {}
        for finding in self.findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total findings: {len(self.findings)}")
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            print(f"{severity} severity: {count}")
        
        print()
        
        if severity_counts.get('HIGH', 0) > 0:
            print("⚠️  CRITICAL: High severity issues found - immediate attention required!")
        elif severity_counts.get('MEDIUM', 0) > 0:
            print("⚠️  WARNING: Medium severity issues found - review recommended")
        else:
            print("✅ GOOD: No high or medium severity issues found")
        
        print()
        print("🔗 For more information, refer to:")
        print("   • AWS Security Best Practices: https://aws.amazon.com/security/security-resources/")
        print("   • AWS Well-Architected Security Pillar: https://aws.amazon.com/architecture/well-architected/")
        print("   • CIS AWS Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services")
    
    def save_report(self, output_file: str) -> None:
        """Save report to JSON file"""
        report_data = {
            "analysis_date": datetime.now().isoformat(),
            "infrastructure_path": str(self.infra_path),
            "total_findings": len(self.findings),
            "findings": [asdict(finding) for finding in self.findings]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"📄 Report saved to: {output_file}")
    
    def save_pdf_report(self, output_file: str) -> None:
        """Save report to PDF file"""
        if not PDF_AVAILABLE:
            print("❌ PDF generation requires reportlab library. Install with: pip install reportlab")
            return
        
        doc = SimpleDocTemplate(output_file, pagesize=landscape(A4), topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        story.append(Paragraph("AWS Security Infrastructure Analysis Report", title_style))
        story.append(Spacer(1, 12))
        
        # Summary
        summary_style = ParagraphStyle(
            'Summary',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=12
        )
        
        story.append(Paragraph(f"<b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", summary_style))
        story.append(Paragraph(f"<b>Infrastructure Path:</b> {self.infra_path}", summary_style))
        story.append(Paragraph(f"<b>Total Findings:</b> {len(self.findings)}", summary_style))
        story.append(Spacer(1, 20))
        
        # Findings by severity
        severity_groups = {}
        for finding in self.findings:
            severity = finding.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
        severity_colors = {
            'HIGH': colors.red,
            'MEDIUM': colors.orange,
            'LOW': colors.yellow,
            'INFO': colors.blue
        }
        
        for severity in severity_order:
            if severity in severity_groups:
                findings = severity_groups[severity]
                
                # Severity header
                severity_style = ParagraphStyle(
                    f'Severity{severity}',
                    parent=styles['Heading2'],
                    fontSize=16,
                    spaceAfter=12,
                    textColor=severity_colors.get(severity, colors.black)
                )
                story.append(Paragraph(f"{severity} SEVERITY ({len(findings)} findings)", severity_style))
                
                # Findings table
                table_data = [['File', 'Line', 'Issue', 'Description']]
                for finding in findings:
                    table_data.append([
                        Path(finding.file_path).name,
                        str(finding.line_number),
                        finding.title,
                        finding.description[:100] + "..." if len(finding.description) > 100 else finding.description
                    ])
                
                table = Table(table_data, colWidths=[2*inch, 0.7*inch, 2.5*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(table)
                story.append(Spacer(1, 20))
        
        # Hardening recommendations
        story.append(Paragraph("Security Hardening Recommendations", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        recommendations = [
            "Network Security: Implement VPC Flow Logs, use private subnets, restrict SSH access",
            "Access Control: Implement least privilege IAM policies, enable MFA",
            "Monitoring: Enable CloudTrail, CloudWatch alarms, GuardDuty",
            "Data Protection: Enable encryption at rest, use AWS KMS",
            "Infrastructure: Use Systems Manager, implement security baselines"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        print(f"📄 PDF report saved to: {output_file}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AWS Security Infrastructure Analyzer')
    parser.add_argument('infra_path', help='Path to infrastructure directory')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-p', '--pdf', help='Output PDF report file')
    parser.add_argument('-f', '--patterns-file', help='Security patterns JSON file (default: security-patterns.json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.infra_path):
        print(f"❌ Infrastructure path not found: {args.infra_path}")
        sys.exit(1)
    
    analyzer = SecurityAnalyzer(args.infra_path, args.patterns_file)
    findings = analyzer.analyze_infrastructure()
    analyzer.generate_report()
    
    if args.output:
        analyzer.save_report(args.output)
    
    if args.pdf:
        analyzer.save_pdf_report(args.pdf)

if __name__ == "__main__":
    main()
