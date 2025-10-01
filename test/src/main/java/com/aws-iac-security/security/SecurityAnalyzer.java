package com.aws-iac-security.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.logging.Logger;

/**
 * AWS Security Infrastructure Analyzer
 * 
 * This class analyzes AWS CDK infrastructure code for potential security vulnerabilities
 * and provides hardening recommendations based on AWS security best practices.
 * 
 * The analyzer examines:
 * - IAM role permissions and policies
 * - Security group configurations
 * - Network security settings
 * - Resource naming and tagging
 * - Access control patterns
 * 
 * Now supports external JSON configuration for easy pattern management.
 */
public class SecurityAnalyzer {
    
    private static final Logger logger = Logger.getLogger(SecurityAnalyzer.class.getName());
    
    // Configuration management
    private final String configPath;
    private final SecurityPatternLoader patternLoader;
    
    private final String infraPath;
    private final List<SecurityFinding> findings;
    
    /**
     * Constructor for SecurityAnalyzer
     * 
     * @param infraPath Path to the infrastructure code directory
     */
    public SecurityAnalyzer(String infraPath) {
        this(infraPath, SecurityPatternLoader.getDefaultConfigPath());
    }
    
    /**
     * Constructor for SecurityAnalyzer with custom config path
     * 
     * @param infraPath Path to the infrastructure code directory
     * @param configPath Path to the security patterns configuration file
     */
    public SecurityAnalyzer(String infraPath, String configPath) {
        this.infraPath = infraPath;
        this.configPath = configPath;
        this.findings = new ArrayList<>();
        this.patternLoader = new SecurityPatternLoader();
    }
    
    /**
     * Load configuration from JSON file
     * 
     * @return SecurityPatternConfig loaded configuration
     * @throws IOException if configuration cannot be loaded
     */
    private SecurityPatternConfig loadConfiguration() throws IOException {
        logger.info("Loading security patterns from: " + configPath);
        SecurityPatternConfig config = patternLoader.loadPatterns(configPath);
        logger.info("Configuration loaded successfully with " + config.getSecurityPatterns().size() + " patterns");
        return config;
    }
    
    /**
     * Main method to run security analysis
     * 
     * @param args Command line arguments (infrastructure path)
     */
    public static void main(String[] args) {
        String infraPath = args.length > 0 ? args[0] : "../infra";
        String configPath = args.length > 1 ? args[1] : SecurityPatternLoader.getDefaultConfigPath();
        
        System.out.println("🔍 AWS Security Infrastructure Analyzer");
        System.out.println("=====================================");
        System.out.println("Analyzing infrastructure at: " + infraPath);
        System.out.println("Using configuration: " + configPath);
        System.out.println();
        
        SecurityAnalyzer analyzer = new SecurityAnalyzer(infraPath, configPath);
        
        try {
            analyzer.analyzeInfrastructure();
            analyzer.generateReport();
        } catch (Exception e) {
            System.err.println("❌ Analysis failed: " + e.getMessage());
            System.exit(1);
        }
    }
    
    /**
     * Analyze the entire infrastructure for security issues
     */
    public void analyzeInfrastructure() throws IOException {
        System.out.println("🔄 Starting security analysis...");
        
        // Load configuration on each run
        SecurityPatternConfig config = loadConfiguration();
        System.out.println("📋 Loaded " + config.getEnabledPatterns().size() + " active security patterns");
        
        // Analyze main stack file
        analyzeFile(infraPath + "/src/main/java/com/aws-iac-security/AwsIacSecurityStack.java", config);
        
        // Analyze app file
        analyzeFile(infraPath + "/src/main/java/com/aws-iac-security/AwsIacSecurityApp.java", config);
        
        // Analyze CDK configuration
        analyzeFile(infraPath + "/cdk.json", config);
        
        // Analyze deployment scripts
        analyzeFile(infraPath + "/deploy.bat", config);
        analyzeFile(infraPath + "/deploy.sh", config);
        
        System.out.println("✅ Analysis complete. Found " + findings.size() + " security findings.");
        System.out.println();
    }
    
    /**
     * Analyze a specific file for security issues
     * 
     * @param filePath Path to the file to analyze
     * @param config Security pattern configuration
     */
    private void analyzeFile(String filePath, SecurityPatternConfig config) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                System.out.println("⚠️  File not found: " + filePath);
                return;
            }
            
            String content = Files.readString(Paths.get(filePath));
            String fileName = file.getName();
            
            System.out.println("📄 Analyzing: " + fileName);
            
            // Check each enabled security pattern from configuration
            for (SecurityPattern pattern : config.getEnabledPatterns()) {
                Pattern regex = Pattern.compile(pattern.getPattern(), Pattern.CASE_INSENSITIVE);
                if (regex.matcher(content).find()) {
                    SecurityIssue issue = new SecurityIssue(
                        pattern.getId(),
                        pattern.getSeverity(),
                        pattern.getDescription(),
                        pattern.getRecommendation()
                    );
                    
                    findings.add(new SecurityFinding(fileName, issue, 
                        findLineNumber(content, pattern.getPattern()), 
                        extractContext(content, pattern.getPattern())));
                }
            }
            
        } catch (IOException e) {
            System.err.println("❌ Error reading file " + filePath + ": " + e.getMessage());
        }
    }
    
    /**
     * Find the line number where a pattern occurs
     * 
     * @param content File content
     * @param pattern Pattern to search for
     * @return Line number (1-based)
     */
    private int findLineNumber(String content, String pattern) {
        String[] lines = content.split("\n");
        Pattern regex = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        
        for (int i = 0; i < lines.length; i++) {
            if (regex.matcher(lines[i]).find()) {
                return i + 1;
            }
        }
        return -1;
    }
    
    /**
     * Extract context around a pattern match
     * 
     * @param content File content
     * @param pattern Pattern to search for
     * @return Context string
     */
    private String extractContext(String content, String pattern) {
        String[] lines = content.split("\n");
        Pattern regex = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        
        for (int i = 0; i < lines.length; i++) {
            if (regex.matcher(lines[i]).find()) {
                StringBuilder context = new StringBuilder();
                int start = Math.max(0, i - 2);
                int end = Math.min(lines.length, i + 3);
                
                for (int j = start; j < end; j++) {
                    context.append(String.format("%3d: %s%n", j + 1, lines[j]));
                }
                return context.toString();
            }
        }
        return "Context not found";
    }
    
    /**
     * Generate comprehensive security report
     */
    public void generateReport() {
        System.out.println("📊 SECURITY ANALYSIS REPORT");
        System.out.println("===========================");
        System.out.println();
        
        // Group findings by severity
        Map<String, List<SecurityFinding>> findingsBySeverity = findings.stream()
            .collect(Collectors.groupingBy(f -> f.getIssue().getSeverity()));
        
        // Report findings by severity (High -> Medium -> Low -> Info)
        String[] severities = {"HIGH", "MEDIUM", "LOW", "INFO"};
        
        for (String severity : severities) {
            List<SecurityFinding> severityFindings = findingsBySeverity.getOrDefault(severity, new ArrayList<>());
            if (!severityFindings.isEmpty()) {
                System.out.println("🚨 " + severity + " SEVERITY ISSUES (" + severityFindings.size() + ")");
                System.out.println("-".repeat(50));
                
                for (SecurityFinding finding : severityFindings) {
                    System.out.println("📁 File: " + finding.getFileName());
                    System.out.println("📍 Line: " + finding.getLineNumber());
                    System.out.println("🔍 Issue: " + finding.getIssue().getDescription());
                    System.out.println("💡 Recommendation: " + finding.getIssue().getRecommendation());
                    System.out.println("📝 Context:");
                    System.out.println(finding.getContext());
                    System.out.println();
                }
            }
        }
        
        // Generate hardening recommendations
        generateHardeningRecommendations();
        
        // Generate summary
        generateSummary();
    }
    
    /**
     * Generate specific hardening recommendations
     */
    private void generateHardeningRecommendations() {
        System.out.println("🛡️  SECURITY HARDENING RECOMMENDATIONS");
        System.out.println("=====================================");
        System.out.println();
        
        System.out.println("1. 🔐 NETWORK SECURITY:");
        System.out.println("   • Implement VPC Flow Logs for network monitoring");
        System.out.println("   • Use private subnets for sensitive resources");
        System.out.println("   • Implement Network ACLs for additional layer of security");
        System.out.println("   • Consider using AWS WAF for web application protection");
        System.out.println();
        
        System.out.println("2. 🚪 ACCESS CONTROL:");
        System.out.println("   • Replace SSH access with SSM Session Manager (already implemented)");
        System.out.println("   • Implement least privilege IAM policies");
        System.out.println("   • Use IAM roles instead of access keys");
        System.out.println("   • Enable MFA for all user accounts");
        System.out.println();
        
        System.out.println("3. 🔍 MONITORING & LOGGING:");
        System.out.println("   • Enable CloudTrail for API call logging");
        System.out.println("   • Implement CloudWatch alarms for security events");
        System.out.println("   • Use AWS Config for compliance monitoring");
        System.out.println("   • Set up GuardDuty for threat detection");
        System.out.println();
        
        System.out.println("4. 🔒 DATA PROTECTION:");
        System.out.println("   • Enable encryption at rest for EBS volumes");
        System.out.println("   • Use AWS KMS for key management");
        System.out.println("   • Implement data classification and handling policies");
        System.out.println("   • Regular security updates and patching");
        System.out.println();
        
        System.out.println("5. 🏗️  INFRASTRUCTURE HARDENING:");
        System.out.println("   • Use AWS Systems Manager for patch management");
        System.out.println("   • Implement security baselines using AWS Config rules");
        System.out.println("   • Regular security assessments and penetration testing");
        System.out.println("   • Implement automated security scanning in CI/CD pipeline");
        System.out.println();
    }
    
    /**
     * Generate analysis summary
     */
    private void generateSummary() {
        System.out.println("📈 ANALYSIS SUMMARY");
        System.out.println("==================");
        
        Map<String, Long> severityCounts = findings.stream()
            .collect(Collectors.groupingBy(f -> f.getIssue().getSeverity(), Collectors.counting()));
        
        System.out.println("Total findings: " + findings.size());
        System.out.println("High severity: " + severityCounts.getOrDefault("HIGH", 0L));
        System.out.println("Medium severity: " + severityCounts.getOrDefault("MEDIUM", 0L));
        System.out.println("Low severity: " + severityCounts.getOrDefault("LOW", 0L));
        System.out.println("Info: " + severityCounts.getOrDefault("INFO", 0L));
        System.out.println();
        
        if (severityCounts.getOrDefault("HIGH", 0L) > 0) {
            System.out.println("⚠️  CRITICAL: High severity issues found - immediate attention required!");
        } else if (severityCounts.getOrDefault("MEDIUM", 0L) > 0) {
            System.out.println("⚠️  WARNING: Medium severity issues found - review recommended");
        } else {
            System.out.println("✅ GOOD: No high or medium severity issues found");
        }
        
        System.out.println();
        System.out.println("🔗 For more information, refer to:");
        System.out.println("   • AWS Security Best Practices: https://aws.amazon.com/security/security-resources/");
        System.out.println("   • AWS Well-Architected Security Pillar: https://aws.amazon.com/architecture/well-architected/");
        System.out.println("   • CIS AWS Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services");
    }
    
    /**
     * Inner class to represent a security issue
     */
    private static class SecurityIssue {
        private final String id;
        private final String severity;
        private final String description;
        private final String recommendation;
        
        public SecurityIssue(String id, String severity, String description, String recommendation) {
            this.id = id;
            this.severity = severity;
            this.description = description;
            this.recommendation = recommendation;
        }
        
        public String getId() { return id; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public String getRecommendation() { return recommendation; }
    }
    
    /**
     * Inner class to represent a security finding
     */
    private static class SecurityFinding {
        private final String fileName;
        private final SecurityIssue issue;
        private final int lineNumber;
        private final String context;
        
        public SecurityFinding(String fileName, SecurityIssue issue, int lineNumber, String context) {
            this.fileName = fileName;
            this.issue = issue;
            this.lineNumber = lineNumber;
            this.context = context;
        }
        
        public String getFileName() { return fileName; }
        public SecurityIssue getIssue() { return issue; }
        public int getLineNumber() { return lineNumber; }
        public String getContext() { return context; }
    }
}
