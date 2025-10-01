package com.aws-iac-security.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Security Pattern Configuration Container
 * 
 * Represents the complete configuration loaded from JSON file.
 * Contains all security patterns, categories, and severity levels.
 */
public class SecurityPatternConfig {
    
    @JsonProperty("version")
    private String version;
    
    @JsonProperty("lastUpdated")
    private String lastUpdated;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("securityPatterns")
    private List<SecurityPattern> securityPatterns;
    
    @JsonProperty("categories")
    private Map<String, String> categories;
    
    @JsonProperty("severityLevels")
    private Map<String, SeverityLevel> severityLevels;
    
    // Default constructor for Jackson
    public SecurityPatternConfig() {}
    
    // Getters and Setters
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    
    public String getLastUpdated() { return lastUpdated; }
    public void setLastUpdated(String lastUpdated) { this.lastUpdated = lastUpdated; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public List<SecurityPattern> getSecurityPatterns() { return securityPatterns; }
    public void setSecurityPatterns(List<SecurityPattern> securityPatterns) { this.securityPatterns = securityPatterns; }
    
    public Map<String, String> getCategories() { return categories; }
    public void setCategories(Map<String, String> categories) { this.categories = categories; }
    
    public Map<String, SeverityLevel> getSeverityLevels() { return severityLevels; }
    public void setSeverityLevels(Map<String, SeverityLevel> severityLevels) { this.severityLevels = severityLevels; }
    
    /**
     * Get enabled security patterns only
     * @return List of enabled security patterns
     */
    public List<SecurityPattern> getEnabledPatterns() {
        return securityPatterns.stream()
                .filter(SecurityPattern::isEnabled)
                .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * Get patterns by severity level
     * @param severity Severity level to filter by
     * @return List of patterns with specified severity
     */
    public List<SecurityPattern> getPatternsBySeverity(String severity) {
        return securityPatterns.stream()
                .filter(pattern -> pattern.getSeverity().equals(severity))
                .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * Get patterns by category
     * @param category Category to filter by
     * @return List of patterns in specified category
     */
    public List<SecurityPattern> getPatternsByCategory(String category) {
        return securityPatterns.stream()
                .filter(pattern -> pattern.getCategory().equals(category))
                .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * Inner class for severity level configuration
     */
    public static class SeverityLevel {
        @JsonProperty("priority")
        private int priority;
        
        @JsonProperty("color")
        private String color;
        
        @JsonProperty("description")
        private String description;
        
        // Default constructor for Jackson
        public SeverityLevel() {}
        
        // Constructor
        public SeverityLevel(int priority, String color, String description) {
            this.priority = priority;
            this.color = color;
            this.description = description;
        }
        
        // Getters and Setters
        public int getPriority() { return priority; }
        public void setPriority(int priority) { this.priority = priority; }
        
        public String getColor() { return color; }
        public void setColor(String color) { this.color = color; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
    }
}
