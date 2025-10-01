package com.aws-iac-security.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Security Pattern Configuration
 * 
 * Represents a security pattern loaded from JSON configuration file.
 * Contains all the necessary information for pattern matching and reporting.
 */
public class SecurityPattern {
    
    @JsonProperty("id")
    private String id;
    
    @JsonProperty("pattern")
    private String pattern;
    
    @JsonProperty("severity")
    private String severity;
    
    @JsonProperty("category")
    private String category;
    
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("recommendation")
    private String recommendation;
    
    @JsonProperty("standards")
    private List<String> standards;
    
    @JsonProperty("enabled")
    private boolean enabled;
    
    // Default constructor for Jackson
    public SecurityPattern() {}
    
    // Constructor for programmatic creation
    public SecurityPattern(String id, String pattern, String severity, String category, 
                          String description, String recommendation, List<String> standards, boolean enabled) {
        this.id = id;
        this.pattern = pattern;
        this.severity = severity;
        this.category = category;
        this.description = description;
        this.recommendation = recommendation;
        this.standards = standards;
        this.enabled = enabled;
    }
    
    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    
    public List<String> getStandards() { return standards; }
    public void setStandards(List<String> standards) { this.standards = standards; }
    
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    @Override
    public String toString() {
        return "SecurityPattern{" +
                "id='" + id + '\'' +
                ", pattern='" + pattern + '\'' +
                ", severity='" + severity + '\'' +
                ", category='" + category + '\'' +
                ", enabled=" + enabled +
                '}';
    }
}
