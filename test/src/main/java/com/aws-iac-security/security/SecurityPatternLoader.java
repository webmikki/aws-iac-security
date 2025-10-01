package com.aws-iac-security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.logging.Logger;

/**
 * Security Pattern Configuration Loader
 * 
 * Handles loading security patterns from JSON configuration files.
 * Provides methods for loading from local files and validating configurations.
 */
public class SecurityPatternLoader {
    
    private static final Logger logger = Logger.getLogger(SecurityPatternLoader.class.getName());
    private final ObjectMapper objectMapper;
    
    public SecurityPatternLoader() {
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Load security patterns from JSON configuration file
     * 
     * @param configPath Path to the JSON configuration file
     * @return SecurityPatternConfig object containing all patterns
     * @throws IOException if file cannot be read or parsed
     */
    public SecurityPatternConfig loadPatterns(String configPath) throws IOException {
        logger.info("Loading security patterns from: " + configPath);
        
        // Check if file exists
        File configFile = new File(configPath);
        if (!configFile.exists()) {
            throw new IOException("Configuration file not found: " + configPath);
        }
        
        // Read and parse JSON
        String jsonContent = Files.readString(Paths.get(configPath));
        SecurityPatternConfig config = objectMapper.readValue(jsonContent, SecurityPatternConfig.class);
        
        // Validate configuration
        validateConfiguration(config);
        
        logger.info("Successfully loaded " + config.getSecurityPatterns().size() + " security patterns");
        return config;
    }
    
    /**
     * Load security patterns from JSON string
     * 
     * @param jsonContent JSON content as string
     * @return SecurityPatternConfig object containing all patterns
     * @throws IOException if JSON cannot be parsed
     */
    public SecurityPatternConfig loadPatternsFromString(String jsonContent) throws IOException {
        logger.info("Loading security patterns from JSON string");
        
        SecurityPatternConfig config = objectMapper.readValue(jsonContent, SecurityPatternConfig.class);
        validateConfiguration(config);
        
        logger.info("Successfully loaded " + config.getSecurityPatterns().size() + " security patterns");
        return config;
    }
    
    /**
     * Validate the loaded configuration
     * 
     * @param config Configuration to validate
     * @throws IllegalArgumentException if configuration is invalid
     */
    private void validateConfiguration(SecurityPatternConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        
        if (config.getSecurityPatterns() == null || config.getSecurityPatterns().isEmpty()) {
            throw new IllegalArgumentException("No security patterns found in configuration");
        }
        
        // Validate each pattern
        for (SecurityPattern pattern : config.getSecurityPatterns()) {
            validatePattern(pattern);
        }
        
        // Validate severity levels
        if (config.getSeverityLevels() == null || config.getSeverityLevels().isEmpty()) {
            throw new IllegalArgumentException("No severity levels defined in configuration");
        }
        
        logger.info("Configuration validation completed successfully");
    }
    
    /**
     * Validate individual security pattern
     * 
     * @param pattern Pattern to validate
     * @throws IllegalArgumentException if pattern is invalid
     */
    private void validatePattern(SecurityPattern pattern) {
        if (pattern.getId() == null || pattern.getId().trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern ID cannot be null or empty");
        }
        
        if (pattern.getPattern() == null || pattern.getPattern().trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern regex cannot be null or empty for pattern: " + pattern.getId());
        }
        
        if (pattern.getSeverity() == null || pattern.getSeverity().trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern severity cannot be null or empty for pattern: " + pattern.getId());
        }
        
        if (pattern.getDescription() == null || pattern.getDescription().trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern description cannot be null or empty for pattern: " + pattern.getId());
        }
        
        if (pattern.getRecommendation() == null || pattern.getRecommendation().trim().isEmpty()) {
            throw new IllegalArgumentException("Pattern recommendation cannot be null or empty for pattern: " + pattern.getId());
        }
        
        // Validate regex pattern
        try {
            java.util.regex.Pattern.compile(pattern.getPattern());
        } catch (java.util.regex.PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid regex pattern for pattern " + pattern.getId() + ": " + e.getMessage());
        }
    }
    
    /**
     * Get default configuration path
     * 
     * @return Default path to security patterns configuration
     */
    public static String getDefaultConfigPath() {
        return "config/securitycheck-patterns.json";
    }
    
    /**
     * Check if configuration file exists
     * 
     * @param configPath Path to configuration file
     * @return true if file exists, false otherwise
     */
    public boolean configFileExists(String configPath) {
        return new File(configPath).exists();
    }
    
    /**
     * Get configuration file info
     * 
     * @param configPath Path to configuration file
     * @return File info string
     */
    public String getConfigFileInfo(String configPath) {
        File configFile = new File(configPath);
        if (!configFile.exists()) {
            return "Configuration file not found: " + configPath;
        }
        
        return String.format("Configuration file: %s (Size: %d bytes, Modified: %s)", 
                configPath, 
                configFile.length(), 
                new java.util.Date(configFile.lastModified()));
    }
}
