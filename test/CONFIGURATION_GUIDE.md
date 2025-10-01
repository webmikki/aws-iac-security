# Security Configuration Guide

## ⚙️ **External Configuration**

The security analyzer uses external JSON configuration for security patterns. This means you can add, modify, or disable security patterns without recompiling the code.

## 📁 **Configuration File**

**Location**: `test/config/securitycheck-patterns.json`

This JSON file contains all security patterns, their severity levels, and recommendations.

## 🚀 **How to Use Configuration**

### **1. Run the Analyzer**
```bash
cd test
./run-security-test.sh
```

The analyzer will load the configuration file on each run.

### **2. Modify Patterns**
Edit `config/securitycheck-patterns.json` to:
- Add new security patterns
- Modify existing patterns
- Change severity levels
- Update recommendations
- Enable/disable patterns

### **3. Run Again**
After modifying the JSON file, simply run the analyzer again:
```bash
./run-security-test.sh
```

The analyzer will load the updated configuration and apply new patterns.

## 📝 **Example: Adding a New Pattern**

### **1. Edit the JSON file:**
```json
{
  "securityPatterns": [
    {
      "id": "NEW_SECURITY_ISSUE",
      "pattern": "somePattern.*here",
      "severity": "MEDIUM",
      "category": "CUSTOM_SECURITY",
      "description": "Description of the new security issue",
      "recommendation": "Recommendation for fixing the issue",
      "standards": ["CIS-4.1"],
      "enabled": true
    }
  ]
}
```

### **2. Run the analyzer**
```bash
./run-security-test.sh
```

The analyzer will load the updated configuration and show:
```
📋 Loaded 12 active security patterns
```

## 🛠️ **Configuration Structure**

### **Security Pattern Fields:**
- `id`: Unique identifier for the pattern
- `pattern`: Regex pattern to match in code
- `severity`: HIGH, MEDIUM, LOW, or INFO
- `category`: Category for grouping patterns
- `description`: Human-readable description
- `recommendation`: Security hardening recommendation
- `standards`: Array of security standards (CIS, NIST, etc.)
- `enabled`: Whether the pattern is active

### **Categories:**
- `NETWORK_SECURITY`: Network and firewall issues
- `ACCESS_CONTROL`: IAM and access management
- `WEB_SECURITY`: HTTP/HTTPS and web application issues
- `MONITORING`: Logging and monitoring issues
- `RESOURCE_MANAGEMENT`: Naming, tagging, and organization

## ⚡ **Performance Notes**

- Configuration is loaded fresh on each run
- No background processes or file monitoring
- Simple and reliable approach
- Fast startup and analysis

## 🔧 **Troubleshooting**

### **Configuration Not Loading:**
1. Check file permissions
2. Ensure JSON syntax is valid
3. Verify file path is correct
4. Check console for error messages

### **Invalid JSON:**
The analyzer will show an error and exit:
```
❌ Failed to load security patterns configuration: [error details]
```

### **Pattern Not Working:**
1. Validate regex syntax
2. Check if pattern is enabled
3. Verify pattern matches your code
4. Test with simple patterns first

## 📊 **Benefits**

- **No Recompilation**: Add patterns without rebuilding
- **Easy Maintenance**: Non-technical users can update patterns
- **Version Control**: Track pattern changes in Git
- **Environment Specific**: Different patterns for dev/prod
- **Simple Workflow**: Edit JSON → Run analyzer → See results

## 🎯 **Best Practices**

1. **Test Patterns**: Validate regex patterns before adding
2. **Version Control**: Commit pattern changes to Git
3. **Documentation**: Document custom patterns
4. **Backup**: Keep backup of working configurations
5. **Validation**: Use JSON validators for syntax checking
6. **Incremental Changes**: Add one pattern at a time for testing

## 🔄 **Workflow**

1. **Edit** `config/securitycheck-patterns.json`
2. **Save** the file
3. **Run** `./run-security-test.sh`
4. **Review** the analysis results
5. **Repeat** as needed

This simple approach ensures reliability and ease of use while maintaining the flexibility of external configuration.
