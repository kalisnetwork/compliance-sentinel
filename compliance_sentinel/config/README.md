# Compliance Sentinel Configuration Guide

This guide explains how to configure Compliance Sentinel for your project's specific security and compliance requirements.

## Configuration Files

Compliance Sentinel uses a cascading configuration system with the following precedence (highest to lowest):

1. **Local Configuration** (`compliance-sentinel.yaml` in project root)
2. **Project Configuration** (`.compliance-sentinel/config.yaml`)
3. **User Configuration** (`~/.compliance-sentinel/config.yaml`)
4. **Default Configuration** (built-in defaults)

## Configuration Sections

### Project Information

```yaml
project_name: "my-project"
version: "1.0.0"
description: "Project description"
```

### File Patterns

Control which files are analyzed:

```yaml
file_patterns:
  included_patterns:
    - "*.py"
    - "*.js"
    - "*.ts"
  excluded_patterns:
    - "*.pyc"
    - "*test*"
  excluded_directories:
    - ".git"
    - "__pycache__"
    - "node_modules"
  max_file_size_mb: 10.0
```

### Severity Thresholds

Configure when analysis should block based on issue severity:

```yaml
severity_thresholds:
  critical_threshold: 0    # Block on any critical issues
  high_threshold: 5        # Block if more than 5 high issues
  medium_threshold: 20     # Block if more than 20 medium issues
  low_threshold: 50        # Block if more than 50 low issues
  
  # Scoring system
  critical_score: 100
  high_score: 25
  medium_score: 5
  low_score: 1
  max_total_score: 200     # Block if total score exceeds this
```

### Custom Rules

Add project-specific security rules:

```yaml
custom_rules:
  - rule_id: "CUSTOM-001"
    name: "No hardcoded API keys"
    description: "API keys should not be hardcoded"
    severity: "critical"
    enabled: true
    pattern: "api_key\\s*=\\s*['\"][^'\"]{20,}['\"]"
    file_patterns:
      - "*.py"
      - "*.js"
    custom_message: "Remove hardcoded API key"
    remediation_guidance: "Use environment variables or secure key management"
    references:
      - "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"
```

### MCP Servers

Configure external vulnerability intelligence sources:

```yaml
mcp_servers:
  - server_name: "nvd-database"
    endpoint_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: null
    timeout_seconds: 30
    max_retries: 3
    rate_limit_requests: 50
    rate_limit_window: 60
    enabled: true
```

### System Configuration

Core system settings:

```yaml
system_config:
  hooks_enabled: true
  ide_feedback_enabled: true
  summary_reports_enabled: true
  analysis_timeout: 60
  max_concurrent_analyses: 3
  log_level: "INFO"
  cache_enabled: true
  cache_ttl_seconds: 3600
```

### Hook Settings

Configure real-time analysis triggers:

```yaml
hook_settings:
  enabled_file_patterns:
    - "*.py"
    - "*.js"
  excluded_directories:
    - ".git"
    - "__pycache__"
  debounce_delay: 1.0
  async_processing: true
  analysis_timeout: 30
```

## CLI Commands

### Initialize Configuration

```bash
# Initialize project configuration
compliance-sentinel config init --project-name "my-project"

# Initialize user-level configuration
compliance-sentinel config init --project-name "my-project" --scope user
```

### View Configuration

```bash
# Show current configuration
compliance-sentinel config show

# Show as JSON
compliance-sentinel config show --format json
```

### Validate Configuration

```bash
# Validate current configuration
compliance-sentinel config validate
```

### Export/Import Configuration

```bash
# Export configuration
compliance-sentinel config export config-backup.yaml

# Import configuration
compliance-sentinel config import config-backup.yaml
```

### Manage Custom Rules

```bash
# List custom rules
compliance-sentinel config rules list

# Add custom rule
compliance-sentinel config rules add \
  --rule-id "CUSTOM-003" \
  --name "No eval() usage" \
  --description "eval() function should not be used" \
  --severity "high" \
  --pattern "eval\\s*\\(" \
  --file-pattern "*.js" \
  --file-pattern "*.py"

# Remove custom rule
compliance-sentinel config rules remove "CUSTOM-003"
```

### Manage Severity Thresholds

```bash
# Show current thresholds
compliance-sentinel config thresholds show

# Update thresholds
compliance-sentinel config thresholds set \
  --critical 0 \
  --high 3 \
  --medium 15 \
  --max-score 150
```

### Manage MCP Servers

```bash
# List MCP servers
compliance-sentinel config mcp list

# Add MCP server
compliance-sentinel config mcp add \
  --name "custom-vuln-db" \
  --url "https://api.example.com/vulns" \
  --api-key "your-api-key" \
  --timeout 45
```

## Configuration Validation

The configuration system includes comprehensive validation:

### Automatic Validation

- **On Save**: Configurations are validated before saving
- **On Load**: Configurations are validated when loaded
- **CLI Validation**: Use `compliance-sentinel config validate`

### Validation Rules

1. **Project Name**: Required, alphanumeric with hyphens/underscores
2. **File Patterns**: Valid glob patterns
3. **Regex Patterns**: Valid regular expressions
4. **URLs**: Valid HTTP/HTTPS URLs for MCP servers
5. **Thresholds**: Non-negative integers
6. **Rule IDs**: Unique within project

### Error Handling

- **Errors**: Block configuration save/load
- **Warnings**: Allow operation but notify user
- **Detailed Messages**: Specific error descriptions

## Best Practices

### 1. Start with Defaults

```bash
compliance-sentinel config init --project-name "my-project"
```

### 2. Customize Gradually

- Start with default configuration
- Add custom rules incrementally
- Adjust thresholds based on project needs

### 3. Use Appropriate Scopes

- **User**: Personal preferences across projects
- **Project**: Team-wide settings
- **Local**: Developer-specific overrides

### 4. Version Control

- Include project configuration in version control
- Exclude local configuration files
- Document configuration changes

### 5. Regular Validation

```bash
# Add to CI/CD pipeline
compliance-sentinel config validate
```

### 6. Security Considerations

- Never commit API keys in configuration
- Use environment variables for secrets
- Regularly review custom rules
- Keep MCP server configurations updated

## Troubleshooting

### Common Issues

1. **Invalid Configuration**
   ```bash
   compliance-sentinel config validate
   ```

2. **Missing Configuration**
   ```bash
   compliance-sentinel config init --project-name "my-project"
   ```

3. **Permission Issues**
   - Check file permissions
   - Ensure config directory is writable

4. **Pattern Matching Issues**
   - Test glob patterns with sample files
   - Validate regex patterns separately

### Debug Mode

Enable debug logging for configuration issues:

```yaml
system_config:
  log_level: "DEBUG"
```

## Examples

### Minimal Configuration

```yaml
project_name: "simple-project"
severity_thresholds:
  critical_threshold: 0
  high_threshold: 10
```

### Comprehensive Configuration

See `templates/default_config.yaml` for a complete example with all options.

### Language-Specific Configuration

#### Python Project
```yaml
file_patterns:
  included_patterns:
    - "*.py"
  excluded_directories:
    - "__pycache__"
    - ".pytest_cache"
    - "venv"

custom_rules:
  - rule_id: "PY-001"
    name: "No eval usage"
    pattern: "eval\\s*\\("
    severity: "critical"
```

#### JavaScript Project
```yaml
file_patterns:
  included_patterns:
    - "*.js"
    - "*.ts"
  excluded_directories:
    - "node_modules"
    - "dist"

custom_rules:
  - rule_id: "JS-001"
    name: "No eval usage"
    pattern: "eval\\s*\\("
    severity: "critical"
```

## Migration Guide

### From Version 0.x to 1.x

1. Export existing configuration:
   ```bash
   compliance-sentinel config export old-config.yaml
   ```

2. Initialize new configuration:
   ```bash
   compliance-sentinel config init --project-name "my-project"
   ```

3. Merge settings manually or use import:
   ```bash
   compliance-sentinel config import old-config.yaml
   ```

4. Validate new configuration:
   ```bash
   compliance-sentinel config validate
   ```