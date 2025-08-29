# Configuration Guide

This guide covers how to configure Compliance Sentinel for your specific environment and requirements.

## 📁 Configuration File Locations

Compliance Sentinel looks for configuration files in the following order (highest to lowest priority):

1. **Project Configuration**: `./.compliance-sentinel/config.yaml`
2. **User Configuration**: `~/.compliance-sentinel/config.yaml`
3. **System Configuration**: `/etc/compliance-sentinel/config.yaml`

## 🚀 Quick Configuration

### Initialize Default Configuration

```bash
# Create basic configuration
compliance-sentinel init

# Create configuration with specific frameworks
compliance-sentinel init --frameworks soc2,pci_dss,hipaa

# Create enterprise configuration
compliance-sentinel init --template enterprise
```

### Basic Configuration File

```yaml
# ~/.compliance-sentinel/config.yaml
general:
  log_level: INFO
  output_format: json
  parallel_workers: 4
  
analysis:
  timeout_seconds: 300
  incremental_scanning: true
  cache_results: true
  
frameworks:
  enabled:
    - soc2
    - pci_dss
    - owasp_top10
  
exclusions:
  paths:
    - "*/node_modules/*"
    - "*/venv/*"
    - "*/.git/*"
  files:
    - "*.min.js"
    - "*.test.js"
```

## 🔧 Detailed Configuration Options

### General Settings

```yaml
general:
  # Logging configuration
  log_level: INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_file: "/var/log/compliance-sentinel.log"
  log_rotation: true
  log_max_size: "100MB"
  log_backup_count: 5
  
  # Output configuration
  output_format: json  # json, yaml, xml, csv
  output_directory: "./reports"
  
  # Performance settings
  parallel_workers: 4  # Number of parallel analysis workers
  max_memory_usage: "8GB"
  temp_directory: "/tmp/compliance-sentinel"
```

### Analysis Configuration

```yaml
analysis:
  # Scanning behavior
  timeout_seconds: 300
  max_file_size: "50MB"
  follow_symlinks: false
  scan_hidden_files: false
  
  # Performance optimizations
  incremental_scanning: true
  cache_results: true
  cache_ttl: 3600  # Cache time-to-live in seconds
  
  # Language-specific settings
  languages:
    python:
      enabled: true
      extensions: [".py", ".pyw"]
      exclude_patterns: ["*_test.py", "*test*.py"]
    javascript:
      enabled: true
      extensions: [".js", ".jsx", ".ts", ".tsx"]
      exclude_patterns: ["*.min.js", "*.bundle.js"]
    java:
      enabled: true
      extensions: [".java"]
      classpath_scanning: true
```

### Compliance Frameworks

```yaml
frameworks:
  # Enable specific frameworks
  enabled:
    - soc2
    - pci_dss
    - hipaa
    - gdpr
    - owasp_top10
    - nist_csf
  
  # Framework-specific configuration
  soc2:
    trust_service_criteria: ["security", "availability", "confidentiality"]
    evidence_collection: true
    
  pci_dss:
    version: "4.0"
    scope: ["cardholder_data", "authentication"]
    
  hipaa:
    covered_entities: true
    business_associates: true
    
  owasp_top10:
    version: "2021"
    include_experimental: false
```

### Security Rules Configuration

```yaml
security_rules:
  # Rule categories to enable
  categories:
    - authentication
    - authorization
    - injection
    - cryptography
    - sensitive_data
    - input_validation
  
  # Severity levels to report
  severity_levels:
    - critical
    - high
    - medium
    - low
  
  # Custom rule directories
  custom_rule_paths:
    - "./custom_rules"
    - "/etc/compliance-sentinel/custom_rules"
  
  # Rule-specific configuration
  rules:
    hardcoded_secrets:
      enabled: true
      severity: high
      patterns:
        - "(password|secret|key|token)\\s*=\\s*[\"'][^\"']{3,}[\"']"
    
    sql_injection:
      enabled: true
      severity: critical
      check_stored_procedures: true
```

### Database Configuration

```yaml
database:
  # Database type: sqlite, postgresql, mysql
  type: postgresql
  
  # Connection settings
  host: localhost
  port: 5432
  name: compliance_sentinel
  username: cs_user
  password: "${CS_DB_PASSWORD}"  # Environment variable
  
  # Connection pool settings
  pool_size: 10
  max_overflow: 20
  pool_timeout: 30
  
  # SQLite-specific (if using SQLite)
  sqlite:
    path: "~/.compliance-sentinel/database.db"
    timeout: 30
```

### Caching Configuration

```yaml
cache:
  # Cache backend: memory, redis, file
  backend: redis
  
  # Redis configuration
  redis:
    host: localhost
    port: 6379
    db: 0
    password: "${REDIS_PASSWORD}"
    ssl: false
  
  # File cache configuration
  file:
    directory: "~/.compliance-sentinel/cache"
    max_size: "1GB"
  
  # Cache behavior
  ttl: 3600  # Time-to-live in seconds
  max_entries: 10000
```

### Threat Intelligence Configuration

```yaml
threat_intelligence:
  enabled: true
  
  # Update frequency
  update_interval: 3600  # seconds
  auto_update: true
  
  # Feed configurations
  feeds:
    virustotal:
      enabled: true
      api_key: "${VIRUSTOTAL_API_KEY}"
      rate_limit: 4  # requests per minute
      
    alienvault_otx:
      enabled: true
      api_key: "${OTX_API_KEY}"
      
    misp:
      enabled: false
      url: "https://misp.company.com"
      api_key: "${MISP_API_KEY}"
      verify_ssl: true
  
  # IOC matching configuration
  ioc_matching:
    hash_matching: true
    domain_matching: true
    ip_matching: true
    url_matching: true
```

### Integration Configuration

```yaml
integrations:
  # CI/CD integrations
  cicd:
    jenkins:
      enabled: false
      url: "https://jenkins.company.com"
      username: "${JENKINS_USER}"
      api_token: "${JENKINS_TOKEN}"
      
    github_actions:
      enabled: true
      token: "${GITHUB_TOKEN}"
      
    gitlab_ci:
      enabled: false
      url: "https://gitlab.company.com"
      token: "${GITLAB_TOKEN}"
  
  # Monitoring integrations
  monitoring:
    splunk:
      enabled: false
      host: "splunk.company.com"
      port: 8089
      username: "${SPLUNK_USER}"
      password: "${SPLUNK_PASSWORD}"
      
    elasticsearch:
      enabled: true
      hosts: ["elasticsearch.company.com:9200"]
      username: "${ES_USER}"
      password: "${ES_PASSWORD}"
  
  # Ticketing integrations
  ticketing:
    jira:
      enabled: true
      url: "https://company.atlassian.net"
      username: "${JIRA_USER}"
      api_token: "${JIRA_TOKEN}"
      project_key: "SEC"
      
    servicenow:
      enabled: false
      instance: "company.service-now.com"
      username: "${SNOW_USER}"
      password: "${SNOW_PASSWORD}"
```

### Notification Configuration

```yaml
notifications:
  # Email notifications
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    smtp_port: 587
    username: "${EMAIL_USER}"
    password: "${EMAIL_PASSWORD}"
    from_address: "compliance-sentinel@company.com"
    
    # Notification rules
    rules:
      - severity: critical
        recipients: ["security-team@company.com"]
      - severity: high
        recipients: ["dev-team@company.com"]
  
  # Slack notifications
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    
    # Message formatting
    include_details: true
    mention_users: ["@security-team"]
  
  # Microsoft Teams
  teams:
    enabled: false
    webhook_url: "${TEAMS_WEBHOOK_URL}"
```

### Exclusions and Filters

```yaml
exclusions:
  # Path exclusions (glob patterns)
  paths:
    - "*/node_modules/*"
    - "*/venv/*"
    - "*/.git/*"
    - "*/build/*"
    - "*/dist/*"
    - "*/__pycache__/*"
  
  # File exclusions
  files:
    - "*.min.js"
    - "*.min.css"
    - "*.test.js"
    - "*.spec.js"
    - "*.pyc"
  
  # Rule exclusions by file pattern
  rule_exclusions:
    - rule: "hardcoded_secrets"
      paths: ["*/test/*", "*/tests/*"]
    - rule: "sql_injection"
      files: ["*_test.py"]
  
  # False positive suppression
  suppressions:
    - rule: "SEC-001"
      file: "src/config.py"
      line: 15
      reason: "Test configuration file"
      expires: "2024-12-31"
```

## 🔐 Environment Variables

### Security-Related Variables

```bash
# Database credentials
export CS_DB_PASSWORD="secure_database_password"
export REDIS_PASSWORD="secure_redis_password"

# API keys for threat intelligence
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export OTX_API_KEY="your_alienvault_otx_key"
export MISP_API_KEY="your_misp_api_key"

# Integration credentials
export JENKINS_USER="jenkins_username"
export JENKINS_TOKEN="jenkins_api_token"
export GITHUB_TOKEN="github_personal_access_token"
export JIRA_USER="jira_username"
export JIRA_TOKEN="jira_api_token"

# Notification credentials
export EMAIL_USER="smtp_username"
export EMAIL_PASSWORD="smtp_password"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

### Configuration Variables

```bash
# Core configuration
export CS_CONFIG_PATH="/path/to/config.yaml"
export CS_LOG_LEVEL="INFO"
export CS_WORKERS="4"

# Performance tuning
export CS_MAX_MEMORY="8GB"
export CS_CACHE_SIZE="1GB"
export CS_TIMEOUT="300"

# Feature flags
export CS_ENABLE_ML="true"
export CS_ENABLE_THREAT_INTEL="true"
export CS_ENABLE_MONITORING="true"
```

## 🔧 Configuration Management

### Validate Configuration

```bash
# Validate current configuration
compliance-sentinel config validate

# Validate specific configuration file
compliance-sentinel config validate --config /path/to/config.yaml

# Show current configuration
compliance-sentinel config show

# Show configuration with resolved environment variables
compliance-sentinel config show --resolved
```

### Update Configuration

```bash
# Set configuration values
compliance-sentinel config set general.log_level DEBUG
compliance-sentinel config set analysis.parallel_workers 8

# Enable/disable frameworks
compliance-sentinel config set frameworks.enabled soc2,pci_dss,hipaa

# Add exclusion patterns
compliance-sentinel config add exclusions.paths "*/temp/*"
```

### Configuration Templates

```bash
# List available templates
compliance-sentinel config templates

# Create configuration from template
compliance-sentinel config create --template enterprise
compliance-sentinel config create --template minimal
compliance-sentinel config create --template development
```

## 🏢 Enterprise Configuration Examples

### High-Performance Setup

```yaml
general:
  parallel_workers: 16
  max_memory_usage: "32GB"

analysis:
  timeout_seconds: 600
  incremental_scanning: true
  cache_results: true

database:
  type: postgresql
  pool_size: 50
  max_overflow: 100

cache:
  backend: redis
  redis:
    host: redis-cluster.company.com
    port: 6379
```

### Security-Hardened Setup

```yaml
general:
  log_level: WARNING
  log_file: "/var/log/compliance-sentinel/audit.log"

security:
  api_authentication: true
  rate_limiting: true
  ssl_required: true
  
database:
  ssl_mode: require
  ssl_cert: "/etc/ssl/certs/client.crt"
  ssl_key: "/etc/ssl/private/client.key"

threat_intelligence:
  feeds:
    # Only use internal/trusted feeds
    internal_feed:
      enabled: true
      url: "https://threat-intel.company.com/api"
```

## 🔍 Troubleshooting Configuration

### Common Configuration Issues

```bash
# Check configuration syntax
compliance-sentinel config validate

# Test database connection
compliance-sentinel db test-connection

# Test integrations
compliance-sentinel integrations test

# Verify permissions
compliance-sentinel doctor --check-permissions
```

### Debug Configuration Loading

```bash
# Show configuration loading process
compliance-sentinel --debug config show

# Show which configuration files are loaded
compliance-sentinel config sources

# Show environment variable resolution
compliance-sentinel config env-vars
```

---

**Next Steps**: After configuration, proceed to run your [First Analysis](first-analysis.md) or explore the [User Manual](../user-guides/user-manual.md).