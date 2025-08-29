# User Manual

Complete guide to using Compliance Sentinel for security analysis and compliance monitoring.

## 📖 Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Operations](#basic-operations)
3. [Advanced Features](#advanced-features)
4. [Compliance Frameworks](#compliance-frameworks)
5. [Reporting and Analytics](#reporting-and-analytics)
6. [Integration Workflows](#integration-workflows)
7. [Troubleshooting](#troubleshooting)

## 🚀 Getting Started

### First Time Setup

After installation, initialize your configuration:

```bash
# Initialize with default settings
compliance-sentinel init

# Initialize with specific frameworks
compliance-sentinel init --frameworks soc2,pci_dss

# Verify setup
compliance-sentinel doctor
```

### Understanding the Interface

Compliance Sentinel provides multiple interfaces:

- **Command Line Interface (CLI)**: Primary interface for automation and scripting
- **Web Interface**: Browser-based dashboard for interactive analysis
- **IDE Integrations**: Real-time analysis within your development environment
- **API**: RESTful API for custom integrations

## 🔍 Basic Operations

### Running Security Scans

#### Quick Scan

```bash
# Scan current directory
compliance-sentinel scan .

# Scan specific directory
compliance-sentinel scan /path/to/project

# Quick scan (faster, less comprehensive)
compliance-sentinel scan . --quick
```

#### Targeted Scans

```bash
# Scan specific file types
compliance-sentinel scan . --include "*.py,*.js"

# Exclude certain paths
compliance-sentinel scan . --exclude "*/tests/*,*/node_modules/*"

# Scan with specific severity threshold
compliance-sentinel scan . --severity high,critical
```

#### Framework-Specific Scans

```bash
# SOC 2 compliance scan
compliance-sentinel scan . --framework soc2

# Multiple frameworks
compliance-sentinel scan . --framework soc2,pci_dss,hipaa

# Custom rule set
compliance-sentinel scan . --rules custom_security_rules.yaml
```

### Understanding Scan Results

#### Result Structure

```json
{
  "scan_id": "scan_20240115_103045",
  "timestamp": "2024-01-15T10:30:45Z",
  "project_path": "/home/user/project",
  "framework": "soc2",
  "summary": {
    "files_scanned": 156,
    "issues_found": 12,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1
  },
  "issues": [
    {
      "id": "SEC-001",
      "rule": "hardcoded_secrets",
      "severity": "critical",
      "category": "authentication",
      "file": "src/config.py",
      "line": 15,
      "column": 20,
      "message": "Hardcoded API key detected",
      "description": "API keys should not be hardcoded in source code",
      "remediation": "Use environment variables or secure key management",
      "cwe": "CWE-798",
      "owasp": "A07:2021 – Identification and Authentication Failures"
    }
  ]
}
```

#### Interpreting Severity Levels

- **Critical**: Immediate security risk, requires urgent attention
- **High**: Significant security concern, should be addressed soon
- **Medium**: Moderate risk, should be reviewed and addressed
- **Low**: Minor issue or best practice recommendation

### Managing Results

#### Viewing Results

```bash
# View latest scan results
compliance-sentinel results

# View specific scan
compliance-sentinel results --scan-id scan_20240115_103045

# Filter by severity
compliance-sentinel results --severity critical,high

# Filter by category
compliance-sentinel results --category authentication,injection
```

#### Generating Reports

```bash
# HTML report
compliance-sentinel report --format html --output security_report.html

# PDF report
compliance-sentinel report --format pdf --output compliance_report.pdf

# JSON export
compliance-sentinel report --format json --output results.json

# CSV for spreadsheet analysis
compliance-sentinel report --format csv --output issues.csv
```

## 🔧 Advanced Features

### Custom Rules Development

#### Creating Custom Rules

```yaml
# custom_rules.yaml
rules:
  - id: CUSTOM-001
    name: "Company API Key Pattern"
    description: "Detect company-specific API key patterns"
    category: "authentication"
    severity: "high"
    pattern: "COMP_[A-Z0-9]{32}"
    file_types: [".py", ".js", ".java"]
    
  - id: CUSTOM-002
    name: "Deprecated Function Usage"
    description: "Usage of deprecated security functions"
    category: "cryptography"
    severity: "medium"
    patterns:
      - "md5\\("
      - "sha1\\("
    remediation: "Use SHA-256 or stronger hashing algorithms"
```

#### Using Custom Rules

```bash
# Scan with custom rules
compliance-sentinel scan . --rules custom_rules.yaml

# Add custom rules to configuration
compliance-sentinel config set security_rules.custom_rule_paths ./custom_rules.yaml
```

### Machine Learning Features

#### Threat Detection

```bash
# Enable ML-based threat detection
compliance-sentinel scan . --enable-ml

# Train custom model on your codebase
compliance-sentinel ml train --data ./training_data

# Update threat intelligence models
compliance-sentinel ml update-models
```

#### False Positive Reduction

```bash
# Mark false positives for learning
compliance-sentinel results mark-false-positive --issue-id SEC-001-file.py:15

# Retrain model with feedback
compliance-sentinel ml retrain --include-feedback

# Show model accuracy metrics
compliance-sentinel ml metrics
```

### Incremental Analysis

#### Smart Scanning

```bash
# Enable incremental scanning
compliance-sentinel config set analysis.incremental_scanning true

# Scan only changed files (Git integration)
compliance-sentinel scan . --incremental

# Force full scan
compliance-sentinel scan . --full-scan
```

#### Change Detection

```bash
# Compare with previous scan
compliance-sentinel diff --baseline scan_20240114_103045

# Show new issues only
compliance-sentinel results --new-only

# Show resolved issues
compliance-sentinel results --resolved-only
```

## 📋 Compliance Frameworks

### SOC 2 Compliance

#### Trust Service Criteria Coverage

```bash
# Security criteria scan
compliance-sentinel scan . --framework soc2 --criteria security

# All criteria scan
compliance-sentinel scan . --framework soc2 --criteria all

# Generate SOC 2 evidence report
compliance-sentinel report --framework soc2 --evidence-collection
```

#### SOC 2 Specific Checks

- **Security**: Access controls, authentication, authorization
- **Availability**: System uptime, disaster recovery, monitoring
- **Processing Integrity**: Data processing accuracy and completeness
- **Confidentiality**: Data protection and access restrictions
- **Privacy**: Personal information handling and protection

### PCI DSS Compliance

#### Requirement Coverage

```bash
# PCI DSS scan
compliance-sentinel scan . --framework pci_dss

# Specific requirement check
compliance-sentinel scan . --framework pci_dss --requirement 3.4

# Cardholder data environment scan
compliance-sentinel scan . --framework pci_dss --scope cde
```

#### Key PCI DSS Checks

- **Requirement 3**: Protect stored cardholder data
- **Requirement 4**: Encrypt transmission of cardholder data
- **Requirement 6**: Develop and maintain secure systems
- **Requirement 8**: Identify and authenticate access
- **Requirement 11**: Regularly test security systems

### HIPAA Compliance

#### HIPAA Security Rule

```bash
# HIPAA compliance scan
compliance-sentinel scan . --framework hipaa

# Administrative safeguards
compliance-sentinel scan . --framework hipaa --safeguards administrative

# Technical safeguards
compliance-sentinel scan . --framework hipaa --safeguards technical
```

#### HIPAA Safeguards

- **Administrative**: Security officer, workforce training, access management
- **Physical**: Facility access, workstation use, device controls
- **Technical**: Access control, audit controls, integrity, transmission security

### GDPR Compliance

#### Data Protection Principles

```bash
# GDPR compliance scan
compliance-sentinel scan . --framework gdpr

# Data processing checks
compliance-sentinel scan . --framework gdpr --focus data_processing

# Privacy by design assessment
compliance-sentinel scan . --framework gdpr --privacy-by-design
```

## 📊 Reporting and Analytics

### Dashboard Overview

Access the web dashboard at `http://localhost:8080` (default) to view:

- **Security Metrics**: Trend analysis and KPIs
- **Compliance Status**: Framework-specific compliance scores
- **Issue Tracking**: Issue lifecycle and resolution tracking
- **Risk Assessment**: Risk scoring and prioritization

### Custom Reports

#### Report Templates

```bash
# List available report templates
compliance-sentinel report templates

# Executive summary report
compliance-sentinel report --template executive

# Technical details report
compliance-sentinel report --template technical

# Compliance audit report
compliance-sentinel report --template audit
```

#### Scheduled Reports

```bash
# Schedule daily reports
compliance-sentinel schedule report --frequency daily --template executive

# Schedule weekly compliance reports
compliance-sentinel schedule report --frequency weekly --framework soc2

# Email reports to stakeholders
compliance-sentinel schedule report --email security-team@company.com
```

### Metrics and KPIs

#### Security Metrics

- **Vulnerability Density**: Issues per 1000 lines of code
- **Mean Time to Resolution (MTTR)**: Average time to fix issues
- **Security Debt**: Accumulated technical security debt
- **Compliance Score**: Overall compliance percentage

#### Tracking Progress

```bash
# Show security metrics
compliance-sentinel metrics security

# Show compliance trends
compliance-sentinel metrics compliance --timeframe 30d

# Export metrics for external analysis
compliance-sentinel metrics export --format csv
```

## 🔗 Integration Workflows

### CI/CD Integration

#### Pre-commit Hooks

```bash
# Install pre-commit hook
compliance-sentinel hooks install

# Configure hook behavior
compliance-sentinel config set hooks.fail_on_critical true
compliance-sentinel config set hooks.auto_fix_enabled true
```

#### Pipeline Integration

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Compliance Sentinel
        run: |
          pip install compliance-sentinel
          compliance-sentinel scan . --fail-on critical
          compliance-sentinel report --format json --output security-report.json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
```

### IDE Integration

#### Real-time Analysis

- **VS Code**: Install Compliance Sentinel extension for real-time highlighting
- **IntelliJ/PyCharm**: Plugin provides inline security suggestions
- **Vim/Neovim**: LSP integration for security linting

#### IDE Features

- **Inline Warnings**: Security issues highlighted in code
- **Quick Fixes**: Automated remediation suggestions
- **Contextual Help**: Detailed explanations and remediation guides
- **Bulk Actions**: Fix multiple issues across files

### Monitoring Integration

#### SIEM Integration

```bash
# Configure Splunk integration
compliance-sentinel integrations setup splunk --host splunk.company.com

# Configure Elasticsearch integration
compliance-sentinel integrations setup elasticsearch --hosts es.company.com:9200

# Send events to SIEM
compliance-sentinel monitor start --siem-integration
```

#### Alerting

```bash
# Configure Slack alerts
compliance-sentinel integrations setup slack --webhook-url $SLACK_WEBHOOK

# Configure email alerts
compliance-sentinel integrations setup email --smtp-server smtp.company.com

# Set alert thresholds
compliance-sentinel config set alerts.critical_threshold 1
compliance-sentinel config set alerts.high_threshold 5
```

## 🔧 Troubleshooting

### Common Issues

#### Performance Issues

```bash
# Reduce memory usage
compliance-sentinel scan . --workers 2 --batch-size 50

# Enable incremental scanning
compliance-sentinel config set analysis.incremental_scanning true

# Clear cache
compliance-sentinel cache clear
```

#### False Positives

```bash
# Suppress specific issues
compliance-sentinel suppress --rule SEC-001 --file src/config.py --line 15

# Disable problematic rules
compliance-sentinel config set security_rules.rules.hardcoded_secrets.enabled false

# Create custom exclusions
compliance-sentinel config add exclusions.paths "*/test_data/*"
```

#### Integration Issues

```bash
# Test integrations
compliance-sentinel integrations test

# Reset integration configuration
compliance-sentinel integrations reset jira

# Debug integration issues
compliance-sentinel --debug integrations test jira
```

### Getting Help

```bash
# System diagnostics
compliance-sentinel doctor

# Show configuration
compliance-sentinel config show

# Enable debug logging
compliance-sentinel --log-level DEBUG scan .

# Check system requirements
compliance-sentinel system-info
```

### Support Resources

- **Documentation**: [https://docs.compliance-sentinel.io](https://docs.compliance-sentinel.io)
- **Community Forum**: [https://community.compliance-sentinel.io](https://community.compliance-sentinel.io)
- **Issue Tracker**: [https://github.com/your-org/compliance-sentinel/issues](https://github.com/your-org/compliance-sentinel/issues)
- **Support Email**: support@compliance-sentinel.io

---

**Next Steps**: Explore [Advanced Configuration](../getting-started/configuration.md) or check out [Integration Examples](../examples/integration-examples.md).