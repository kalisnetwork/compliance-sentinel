# Compliance Sentinel User Guide

This comprehensive guide will help you get started with Compliance Sentinel and make the most of its security analysis and compliance monitoring capabilities.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Security Analysis](#security-analysis)
3. [Compliance Monitoring](#compliance-monitoring)
4. [Real-time Monitoring](#real-time-monitoring)
5. [Dashboards and Reporting](#dashboards-and-reporting)
6. [Integrations](#integrations)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Getting Started

### System Requirements

- **Operating System**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Python**: Version 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: 2GB free disk space
- **Network**: Internet connection for updates and integrations

### Installation

#### Option 1: pip Installation (Recommended)

```bash
pip install compliance-sentinel
```

#### Option 2: From Source

```bash
git clone https://github.com/your-org/compliance-sentinel.git
cd compliance-sentinel
pip install -e .
```

#### Option 3: Docker

```bash
docker pull compliance-sentinel:latest
docker run -p 8080:8080 compliance-sentinel
```

### Initial Setup

1. **Create Configuration File**

Create a `config.yaml` file in your project directory:

```yaml
analysis:
  languages:
    - javascript
    - python
    - java
  
monitoring:
  enabled: true
  
compliance:
  frameworks:
    - soc2
    - pci_dss
```

2. **Initialize Database**

```bash
compliance-sentinel init-db
```

3. **Verify Installation**

```bash
compliance-sentinel --version
compliance-sentinel health-check
```

## Security Analysis

### Supported Languages

Compliance Sentinel supports comprehensive security analysis for:

- **JavaScript/TypeScript**: XSS, prototype pollution, npm vulnerabilities
- **Java**: Deserialization, XXE, Spring Security issues
- **C#**: Unsafe deserialization, SQL injection, .NET security
- **Go**: Race conditions, unsafe pointers, goroutine leaks
- **Rust**: Unsafe blocks, memory safety, FFI security
- **PHP**: File inclusion, session management, WordPress security

### Running Security Analysis

#### Command Line Analysis

```bash
# Analyze a single file
compliance-sentinel analyze --file src/app.js

# Analyze entire project
compliance-sentinel analyze --project /path/to/project

# Analyze with specific rules
compliance-sentinel analyze --project . --rules security_critical

# Output to different formats
compliance-sentinel analyze --project . --format json --output results.json
compliance-sentinel analyze --project . --format html --output report.html
compliance-sentinel analyze --project . --format pdf --output security-report.pdf
```

#### Python API Analysis

```python
from compliance_sentinel import ComplianceSentinel

# Initialize analyzer
sentinel = ComplianceSentinel()

# Analyze a file
results = sentinel.analyze_file('src/app.js')

# Analyze project
results = sentinel.analyze_project('/path/to/project')

# Analyze code string
results = sentinel.analyze_code("""
const password = "hardcoded123";
document.innerHTML = userInput;
""", language='javascript')

# Process results
for issue in results.security_issues:
    print(f"{issue.severity.value}: {issue.description}")
    print(f"File: {issue.file_path}:{issue.line_number}")
    print(f"Rule: {issue.rule_id}")
    print("---")
```

#### Web Interface Analysis

1. Open your browser to `http://localhost:8080`
2. Navigate to **Security Analysis**
3. Upload files or paste code
4. Select analysis options
5. Click **Analyze**
6. Review results in the interactive interface

### Understanding Security Issues

Each security issue includes:

- **Severity**: Critical, High, Medium, Low
- **Category**: Authentication, Encryption, Input Validation, etc.
- **Description**: Detailed explanation of the issue
- **Location**: File path and line number
- **Rule ID**: Identifier for the triggered rule
- **Confidence**: How certain the analyzer is about the issue
- **Remediation**: Suggested fixes and best practices

#### Severity Levels

- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant security vulnerability that should be fixed soon
- **Medium**: Moderate security issue that should be addressed
- **Low**: Minor security concern or best practice violation

### Custom Rules

#### Creating Custom Rules

```python
# Add custom rule via API
sentinel.add_custom_rule({
    'id': 'hardcoded_api_key',
    'pattern': r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']',
    'severity': 'high',
    'category': 'authentication',
    'description': 'Hardcoded API key detected',
    'remediation': 'Use environment variables for API keys'
})
```

#### Rule Configuration File

Create `custom_rules.yaml`:

```yaml
rules:
  - id: custom_password_check
    pattern: 'password\s*=\s*["\'][^"\']{1,10}["\']'
    severity: medium
    category: authentication
    description: Weak password detected
    languages:
      - javascript
      - python
    
  - id: custom_sql_injection
    pattern: 'SELECT.*\+.*'
    severity: high
    category: injection
    description: Potential SQL injection
    languages:
      - java
      - csharp
```

Load custom rules:

```bash
compliance-sentinel analyze --project . --custom-rules custom_rules.yaml
```

## Compliance Monitoring

### Supported Frameworks

- **SOC 2 Type II**: System and Organization Controls
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation
- **ISO 27001**: Information Security Management

### Running Compliance Checks

#### Command Line

```bash
# Check all frameworks
compliance-sentinel compliance-check --project .

# Check specific framework
compliance-sentinel compliance-check --project . --framework soc2

# Generate compliance report
compliance-sentinel compliance-report --framework pci_dss --output compliance-report.pdf
```

#### Python API

```python
from compliance_sentinel.compliance import SOC2Checker, PCIDSSChecker

# SOC 2 compliance check
soc2_checker = SOC2Checker()
soc2_results = soc2_checker.check_project('/path/to/project')

print(f"SOC 2 Compliance Score: {soc2_results.compliance_score}%")
for violation in soc2_results.violations:
    print(f"Violation: {violation.description}")

# PCI DSS compliance check
pci_checker = PCIDSSChecker()
pci_results = pci_checker.check_project('/path/to/project')
```

### Compliance Requirements

#### SOC 2 Type II Requirements

- **CC6.1**: Logical and physical access controls
- **CC6.2**: System access is removed when no longer required
- **CC6.3**: Network security controls
- **CC6.7**: Data transmission controls
- **CC6.8**: System development lifecycle controls

#### PCI DSS Requirements

- **Requirement 1**: Install and maintain firewall configuration
- **Requirement 2**: Do not use vendor-supplied defaults
- **Requirement 3**: Protect stored cardholder data
- **Requirement 4**: Encrypt transmission of cardholder data
- **Requirement 6**: Develop and maintain secure systems

### Compliance Reporting

Generate comprehensive compliance reports:

```python
from compliance_sentinel.reporting import ComplianceReporter

reporter = ComplianceReporter()

# Generate executive summary
executive_report = reporter.generate_executive_summary(
    frameworks=['soc2', 'pci_dss'],
    time_period='last_30_days'
)

# Generate detailed technical report
technical_report = reporter.generate_technical_report(
    framework='soc2',
    include_remediation=True
)

# Export to various formats
reporter.export_report(executive_report, format='pdf', output='executive-summary.pdf')
reporter.export_report(technical_report, format='html', output='technical-report.html')
```

## Real-time Monitoring

### Setting Up Monitoring

#### Configuration

```yaml
monitoring:
  real_time_monitoring: true
  metrics_collection_interval: 60
  
  alert_channels:
    email:
      type: email
      smtp_server: smtp.gmail.com
      username: alerts@company.com
      password: ${EMAIL_PASSWORD}
      to_emails:
        - security@company.com
        - compliance@company.com
    
    slack:
      type: slack
      webhook_url: ${SLACK_WEBHOOK_URL}
      channel: '#security-alerts'
```

#### Starting Monitoring

```bash
# Start monitoring daemon
compliance-sentinel monitor --daemon

# Start with custom config
compliance-sentinel monitor --config monitoring-config.yaml
```

#### Python API

```python
from compliance_sentinel.monitoring import create_monitoring_system

# Create monitoring system
monitoring = create_monitoring_system()

# Configure alert channels
monitoring.config.alert_channels = {
    'email': {
        'type': 'email',
        'smtp_server': 'smtp.gmail.com',
        'username': 'alerts@company.com',
        'password': 'your_password',
        'to_emails': ['security@company.com']
    }
}

# Start monitoring
monitoring.start()

# Emit custom events
from compliance_sentinel.monitoring import MonitoringEvent, EventType, EventSeverity

event = MonitoringEvent(
    event_id='custom_event',
    event_type=EventType.VULNERABILITY_DETECTED,
    severity=EventSeverity.HIGH,
    title='Custom Security Alert',
    description='Custom security issue detected',
    source='custom_scanner'
)

monitoring.emit_event(event)
```

### Alert Configuration

#### Alert Channels

**Email Alerts**
```yaml
email:
  type: email
  smtp_server: smtp.gmail.com
  smtp_port: 587
  username: alerts@company.com
  password: your_password
  from_email: noreply@company.com
  to_emails:
    - security@company.com
    - admin@company.com
  use_tls: true
  min_severity: medium
```

**Slack Alerts**
```yaml
slack:
  type: slack
  webhook_url: https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
  channel: '#security-alerts'
  username: 'Compliance Sentinel'
  icon_emoji: ':warning:'
  min_severity: high
```

**Webhook Alerts**
```yaml
webhook:
  type: webhook
  webhook_url: https://your-api.com/webhooks/security
  method: POST
  headers:
    Content-Type: application/json
    Authorization: Bearer your_token
  timeout: 30
```

#### Alert Rules

Create custom alert rules:

```python
from compliance_sentinel.monitoring import MonitoringRule, EventType, EventSeverity

# Critical security events rule
critical_rule = MonitoringRule(
    rule_id='critical_security',
    name='Critical Security Events',
    description='Alert on critical security vulnerabilities',
    event_types={EventType.VULNERABILITY_DETECTED},
    severity_threshold=EventSeverity.CRITICAL,
    alert_channels=['email', 'slack'],
    auto_escalate=True,
    rate_limit_minutes=1
)

monitoring.real_time_monitor.add_rule(critical_rule)
```

### Metrics Collection

#### System Metrics

- CPU usage percentage
- Memory usage and availability
- Disk usage and I/O
- Network traffic
- Process and thread counts

#### Security Metrics

- Vulnerability counts by severity
- Files and lines analyzed
- Analysis duration
- Compliance violations
- Alert counts

#### Performance Metrics

- Request rates and response times
- Error rates
- Queue sizes and processing times
- Cache hit rates

#### Custom Metrics

```python
from compliance_sentinel.monitoring import MetricsCollector, Metric, MetricType

collector = MetricsCollector()

# Record custom metrics
collector.record_counter('custom.security.scans', 1, tags={'scanner': 'custom'})
collector.record_gauge('custom.risk.score', 85.5, tags={'project': 'web-app'})
collector.record_timer('custom.analysis.duration', 12.5, tags={'language': 'javascript'})

# Use timer context manager
with collector.timer_context('custom.operation.time'):
    # Your operation here
    perform_security_analysis()
```

## Dashboards and Reporting

### Built-in Dashboards

#### Security Overview Dashboard
- Vulnerability counts by severity
- Recent security alerts
- Analysis timeline
- Compliance scores

#### System Monitoring Dashboard
- CPU and memory usage
- Network I/O
- Disk usage
- Process counts

#### Compliance Dashboard
- Compliance scores by framework
- Violation categories
- Recent violations
- Audit trail

### Creating Custom Dashboards

```python
from compliance_sentinel.monitoring import DashboardGenerator, ChartWidget, MetricWidget

generator = DashboardGenerator()

# Create custom dashboard
dashboard = generator.create_dashboard(
    'custom_security',
    'Custom Security Dashboard',
    'Custom security metrics and alerts'
)

# Add vulnerability chart
vuln_chart = ChartWidget(
    widget_id='vuln_chart',
    title='Vulnerabilities by Language',
    chart_type='bar',
    position={'x': 0, 'y': 0, 'width': 6, 'height': 4}
)
dashboard.add_widget(vuln_chart)

# Add critical vulnerabilities metric
critical_metric = MetricWidget(
    widget_id='critical_vulns',
    title='Critical Vulnerabilities',
    metric_name='security.vulnerabilities.critical',
    position={'x': 6, 'y': 0, 'width': 3, 'height': 2}
)
dashboard.add_widget(critical_metric)
```

### Accessing Dashboards

#### Web Interface
1. Navigate to `http://localhost:8080/dashboards`
2. Select dashboard from the list
3. View real-time metrics and charts
4. Configure refresh intervals
5. Export dashboard data

#### API Access
```bash
# Get dashboard data
curl http://localhost:8080/api/v1/dashboards/security_overview

# Refresh dashboard
curl -X POST http://localhost:8080/api/v1/dashboards/security_overview/refresh

# Export dashboard
curl http://localhost:8080/api/v1/dashboards/security_overview/export?format=json
```

### Report Generation

#### Automated Reports

```python
from compliance_sentinel.reporting import ReportScheduler

scheduler = ReportScheduler()

# Schedule daily security report
scheduler.schedule_report(
    report_type='security_summary',
    schedule='daily',
    time='09:00',
    recipients=['security@company.com'],
    format='pdf'
)

# Schedule weekly compliance report
scheduler.schedule_report(
    report_type='compliance_status',
    schedule='weekly',
    day='monday',
    time='08:00',
    recipients=['compliance@company.com', 'ceo@company.com'],
    format='html'
)
```

#### Manual Report Generation

```bash
# Generate security report
compliance-sentinel report security --period last_30_days --format pdf --output security-report.pdf

# Generate compliance report
compliance-sentinel report compliance --framework soc2 --format html --output compliance-report.html

# Generate executive summary
compliance-sentinel report executive --include-trends --format pdf --output executive-summary.pdf
```

## Integrations

### IDE Integrations

#### Visual Studio Code

1. Install the Compliance Sentinel extension from the VS Code marketplace
2. Configure the extension settings
3. Enjoy real-time security feedback while coding

#### IntelliJ IDEA

1. Download the Compliance Sentinel plugin
2. Install via Settings > Plugins > Install Plugin from Disk
3. Configure connection to Compliance Sentinel server

#### Command Line Integration

```bash
# Add to your shell profile (.bashrc, .zshrc)
alias cs='compliance-sentinel'
alias cs-analyze='compliance-sentinel analyze --project .'
alias cs-check='compliance-sentinel compliance-check --project .'
```

### CI/CD Integrations

#### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    
    - name: Install Compliance Sentinel
      run: pip install compliance-sentinel
    
    - name: Run Security Analysis
      run: compliance-sentinel analyze --project . --format json --output security-results.json
    
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: security-results
        path: security-results.json
```

#### Jenkins

Create a Jenkinsfile:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Analysis') {
            steps {
                sh 'pip install compliance-sentinel'
                sh 'compliance-sentinel analyze --project . --format junit --output security-results.xml'
            }
            post {
                always {
                    junit 'security-results.xml'
                }
            }
        }
        
        stage('Compliance Check') {
            steps {
                sh 'compliance-sentinel compliance-check --project . --format json --output compliance-results.json'
                archiveArtifacts artifacts: 'compliance-results.json'
            }
        }
    }
}
```

### Version Control Integration

#### Git Hooks

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Run security analysis on staged files
staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|py|java|cs|go|rs|php)$')

if [ -n "$staged_files" ]; then
    echo "Running security analysis on staged files..."
    
    for file in $staged_files; do
        compliance-sentinel analyze --file "$file" --format json --quiet
        if [ $? -ne 0 ]; then
            echo "Security issues found in $file. Commit aborted."
            exit 1
        fi
    done
    
    echo "Security analysis passed."
fi
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### Project Management Integration

#### Jira Integration

```python
from compliance_sentinel.integrations import JiraIntegration

jira = JiraIntegration(
    server='https://your-company.atlassian.net',
    username='your-username',
    api_token='your-api-token',
    project_key='SEC'
)

# Create security tickets automatically
jira.create_security_tickets(security_issues, assignee='security-team')

# Update existing tickets
jira.update_ticket_status('SEC-123', 'In Progress')
```

## Best Practices

### Security Analysis Best Practices

1. **Regular Scanning**: Run security analysis on every commit and pull request
2. **Incremental Analysis**: Use incremental scanning for large codebases
3. **Custom Rules**: Create organization-specific security rules
4. **False Positive Management**: Review and suppress false positives appropriately
5. **Severity Prioritization**: Focus on critical and high-severity issues first

### Compliance Best Practices

1. **Framework Selection**: Choose relevant compliance frameworks for your industry
2. **Regular Audits**: Perform compliance checks regularly, not just before audits
3. **Documentation**: Maintain comprehensive documentation of compliance efforts
4. **Training**: Ensure team members understand compliance requirements
5. **Continuous Monitoring**: Implement continuous compliance monitoring

### Monitoring Best Practices

1. **Alert Tuning**: Configure alerts to avoid noise while catching real issues
2. **Escalation Procedures**: Define clear escalation paths for different severity levels
3. **Response Procedures**: Document incident response procedures
4. **Regular Reviews**: Regularly review and update monitoring rules
5. **Performance Monitoring**: Monitor system performance to ensure optimal operation

### Integration Best Practices

1. **Gradual Rollout**: Implement integrations gradually across teams
2. **Training**: Provide adequate training on new tools and processes
3. **Feedback Loop**: Establish feedback mechanisms for continuous improvement
4. **Documentation**: Maintain up-to-date integration documentation
5. **Backup Plans**: Have fallback procedures if integrations fail

## Troubleshooting

### Common Issues

#### Installation Issues

**Problem**: pip install fails with permission errors
```bash
# Solution: Use virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install compliance-sentinel
```

**Problem**: Docker container won't start
```bash
# Solution: Check logs and port conflicts
docker logs compliance-sentinel
netstat -tulpn | grep 8080
```

#### Analysis Issues

**Problem**: Analysis is very slow
```bash
# Solution: Use incremental analysis and exclude unnecessary files
compliance-sentinel analyze --project . --incremental --exclude "node_modules,*.min.js"
```

**Problem**: Too many false positives
```python
# Solution: Tune rules and add suppressions
sentinel.suppress_issue('rule_id', 'file_path', 'line_number', 'reason')
```

#### Monitoring Issues

**Problem**: Alerts not being sent
```bash
# Solution: Check alert channel configuration and connectivity
compliance-sentinel test-alerts --channel email
compliance-sentinel test-alerts --channel slack
```

**Problem**: High memory usage
```yaml
# Solution: Adjust configuration
monitoring:
  max_events_in_memory: 500
  event_retention_days: 7
```

### Getting Help

1. **Documentation**: Check the comprehensive documentation
2. **GitHub Issues**: Search existing issues or create a new one
3. **Community Forum**: Join the community discussions
4. **Support Email**: Contact support@compliance-sentinel.com for enterprise users

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Command line
compliance-sentinel --debug analyze --project .

# Environment variable
export CS_DEBUG=true
compliance-sentinel analyze --project .
```

```python
# Python API
import logging
logging.getLogger('compliance_sentinel').setLevel(logging.DEBUG)

sentinel = ComplianceSentinel(debug=True)
```

### Log Files

Default log locations:
- **Linux/macOS**: `~/.compliance-sentinel/logs/`
- **Windows**: `%APPDATA%\compliance-sentinel\logs\`
- **Docker**: `/app/logs/`

Log files:
- `compliance-sentinel.log`: Main application log
- `security-analysis.log`: Security analysis specific logs
- `monitoring.log`: Monitoring system logs
- `api.log`: API server logs

---

This user guide provides comprehensive information for getting started with Compliance Sentinel. For more detailed information, refer to the specific guides for administrators, developers, compliance officers, and security analysts.