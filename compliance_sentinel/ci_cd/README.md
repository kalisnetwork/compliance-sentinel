# CI/CD Pipeline Integration

This module provides comprehensive CI/CD pipeline integration for Compliance Sentinel, enabling automated security scanning and gate enforcement across multiple platforms.

## Supported Platforms

- **Jenkins** - Plugin for security gate integration
- **GitHub Actions** - Workflow for automated security scanning  
- **GitLab CI** - Job templates with security reports
- **Azure DevOps** - Pipeline tasks and extensions

## Quick Start

### Jenkins Integration

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh 'python -m compliance_sentinel.ci_cd.jenkins_plugin --workspace ${WORKSPACE}'
                }
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: '*.html',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
    }
}
```

### GitHub Actions Integration

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Scan
        run: python -m compliance_sentinel.ci_cd.github_actions
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-reports/security-report.sarif
```

### GitLab CI Integration

```yaml
security_scan:
  stage: security
  script:
    - python -m compliance_sentinel.ci_cd.gitlab_ci
  artifacts:
    reports:
      sast: security-reports/gl-sast-report.json
      codequality: security-reports/gl-code-quality-report.json
```

### Azure DevOps Integration

```yaml
- task: PythonScript@0
  displayName: 'Security Scan'
  inputs:
    scriptSource: 'inline'
    script: 'python -m compliance_sentinel.ci_cd.azure_devops'
- task: PublishTestResults@2
  inputs:
    testResultsFiles: 'security-reports/security-test-results.trx'
```

## Security Gate Configuration

Create a `security-gate.yml` file to configure security gate rules:

```yaml
# Basic configuration
enabled: true
fail_on_error: true

# Severity thresholds
block_on_critical: true
block_on_high: true
block_on_medium: false

# Issue limits
max_critical_issues: 0
max_high_issues: 5
max_medium_issues: 20

# Custom rules
rules:
  - name: "No Hardcoded Secrets"
    severity_threshold: "HIGH"
    max_issues: 0
    categories: ["HARDCODED_SECRETS"]
    action: "block"

# Exclusions
excluded_files:
  - "*.test.js"
  - "test_*.py"
  - "**/node_modules/**"

# Reporting
generate_report: true
report_format: "json"
```

## Features

### Security Gate Enforcement

- **Configurable Thresholds** - Set limits by severity level
- **Custom Rules** - Define category-specific rules
- **File Exclusions** - Skip test files and dependencies
- **Environment-Specific** - Different rules for prod/staging/dev

### Report Generation

- **Multiple Formats** - JSON, XML, HTML, SARIF
- **Platform Integration** - Native format support for each CI/CD platform
- **Visual Reports** - HTML dashboards with charts and metrics
- **Test Integration** - JUnit/VSTest format for test result publishing

### Deployment Validation

- **Pre-deployment Checks** - Validate artifacts before release
- **Regression Detection** - Compare against previous scans
- **Environment Requirements** - Enforce production-specific rules
- **Compliance Validation** - Check regulatory framework requirements

## Platform-Specific Features

### Jenkins
- JUnit XML test results
- HTML report publishing
- Build status integration
- Email notifications
- Pipeline variables

### GitHub Actions
- SARIF upload to Security tab
- PR comments with results
- Check runs and status
- Job summaries
- Artifact uploads

### GitLab CI
- Security report format
- Code Quality integration
- GitLab Pages reports
- Merge request notes
- Pipeline variables

### Azure DevOps
- VSTest (TRX) results
- Security analysis logs
- Work item creation
- Pipeline variables
- Code coverage reports

## Advanced Configuration

### Environment-Specific Rules

```yaml
environments:
  production:
    max_critical_issues: 0
    max_high_issues: 0
    block_on_medium: true
  
  staging:
    max_critical_issues: 0
    max_high_issues: 2
    block_on_medium: false
  
  development:
    max_critical_issues: 5
    max_high_issues: 10
    block_on_medium: false
```

### Compliance Framework Integration

```yaml
frameworks:
  soc2: true
  pci_dss: true
  hipaa: false
  gdpr: true
  iso_27001: false
```

### Notification Configuration

```yaml
notifications:
  email:
    enabled: true
    recipients: ["security@company.com"]
    on_failure: true
  
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
    channel: "#security"
    on_failure: true
    on_warning: true
```

## Deployment Validation

Use the deployment validator for production releases:

```bash
python -m compliance_sentinel.ci_cd.deployment_validator \
  --deployment-path ./dist \
  --environment production \
  --config security-gate.yml \
  --previous-results previous-scan.json
```

### Deployment Checks

- **Artifact Validation** - Check for sensitive files
- **Security Regression** - Compare with previous scans  
- **Environment Requirements** - Production-specific rules
- **Compliance Validation** - Regulatory requirements
- **Dependency Security** - Vulnerable dependency detection

## API Reference

### SecurityGateConfig

Configuration class for security gate rules.

```python
from compliance_sentinel.ci_cd import SecurityGateConfig

config = SecurityGateConfig(
    enabled=True,
    fail_on_error=True,
    max_critical_issues=0,
    max_high_issues=5,
    excluded_files=["*.test.js"]
)
```

### SecurityGateEvaluator

Evaluates security issues against gate configuration.

```python
from compliance_sentinel.ci_cd import SecurityGateEvaluator

evaluator = SecurityGateEvaluator(config)
result = evaluator.evaluate(issues, scan_duration, files_scanned)
```

### Platform Integrations

```python
# Jenkins
from compliance_sentinel.ci_cd import JenkinsSecurityGate
jenkins = JenkinsSecurityGate(config)
result = jenkins.execute_security_scan(workspace_path)

# GitHub Actions  
from compliance_sentinel.ci_cd import GitHubActionsWorkflow
github = GitHubActionsWorkflow(config)
result = github.execute_action(workspace_path)

# GitLab CI
from compliance_sentinel.ci_cd import GitLabCIIntegration
gitlab = GitLabCIIntegration(config)
result = gitlab.execute_security_job(project_path)

# Azure DevOps
from compliance_sentinel.ci_cd import AzureDevOpsExtension
azure = AzureDevOpsExtension(config)
result = azure.execute_pipeline_task(source_path)
```

## Best Practices

### Security Gate Configuration

1. **Start Permissive** - Begin with higher thresholds and gradually tighten
2. **Environment-Specific** - Use stricter rules for production
3. **Exclude Test Files** - Don't scan test code and dependencies
4. **Custom Rules** - Define rules for critical security categories
5. **Regular Review** - Update thresholds based on team capabilities

### CI/CD Integration

1. **Fail Fast** - Run security scans early in the pipeline
2. **Parallel Execution** - Run security scans in parallel with other tests
3. **Artifact Storage** - Store security reports as build artifacts
4. **Notification Strategy** - Alert on failures, summarize on success
5. **Incremental Scanning** - Only scan changed files when possible

### Deployment Validation

1. **Pre-deployment Gates** - Validate before production deployment
2. **Regression Checks** - Compare with previous successful deployments
3. **Artifact Validation** - Check deployment packages for sensitive files
4. **Environment Isolation** - Use different rules for different environments
5. **Rollback Planning** - Have procedures for failed security validations

## Troubleshooting

### Common Issues

**Security Gate Fails with No Issues**
- Check configuration file syntax
- Verify file exclusion patterns
- Review custom rule definitions

**Reports Not Generated**
- Ensure output directory permissions
- Check disk space availability
- Verify report format configuration

**Platform Integration Issues**
- Verify environment variables are set
- Check platform-specific permissions
- Review authentication configuration

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
python -m compliance_sentinel.ci_cd.jenkins_plugin --workspace .
```

### Configuration Validation

Validate your security gate configuration:

```python
from compliance_sentinel.ci_cd import SecurityGateConfig

try:
    config = SecurityGateConfig.from_dict(config_dict)
    print("Configuration is valid")
except Exception as e:
    print(f"Configuration error: {e}")
```

## Examples

See the `examples/` directory for complete CI/CD integration examples:

- `examples/jenkins/` - Complete Jenkins pipeline examples
- `examples/github/` - GitHub Actions workflow examples  
- `examples/gitlab/` - GitLab CI configuration examples
- `examples/azure/` - Azure DevOps pipeline examples
- `examples/configs/` - Security gate configuration examples

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the examples directory
3. Open an issue on GitHub
4. Consult the main documentation