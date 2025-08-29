# Compliance Sentinel Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Compliance Sentinel.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Configuration Problems](#configuration-problems)
3. [Analysis Issues](#analysis-issues)
4. [Performance Problems](#performance-problems)
5. [Monitoring Issues](#monitoring-issues)
6. [Database Issues](#database-issues)
7. [Network and Connectivity](#network-and-connectivity)
8. [Authentication Problems](#authentication-problems)
9. [Integration Issues](#integration-issues)
10. [Getting Help](#getting-help)

## Installation Issues

### Python Installation Problems

**Problem**: `pip install compliance-sentinel` fails with permission errors

**Solution**:
```bash
# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
pip install compliance-sentinel
```

**Problem**: ImportError: No module named 'compliance_sentinel'

**Solution**:
```bash
# Verify installation
pip list | grep compliance-sentinel

# Reinstall if missing
pip uninstall compliance-sentinel
pip install compliance-sentinel

# Check Python path
python -c "import sys; print(sys.path)"
```

### Docker Installation Issues

**Problem**: Docker container fails to start

**Solution**:
```bash
# Check Docker logs
docker logs compliance-sentinel

# Check port conflicts
netstat -tulpn | grep 8080
lsof -i :8080

# Run with different port
docker run -p 8081:8080 compliance-sentinel
```

**Problem**: Permission denied errors in container

**Solution**:
```bash
# Check file permissions
ls -la /path/to/mounted/volume

# Fix permissions
sudo chown -R 1000:1000 /path/to/mounted/volume

# Run with user mapping
docker run --user $(id -u):$(id -g) compliance-sentinel
```

### Dependency Issues

**Problem**: Conflicting package versions

**Solution**:
```bash
# Create clean environment
python -m venv fresh_env
source fresh_env/bin/activate
pip install --no-cache-dir compliance-sentinel

# Check for conflicts
pip check

# Update all packages
pip install --upgrade pip setuptools wheel
pip install --upgrade compliance-sentinel
```

## Configuration Problems

### Configuration File Issues

**Problem**: Configuration file not found

**Solution**:
```bash
# Check default locations
ls -la ~/.compliance-sentinel/config.yaml
ls -la /etc/compliance-sentinel/config.yaml
ls -la ./config.yaml

# Create default config
compliance-sentinel init-config

# Specify config location
compliance-sentinel --config /path/to/config.yaml analyze
```

**Problem**: Invalid YAML syntax

**Solution**:
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Use online YAML validator
# Check indentation (use spaces, not tabs)
# Ensure proper quoting of strings with special characters
```

### Environment Variables

**Problem**: Environment variables not loaded

**Solution**:
```bash
# Check environment variables
env | grep CS_

# Load from file
source /etc/compliance-sentinel/environment
export $(cat .env | xargs)

# Verify in Python
python -c "import os; print(os.environ.get('CS_DB_PASSWORD'))"
```

### Database Configuration

**Problem**: Database connection failed

**Solution**:
```bash
# Test database connectivity
pg_isready -h localhost -p 5432 -U cs_user

# Check connection string
psql "postgresql://cs_user:password@localhost:5432/compliance_sentinel"

# Verify database exists
sudo -u postgres psql -l | grep compliance_sentinel

# Create database if missing
sudo -u postgres createdb compliance_sentinel
sudo -u postgres createuser cs_user
```

## Analysis Issues

### Analysis Failures

**Problem**: Analysis times out

**Solution**:
```yaml
# Increase timeout in config.yaml
analysis:
  timeout: 600  # 10 minutes
  max_file_size: 52428800  # 50MB
  parallel_workers: 2  # Reduce if memory limited
```

**Problem**: Out of memory during analysis

**Solution**:
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Reduce parallel workers
export CS_ANALYSIS_WORKERS=1

# Increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Language Detection Issues

**Problem**: Wrong language detected

**Solution**:
```python
# Explicitly specify language
from compliance_sentinel import ComplianceSentinel

client = ComplianceSentinel()
result = client.analyze_code(
    code=your_code,
    language='javascript'  # Force language
)
```

**Problem**: Unsupported language

**Solution**:
```bash
# Check supported languages
compliance-sentinel list-languages

# Add custom language support
compliance-sentinel add-language --name kotlin --extensions .kt,.kts
```

### Rule Issues

**Problem**: Custom rules not loading

**Solution**:
```bash
# Validate rule syntax
compliance-sentinel validate-rules --file custom_rules.yaml

# Check rule file permissions
ls -la custom_rules.yaml

# Test rule individually
compliance-sentinel test-rule --rule-id custom_rule --code "test code"
```

**Problem**: Too many false positives

**Solution**:
```python
# Suppress specific issues
client.suppress_issue(
    rule_id='rule_name',
    file_path='path/to/file.js',
    line_number=42,
    reason='False positive - validated manually'
)

# Adjust rule sensitivity
client.configure_rule('rule_name', sensitivity='low')
```

## Performance Problems

### Slow Analysis

**Problem**: Analysis takes too long

**Diagnosis**:
```bash
# Enable profiling
compliance-sentinel --profile analyze --project /path/to/project

# Check system resources
top
htop
iotop
```

**Solutions**:
```yaml
# Optimize configuration
analysis:
  parallel_workers: 4  # Match CPU cores
  cache_enabled: true
  incremental: true
  exclude_patterns:
    - "node_modules"
    - "*.min.js"
    - "vendor"
    - "third_party"
```

### High Memory Usage

**Problem**: Memory consumption too high

**Solutions**:
```yaml
# Reduce memory usage
analysis:
  max_file_size: 10485760  # 10MB
  batch_size: 10
  streaming_analysis: true

monitoring:
  max_events_in_memory: 1000
  event_retention_days: 7
```

### Database Performance

**Problem**: Slow database queries

**Solutions**:
```sql
-- Add indexes
CREATE INDEX idx_security_issues_severity ON security_issues(severity);
CREATE INDEX idx_security_issues_created_at ON security_issues(created_at);
CREATE INDEX idx_analysis_results_project_id ON analysis_results(project_id);

-- Analyze tables
ANALYZE security_issues;
ANALYZE analysis_results;

-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

## Monitoring Issues

### Alerts Not Working

**Problem**: Email alerts not being sent

**Diagnosis**:
```bash
# Test SMTP connectivity
telnet smtp.gmail.com 587

# Check email configuration
compliance-sentinel test-email --to test@example.com

# Check logs
tail -f /var/log/compliance-sentinel/monitoring.log
```

**Solutions**:
```yaml
# Fix email configuration
monitoring:
  alert_channels:
    email:
      smtp_server: smtp.gmail.com
      smtp_port: 587
      username: your-email@gmail.com
      password: your-app-password  # Use app password for Gmail
      use_tls: true
      from_email: alerts@yourcompany.com
```

**Problem**: Slack alerts not working

**Solutions**:
```bash
# Test webhook URL
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message"}' \
  YOUR_SLACK_WEBHOOK_URL

# Verify webhook URL format
# Should be: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

### Dashboard Issues

**Problem**: Dashboard not loading data

**Solutions**:
```bash
# Check API connectivity
curl http://localhost:8080/api/v1/metrics

# Refresh dashboard data
curl -X POST http://localhost:8080/api/v1/dashboards/security_overview/refresh

# Check browser console for JavaScript errors
# Clear browser cache and cookies
```

### Metrics Collection Problems

**Problem**: Metrics not being collected

**Solutions**:
```python
# Check metrics collector status
from compliance_sentinel.monitoring import MetricsCollector

collector = MetricsCollector()
stats = collector.get_collection_stats()
print(f"Is running: {stats['is_running']}")
print(f"Errors: {stats['collection_stats']['collections_failed']}")
```

## Database Issues

### Connection Problems

**Problem**: Cannot connect to database

**Diagnosis**:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check if PostgreSQL is listening
sudo netstat -tulpn | grep 5432

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

**Solutions**:
```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Check pg_hba.conf
sudo nano /etc/postgresql/14/main/pg_hba.conf
# Add: host compliance_sentinel cs_user 127.0.0.1/32 md5

# Reload PostgreSQL configuration
sudo systemctl reload postgresql
```

### Migration Issues

**Problem**: Database migration fails

**Solutions**:
```bash
# Check current migration status
compliance-sentinel db-status

# Run migrations manually
compliance-sentinel migrate --verbose

# Rollback if needed
compliance-sentinel migrate --rollback --version 001

# Reset database (WARNING: destroys data)
compliance-sentinel db-reset --confirm
```

### Data Corruption

**Problem**: Database corruption detected

**Solutions**:
```bash
# Check database integrity
sudo -u postgres pg_dump compliance_sentinel > /dev/null

# Repair corruption
sudo -u postgres reindexdb compliance_sentinel

# Restore from backup
sudo -u postgres dropdb compliance_sentinel
sudo -u postgres createdb compliance_sentinel
sudo -u postgres psql compliance_sentinel < backup.sql
```

## Network and Connectivity

### API Connectivity Issues

**Problem**: Cannot reach API endpoints

**Diagnosis**:
```bash
# Test local connectivity
curl http://localhost:8080/health

# Test external connectivity
curl https://api.compliance-sentinel.com/v1/health

# Check firewall rules
sudo ufw status
sudo iptables -L

# Check DNS resolution
nslookup api.compliance-sentinel.com
dig api.compliance-sentinel.com
```

### SSL/TLS Issues

**Problem**: SSL certificate errors

**Solutions**:
```bash
# Check certificate validity
openssl s_client -connect api.compliance-sentinel.com:443

# Update CA certificates
sudo apt update && sudo apt install ca-certificates

# Disable SSL verification (temporary)
export PYTHONHTTPSVERIFY=0
```

### Proxy Issues

**Problem**: Requests failing behind corporate proxy

**Solutions**:
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Configure in Python
import os
os.environ['HTTP_PROXY'] = 'http://proxy.company.com:8080'
os.environ['HTTPS_PROXY'] = 'http://proxy.company.com:8080'
```

## Authentication Problems

### Login Issues

**Problem**: Cannot log in to web interface

**Solutions**:
```bash
# Reset admin password
compliance-sentinel reset-password --username admin

# Check user status
compliance-sentinel list-users --username admin

# Enable user account
compliance-sentinel enable-user --username admin
```

### API Authentication

**Problem**: API key authentication fails

**Solutions**:
```bash
# Generate new API key
compliance-sentinel generate-api-key --username your-username

# Test API key
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/health

# Check API key permissions
compliance-sentinel check-api-key --key YOUR_API_KEY
```

### JWT Token Issues

**Problem**: JWT tokens expire too quickly

**Solutions**:
```yaml
# Increase token expiration
security:
  jwt_expiration: 7200  # 2 hours
  refresh_token_expiration: 86400  # 24 hours
```

## Integration Issues

### CI/CD Integration Problems

**Problem**: GitHub Actions integration fails

**Solutions**:
```yaml
# Check GitHub Actions workflow
name: Security Analysis
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install Compliance Sentinel
      run: pip install compliance-sentinel
    - name: Run Analysis
      run: compliance-sentinel analyze --project . --format json
      env:
        CS_API_KEY: ${{ secrets.CS_API_KEY }}
```

### IDE Integration Issues

**Problem**: VS Code extension not working

**Solutions**:
```bash
# Check extension installation
code --list-extensions | grep compliance-sentinel

# Reinstall extension
code --uninstall-extension compliance-sentinel.vscode-extension
code --install-extension compliance-sentinel.vscode-extension

# Check extension logs
# View -> Output -> Compliance Sentinel
```

## Getting Help

### Debug Information

Collect debug information:
```bash
# System information
compliance-sentinel system-info

# Generate debug report
compliance-sentinel debug-report --output debug-report.zip

# Enable verbose logging
compliance-sentinel --verbose --debug analyze --project .
```

### Log Analysis

Check relevant log files:
```bash
# Application logs
tail -f /var/log/compliance-sentinel/app.log

# Analysis logs
tail -f /var/log/compliance-sentinel/analysis.log

# Monitoring logs
tail -f /var/log/compliance-sentinel/monitoring.log

# System logs
journalctl -u compliance-sentinel -f
```

### Support Channels

1. **GitHub Issues**: https://github.com/your-org/compliance-sentinel/issues
2. **Community Forum**: https://community.compliance-sentinel.com
3. **Documentation**: https://docs.compliance-sentinel.com
4. **Email Support**: support@compliance-sentinel.com (Enterprise)

### Creating Support Tickets

Include the following information:
- Compliance Sentinel version
- Operating system and version
- Python version
- Configuration file (sanitized)
- Error messages and stack traces
- Steps to reproduce the issue
- Debug report (if applicable)

### Emergency Support

For critical production issues:
- **Enterprise Hotline**: +1 (555) 123-4567
- **Emergency Email**: emergency@compliance-sentinel.com
- **Slack Channel**: #emergency-support (Enterprise customers)

This troubleshooting guide covers the most common issues. If you encounter a problem not covered here, please check the documentation or contact support.