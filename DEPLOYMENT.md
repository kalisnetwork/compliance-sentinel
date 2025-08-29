# Compliance Sentinel Deployment Guide

This guide covers all deployment options for Compliance Sentinel, from local development to production environments.

## Quick Start

### Local Installation

```bash
# Download and run installation script
curl -sSL https://raw.githubusercontent.com/compliance-sentinel/compliance-sentinel/main/scripts/install.sh | bash

# Or for Windows PowerShell
iwr -useb https://raw.githubusercontent.com/compliance-sentinel/compliance-sentinel/main/scripts/install.ps1 | iex
```

### Verify Installation

```bash
compliance-sentinel --version
compliance-sentinel config validate
```

## Deployment Options

### 1. Local Development Installation

#### Prerequisites
- Python 3.9 or later
- Git
- curl (for installation script)

#### Installation Methods

**Option A: Automated Installation Script**
```bash
# Linux/macOS
curl -sSL https://install.compliance-sentinel.dev | bash

# Windows PowerShell
iwr -useb https://install.compliance-sentinel.dev/install.ps1 | iex
```

**Option B: Manual Installation**
```bash
# Create virtual environment
python -m venv compliance-sentinel-env
source compliance-sentinel-env/bin/activate  # Linux/macOS
# compliance-sentinel-env\Scripts\activate  # Windows

# Install from PyPI
pip install compliance-sentinel

# Or install from source
git clone https://github.com/compliance-sentinel/compliance-sentinel.git
cd compliance-sentinel
pip install -e .
```

**Option C: Package Managers**
```bash
# Using pipx (recommended for CLI tools)
pipx install compliance-sentinel

# Using conda
conda install -c conda-forge compliance-sentinel

# Using homebrew (macOS)
brew install compliance-sentinel
```

#### Configuration
```bash
# Initialize configuration
compliance-sentinel config init --project-name "my-project"

# Validate configuration
compliance-sentinel config validate

# View configuration
compliance-sentinel config show
```

### 2. Docker Deployment

#### Prerequisites
- Docker 20.10 or later
- Docker Compose 2.0 or later

#### Quick Start
```bash
# Clone repository
git clone https://github.com/compliance-sentinel/compliance-sentinel.git
cd compliance-sentinel

# Start services
docker-compose -f deployment/docker/docker-compose.yml up -d

# Check status
docker-compose -f deployment/docker/docker-compose.yml ps
```

#### Custom Configuration
```bash
# Create custom configuration
mkdir -p deployment/docker/config
cp compliance_sentinel/config/templates/default_config.yaml deployment/docker/config/

# Edit configuration
vim deployment/docker/config/default_config.yaml

# Restart services
docker-compose -f deployment/docker/docker-compose.yml restart
```

#### Production Docker Setup
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  compliance-sentinel-mcp:
    image: compliance-sentinel:latest
    restart: always
    environment:
      - COMPLIANCE_SENTINEL_ENV=production
      - COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
    ports:
      - "8000:8000"
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '1.0'
          memory: 512M
```

### 3. MCP Server Deployment

#### Standalone MCP Server
```bash
# Install with MCP server dependencies
pip install compliance-sentinel[mcp]

# Start MCP server
compliance-sentinel mcp start --host 0.0.0.0 --port 8000

# Or using uvicorn directly
uvicorn compliance_sentinel.mcp_server.server:app --host 0.0.0.0 --port 8000
```

#### MCP Server Configuration
```yaml
# mcp_server_config.yaml
server:
  host: "0.0.0.0"
  port: 8000
  workers: 4
  
authentication:
  enabled: true
  api_key_header: "X-API-Key"
  
rate_limiting:
  enabled: true
  requests_per_minute: 100
  burst_size: 20

caching:
  enabled: true
  ttl_seconds: 3600
  max_size: 1000

logging:
  level: "INFO"
  format: "json"
  file: "/app/logs/mcp_server.log"
```

#### Health Checks
```bash
# Health check endpoint
curl http://localhost:8000/health

# Metrics endpoint
curl http://localhost:8000/metrics

# API documentation
curl http://localhost:8000/docs
```

### 4. Kiro IDE Integration

#### Prerequisites
- Kiro IDE installed
- Compliance Sentinel installed locally

#### Installation
```bash
# Install Kiro hooks
compliance-sentinel hooks install

# Or manually copy hook configurations
cp kiro_hooks/*.json ~/.kiro/hooks/
```

#### Hook Configuration
```json
{
  "name": "compliance-sentinel-file-save",
  "triggers": [
    {
      "event": "file:save",
      "patterns": ["*.py", "*.js", "*.ts", "*.java"]
    }
  ],
  "execution": {
    "command": "compliance-sentinel",
    "args": ["analyze", "--format", "kiro", "${file}"]
  }
}
```

#### Verification
```bash
# Test hook integration
echo 'password = "test123"' > test.py
# Save file in Kiro - should trigger analysis

# Check hook status
compliance-sentinel hooks status
```

### 5. CI/CD Integration

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Compliance Sentinel
        run: pip install compliance-sentinel
      
      - name: Run Security Analysis
        run: |
          compliance-sentinel analyze --project --format json --output security-report.json
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

#### GitLab CI
```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install compliance-sentinel
  script:
    - compliance-sentinel analyze --project --format summary
  artifacts:
    reports:
      junit: security-report.xml
    paths:
      - security-report.json
  only:
    - merge_requests
    - main
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install compliance-sentinel'
                sh 'compliance-sentinel analyze --project --format json --output security-report.json'
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

## Configuration Management

### Environment-Specific Configuration

#### Development
```yaml
# .compliance-sentinel/config.yaml
project_name: "my-project-dev"
severity_thresholds:
  critical_threshold: 0
  high_threshold: 10
  medium_threshold: 50
system_config:
  hooks_enabled: true
  ide_feedback_enabled: true
```

#### Staging
```yaml
# .compliance-sentinel/config.yaml
project_name: "my-project-staging"
severity_thresholds:
  critical_threshold: 0
  high_threshold: 5
  medium_threshold: 20
system_config:
  hooks_enabled: false
  summary_reports_enabled: true
```

#### Production
```yaml
# .compliance-sentinel/config.yaml
project_name: "my-project-prod"
severity_thresholds:
  critical_threshold: 0
  high_threshold: 0
  medium_threshold: 5
system_config:
  hooks_enabled: false
  analysis_timeout: 300
```

### Configuration Validation
```bash
# Validate configuration
compliance-sentinel config validate

# Test configuration with dry run
compliance-sentinel analyze --dry-run --config-file custom-config.yaml
```

## Monitoring and Observability

### Logging Configuration
```yaml
system_config:
  log_level: "INFO"
  log_file: "/var/log/compliance-sentinel/app.log"
  log_format: "json"
  log_rotation: true
  log_max_size: "100MB"
  log_backup_count: 5
```

### Metrics Collection
```bash
# Enable metrics collection
export COMPLIANCE_SENTINEL_METRICS_ENABLED=true
export COMPLIANCE_SENTINEL_METRICS_PORT=9090

# Start with metrics
compliance-sentinel mcp start --enable-metrics
```

### Health Checks
```bash
# Application health
curl http://localhost:8000/health

# Detailed health with dependencies
curl http://localhost:8000/health/detailed

# Readiness check
curl http://localhost:8000/ready
```

## Security Considerations

### Authentication
```yaml
# Enable API authentication
mcp_servers:
  - server_name: "production-mcp"
    endpoint_url: "https://mcp.example.com"
    api_key: "${MCP_API_KEY}"  # Use environment variable
    verify_ssl: true
```

### Network Security
```bash
# Firewall rules (example for Ubuntu)
sudo ufw allow 8000/tcp  # MCP server port
sudo ufw enable

# TLS configuration
compliance-sentinel mcp start --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### Secrets Management
```bash
# Use environment variables for secrets
export COMPLIANCE_SENTINEL_API_KEY="your-secret-key"
export COMPLIANCE_SENTINEL_DB_PASSWORD="your-db-password"

# Or use external secret management
compliance-sentinel config set-secret --vault-path "secret/compliance-sentinel"
```

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Check Python version
python --version

# Check pip version
pip --version

# Clear pip cache
pip cache purge

# Reinstall with verbose output
pip install --verbose --force-reinstall compliance-sentinel
```

#### Configuration Issues
```bash
# Reset configuration
compliance-sentinel config reset

# Validate configuration with verbose output
compliance-sentinel config validate --verbose

# Check configuration file locations
compliance-sentinel config show --paths
```

#### Performance Issues
```bash
# Enable performance profiling
export COMPLIANCE_SENTINEL_PROFILE=true

# Check resource usage
compliance-sentinel analyze --profile --memory-limit 1GB

# Optimize configuration
compliance-sentinel config optimize
```

### Debugging
```bash
# Enable debug logging
export COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG

# Run with verbose output
compliance-sentinel --verbose analyze file.py

# Generate debug report
compliance-sentinel debug-report --output debug.zip
```

### Log Analysis
```bash
# View recent logs
tail -f ~/.compliance-sentinel/logs/app.log

# Search for errors
grep -i error ~/.compliance-sentinel/logs/app.log

# Analyze performance
compliance-sentinel logs analyze --performance
```

## Deployment Validation

### Automated Validation
```bash
# Run deployment validation
python scripts/validate_deployment.py --type local

# Validate Docker deployment
python scripts/validate_deployment.py --type docker --output validation-report.md

# Validate all deployment types
python scripts/validate_deployment.py --type all --json --output validation.json
```

### Manual Testing
```bash
# Test basic functionality
compliance-sentinel --version
compliance-sentinel config validate
echo 'password = "test"' | compliance-sentinel analyze --stdin

# Test MCP server
curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" -d '{"code": "password = \"test\""}'

# Test Kiro integration
compliance-sentinel hooks test --hook file-save --file test.py
```

## Scaling and Performance

### Horizontal Scaling
```yaml
# docker-compose.scale.yml
version: '3.8'
services:
  compliance-sentinel-mcp:
    deploy:
      replicas: 3
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    depends_on:
      - compliance-sentinel-mcp
```

### Performance Tuning
```yaml
system_config:
  max_concurrent_analyses: 10
  analysis_timeout: 120
  cache_enabled: true
  cache_ttl_seconds: 3600
  
performance:
  worker_processes: 4
  max_memory_per_worker: "512MB"
  enable_async_processing: true
```

### Load Balancing
```nginx
# nginx.conf
upstream compliance_sentinel {
    server compliance-sentinel-1:8000;
    server compliance-sentinel-2:8000;
    server compliance-sentinel-3:8000;
}

server {
    listen 80;
    location / {
        proxy_pass http://compliance_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Backup and Recovery

### Configuration Backup
```bash
# Backup configuration
compliance-sentinel config export --output config-backup.yaml

# Backup with encryption
compliance-sentinel config export --encrypt --output config-backup.enc

# Restore configuration
compliance-sentinel config import config-backup.yaml
```

### Data Backup
```bash
# Backup analysis data
tar -czf compliance-data-backup.tar.gz ~/.compliance-sentinel/data/

# Backup logs
tar -czf compliance-logs-backup.tar.gz ~/.compliance-sentinel/logs/
```

## Support and Maintenance

### Updates
```bash
# Check for updates
compliance-sentinel update check

# Update to latest version
pip install --upgrade compliance-sentinel

# Update with specific version
pip install compliance-sentinel==1.2.0
```

### Maintenance Tasks
```bash
# Clean up old logs
compliance-sentinel maintenance clean-logs --older-than 30d

# Optimize cache
compliance-sentinel maintenance optimize-cache

# Health check
compliance-sentinel maintenance health-check --detailed
```

### Getting Help
- **Documentation**: https://compliance-sentinel.readthedocs.io/
- **GitHub Issues**: https://github.com/compliance-sentinel/compliance-sentinel/issues
- **Community Forum**: https://community.compliance-sentinel.dev/
- **Support Email**: support@compliance-sentinel.dev

## License and Legal

Compliance Sentinel is released under the MIT License. See [LICENSE](LICENSE) for details.

For enterprise support and custom deployments, contact: enterprise@compliance-sentinel.dev