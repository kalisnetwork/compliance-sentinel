# Deployment Guide

This guide covers deploying Compliance Sentinel across different environments with proper configuration management, security, and monitoring.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment-Specific Deployments](#environment-specific-deployments)
- [Container Deployment](#container-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Management](#configuration-management)
- [Security Considerations](#security-considerations)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Python**: 3.9 or higher
- **Memory**: Minimum 2GB RAM, Recommended 4GB+
- **CPU**: Minimum 2 cores, Recommended 4+ cores
- **Storage**: Minimum 10GB, Recommended 50GB+
- **Network**: HTTPS access to external vulnerability databases

### Dependencies

- **Redis**: For caching (optional but recommended)
- **PostgreSQL**: For persistent storage (optional)
- **Docker**: For containerized deployment
- **Kubernetes**: For orchestrated deployment

### External Services

- **NVD API**: National Vulnerability Database (FREE - no API key required)
- **CVE API**: Common Vulnerabilities and Exposures (FREE - CIRCL.lu)
- **OSV API**: Open Source Vulnerabilities (FREE - Google)
- **GitHub Advisory API**: GitHub Security Advisories (FREE with token)

### Real-Time Data Integration Requirements

- **Network Access**: HTTPS connectivity to vulnerability databases
- **Cache Storage**: Redis or in-memory caching for performance
- **Circuit Breaker**: Resilience for external service failures
- **Rate Limiting**: Respect API rate limits (configured per environment)
- **Data Freshness**: Configurable sync intervals for real-time updates

## Environment-Specific Deployments

### Development Environment

Development deployments prioritize ease of use and debugging capabilities.

#### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/compliance-sentinel.git
cd compliance-sentinel

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Copy development configuration
cp docs/configuration/development.env.template .env

# Edit configuration
nano .env

# Run application
python -m compliance_sentinel.cli --help
```

#### Development Configuration

```bash
# .env (Development)
COMPLIANCE_SENTINEL_ENVIRONMENT=development
COMPLIANCE_SENTINEL_DEBUG_ENABLED=true
COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG

# Real-time data settings (development)
COMPLIANCE_SENTINEL_CACHE_ENABLED=true
COMPLIANCE_SENTINEL_CACHE_BACKEND=memory
COMPLIANCE_SENTINEL_CACHE_TTL=300
COMPLIANCE_SENTINEL_DATA_SYNC_INTERVAL=3600

# API settings (relaxed for development)
COMPLIANCE_SENTINEL_NVD_RATE_LIMIT=100
COMPLIANCE_SENTINEL_OSV_RATE_LIMIT=500
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_ENABLED=false

# Performance settings
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=10
COMPLIANCE_SENTINEL_FILE_WATCHER_DEBOUNCE_MS=500

# Free API endpoints (no keys required)
COMPLIANCE_SENTINEL_NVD_BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
COMPLIANCE_SENTINEL_OSV_BASE_URL=https://api.osv.dev/v1
COMPLIANCE_SENTINEL_CVE_BASE_URL=https://cve.circl.lu/api
COMPLIANCE_SENTINEL_GITHUB_BASE_URL=https://api.github.com/advisories
```

#### Development Features

- Debug logging enabled
- Hot-reload configuration
- Test data allowed
- Relaxed rate limits
- Local file caching

### Staging Environment

Staging deployments mirror production but with additional monitoring and testing capabilities.

#### Staging Setup

```bash
# Set up staging environment
export COMPLIANCE_SENTINEL_ENVIRONMENT=staging

# Copy staging configuration
cp docs/configuration/staging.env.template .env.staging

# Install with production dependencies
pip install -e .[production]

# Run with staging config
source .env.staging
python -m compliance_sentinel.mcp_server
```

#### Staging Configuration

```bash
# .env.staging
COMPLIANCE_SENTINEL_ENVIRONMENT=staging
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO

# Real-time data settings (staging)
COMPLIANCE_SENTINEL_CACHE_ENABLED=true
COMPLIANCE_SENTINEL_CACHE_BACKEND=redis
COMPLIANCE_SENTINEL_REDIS_HOST=staging-redis.internal
COMPLIANCE_SENTINEL_REDIS_PORT=6379
COMPLIANCE_SENTINEL_CACHE_TTL=1800
COMPLIANCE_SENTINEL_DATA_SYNC_INTERVAL=1800

# API settings (production-like)
COMPLIANCE_SENTINEL_NVD_RATE_LIMIT=50
COMPLIANCE_SENTINEL_OSV_RATE_LIMIT=200
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_ENABLED=true
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60

# Performance settings
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=5
COMPLIANCE_SENTINEL_FILE_WATCHER_DEBOUNCE_MS=1000

# Monitoring
COMPLIANCE_SENTINEL_METRICS_ENABLED=true
COMPLIANCE_SENTINEL_METRICS_PORT=9090
```

#### Staging Features

- Production-like configuration
- Performance monitoring
- Load testing capabilities
- Staging API endpoints
- Automated testing integration

### Production Environment

Production deployments prioritize security, performance, and reliability.

#### Production Setup

```bash
# Set up production environment
export COMPLIANCE_SENTINEL_ENVIRONMENT=production

# Copy production configuration template
cp docs/configuration/production.env.template .env.production

# Install production dependencies
pip install -e .[production]

# Set up systemd service
sudo cp deployment/systemd/compliance-sentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable compliance-sentinel
sudo systemctl start compliance-sentinel
```

#### Production Configuration

```bash
# .env.production
COMPLIANCE_SENTINEL_ENVIRONMENT=production
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_LOG_LEVEL=WARNING

# Real-time data settings (production)
COMPLIANCE_SENTINEL_CACHE_ENABLED=true
COMPLIANCE_SENTINEL_CACHE_BACKEND=redis
COMPLIANCE_SENTINEL_REDIS_HOST=prod-redis.internal
COMPLIANCE_SENTINEL_REDIS_PORT=6379
COMPLIANCE_SENTINEL_REDIS_PASSWORD=${REDIS_PASSWORD}
COMPLIANCE_SENTINEL_CACHE_TTL=3600
COMPLIANCE_SENTINEL_DATA_SYNC_INTERVAL=900

# API settings (conservative for production)
COMPLIANCE_SENTINEL_NVD_RATE_LIMIT=20
COMPLIANCE_SENTINEL_OSV_RATE_LIMIT=100
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_ENABLED=true
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_FAILURE_THRESHOLD=3
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=300

# Performance settings (conservative)
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=3
COMPLIANCE_SENTINEL_FILE_WATCHER_DEBOUNCE_MS=2000

# Security settings
COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=${JWT_SECRET}
COMPLIANCE_SENTINEL_AUTH_ENABLED=true
COMPLIANCE_SENTINEL_API_KEY_REQUIRED=true

# Monitoring and alerting
COMPLIANCE_SENTINEL_METRICS_ENABLED=true
COMPLIANCE_SENTINEL_METRICS_PORT=9090
COMPLIANCE_SENTINEL_AUDIT_LOGGING_ENABLED=true

# Fallback settings
COMPLIANCE_SENTINEL_FALLBACK_ENABLED=true
COMPLIANCE_SENTINEL_FALLBACK_CACHE_ONLY=true
```

#### Production Features

- Minimal logging
- Strict security settings
- Circuit breaker protection
- Audit logging
- Performance optimization

## Container Deployment

### Docker Deployment

#### Build Image

```bash
# Build production image
docker build -t compliance-sentinel:latest .

# Build with specific version
docker build -t compliance-sentinel:1.0.0 .
```

#### Run Container

```bash
# Run with environment file
docker run -d \
  --name compliance-sentinel \
  --env-file .env.production \
  -p 8000:8000 \
  -p 8080:8080 \
  -v /var/log/compliance-sentinel:/var/log/compliance-sentinel \
  compliance-sentinel:latest

# Run with individual environment variables
docker run -d \
  --name compliance-sentinel \
  -e COMPLIANCE_SENTINEL_ENVIRONMENT=production \
  -e COMPLIANCE_SENTINEL_LOG_LEVEL=INFO \
  -e COMPLIANCE_SENTINEL_REDIS_HOST=redis \
  -p 8000:8000 \
  compliance-sentinel:latest
```

#### Docker Compose

```bash
# Deploy with Docker Compose
cp docs/configuration/docker-compose.production.yml docker-compose.yml
docker-compose up -d

# Scale application
docker-compose up -d --scale compliance-sentinel=3

# View logs
docker-compose logs -f compliance-sentinel

# Update deployment
docker-compose pull
docker-compose up -d
```

### Multi-Stage Docker Build

```dockerfile
# Dockerfile.production
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim as runtime

# Create non-root user
RUN groupadd -r compliance && useradd -r -g compliance compliance

# Install runtime dependencies
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY . /app
WORKDIR /app

# Set permissions
RUN chown -R compliance:compliance /app
USER compliance

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8000 8080 9090

# Run application
CMD ["python", "-m", "compliance_sentinel.mcp_server"]
```

## Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Verify cluster access
kubectl cluster-info
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f docs/configuration/kubernetes/namespace.yaml

# Create secrets (customize first)
kubectl apply -f docs/configuration/kubernetes/secrets.yaml

# Create configmap
kubectl apply -f docs/configuration/kubernetes/configmap.yaml

# Deploy application
kubectl apply -f docs/configuration/kubernetes/deployment.yaml

# Create services
kubectl apply -f docs/configuration/kubernetes/service.yaml

# Create ingress (if needed)
kubectl apply -f docs/configuration/kubernetes/ingress.yaml
```

### Kubernetes Configuration Management

#### Using Helm

```bash
# Install Helm
curl https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz | tar xz
sudo mv linux-amd64/helm /usr/local/bin/

# Create Helm chart
helm create compliance-sentinel-chart

# Deploy with Helm
helm install compliance-sentinel ./compliance-sentinel-chart \
  --namespace compliance-sentinel \
  --set image.tag=1.0.0 \
  --set environment=production
```

#### Using Kustomize

```bash
# Create kustomization.yaml
cat <<EOF > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- docs/configuration/kubernetes/namespace.yaml
- docs/configuration/kubernetes/configmap.yaml
- docs/configuration/kubernetes/secrets.yaml
- docs/configuration/kubernetes/deployment.yaml

patchesStrategicMerge:
- production-patches.yaml
EOF

# Deploy with Kustomize
kubectl apply -k .
```

### Kubernetes Monitoring

```bash
# Check deployment status
kubectl get deployments -n compliance-sentinel

# View pod logs
kubectl logs -f deployment/compliance-sentinel -n compliance-sentinel

# Check pod health
kubectl get pods -n compliance-sentinel
kubectl describe pod <pod-name> -n compliance-sentinel

# Port forward for testing
kubectl port-forward service/compliance-sentinel 8000:8000 -n compliance-sentinel
```

## Configuration Management

### Environment Variables

#### Loading Order

1. Default values in code
2. Configuration files
3. Environment variables
4. Command line arguments
5. Secret manager values

#### Validation

```bash
# Validate configuration
python -m compliance_sentinel.cli config validate

# Validate specific environment
python -m compliance_sentinel.cli config validate --environment production

# Show current configuration
python -m compliance_sentinel.cli config show --format json
```

### Secret Management

#### AWS Secrets Manager

```bash
# Configure AWS credentials
aws configure

# Create secrets
aws secretsmanager create-secret \
  --name compliance-sentinel/prod/jwt-secret \
  --secret-string '{"secret":"your-jwt-secret-here"}'

aws secretsmanager create-secret \
  --name compliance-sentinel/prod/redis-password \
  --secret-string '{"password":"your-redis-password"}'

# Configure application
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=aws
export COMPLIANCE_SENTINEL_SECRET_MANAGER_REGION=us-east-1
export COMPLIANCE_SENTINEL_SECRET_MANAGER_PREFIX=compliance-sentinel/prod/
```

#### HashiCorp Vault

```bash
# Install Vault
wget https://releases.hashicorp.com/vault/1.14.0/vault_1.14.0_linux_amd64.zip
unzip vault_1.14.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Configure Vault
export VAULT_ADDR=https://vault.company.com
export VAULT_TOKEN=your-vault-token

# Store secrets
vault kv put secret/compliance-sentinel/prod jwt-secret=your-jwt-secret
vault kv put secret/compliance-sentinel/prod redis-password=your-redis-password

# Configure application
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=vault
export COMPLIANCE_SENTINEL_VAULT_URL=https://vault.company.com
export COMPLIANCE_SENTINEL_VAULT_TOKEN=${VAULT_TOKEN}
export COMPLIANCE_SENTINEL_VAULT_PATH=secret/compliance-sentinel/prod
```

#### Kubernetes Secrets

```bash
# Create secret from literal values
kubectl create secret generic compliance-sentinel-secrets \
  --from-literal=jwt-secret=your-jwt-secret \
  --from-literal=redis-password=your-redis-password \
  -n compliance-sentinel

# Create secret from file
kubectl create secret generic compliance-sentinel-secrets \
  --from-env-file=.env.secrets \
  -n compliance-sentinel

# Use External Secrets Operator
kubectl apply -f docs/configuration/kubernetes/external-secrets.yaml
```

## Security Considerations

### Network Security

#### Firewall Configuration

```bash
# Allow required ports
sudo ufw allow 8000/tcp  # MCP Server
sudo ufw allow 8080/tcp  # Health check
sudo ufw allow 9090/tcp  # Metrics (internal only)

# Restrict metrics port to internal network
sudo ufw allow from 10.0.0.0/8 to any port 9090
```

#### TLS/SSL Configuration

```bash
# Generate self-signed certificate (development only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Use Let's Encrypt (production)
sudo apt install certbot
sudo certbot certonly --standalone -d your-domain.com

# Configure nginx with SSL
sudo cp deployment/nginx/ssl.conf /etc/nginx/sites-available/compliance-sentinel
sudo ln -s /etc/nginx/sites-available/compliance-sentinel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Access Control

#### API Key Management

```bash
# Generate API key
python -m compliance_sentinel.cli auth create-api-key \
  --name "production-client" \
  --permissions read,write \
  --expires-in-days 90

# List API keys
python -m compliance_sentinel.cli auth list-api-keys

# Revoke API key
python -m compliance_sentinel.cli auth revoke-api-key --key-id <key-id>
```

#### JWT Configuration

```bash
# Generate strong JWT secret
openssl rand -base64 64

# Configure JWT settings
export COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=<generated-secret>
export COMPLIANCE_SENTINEL_AUTH_JWT_EXPIRY_HOURS=24
export COMPLIANCE_SENTINEL_AUTH_JWT_ALGORITHM=HS256
```

### Security Hardening

#### System Hardening

```bash
# Create dedicated user
sudo useradd -r -s /bin/false compliance-sentinel

# Set file permissions
sudo chown -R compliance-sentinel:compliance-sentinel /opt/compliance-sentinel
sudo chmod 750 /opt/compliance-sentinel
sudo chmod 640 /opt/compliance-sentinel/config/*

# Configure systemd service with security
sudo systemctl edit compliance-sentinel --full
```

#### Container Security

```dockerfile
# Use non-root user
USER 1000:1000

# Read-only root filesystem
--read-only --tmpfs /tmp:noexec,nosuid,size=100m

# Drop capabilities
--cap-drop=ALL --cap-add=NET_BIND_SERVICE

# Security options
--security-opt=no-new-privileges:true
```

## Monitoring and Alerting

### Metrics Collection

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'compliance-sentinel'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
    scrape_interval: 30s
```

#### Grafana Dashboards

```bash
# Import dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @deployment/grafana/compliance-sentinel-dashboard.json
```

### Health Checks

#### Application Health

```bash
# Check application health
curl -f http://localhost:8080/health

# Check with timeout
timeout 10 curl -f http://localhost:8080/health || echo "Health check failed"
```

#### External Dependencies

```bash
# Check Redis connectivity
redis-cli -h redis-host ping

# Check database connectivity
pg_isready -h db-host -p 5432 -U username

# Check external APIs
curl -f https://services.nvd.nist.gov/rest/json/cves/2.0
```

### Alerting Rules

#### Prometheus Alerts

```yaml
# alerts.yml
groups:
  - name: compliance-sentinel
    rules:
      - alert: ComplianceSentinelDown
        expr: up{job="compliance-sentinel"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Compliance Sentinel is down"
          
      - alert: HighErrorRate
        expr: rate(compliance_sentinel_errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
```

### Log Management

#### Centralized Logging

```bash
# Configure rsyslog
echo "*.* @@log-server:514" >> /etc/rsyslog.conf
sudo systemctl restart rsyslog

# Configure logrotate
cat <<EOF > /etc/logrotate.d/compliance-sentinel
/var/log/compliance-sentinel/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 compliance-sentinel compliance-sentinel
    postrotate
        systemctl reload compliance-sentinel
    endscript
}
EOF
```

## Troubleshooting

### Common Issues

#### Configuration Issues

**Problem**: Application fails to start with configuration errors.

**Solution**:
```bash
# Validate configuration
python -m compliance_sentinel.cli config validate

# Check environment variables
env | grep COMPLIANCE_SENTINEL

# Test configuration loading
python -c "from compliance_sentinel.config import DynamicConfigManager; print(DynamicConfigManager().get_system_config())"
```

#### Connection Issues

**Problem**: Cannot connect to external APIs.

**Solution**:
```bash
# Test network connectivity
curl -v https://services.nvd.nist.gov/rest/json/cves/2.0

# Check DNS resolution
nslookup services.nvd.nist.gov

# Test with proxy (if applicable)
curl -x proxy:8080 https://services.nvd.nist.gov/rest/json/cves/2.0
```

#### Performance Issues

**Problem**: Slow response times or high resource usage.

**Solution**:
```bash
# Check system resources
top -p $(pgrep -f compliance-sentinel)
free -h
df -h

# Check application metrics
curl http://localhost:9090/metrics | grep compliance_sentinel

# Enable debug logging temporarily
export COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
systemctl restart compliance-sentinel
```

### Debugging Tools

#### Log Analysis

```bash
# View recent logs
journalctl -u compliance-sentinel -f

# Search for errors
journalctl -u compliance-sentinel | grep -i error

# View logs with timestamp
journalctl -u compliance-sentinel --since "1 hour ago"
```

#### Performance Profiling

```bash
# CPU profiling
python -m cProfile -o profile.stats -m compliance_sentinel.mcp_server

# Memory profiling
python -m memory_profiler -m compliance_sentinel.mcp_server

# Network monitoring
sudo netstat -tulpn | grep :8000
sudo ss -tulpn | grep :8000
```

### Recovery Procedures

#### Service Recovery

```bash
# Restart service
sudo systemctl restart compliance-sentinel

# Check service status
sudo systemctl status compliance-sentinel

# View service logs
sudo journalctl -u compliance-sentinel -n 50
```

#### Database Recovery

```bash
# Backup database
pg_dump compliance_sentinel > backup.sql

# Restore database
psql compliance_sentinel < backup.sql

# Check database connectivity
psql -h localhost -U username -d compliance_sentinel -c "SELECT 1;"
```

#### Cache Recovery

```bash
# Clear Redis cache
redis-cli FLUSHALL

# Restart Redis
sudo systemctl restart redis

# Check Redis status
redis-cli ping
```

## Support and Maintenance

### Regular Maintenance

#### Daily Tasks
- Check application logs for errors
- Monitor system resources
- Verify external API connectivity

#### Weekly Tasks
- Review security alerts
- Update vulnerability databases
- Check backup integrity

#### Monthly Tasks
- Update dependencies
- Rotate secrets and API keys
- Review access logs

### Support Contacts

- **Development Team**: dev-team@company.com
- **Operations Team**: ops-team@company.com
- **Security Team**: security-team@company.com

### Documentation Updates

Keep this documentation updated with:
- Configuration changes
- New deployment procedures
- Troubleshooting solutions
- Performance optimizations

For the latest documentation, visit: https://docs.compliance-sentinel.com