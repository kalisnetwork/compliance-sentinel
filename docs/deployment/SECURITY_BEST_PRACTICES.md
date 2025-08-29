# Security Best Practices

This document outlines security best practices for deploying and operating Compliance Sentinel in production environments.

## Table of Contents

- [Configuration Security](#configuration-security)
- [Authentication and Authorization](#authentication-and-authorization)
- [Network Security](#network-security)
- [Container Security](#container-security)
- [Kubernetes Security](#kubernetes-security)
- [Secret Management](#secret-management)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Incident Response](#incident-response)
- [Compliance Requirements](#compliance-requirements)

## Configuration Security

### Environment Variables

**Secure Configuration Practices:**

1. **Never hardcode secrets in configuration files:**
```bash
# ❌ WRONG - Hardcoded secret
COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=hardcoded-secret-123

# ✅ CORRECT - Reference to secret manager
COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=${JWT_SECRET_FROM_VAULT}
```

2. **Use strong, randomly generated secrets:**
```bash
# Generate strong JWT secret
export COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=$(openssl rand -base64 64)

# Generate API keys with sufficient entropy
export API_KEY=$(openssl rand -hex 32)
```

3. **Implement proper secret rotation:**
```bash
# Configure automatic secret rotation
export COMPLIANCE_SENTINEL_SECRET_ROTATION_ENABLED=true
export COMPLIANCE_SENTINEL_SECRET_ROTATION_INTERVAL_DAYS=30
```

4. **Validate configuration security:**
```bash
# Check for hardcoded secrets
python -m compliance_sentinel.testing.production_data_validator validate-secrets

# Validate configuration security
python -m compliance_sentinel.cli config validate --security-check
```

### File Permissions

**Secure File Permissions:**
```bash
# Configuration files should be readable only by the application user
chmod 600 .env.production
chown compliance-sentinel:compliance-sentinel .env.production

# Log files should be writable by application, readable by monitoring
chmod 640 /var/log/compliance-sentinel/*.log
chown compliance-sentinel:adm /var/log/compliance-sentinel/*.log

# Application directory permissions
chmod 750 /opt/compliance-sentinel
chown -R compliance-sentinel:compliance-sentinel /opt/compliance-sentinel
```

### Real-Time Data Integration Security

**Secure External API Access:**

1. **API Key Management for External Services:**
```bash
# Use separate API keys for different environments
export COMPLIANCE_SENTINEL_NVD_API_KEY_PROD=${NVD_API_KEY_PROD}
export COMPLIANCE_SENTINEL_NVD_API_KEY_STAGING=${NVD_API_KEY_STAGING}

# Rotate API keys regularly
export COMPLIANCE_SENTINEL_API_KEY_ROTATION_INTERVAL_DAYS=90

# Monitor API key usage
export COMPLIANCE_SENTINEL_API_KEY_USAGE_MONITORING=true
```

2. **Secure Data Synchronization:**
```bash
# Enable secure data sync
export COMPLIANCE_SENTINEL_DATA_SYNC_ENCRYPTION=true
export COMPLIANCE_SENTINEL_DATA_SYNC_INTEGRITY_CHECK=true

# Validate data sources
export COMPLIANCE_SENTINEL_DATA_SOURCE_VALIDATION=true
export COMPLIANCE_SENTINEL_DATA_SOURCE_WHITELIST="nvd.nist.gov,api.osv.dev,cve.circl.lu"

# Secure fallback mechanisms
export COMPLIANCE_SENTINEL_FALLBACK_DATA_ENCRYPTION=true
export COMPLIANCE_SENTINEL_FALLBACK_DATA_VALIDATION=true
```

3. **Configuration Hot-Reload Security:**
```bash
# Secure configuration reloading
export COMPLIANCE_SENTINEL_CONFIG_RELOAD_AUTHENTICATION=true
export COMPLIANCE_SENTINEL_CONFIG_RELOAD_AUTHORIZATION=admin

# Validate configuration changes
export COMPLIANCE_SENTINEL_CONFIG_CHANGE_VALIDATION=true
export COMPLIANCE_SENTINEL_CONFIG_CHANGE_AUDIT=true

# Prevent malicious configuration injection
export COMPLIANCE_SENTINEL_CONFIG_INJECTION_PROTECTION=true
```

### Configuration Validation

**Security Configuration Checks:**
```python
# Implement configuration security validation
from compliance_sentinel.config.dynamic_config import DynamicConfigManager

def validate_security_configuration():
    config = DynamicConfigManager()
    
    # Check for production environment
    if config.get_environment() == "production":
        # Ensure debug is disabled
        assert not config.get_system_config().get("debug_enabled", False)
        
        # Ensure strong JWT secret
        jwt_secret = config.get_auth_config().get("jwt_secret")
        assert jwt_secret and len(jwt_secret) >= 32
        
        # Ensure HTTPS is enabled
        assert config.get_mcp_config().get("ssl_enabled", False)
        
        # Ensure audit logging is enabled
        assert config.get_audit_config().get("enabled", False)
```

## Authentication and Authorization

### JWT Security

**JWT Best Practices:**

1. **Use strong signing algorithms:**
```bash
export COMPLIANCE_SENTINEL_AUTH_JWT_ALGORITHM=HS256  # or RS256 for asymmetric
export COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=$(openssl rand -base64 64)
```

2. **Implement proper token expiration:**
```bash
export COMPLIANCE_SENTINEL_AUTH_JWT_EXPIRY_HOURS=24
export COMPLIANCE_SENTINEL_AUTH_JWT_REFRESH_ENABLED=true
export COMPLIANCE_SENTINEL_AUTH_JWT_REFRESH_THRESHOLD_HOURS=6
```

3. **Add security claims:**
```python
# Include security-relevant claims in JWT
def create_secure_jwt(user_id, permissions):
    payload = {
        "user_id": user_id,
        "permissions": permissions,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iss": "compliance-sentinel",
        "aud": "compliance-sentinel-api",
        "jti": str(uuid.uuid4()),  # Unique token ID for revocation
        "ip": request.remote_addr,  # Bind to IP address
        "user_agent": request.headers.get("User-Agent")
    }
    return jwt.encode(payload, secret, algorithm="HS256")
```

### API Key Management

**Secure API Key Practices:**

1. **Generate cryptographically secure API keys:**
```python
import secrets
import string

def generate_secure_api_key(length=64):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))
```

2. **Implement API key rotation:**
```bash
# Configure API key rotation
export COMPLIANCE_SENTINEL_AUTH_API_KEY_EXPIRY_DAYS=90
export COMPLIANCE_SENTINEL_AUTH_API_KEY_ROTATION_WARNING_DAYS=7

# Rotate API keys
python -m compliance_sentinel.cli auth rotate-api-keys --older-than-days 90
```

3. **Implement rate limiting per API key:**
```bash
export COMPLIANCE_SENTINEL_AUTH_API_KEY_RATE_LIMIT=1000
export COMPLIANCE_SENTINEL_AUTH_API_KEY_RATE_WINDOW=3600
```

### Multi-Factor Authentication

**Enable MFA for Administrative Access:**
```bash
export COMPLIANCE_SENTINEL_AUTH_MFA_ENABLED=true
export COMPLIANCE_SENTINEL_AUTH_MFA_ISSUER="Compliance Sentinel"
export COMPLIANCE_SENTINEL_AUTH_MFA_REQUIRED_FOR_ADMIN=true
```

### Session Security

**Secure Session Management:**
```bash
# Session configuration
export COMPLIANCE_SENTINEL_AUTH_SESSION_TIMEOUT_MINUTES=60
export COMPLIANCE_SENTINEL_AUTH_SESSION_SECURE_COOKIES=true
export COMPLIANCE_SENTINEL_AUTH_SESSION_HTTPONLY_COOKIES=true
export COMPLIANCE_SENTINEL_AUTH_SESSION_SAMESITE=Strict

# Account lockout protection
export COMPLIANCE_SENTINEL_AUTH_MAX_FAILED_ATTEMPTS=3
export COMPLIANCE_SENTINEL_AUTH_LOCKOUT_DURATION_MINUTES=30
export COMPLIANCE_SENTINEL_AUTH_PROGRESSIVE_LOCKOUT=true
```

## Network Security

### TLS/SSL Configuration

**Enable HTTPS Everywhere:**

1. **MCP Server TLS:**
```bash
export MCP_SSL_ENABLED=true
export MCP_SSL_CERT_PATH=/etc/ssl/certs/compliance-sentinel.crt
export MCP_SSL_KEY_PATH=/etc/ssl/private/compliance-sentinel.key
export MCP_SSL_PROTOCOLS=TLSv1.2,TLSv1.3
export MCP_SSL_CIPHERS=ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
```

2. **Nginx SSL Configuration:**
```nginx
server {
    listen 443 ssl http2;
    server_name compliance-sentinel.company.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/compliance-sentinel.crt;
    ssl_certificate_key /etc/ssl/private/compliance-sentinel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_verify on;
    }
}
```

### Firewall Configuration

**Configure Host-Based Firewall:**
```bash
# Enable UFW
sudo ufw enable

# Allow SSH (restrict to management network)
sudo ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS
sudo ufw allow 443/tcp

# Allow application ports (restrict to internal network)
sudo ufw allow from 10.0.0.0/8 to any port 8000  # MCP Server
sudo ufw allow from 10.0.0.0/8 to any port 8080  # Health checks
sudo ufw allow from 10.0.0.0/8 to any port 9090  # Metrics

# Deny all other traffic
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### Network Segmentation

**Implement Network Segmentation:**
```bash
# Application tier (DMZ)
# - Web servers, load balancers
# - Limited access to application tier

# Application tier
# - Compliance Sentinel instances
# - Access to database and cache tiers only

# Database tier
# - PostgreSQL, Redis
# - No direct external access
# - Access only from application tier

# Management tier
# - Monitoring, logging, backup systems
# - Access from management network only
```

## Container Security

### Docker Security

**Secure Docker Configuration:**

1. **Use non-root user:**
```dockerfile
# Create non-root user
RUN groupadd -r compliance && useradd -r -g compliance compliance

# Set ownership
RUN chown -R compliance:compliance /app

# Switch to non-root user
USER compliance
```

2. **Use read-only root filesystem:**
```bash
docker run --read-only --tmpfs /tmp:noexec,nosuid,size=100m compliance-sentinel:latest
```

3. **Drop unnecessary capabilities:**
```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE compliance-sentinel:latest
```

4. **Use security options:**
```bash
docker run \
  --security-opt=no-new-privileges:true \
  --security-opt=seccomp=seccomp-profile.json \
  --security-opt=apparmor=compliance-sentinel-profile \
  compliance-sentinel:latest
```

### Container Image Security

**Secure Image Building:**

1. **Use minimal base images:**
```dockerfile
# Use distroless or alpine base images
FROM gcr.io/distroless/python3:latest
# OR
FROM python:3.11-alpine
```

2. **Scan images for vulnerabilities:**
```bash
# Scan with Trivy
trivy image compliance-sentinel:latest

# Scan with Clair
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  arminc/clair-scanner:latest \
  --clair="http://clair:6060" \
  --ip="$(hostname -i)" \
  compliance-sentinel:latest
```

3. **Sign and verify images:**
```bash
# Sign images with Docker Content Trust
export DOCKER_CONTENT_TRUST=1
docker push compliance-sentinel:latest

# Verify image signatures
docker trust inspect compliance-sentinel:latest
```

### Docker Compose Security

**Secure Docker Compose Configuration:**
```yaml
version: '3.8'
services:
  compliance-sentinel:
    image: compliance-sentinel:latest
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
    
    # Read-only root filesystem
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
    
    # User specification
    user: "1000:1000"
    
    # Network isolation
    networks:
      - internal
    
    # No privileged access
    privileged: false
    
networks:
  internal:
    driver: bridge
    internal: true
```

## Kubernetes Security

### Pod Security

**Pod Security Standards:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: compliance-sentinel
spec:
  # Security context for pod
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: compliance-sentinel
    image: compliance-sentinel:1.0.0
    
    # Security context for container
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    
    # Resource limits
    resources:
      limits:
        cpu: 2000m
        memory: 4Gi
        ephemeral-storage: 2Gi
      requests:
        cpu: 1000m
        memory: 2Gi
        ephemeral-storage: 1Gi
```

### Network Policies

**Implement Network Policies:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: compliance-sentinel-netpol
  namespace: compliance-sentinel
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: compliance-sentinel
  
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow ingress from load balancer
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000
  
  # Allow ingress from monitoring
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
  
  egress:
  # Allow egress to Redis
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: redis
    ports:
    - protocol: TCP
      port: 6379
  
  # Allow egress to external APIs (HTTPS)
  - to: []
    ports:
    - protocol: TCP
      port: 443
  
  # Allow DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53
```

### RBAC Configuration

**Role-Based Access Control:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: compliance-sentinel-sa
  namespace: compliance-sentinel

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: compliance-sentinel-role
  namespace: compliance-sentinel
rules:
# Allow reading secrets for configuration
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
# Allow reading configmaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: compliance-sentinel-rolebinding
  namespace: compliance-sentinel
subjects:
- kind: ServiceAccount
  name: compliance-sentinel-sa
  namespace: compliance-sentinel
roleRef:
  kind: Role
  name: compliance-sentinel-role
  apiGroup: rbac.authorization.k8s.io
```

### Pod Security Policies

**Pod Security Policy (deprecated, use Pod Security Standards):**
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: compliance-sentinel-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  allowedCapabilities:
    - NET_BIND_SERVICE
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

## Secret Management

### AWS Secrets Manager

**Secure Secret Management with AWS:**
```bash
# Configure IAM role for secret access
aws iam create-role --role-name ComplianceSentinelSecretsRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'

# Attach policy for secret access
aws iam attach-role-policy \
  --role-name ComplianceSentinelSecretsRole \
  --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite

# Create secrets
aws secretsmanager create-secret \
  --name compliance-sentinel/prod/jwt-secret \
  --secret-string '{"secret":"'$(openssl rand -base64 64)'"}'

aws secretsmanager create-secret \
  --name compliance-sentinel/prod/redis-password \
  --secret-string '{"password":"'$(openssl rand -base64 32)'"}'

# Configure application
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=aws
export COMPLIANCE_SENTINEL_SECRET_MANAGER_REGION=us-east-1
export COMPLIANCE_SENTINEL_SECRET_MANAGER_PREFIX=compliance-sentinel/prod/
```

### HashiCorp Vault

**Secure Secret Management with Vault:**
```bash
# Initialize Vault
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Enable KV secrets engine
vault secrets enable -path=compliance-sentinel kv-v2

# Create policy for application
vault policy write compliance-sentinel-policy - <<EOF
path "compliance-sentinel/data/prod/*" {
  capabilities = ["read"]
}
EOF

# Create application token
vault token create -policy=compliance-sentinel-policy -ttl=24h

# Store secrets
vault kv put compliance-sentinel/prod jwt-secret=<secret>
vault kv put compliance-sentinel/prod redis-password=<password>

# Configure application
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=vault
export COMPLIANCE_SENTINEL_VAULT_URL=https://vault.company.com
export COMPLIANCE_SENTINEL_VAULT_TOKEN=<token>
export COMPLIANCE_SENTINEL_VAULT_PATH=compliance-sentinel/prod
```

### Kubernetes Secrets

**Secure Kubernetes Secret Management:**
```bash
# Create secrets from command line
kubectl create secret generic compliance-sentinel-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 64) \
  --from-literal=redis-password=$(openssl rand -base64 32) \
  -n compliance-sentinel

# Use External Secrets Operator
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: compliance-sentinel-external-secrets
  namespace: compliance-sentinel
spec:
  refreshInterval: 15m
  secretStoreRef:
    name: vault-secret-store
    kind: SecretStore
  target:
    name: compliance-sentinel-secrets
    creationPolicy: Owner
  data:
  - secretKey: jwt-secret
    remoteRef:
      key: compliance-sentinel/prod
      property: jwt-secret
  - secretKey: redis-password
    remoteRef:
      key: compliance-sentinel/prod
      property: redis-password
EOF
```

## Monitoring and Auditing

### Security Monitoring

**Enable Security Monitoring:**
```bash
# Enable audit logging
export COMPLIANCE_SENTINEL_AUDIT_ENABLED=true
export COMPLIANCE_SENTINEL_AUDIT_LOG_PATH=/var/log/compliance-sentinel/audit.log
export COMPLIANCE_SENTINEL_AUDIT_LOG_FORMAT=json
export COMPLIANCE_SENTINEL_AUDIT_RETENTION_DAYS=365

# Enable security metrics
export COMPLIANCE_SENTINEL_SECURITY_METRICS_ENABLED=true
export COMPLIANCE_SENTINEL_SECURITY_EVENTS_TRACKING=true

# Configure intrusion detection
export COMPLIANCE_SENTINEL_IDS_ENABLED=true
export COMPLIANCE_SENTINEL_IDS_THRESHOLD_FAILED_LOGINS=5
export COMPLIANCE_SENTINEL_IDS_THRESHOLD_TIME_WINDOW=300
```

### Audit Logging

**Comprehensive Audit Logging:**
```python
# Audit log format
{
  "timestamp": "2023-12-01T10:00:00Z",
  "event_type": "authentication",
  "user_id": "user123",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "action": "login_attempt",
  "result": "success",
  "resource": "/api/vulnerabilities",
  "method": "GET",
  "status_code": 200,
  "request_id": "req-123456",
  "session_id": "sess-789012",
  "additional_data": {
    "api_key_id": "key-456789",
    "permissions": ["read", "write"]
  }
}
```

### Security Alerting

**Security Alert Rules:**
```yaml
# Prometheus security alerts
groups:
  - name: security.rules
    rules:
      - alert: MultipleFailedLogins
        expr: increase(compliance_sentinel_auth_failures_total[5m]) > 10
        for: 1m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "Multiple failed login attempts"
          description: "{{ $value }} failed login attempts in the last 5 minutes"
          
      - alert: SuspiciousIPActivity
        expr: increase(compliance_sentinel_requests_total{status=~"4.."}[5m]) by (ip) > 50
        for: 2m
        labels:
          severity: critical
          category: security
        annotations:
          summary: "Suspicious activity from IP {{ $labels.ip }}"
          description: "High number of 4xx responses from IP {{ $labels.ip }}"
          
      - alert: UnauthorizedAPIAccess
        expr: increase(compliance_sentinel_requests_total{status="401"}[5m]) > 20
        for: 1m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High number of unauthorized API access attempts"
          description: "{{ $value }} unauthorized access attempts in the last 5 minutes"
```

## Incident Response

### Security Incident Response Plan

**Incident Response Procedures:**

1. **Detection and Analysis:**
```bash
# Monitor security alerts
tail -f /var/log/compliance-sentinel/audit.log | grep -i "security"

# Check for suspicious patterns
grep "failed_login" /var/log/compliance-sentinel/audit.log | \
  jq -r '.ip_address' | sort | uniq -c | sort -nr

# Analyze authentication failures
grep "auth_failure" /var/log/compliance-sentinel/audit.log | \
  jq -r '.timestamp + " " + .ip_address + " " + .user_id'
```

2. **Containment:**
```bash
# Block suspicious IP addresses
sudo ufw insert 1 deny from <suspicious-ip>

# Revoke compromised API keys
python -m compliance_sentinel.cli auth revoke-api-key --key-id <compromised-key>

# Force password reset for affected users
python -m compliance_sentinel.cli auth force-password-reset --user-id <user-id>

# Enable emergency lockdown mode
export COMPLIANCE_SENTINEL_EMERGENCY_LOCKDOWN=true
systemctl restart compliance-sentinel
```

3. **Eradication and Recovery:**
```bash
# Rotate all secrets
python -m compliance_sentinel.cli auth rotate-all-secrets

# Update security configurations
export COMPLIANCE_SENTINEL_AUTH_MAX_FAILED_ATTEMPTS=3
export COMPLIANCE_SENTINEL_AUTH_LOCKOUT_DURATION_MINUTES=60

# Apply security patches
apt update && apt upgrade
pip install --upgrade compliance-sentinel

# Restart services with new configuration
systemctl restart compliance-sentinel
```

4. **Post-Incident Activities:**
```bash
# Generate incident report
python -m compliance_sentinel.cli security generate-incident-report \
  --start-time "2023-12-01T10:00:00Z" \
  --end-time "2023-12-01T12:00:00Z" \
  --output incident-report.json

# Review and update security policies
python -m compliance_sentinel.cli security review-policies

# Conduct security assessment
python -m compliance_sentinel.cli security assess --full-scan
```

### Backup and Recovery

**Security-Focused Backup Strategy:**
```bash
# Encrypted backups
export COMPLIANCE_SENTINEL_BACKUP_ENCRYPTION=true
export COMPLIANCE_SENTINEL_BACKUP_ENCRYPTION_KEY=$(openssl rand -base64 32)

# Secure backup storage
export COMPLIANCE_SENTINEL_BACKUP_S3_BUCKET=compliance-sentinel-secure-backups
export COMPLIANCE_SENTINEL_BACKUP_S3_ENCRYPTION=AES256
export COMPLIANCE_SENTINEL_BACKUP_S3_ACCESS_LOGGING=true

# Backup verification
python -m compliance_sentinel.cli backup verify --backup-id <backup-id>

# Secure restore procedure
python -m compliance_sentinel.cli restore \
  --backup-id <backup-id> \
  --verify-integrity \
  --decrypt-key <encryption-key>
```

## Compliance Requirements

### SOC 2 Type II Compliance

**SOC 2 Security Controls:**
```bash
# Access controls
export COMPLIANCE_SENTINEL_SOC2_ACCESS_CONTROLS=true
export COMPLIANCE_SENTINEL_SOC2_USER_ACCESS_REVIEW_INTERVAL=90

# Change management
export COMPLIANCE_SENTINEL_SOC2_CHANGE_MANAGEMENT=true
export COMPLIANCE_SENTINEL_SOC2_CHANGE_APPROVAL_REQUIRED=true

# Monitoring and logging
export COMPLIANCE_SENTINEL_SOC2_CONTINUOUS_MONITORING=true
export COMPLIANCE_SENTINEL_SOC2_LOG_RETENTION_DAYS=2555  # 7 years

# Incident response
export COMPLIANCE_SENTINEL_SOC2_INCIDENT_RESPONSE=true
export COMPLIANCE_SENTINEL_SOC2_INCIDENT_NOTIFICATION_TIME=24  # hours
```

### PCI DSS Compliance

**PCI DSS Security Requirements:**
```bash
# Network security
export COMPLIANCE_SENTINEL_PCI_NETWORK_SEGMENTATION=true
export COMPLIANCE_SENTINEL_PCI_FIREWALL_RULES=strict

# Data protection
export COMPLIANCE_SENTINEL_PCI_DATA_ENCRYPTION=true
export COMPLIANCE_SENTINEL_PCI_KEY_MANAGEMENT=true

# Access controls
export COMPLIANCE_SENTINEL_PCI_UNIQUE_USER_IDS=true
export COMPLIANCE_SENTINEL_PCI_TWO_FACTOR_AUTH=true

# Monitoring and testing
export COMPLIANCE_SENTINEL_PCI_LOG_MONITORING=true
export COMPLIANCE_SENTINEL_PCI_VULNERABILITY_SCANNING=true
```

### GDPR Compliance

**GDPR Privacy Controls:**
```bash
# Data protection
export COMPLIANCE_SENTINEL_GDPR_DATA_PROTECTION=true
export COMPLIANCE_SENTINEL_GDPR_ENCRYPTION_AT_REST=true
export COMPLIANCE_SENTINEL_GDPR_ENCRYPTION_IN_TRANSIT=true

# Privacy by design
export COMPLIANCE_SENTINEL_GDPR_PRIVACY_BY_DESIGN=true
export COMPLIANCE_SENTINEL_GDPR_DATA_MINIMIZATION=true

# Individual rights
export COMPLIANCE_SENTINEL_GDPR_RIGHT_TO_ACCESS=true
export COMPLIANCE_SENTINEL_GDPR_RIGHT_TO_ERASURE=true
export COMPLIANCE_SENTINEL_GDPR_DATA_PORTABILITY=true

# Breach notification
export COMPLIANCE_SENTINEL_GDPR_BREACH_NOTIFICATION=true
export COMPLIANCE_SENTINEL_GDPR_BREACH_NOTIFICATION_TIME=72  # hours
```

### HIPAA Compliance

**HIPAA Security Controls:**
```bash
# Administrative safeguards
export COMPLIANCE_SENTINEL_HIPAA_SECURITY_OFFICER=true
export COMPLIANCE_SENTINEL_HIPAA_WORKFORCE_TRAINING=true

# Physical safeguards
export COMPLIANCE_SENTINEL_HIPAA_FACILITY_ACCESS=true
export COMPLIANCE_SENTINEL_HIPAA_WORKSTATION_USE=true

# Technical safeguards
export COMPLIANCE_SENTINEL_HIPAA_ACCESS_CONTROL=true
export COMPLIANCE_SENTINEL_HIPAA_AUDIT_CONTROLS=true
export COMPLIANCE_SENTINEL_HIPAA_INTEGRITY=true
export COMPLIANCE_SENTINEL_HIPAA_TRANSMISSION_SECURITY=true
```

## Security Checklist

### Pre-Deployment Security Checklist

- [ ] All secrets are stored in secure secret management system
- [ ] No hardcoded credentials in configuration or code
- [ ] Strong, randomly generated passwords and API keys
- [ ] TLS/SSL enabled for all network communications
- [ ] Proper firewall rules configured
- [ ] Non-root user configured for application
- [ ] File permissions properly set
- [ ] Security headers configured in web server
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Backup and recovery procedures tested
- [ ] Incident response plan documented
- [ ] Security scanning completed
- [ ] Compliance requirements validated

### Post-Deployment Security Checklist

- [ ] Security monitoring active
- [ ] Audit logs being collected and analyzed
- [ ] Alerts configured and tested
- [ ] Access controls validated
- [ ] Secret rotation scheduled
- [ ] Security patches applied
- [ ] Vulnerability scanning scheduled
- [ ] Penetration testing completed
- [ ] Compliance audits scheduled
- [ ] Staff security training completed

### Regular Security Maintenance

**Daily:**
- Review security alerts and logs
- Monitor authentication failures
- Check system resource usage

**Weekly:**
- Review access logs
- Update security patches
- Test backup procedures

**Monthly:**
- Rotate secrets and API keys
- Review user access permissions
- Conduct vulnerability scans
- Update security documentation

**Quarterly:**
- Conduct penetration testing
- Review and update security policies
- Audit compliance controls
- Security awareness training

**Annually:**
- Comprehensive security assessment
- Compliance audit
- Disaster recovery testing
- Security policy review and update

For additional security guidance, consult with your security team and refer to relevant compliance frameworks and industry best practices.