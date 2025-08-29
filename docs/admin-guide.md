# Compliance Sentinel Administrator Guide

This guide provides comprehensive information for system administrators responsible for deploying, configuring, and maintaining Compliance Sentinel in production environments.

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Installation and Deployment](#installation-and-deployment)
3. [Configuration Management](#configuration-management)
4. [User Management](#user-management)
5. [Security Configuration](#security-configuration)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Backup and Recovery](#backup-and-recovery)
8. [Performance Tuning](#performance-tuning)
9. [Troubleshooting](#troubleshooting)
10. [Upgrade Procedures](#upgrade-procedures)

## System Architecture

### Core Components

- **Analysis Engine**: Multi-language security analysis
- **Monitoring System**: Real-time event processing and alerting
- **Compliance Framework**: Regulatory compliance checking
- **Web Interface**: User dashboard and management interface
- **API Server**: RESTful API for integrations
- **Database**: PostgreSQL for data persistence
- **Message Queue**: Redis for async processing
- **File Storage**: Local or cloud storage for reports and logs

### System Requirements

#### Minimum Requirements
- **CPU**: 4 cores, 2.4 GHz
- **Memory**: 8 GB RAM
- **Storage**: 50 GB SSD
- **Network**: 1 Gbps connection
- **OS**: Ubuntu 20.04 LTS, CentOS 8, or Windows Server 2019

#### Recommended Requirements
- **CPU**: 8 cores, 3.0 GHz
- **Memory**: 16 GB RAM
- **Storage**: 200 GB SSD
- **Network**: 10 Gbps connection
- **OS**: Ubuntu 22.04 LTS

#### High Availability Requirements
- **Load Balancer**: HAProxy or AWS ALB
- **Database**: PostgreSQL cluster with replication
- **Cache**: Redis cluster
- **Storage**: Distributed file system or cloud storage

## Installation and Deployment

### Production Deployment with Docker

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  compliance-sentinel:
    image: compliance-sentinel:latest
    ports:
      - "8080:8080"
    environment:
      - CS_DB_HOST=postgres
      - CS_DB_PASSWORD=${DB_PASSWORD}
      - CS_REDIS_HOST=redis
      - CS_SECRET_KEY=${SECRET_KEY}
    depends_on:
      - postgres
      - redis
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./data:/app/data
    restart: unless-stopped
  
  postgres:
    image: postgres:14
    environment:
      - POSTGRES_DB=compliance_sentinel
      - POSTGRES_USER=cs_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
  
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - compliance-sentinel
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

Deploy:
```bash
docker-compose -f docker-compose.prod.yml up -d
```### Kubern
etes Deployment

Create `k8s/namespace.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: compliance-sentinel
```

Create `k8s/deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-sentinel
  namespace: compliance-sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: compliance-sentinel
  template:
    metadata:
      labels:
        app: compliance-sentinel
    spec:
      containers:
      - name: compliance-sentinel
        image: compliance-sentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: CS_DB_HOST
          value: "postgres-service"
        - name: CS_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

Deploy to Kubernetes:
```bash
kubectl apply -f k8s/
```

### Manual Installation

#### System Dependencies

Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev
sudo apt install -y postgresql-14 redis-server nginx
sudo apt install -y build-essential libpq-dev
```

CentOS/RHEL:
```bash
sudo yum update
sudo yum install -y python39 python39-devel
sudo yum install -y postgresql14-server redis nginx
sudo yum groupinstall -y "Development Tools"
```

#### Application Installation

```bash
# Create application user
sudo useradd -r -s /bin/false compliance-sentinel

# Create directories
sudo mkdir -p /opt/compliance-sentinel
sudo mkdir -p /var/log/compliance-sentinel
sudo mkdir -p /etc/compliance-sentinel

# Set permissions
sudo chown -R compliance-sentinel:compliance-sentinel /opt/compliance-sentinel
sudo chown -R compliance-sentinel:compliance-sentinel /var/log/compliance-sentinel

# Install application
sudo -u compliance-sentinel python3.9 -m venv /opt/compliance-sentinel/venv
sudo -u compliance-sentinel /opt/compliance-sentinel/venv/bin/pip install compliance-sentinel

# Create systemd service
sudo tee /etc/systemd/system/compliance-sentinel.service > /dev/null <<EOF
[Unit]
Description=Compliance Sentinel Security Analysis Platform
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=compliance-sentinel
Group=compliance-sentinel
WorkingDirectory=/opt/compliance-sentinel
Environment=PATH=/opt/compliance-sentinel/venv/bin
ExecStart=/opt/compliance-sentinel/venv/bin/compliance-sentinel serve --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable compliance-sentinel
sudo systemctl start compliance-sentinel
```

## Configuration Management

### Main Configuration File

Create `/etc/compliance-sentinel/config.yaml`:

```yaml
# Database Configuration
database:
  type: postgresql
  host: localhost
  port: 5432
  database: compliance_sentinel
  username: cs_user
  password: ${CS_DB_PASSWORD}
  pool_size: 20
  max_overflow: 30
  pool_timeout: 30
  pool_recycle: 3600

# Redis Configuration
redis:
  host: localhost
  port: 6379
  password: ${CS_REDIS_PASSWORD}
  db: 0
  max_connections: 50

# Security Configuration
security:
  secret_key: ${CS_SECRET_KEY}
  jwt_secret: ${CS_JWT_SECRET}
  jwt_expiration: 3600
  password_min_length: 12
  password_require_special: true
  session_timeout: 1800
  max_login_attempts: 5
  lockout_duration: 900

# Analysis Configuration
analysis:
  max_file_size: 10485760  # 10MB
  max_project_size: 1073741824  # 1GB
  timeout: 300  # 5 minutes
  parallel_workers: 4
  cache_enabled: true
  cache_ttl: 3600

# Monitoring Configuration
monitoring:
  enabled: true
  metrics_collection_interval: 60
  event_retention_days: 30
  max_events_in_memory: 10000
  alert_channels:
    email:
      type: email
      smtp_server: ${SMTP_SERVER}
      smtp_port: 587
      username: ${SMTP_USERNAME}
      password: ${SMTP_PASSWORD}
      from_email: ${FROM_EMAIL}
      to_emails: ${ALERT_EMAILS}
      use_tls: true

# Logging Configuration
logging:
  level: INFO
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  file: /var/log/compliance-sentinel/app.log
  max_size: 100MB
  backup_count: 10
  rotate_daily: true

# API Configuration
api:
  host: 0.0.0.0
  port: 8080
  workers: 4
  timeout: 60
  max_request_size: 100MB
  cors_enabled: true
  cors_origins: ['https://your-domain.com']
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst_size: 20

# File Storage Configuration
storage:
  type: local  # or 's3', 'gcs', 'azure'
  local:
    path: /var/lib/compliance-sentinel/storage
  s3:
    bucket: compliance-sentinel-storage
    region: us-west-2
    access_key: ${AWS_ACCESS_KEY}
    secret_key: ${AWS_SECRET_KEY}
```

### Environment Variables

Create `/etc/compliance-sentinel/environment`:

```bash
# Database
CS_DB_PASSWORD=secure_database_password

# Redis
CS_REDIS_PASSWORD=secure_redis_password

# Security
CS_SECRET_KEY=your_very_long_secret_key_here
CS_JWT_SECRET=your_jwt_secret_key_here

# Email
SMTP_SERVER=smtp.gmail.com
SMTP_USERNAME=alerts@yourcompany.com
SMTP_PASSWORD=your_email_password
FROM_EMAIL=noreply@yourcompany.com
ALERT_EMAILS=security@yourcompany.com,admin@yourcompany.com

# Cloud Storage (if using)
AWS_ACCESS_KEY=your_aws_access_key
AWS_SECRET_KEY=your_aws_secret_key
```

Load environment variables in systemd service:
```ini
[Service]
EnvironmentFile=/etc/compliance-sentinel/environment
```

### SSL/TLS Configuration

#### Generate SSL Certificate

```bash
# Self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/compliance-sentinel.key \
  -out /etc/ssl/certs/compliance-sentinel.crt

# Let's Encrypt certificate (for production)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

#### Nginx Configuration

Create `/etc/nginx/sites-available/compliance-sentinel`:

```nginx
upstream compliance_sentinel {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;  # If running multiple instances
    server 127.0.0.1:8082;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/ssl/certs/compliance-sentinel.crt;
    ssl_certificate_key /etc/ssl/private/compliance-sentinel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    client_max_body_size 100M;
    proxy_read_timeout 300;
    proxy_connect_timeout 300;
    proxy_send_timeout 300;

    location / {
        proxy_pass http://compliance_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/v1/analyze {
        proxy_pass http://compliance_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600;  # Extended timeout for analysis
    }

    location /static/ {
        alias /opt/compliance-sentinel/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/compliance-sentinel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## User Management

### Database Setup

Initialize the database:

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE compliance_sentinel;
CREATE USER cs_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE compliance_sentinel TO cs_user;
ALTER USER cs_user CREATEDB;
EOF

# Initialize schema
compliance-sentinel init-db
```

### User Roles and Permissions

#### Built-in Roles

- **Super Admin**: Full system access and configuration
- **Admin**: User management and system configuration
- **Security Analyst**: Security analysis and monitoring
- **Compliance Officer**: Compliance reporting and auditing
- **Developer**: Code analysis and basic reporting
- **Viewer**: Read-only access to reports and dashboards

#### Creating Users

```bash
# Command line user creation
compliance-sentinel create-user \
  --username admin \
  --email admin@company.com \
  --role super_admin \
  --password

# Bulk user import from CSV
compliance-sentinel import-users --file users.csv
```

CSV format for bulk import:
```csv
username,email,role,first_name,last_name
john.doe,john.doe@company.com,security_analyst,John,Doe
jane.smith,jane.smith@company.com,compliance_officer,Jane,Smith
```

#### User Management API

```python
from compliance_sentinel.auth import UserManager

user_manager = UserManager()

# Create user
user = user_manager.create_user(
    username='new_user',
    email='user@company.com',
    password='secure_password',
    role='developer',
    first_name='New',
    last_name='User'
)

# Update user role
user_manager.update_user_role('new_user', 'security_analyst')

# Disable user
user_manager.disable_user('old_user')

# Reset password
user_manager.reset_password('user', 'new_password')
```

### Authentication Configuration

#### LDAP Integration

```yaml
authentication:
  type: ldap
  ldap:
    server: ldap://ldap.company.com:389
    bind_dn: cn=admin,dc=company,dc=com
    bind_password: ${LDAP_PASSWORD}
    user_search_base: ou=users,dc=company,dc=com
    user_search_filter: (uid={username})
    group_search_base: ou=groups,dc=company,dc=com
    group_search_filter: (member={user_dn})
    role_mapping:
      security_team: security_analyst
      compliance_team: compliance_officer
      admin_team: admin
```

#### SAML Integration

```yaml
authentication:
  type: saml
  saml:
    sp_entity_id: https://your-domain.com/saml/metadata
    idp_entity_id: https://idp.company.com/saml/metadata
    idp_sso_url: https://idp.company.com/saml/sso
    idp_x509_cert: |
      -----BEGIN CERTIFICATE-----
      MIICertificateDataHere...
      -----END CERTIFICATE-----
    attribute_mapping:
      email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
      first_name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
      last_name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
      role: http://schemas.company.com/ws/2005/05/identity/claims/role
```

## Security Configuration

### Network Security

#### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 8080/tcp   # Block direct access to app
sudo ufw enable

# iptables
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

#### Security Headers

Add to Nginx configuration:
```nginx
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
add_header Referrer-Policy "strict-origin-when-cross-origin";
```

### Database Security

#### PostgreSQL Hardening

Edit `/etc/postgresql/14/main/postgresql.conf`:
```ini
# Connection settings
listen_addresses = 'localhost'
port = 5432
max_connections = 100

# Security settings
ssl = on
ssl_cert_file = '/etc/ssl/certs/postgres.crt'
ssl_key_file = '/etc/ssl/private/postgres.key'
password_encryption = scram-sha-256

# Logging
log_connections = on
log_disconnections = on
log_statement = 'mod'
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
```

Edit `/etc/postgresql/14/main/pg_hba.conf`:
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   compliance_sentinel cs_user                             scram-sha-256
host    compliance_sentinel cs_user        127.0.0.1/32         scram-sha-256
host    compliance_sentinel cs_user        ::1/128              scram-sha-256
```

#### Database Backup Encryption

```bash
# Create encrypted backup
pg_dump compliance_sentinel | gpg --cipher-algo AES256 --compress-algo 1 \
  --symmetric --output backup_$(date +%Y%m%d).sql.gpg

# Restore from encrypted backup
gpg --decrypt backup_20231201.sql.gpg | psql compliance_sentinel
```

### Application Security

#### Secrets Management

Using HashiCorp Vault:
```bash
# Install Vault
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/

# Configure Vault
vault server -config=vault.hcl

# Store secrets
vault kv put secret/compliance-sentinel \
  db_password=secure_db_password \
  jwt_secret=secure_jwt_secret \
  smtp_password=secure_smtp_password
```

Configuration with Vault:
```yaml
secrets:
  provider: vault
  vault:
    address: https://vault.company.com:8200
    token: ${VAULT_TOKEN}
    mount_path: secret
    path: compliance-sentinel
```

#### API Security

Rate limiting configuration:
```yaml
api:
  rate_limiting:
    enabled: true
    global_limit: 1000  # requests per minute
    per_user_limit: 100
    per_ip_limit: 200
    burst_size: 50
    
  authentication:
    jwt_expiration: 3600
    refresh_token_expiration: 86400
    max_sessions_per_user: 5
    
  authorization:
    enforce_rbac: true
    audit_all_requests: true
```

## Monitoring and Maintenance

### System Monitoring

#### Health Checks

Create `/opt/compliance-sentinel/health-check.sh`:
```bash
#!/bin/bash

# Check application health
curl -f http://localhost:8080/health || exit 1

# Check database connectivity
pg_isready -h localhost -p 5432 -U cs_user || exit 1

# Check Redis connectivity
redis-cli ping || exit 1

# Check disk space
df -h / | awk 'NR==2 {if($5+0 > 90) exit 1}'

# Check memory usage
free | awk 'NR==2{printf "%.2f%%\n", $3*100/$2}' | awk '{if($1+0 > 90) exit 1}'

echo "All health checks passed"
```

#### Monitoring with Prometheus

Create `prometheus.yml`:
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'compliance-sentinel'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scrape_interval: 30s
```

#### Log Monitoring

Configure log rotation in `/etc/logrotate.d/compliance-sentinel`:
```
/var/log/compliance-sentinel/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 compliance-sentinel compliance-sentinel
    postrotate
        systemctl reload compliance-sentinel
    endscript
}
```

### Performance Monitoring

#### Database Performance

Monitor slow queries:
```sql
-- Enable slow query logging
ALTER SYSTEM SET log_min_duration_statement = 1000;
SELECT pg_reload_conf();

-- Monitor active connections
SELECT count(*) as active_connections 
FROM pg_stat_activity 
WHERE state = 'active';

-- Monitor database size
SELECT pg_size_pretty(pg_database_size('compliance_sentinel'));
```

#### Application Performance

Monitor key metrics:
```python
from compliance_sentinel.monitoring import MetricsCollector

collector = MetricsCollector()

# Monitor response times
collector.record_timer('api.response_time', response_time)

# Monitor queue sizes
collector.record_gauge('analysis.queue_size', queue.qsize())

# Monitor error rates
collector.record_counter('api.errors', tags={'endpoint': '/analyze'})
```

### Maintenance Tasks

#### Daily Maintenance

Create `/opt/compliance-sentinel/daily-maintenance.sh`:
```bash
#!/bin/bash

# Clean up old analysis results
compliance-sentinel cleanup --older-than 30d

# Vacuum database
sudo -u postgres vacuumdb --analyze compliance_sentinel

# Rotate logs
logrotate -f /etc/logrotate.d/compliance-sentinel

# Update security rules
compliance-sentinel update-rules

# Generate daily report
compliance-sentinel report daily --email admin@company.com
```

#### Weekly Maintenance

Create `/opt/compliance-sentinel/weekly-maintenance.sh`:
```bash
#!/bin/bash

# Full database backup
pg_dump compliance_sentinel | gzip > /backups/weekly_backup_$(date +%Y%m%d).sql.gz

# Update ML models
compliance-sentinel update-models

# Security scan of the system
compliance-sentinel self-scan

# Performance report
compliance-sentinel report performance --period week
```

#### Monthly Maintenance

Create `/opt/compliance-sentinel/monthly-maintenance.sh`:
```bash
#!/bin/bash

# Archive old data
compliance-sentinel archive --older-than 90d

# Update dependencies
pip install --upgrade compliance-sentinel

# Security audit
compliance-sentinel security-audit

# Compliance report
compliance-sentinel report compliance --all-frameworks
```

### Automated Maintenance

Add to crontab:
```bash
# Daily maintenance at 2 AM
0 2 * * * /opt/compliance-sentinel/daily-maintenance.sh

# Weekly maintenance on Sunday at 3 AM
0 3 * * 0 /opt/compliance-sentinel/weekly-maintenance.sh

# Monthly maintenance on 1st at 4 AM
0 4 1 * * /opt/compliance-sentinel/monthly-maintenance.sh

# Health check every 5 minutes
*/5 * * * * /opt/compliance-sentinel/health-check.sh
```

This administrator guide provides comprehensive information for managing Compliance Sentinel in production environments. Continue reading the remaining sections for backup procedures, performance tuning, troubleshooting, and upgrade procedures.