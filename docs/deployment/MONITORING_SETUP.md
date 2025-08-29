# Monitoring and Alerting Setup Guide

This guide covers setting up comprehensive monitoring and alerting for Compliance Sentinel deployments.

## Table of Contents

- [Overview](#overview)
- [Metrics Collection](#metrics-collection)
- [Prometheus Setup](#prometheus-setup)
- [Grafana Dashboards](#grafana-dashboards)
- [Alerting Rules](#alerting-rules)
- [Log Aggregation](#log-aggregation)
- [Health Checks](#health-checks)
- [Performance Monitoring](#performance-monitoring)
- [Security Monitoring](#security-monitoring)
- [Troubleshooting](#troubleshooting)

## Overview

Compliance Sentinel provides comprehensive monitoring capabilities including:

- **Application Metrics**: Performance, errors, and business metrics
- **System Metrics**: CPU, memory, disk, and network usage
- **External Service Metrics**: API response times and availability
- **Security Metrics**: Authentication failures and security events
- **Business Metrics**: Analysis results and compliance status

## Metrics Collection

### Application Metrics

Compliance Sentinel exposes metrics on the `/metrics` endpoint in Prometheus format.

**Enable Metrics:**
```bash
export COMPLIANCE_SENTINEL_METRICS_ENABLED=true
export COMPLIANCE_SENTINEL_METRICS_PORT=9090
export COMPLIANCE_SENTINEL_METRICS_PATH=/metrics
export COMPLIANCE_SENTINEL_METRICS_COLLECTION_INTERVAL=30
```

**Available Metrics:**

| Metric Name | Type | Description |
|-------------|------|-------------|
| `compliance_sentinel_requests_total` | Counter | Total HTTP requests |
| `compliance_sentinel_request_duration_seconds` | Histogram | Request duration |
| `compliance_sentinel_errors_total` | Counter | Total errors by type |
| `compliance_sentinel_cache_hits_total` | Counter | Cache hit count |
| `compliance_sentinel_cache_misses_total` | Counter | Cache miss count |
| `compliance_sentinel_external_service_requests_total` | Counter | External API requests |
| `compliance_sentinel_external_service_errors_total` | Counter | External API errors |
| `compliance_sentinel_circuit_breaker_trips_total` | Counter | Circuit breaker activations |
| `compliance_sentinel_analyses_completed_total` | Counter | Completed security analyses |
| `compliance_sentinel_vulnerabilities_found_total` | Counter | Vulnerabilities detected |
| `compliance_sentinel_active_connections` | Gauge | Active connections |
| `compliance_sentinel_memory_usage_bytes` | Gauge | Memory usage |
| `compliance_sentinel_cpu_usage_percent` | Gauge | CPU usage percentage |
| `compliance_sentinel_data_sync_duration_seconds` | Histogram | Data synchronization duration |
| `compliance_sentinel_data_sync_last_success_timestamp` | Gauge | Last successful data sync |
| `compliance_sentinel_config_reload_total` | Counter | Configuration reload attempts |
| `compliance_sentinel_config_reload_errors_total` | Counter | Configuration reload failures |
| `compliance_sentinel_fallback_activations_total` | Counter | Fallback mechanism activations |
| `compliance_sentinel_cache_evictions_total` | Counter | Cache evictions |
| `compliance_sentinel_api_rate_limit_hits_total` | Counter | API rate limit hits |

### Custom Metrics

Add custom metrics for business-specific monitoring:

```python
from compliance_sentinel.monitoring.real_time_metrics import get_metrics

metrics = get_metrics()

# Counter for custom events
metrics.increment_counter("custom_events_total", 1.0, {"event_type": "user_action"})

# Gauge for current state
metrics.set_gauge("active_users", 42.0)

# Histogram for timing
with metrics.timer("custom_operation_duration"):
    # Your operation here
    pass
```

## Prometheus Setup

### Installation

**Docker Installation:**
```bash
# Create prometheus.yml
cat <<EOF > prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "compliance_sentinel_rules.yml"

scrape_configs:
  - job_name: 'compliance-sentinel'
    static_configs:
      - targets: ['compliance-sentinel:9090']
    scrape_interval: 30s
    metrics_path: /metrics
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
      
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']
EOF

# Run Prometheus
docker run -d \
  --name prometheus \
  -p 9091:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v $(pwd)/rules:/etc/prometheus/rules \
  prom/prometheus:latest
```

**System Installation:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install prometheus

# CentOS/RHEL
sudo yum install prometheus

# Configure Prometheus
sudo cp deployment/prometheus/prometheus.yml /etc/prometheus/
sudo systemctl restart prometheus
sudo systemctl enable prometheus
```

### Configuration

**Complete Prometheus Configuration:**
```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    environment: 'prod'

rule_files:
  - "/etc/prometheus/rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Compliance Sentinel Application
  - job_name: 'compliance-sentinel'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    scrape_timeout: 10s
    metrics_path: /metrics
    honor_labels: true
    
  # System Metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s
    
  # Redis Metrics
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['localhost:9121']
    scrape_interval: 30s
    
  # PostgreSQL Metrics
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']
    scrape_interval: 30s
    
  # Nginx Metrics
  - job_name: 'nginx-exporter'
    static_configs:
      - targets: ['localhost:9113']
    scrape_interval: 30s

# Remote write for long-term storage (optional)
remote_write:
  - url: "https://prometheus-remote-write.example.com/api/v1/write"
    basic_auth:
      username: "user"
      password: "password"
```

### Service Discovery

**Kubernetes Service Discovery:**
```yaml
scrape_configs:
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - compliance-sentinel
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
```

## Grafana Dashboards

### Installation

**Docker Installation:**
```bash
# Run Grafana
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin123 \
  -v grafana-data:/var/lib/grafana \
  grafana/grafana:latest
```

**System Installation:**
```bash
# Ubuntu/Debian
sudo apt install grafana

# CentOS/RHEL
sudo yum install grafana

# Start Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

### Dashboard Configuration

**Main Application Dashboard:**
```json
{
  "dashboard": {
    "id": null,
    "title": "Compliance Sentinel - Application Metrics",
    "tags": ["compliance-sentinel"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(compliance_sentinel_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec"
          }
        ]
      },
      {
        "id": 2,
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(compliance_sentinel_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(compliance_sentinel_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds"
          }
        ]
      },
      {
        "id": 3,
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(compliance_sentinel_errors_total[5m])",
            "legendFormat": "{{error_type}}"
          }
        ],
        "yAxes": [
          {
            "label": "Errors/sec"
          }
        ]
      },
      {
        "id": 4,
        "title": "Cache Hit Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(compliance_sentinel_cache_hits_total[5m]) / (rate(compliance_sentinel_cache_hits_total[5m]) + rate(compliance_sentinel_cache_misses_total[5m])) * 100",
            "legendFormat": "Hit Rate %"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

**System Resources Dashboard:**
```json
{
  "dashboard": {
    "title": "Compliance Sentinel - System Resources",
    "panels": [
      {
        "id": 1,
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "id": 2,
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100",
            "legendFormat": "Memory Usage %"
          }
        ]
      },
      {
        "id": 3,
        "title": "Disk Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(node_filesystem_size_bytes - node_filesystem_avail_bytes) / node_filesystem_size_bytes * 100",
            "legendFormat": "{{mountpoint}}"
          }
        ]
      }
    ]
  }
}
```

### Dashboard Import

**Import via API:**
```bash
# Import dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @compliance-sentinel-dashboard.json
```

**Import via UI:**
1. Open Grafana (http://localhost:3000)
2. Login with admin/admin
3. Go to "+" → Import
4. Upload JSON file or paste JSON content
5. Configure data source (Prometheus)
6. Save dashboard

## Alerting Rules

### Prometheus Alerting Rules

**Create Alert Rules:**
```yaml
# /etc/prometheus/rules/compliance_sentinel_rules.yml
groups:
  - name: compliance-sentinel.rules
    rules:
      # Application Health
      - alert: ComplianceSentinelDown
        expr: up{job="compliance-sentinel"} == 0
        for: 5m
        labels:
          severity: critical
          service: compliance-sentinel
        annotations:
          summary: "Compliance Sentinel is down"
          description: "Compliance Sentinel has been down for more than 5 minutes"
          
      - alert: HighErrorRate
        expr: rate(compliance_sentinel_errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors/sec"
          
      - alert: SlowResponseTime
        expr: histogram_quantile(0.95, rate(compliance_sentinel_request_duration_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Slow response times"
          description: "95th percentile response time is {{ $value }}s"
          
      # Cache Performance
      - alert: LowCacheHitRate
        expr: rate(compliance_sentinel_cache_hits_total[5m]) / (rate(compliance_sentinel_cache_hits_total[5m]) + rate(compliance_sentinel_cache_misses_total[5m])) < 0.8
        for: 10m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Low cache hit rate"
          description: "Cache hit rate is {{ $value | humanizePercentage }}"
          
      # External Services
      - alert: ExternalServiceErrors
        expr: rate(compliance_sentinel_external_service_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "High external service error rate"
          description: "External service error rate is {{ $value }} errors/sec"
          
      - alert: CircuitBreakerOpen
        expr: increase(compliance_sentinel_circuit_breaker_trips_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Circuit breaker activated"
          description: "Circuit breaker has been activated {{ $value }} times in the last 5 minutes"
          
      # System Resources
      - alert: HighMemoryUsage
        expr: compliance_sentinel_memory_usage_bytes / (1024*1024*1024) > 3
        for: 10m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}GB"
          
      - alert: HighCPUUsage
        expr: compliance_sentinel_cpu_usage_percent > 80
        for: 10m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is {{ $value }}%"
          
      # Business Metrics
      - alert: NoAnalysesCompleted
        expr: increase(compliance_sentinel_analyses_completed_total[1h]) == 0
        for: 1h
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "No analyses completed"
          description: "No security analyses have been completed in the last hour"
          
      - alert: HighVulnerabilityCount
        expr: increase(compliance_sentinel_vulnerabilities_found_total[1h]) > 100
        for: 5m
        labels:
          severity: critical
          service: compliance-sentinel
        annotations:
          summary: "High vulnerability count"
          description: "{{ $value }} vulnerabilities found in the last hour"
          
      # Real-Time Data Integration Alerts
      - alert: DataSyncFailure
        expr: time() - compliance_sentinel_data_sync_last_success_timestamp > 7200
        for: 5m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Data synchronization failure"
          description: "Data sync has not succeeded for {{ $value | humanizeDuration }}"
          
      - alert: ConfigReloadFailures
        expr: rate(compliance_sentinel_config_reload_errors_total[5m]) > 0
        for: 2m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Configuration reload failures"
          description: "Configuration reload failing at {{ $value }} failures/sec"
          
      - alert: FrequentFallbackActivation
        expr: rate(compliance_sentinel_fallback_activations_total[5m]) > 0.1
        for: 10m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "Frequent fallback activations"
          description: "Fallback mechanisms activating {{ $value }} times/sec"
          
      - alert: HighCacheEvictionRate
        expr: rate(compliance_sentinel_cache_evictions_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "High cache eviction rate"
          description: "Cache evictions occurring at {{ $value }} evictions/sec"
          
      - alert: APIRateLimitHits
        expr: rate(compliance_sentinel_api_rate_limit_hits_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
          service: compliance-sentinel
        annotations:
          summary: "API rate limits being hit"
          description: "Rate limits hit {{ $value }} times/sec"
```

### Alertmanager Configuration

**Install Alertmanager:**
```bash
# Docker
docker run -d \
  --name alertmanager \
  -p 9093:9093 \
  -v $(pwd)/alertmanager.yml:/etc/alertmanager/alertmanager.yml \
  prom/alertmanager:latest
```

**Configure Alertmanager:**
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alerts@company.com'
  smtp_auth_username: 'alerts@company.com'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://webhook-server:5000/alerts'
        
  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@company.com'
        subject: 'CRITICAL: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#alerts-critical'
        title: 'Critical Alert: {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
        
  - name: 'warning-alerts'
    email_configs:
      - to: 'team@company.com'
        subject: 'WARNING: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'service']
```

## Log Aggregation

### ELK Stack Setup

**Elasticsearch:**
```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "ES_JAVA_OPTS=-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

**Logstash Configuration:**
```ruby
# logstash.conf
input {
  file {
    path => "/var/log/compliance-sentinel/*.log"
    start_position => "beginning"
    codec => "json"
  }
  
  beats {
    port => 5044
  }
}

filter {
  if [service] == "compliance-sentinel" {
    # Parse timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Extract log level
    mutate {
      add_field => { "log_level" => "%{[level]}" }
    }
    
    # Parse error messages
    if [level] == "ERROR" {
      grok {
        match => { "message" => "%{GREEDYDATA:error_message}" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "compliance-sentinel-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
```

**Kibana Setup:**
```bash
docker run -d \
  --name kibana \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  docker.elastic.co/kibana/kibana:8.11.0
```

### Fluentd Configuration

**Alternative to ELK Stack:**
```yaml
# fluent.conf
<source>
  @type tail
  path /var/log/compliance-sentinel/*.log
  pos_file /var/log/fluentd/compliance-sentinel.log.pos
  tag compliance-sentinel
  format json
  time_key timestamp
  time_format %Y-%m-%dT%H:%M:%S.%L%z
</source>

<filter compliance-sentinel>
  @type record_transformer
  <record>
    hostname ${hostname}
    service compliance-sentinel
  </record>
</filter>

<match compliance-sentinel>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name compliance-sentinel
  type_name _doc
  logstash_format true
  logstash_prefix compliance-sentinel
  flush_interval 10s
</match>
```

## Health Checks

### Application Health Checks

**HTTP Health Check:**
```bash
# Basic health check
curl -f http://localhost:8080/health

# Detailed health check
curl http://localhost:8080/health/detailed
```

**Health Check Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T10:00:00Z",
  "version": "1.0.0",
  "environment": "production",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time_ms": 5
    },
    "redis": {
      "status": "healthy",
      "response_time_ms": 2
    },
    "external_apis": {
      "nvd": {
        "status": "healthy",
        "response_time_ms": 150
      },
      "cve": {
        "status": "degraded",
        "response_time_ms": 5000
      }
    }
  }
}
```

### Load Balancer Health Checks

**Nginx Configuration:**
```nginx
upstream compliance_sentinel {
    server 127.0.0.1:8000 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8001 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 80;
    
    location /health {
        access_log off;
        proxy_pass http://compliance_sentinel/health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location / {
        proxy_pass http://compliance_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Kubernetes Health Checks

**Pod Health Checks:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-sentinel
spec:
  template:
    spec:
      containers:
      - name: compliance-sentinel
        image: compliance-sentinel:1.0.0
        ports:
        - containerPort: 8000
        - containerPort: 8080
        
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
          
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
          
        startupProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
```

## Performance Monitoring

### Application Performance Monitoring (APM)

**Enable APM:**
```bash
export COMPLIANCE_SENTINEL_APM_ENABLED=true
export COMPLIANCE_SENTINEL_APM_SERVICE_NAME=compliance-sentinel
export COMPLIANCE_SENTINEL_APM_ENVIRONMENT=production
```

**Custom Performance Metrics:**
```python
from compliance_sentinel.monitoring.real_time_metrics import get_metrics

metrics = get_metrics()

# Track operation performance
@metrics.timer("database_query_duration")
def query_database():
    # Database operation
    pass

# Track business metrics
def process_analysis_result(result):
    metrics.increment_counter("analyses_completed_total", 1.0, {
        "result_type": result.type,
        "severity": result.severity
    })
    
    metrics.set_gauge("last_analysis_timestamp", time.time())
```

### Database Performance Monitoring

**PostgreSQL Exporter:**
```bash
# Install postgres_exporter
docker run -d \
  --name postgres-exporter \
  -p 9187:9187 \
  -e DATA_SOURCE_NAME="postgresql://user:password@localhost/compliance_sentinel?sslmode=disable" \
  prometheuscommunity/postgres-exporter
```

**Redis Exporter:**
```bash
# Install redis_exporter
docker run -d \
  --name redis-exporter \
  -p 9121:9121 \
  -e REDIS_ADDR=redis://localhost:6379 \
  -e REDIS_PASSWORD=your-password \
  oliver006/redis_exporter
```

## Security Monitoring

### Security Metrics

**Authentication Monitoring:**
```python
# Track authentication events
metrics.increment_counter("auth_attempts_total", 1.0, {
    "result": "success",  # success, failure, blocked
    "method": "api_key"   # api_key, jwt, basic
})

# Track security events
metrics.increment_counter("security_events_total", 1.0, {
    "event_type": "suspicious_activity",
    "severity": "high"
})
```

**Security Alerts:**
```yaml
# Security alerting rules
- alert: HighAuthenticationFailures
  expr: rate(compliance_sentinel_auth_attempts_total{result="failure"}[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
    category: security
  annotations:
    summary: "High authentication failure rate"
    description: "Authentication failure rate is {{ $value }} failures/sec"

- alert: SuspiciousActivity
  expr: increase(compliance_sentinel_security_events_total{event_type="suspicious_activity"}[5m]) > 0
  for: 1m
  labels:
    severity: critical
    category: security
  annotations:
    summary: "Suspicious activity detected"
    description: "{{ $value }} suspicious activities detected in the last 5 minutes"
```

### Audit Log Monitoring

**Configure Audit Logging:**
```bash
export COMPLIANCE_SENTINEL_AUDIT_ENABLED=true
export COMPLIANCE_SENTINEL_AUDIT_LOG_PATH=/var/log/compliance-sentinel/audit.log
export COMPLIANCE_SENTINEL_AUDIT_LOG_FORMAT=json
```

**Audit Log Analysis:**
```bash
# Monitor failed authentication attempts
tail -f /var/log/compliance-sentinel/audit.log | jq 'select(.event_type == "auth_failure")'

# Count security events by type
cat /var/log/compliance-sentinel/audit.log | jq -r '.event_type' | sort | uniq -c

# Alert on suspicious patterns
tail -f /var/log/compliance-sentinel/audit.log | \
  jq 'select(.event_type == "suspicious_activity")' | \
  while read line; do
    echo "SECURITY ALERT: $line" | mail -s "Security Alert" security@company.com
  done
```

## Troubleshooting

### Common Monitoring Issues

**Metrics Not Available:**
```bash
# Check metrics endpoint
curl http://localhost:9090/metrics

# Verify metrics configuration
python -c "
from compliance_sentinel.monitoring.real_time_metrics import get_metrics
metrics = get_metrics()
print('Metrics enabled:', metrics.enabled)
print('Metrics port:', metrics.port)
"

# Check firewall
sudo ufw status | grep 9090
```

**Prometheus Not Scraping:**
```bash
# Check Prometheus targets
curl http://localhost:9091/api/v1/targets

# Test connectivity
curl -v http://compliance-sentinel:9090/metrics

# Check Prometheus logs
docker logs prometheus
```

**Grafana Dashboard Issues:**
```bash
# Check Grafana logs
docker logs grafana

# Test data source connection
curl -X GET \
  http://admin:admin@localhost:3000/api/datasources/1/health

# Import dashboard via API
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @dashboard.json
```

### Performance Troubleshooting

**High Resource Usage:**
```bash
# Check metrics collection overhead
curl http://localhost:9090/metrics | grep -E "(process_|go_)"

# Reduce metrics collection frequency
export COMPLIANCE_SENTINEL_METRICS_COLLECTION_INTERVAL=60

# Disable detailed metrics
export COMPLIANCE_SENTINEL_DETAILED_METRICS=false
```

**Storage Issues:**
```bash
# Check Prometheus storage usage
du -sh /var/lib/prometheus/

# Configure retention
prometheus --storage.tsdb.retention.time=30d --storage.tsdb.retention.size=10GB

# Clean up old data
curl -X POST http://localhost:9091/api/v1/admin/tsdb/delete_series?match[]={__name__=~".+"}
```

For additional monitoring support, refer to the [Troubleshooting Guide](./TROUBLESHOOTING.md) or contact the operations team.