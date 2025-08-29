# Compliance Sentinel API Reference

This document provides comprehensive API documentation for Compliance Sentinel, including REST endpoints, Python SDK, and integration examples.

## Table of Contents

1. [Authentication](#authentication)
2. [REST API Endpoints](#rest-api-endpoints)
3. [Python SDK](#python-sdk)
4. [WebSocket API](#websocket-api)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Examples](#examples)

## Authentication

### API Key Authentication

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.compliance-sentinel.com/v1/analyze
```

### JWT Authentication

```bash
# Login to get JWT token
curl -X POST https://api.compliance-sentinel.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# Use JWT token
curl -H "Authorization: Bearer JWT_TOKEN" \
  https://api.compliance-sentinel.com/v1/analyze
```

### OAuth 2.0

```bash
# Get access token
curl -X POST https://api.compliance-sentinel.com/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

## REST API Endpoints

### Security Analysis

#### Analyze Code

**POST** `/api/v1/analyze`

Analyze code for security vulnerabilities.

**Request Body:**
```json
{
  "code": "const password = 'hardcoded123';",
  "language": "javascript",
  "rules": ["security_critical", "authentication"],
  "options": {
    "include_low_severity": false,
    "max_issues": 100
  }
}
```

**Response:**
```json
{
  "analysis_id": "uuid-here",
  "status": "completed",
  "issues": [
    {
      "id": "issue-uuid",
      "rule_id": "hardcoded_password",
      "severity": "high",
      "category": "authentication",
      "description": "Hardcoded password detected",
      "line_number": 1,
      "column": 17,
      "confidence": 0.95,
      "remediation": "Use environment variables for passwords"
    }
  ],
  "summary": {
    "total_issues": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "metadata": {
    "analysis_time": 0.5,
    "lines_analyzed": 1,
    "rules_applied": 25
  }
}
```

#### Analyze File

**POST** `/api/v1/analyze/file`

Upload and analyze a file.

**Request:** Multipart form data
- `file`: File to analyze
- `language`: Programming language (optional, auto-detected)
- `rules`: Comma-separated rule categories

**Response:** Same as analyze code endpoint

#### Analyze Project

**POST** `/api/v1/analyze/project`

Analyze an entire project from a Git repository.

**Request Body:**
```json
{
  "repository_url": "https://github.com/user/repo.git",
  "branch": "main",
  "languages": ["javascript", "python"],
  "exclude_patterns": ["node_modules", "*.min.js"],
  "rules": ["security_critical"]
}
```

#### Get Analysis Results

**GET** `/api/v1/analyze/{analysis_id}`

Retrieve analysis results by ID.

**Response:** Same as analyze endpoints

#### List Analyses

**GET** `/api/v1/analyze`

List recent analyses with pagination.

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20)
- `status`: Filter by status (pending, completed, failed)
- `language`: Filter by programming language

### Compliance

#### Check Compliance

**POST** `/api/v1/compliance/check`

Check project compliance against regulatory frameworks.

**Request Body:**
```json
{
  "project_path": "/path/to/project",
  "frameworks": ["soc2", "pci_dss", "hipaa"],
  "options": {
    "include_recommendations": true,
    "severity_threshold": "medium"
  }
}
```

**Response:**
```json
{
  "compliance_id": "uuid-here",
  "overall_score": 85.5,
  "frameworks": {
    "soc2": {
      "score": 90.0,
      "status": "compliant",
      "violations": [],
      "recommendations": [
        {
          "requirement": "CC6.1",
          "description": "Implement additional access controls",
          "priority": "medium"
        }
      ]
    }
  }
}
```

#### Get Compliance Status

**GET** `/api/v1/compliance/{framework}`

Get current compliance status for a framework.

#### Generate Compliance Report

**POST** `/api/v1/compliance/report`

Generate compliance report.

**Request Body:**
```json
{
  "frameworks": ["soc2"],
  "format": "pdf",
  "include_evidence": true,
  "time_period": "last_30_days"
}
```

### Monitoring

#### Get Metrics

**GET** `/api/v1/metrics`

Retrieve system and security metrics.

**Query Parameters:**
- `metric_names`: Comma-separated metric names
- `start_time`: ISO 8601 timestamp
- `end_time`: ISO 8601 timestamp
- `aggregation`: sum, avg, min, max

**Response:**
```json
{
  "metrics": [
    {
      "name": "security.vulnerabilities.critical",
      "value": 5,
      "timestamp": "2023-12-01T10:00:00Z",
      "tags": {
        "project": "web-app"
      }
    }
  ]
}
```

#### Get Alerts

**GET** `/api/v1/alerts`

Retrieve recent security alerts.

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert-uuid",
      "title": "Critical Vulnerability Detected",
      "severity": "critical",
      "status": "active",
      "created_at": "2023-12-01T10:00:00Z",
      "description": "SQL injection vulnerability found"
    }
  ]
}
```

#### Acknowledge Alert

**POST** `/api/v1/alerts/{alert_id}/acknowledge`

Acknowledge a security alert.

### Dashboards

#### Get Dashboard

**GET** `/api/v1/dashboards/{dashboard_id}`

Retrieve dashboard configuration and data.

**Response:**
```json
{
  "dashboard_id": "security_overview",
  "title": "Security Overview",
  "widgets": [
    {
      "widget_id": "vuln_chart",
      "title": "Vulnerabilities by Severity",
      "type": "chart",
      "data": {
        "labels": ["Critical", "High", "Medium", "Low"],
        "datasets": [
          {
            "data": [2, 5, 10, 15],
            "backgroundColor": ["#dc3545", "#fd7e14", "#ffc107", "#28a745"]
          }
        ]
      }
    }
  ]
}
```

#### Create Dashboard

**POST** `/api/v1/dashboards`

Create a new dashboard.

#### Update Dashboard

**PUT** `/api/v1/dashboards/{dashboard_id}`

Update dashboard configuration.

### Rules Management

#### List Rules

**GET** `/api/v1/rules`

List available security rules.

**Response:**
```json
{
  "rules": [
    {
      "id": "hardcoded_password",
      "name": "Hardcoded Password Detection",
      "category": "authentication",
      "severity": "high",
      "languages": ["javascript", "python", "java"],
      "description": "Detects hardcoded passwords in source code"
    }
  ]
}
```

#### Create Custom Rule

**POST** `/api/v1/rules`

Create a custom security rule.

**Request Body:**
```json
{
  "id": "custom_api_key",
  "name": "Custom API Key Detection",
  "pattern": "api[_-]?key\\s*=\\s*[\"'][^\"']{20,}[\"']",
  "severity": "high",
  "category": "authentication",
  "languages": ["javascript", "python"],
  "description": "Detects hardcoded API keys"
}
```

### User Management

#### List Users

**GET** `/api/v1/users`

List system users (admin only).

#### Create User

**POST** `/api/v1/users`

Create a new user account.

#### Update User

**PUT** `/api/v1/users/{user_id}`

Update user information.

#### Delete User

**DELETE** `/api/v1/users/{user_id}`

Delete user account.

## Python SDK

### Installation

```bash
pip install compliance-sentinel-sdk
```

### Basic Usage

```python
from compliance_sentinel import ComplianceSentinel

# Initialize client
client = ComplianceSentinel(
    api_key='your-api-key',
    base_url='https://api.compliance-sentinel.com'
)

# Analyze code
result = client.analyze_code(
    code='const password = "hardcoded123";',
    language='javascript'
)

# Print issues
for issue in result.issues:
    print(f"{issue.severity}: {issue.description}")
```

### Advanced Usage

```python
from compliance_sentinel import ComplianceSentinel
from compliance_sentinel.models import AnalysisOptions

client = ComplianceSentinel(api_key='your-api-key')

# Configure analysis options
options = AnalysisOptions(
    include_low_severity=False,
    max_issues=50,
    timeout=300
)

# Analyze project
result = client.analyze_project(
    project_path='/path/to/project',
    languages=['javascript', 'python'],
    rules=['security_critical', 'authentication'],
    options=options
)

# Check compliance
compliance_result = client.check_compliance(
    project_path='/path/to/project',
    frameworks=['soc2', 'pci_dss']
)

print(f"Compliance Score: {compliance_result.overall_score}%")
```

### Async Support

```python
import asyncio
from compliance_sentinel import AsyncComplianceSentinel

async def main():
    client = AsyncComplianceSentinel(api_key='your-api-key')
    
    # Async analysis
    result = await client.analyze_code(
        code='const password = "hardcoded123";',
        language='javascript'
    )
    
    print(f"Found {len(result.issues)} issues")

asyncio.run(main())
```

## WebSocket API

### Real-time Analysis Updates

```javascript
const ws = new WebSocket('wss://api.compliance-sentinel.com/v1/ws');

ws.onopen = function() {
    // Subscribe to analysis updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'analysis_updates',
        auth_token: 'your-jwt-token'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    if (data.type === 'analysis_progress') {
        console.log(`Analysis ${data.analysis_id}: ${data.progress}%`);
    } else if (data.type === 'analysis_complete') {
        console.log(`Analysis completed: ${data.analysis_id}`);
    }
};
```

### Real-time Monitoring

```javascript
// Subscribe to security alerts
ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'security_alerts',
    filters: {
        severity: ['critical', 'high']
    }
}));

ws.onmessage = function(event) {
    const alert = JSON.parse(event.data);
    
    if (alert.type === 'security_alert') {
        displayAlert(alert.data);
    }
};
```

## Error Handling

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request is invalid",
    "details": {
      "field": "language",
      "reason": "Unsupported language: 'cobol'"
    },
    "request_id": "req-uuid-here"
  }
}
```

### Common Error Codes

- `INVALID_REQUEST`: Request validation failed
- `AUTHENTICATION_FAILED`: Invalid credentials
- `AUTHORIZATION_FAILED`: Insufficient permissions
- `RESOURCE_NOT_FOUND`: Requested resource not found
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `ANALYSIS_FAILED`: Analysis could not be completed
- `INTERNAL_ERROR`: Unexpected server error

## Rate Limiting

### Rate Limit Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1638360000
```

### Rate Limits by Endpoint

- **Analysis endpoints**: 100 requests/hour
- **Compliance endpoints**: 50 requests/hour
- **Monitoring endpoints**: 1000 requests/hour
- **Dashboard endpoints**: 500 requests/hour

### Handling Rate Limits

```python
import time
from compliance_sentinel import ComplianceSentinel, RateLimitError

client = ComplianceSentinel(api_key='your-api-key')

try:
    result = client.analyze_code(code, language)
except RateLimitError as e:
    # Wait and retry
    time.sleep(e.retry_after)
    result = client.analyze_code(code, language)
```

## Examples

### Complete Analysis Workflow

```python
from compliance_sentinel import ComplianceSentinel

client = ComplianceSentinel(api_key='your-api-key')

# 1. Analyze project
analysis = client.analyze_project('/path/to/project')

# 2. Filter critical issues
critical_issues = [
    issue for issue in analysis.issues 
    if issue.severity == 'critical'
]

# 3. Check compliance
compliance = client.check_compliance(
    project_path='/path/to/project',
    frameworks=['soc2']
)

# 4. Generate report
report = client.generate_report(
    analysis_id=analysis.id,
    compliance_id=compliance.id,
    format='pdf'
)

print(f"Report generated: {report.download_url}")
```

### Monitoring Integration

```python
from compliance_sentinel import ComplianceSentinel
from compliance_sentinel.monitoring import MonitoringClient

# Analysis client
client = ComplianceSentinel(api_key='your-api-key')

# Monitoring client
monitor = MonitoringClient(api_key='your-api-key')

# Set up alert handler
def handle_alert(alert):
    if alert.severity == 'critical':
        # Trigger incident response
        create_incident(alert)
    
    # Log alert
    print(f"Alert: {alert.title} ({alert.severity})")

# Subscribe to alerts
monitor.subscribe_to_alerts(
    callback=handle_alert,
    filters={'severity': ['critical', 'high']}
)

# Start monitoring
monitor.start()
```

This API reference provides comprehensive documentation for integrating with Compliance Sentinel. For additional examples and use cases, refer to the SDK documentation and example repositories.