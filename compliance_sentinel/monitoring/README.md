# Monitoring Tool Integration and Correlation

This module provides comprehensive monitoring tool integrations and security event correlation capabilities for Compliance Sentinel, enabling centralized security event management, analysis, and automated incident response.

## Supported Platforms

- **Splunk** - Enterprise security information and event management (SIEM)
- **Elasticsearch** - Distributed search and analytics engine for log aggregation
- **Datadog** - Cloud monitoring and analytics platform with security metrics
- **New Relic** - Application performance monitoring with security event tracking

## Quick Start

### Basic Configuration

Create a monitoring configuration:

```python
from compliance_sentinel.monitoring import MonitoringManager, MonitoringConfig, MonitoringPlatform

# Configure multiple monitoring platforms
configs = [
    MonitoringConfig(
        platform=MonitoringPlatform.SPLUNK,
        enabled=True,
        host="splunk.company.com",
        port=8089,
        username="security_user",
        password="secure_password",
        index_name="compliance_sentinel"
    ),
    MonitoringConfig(
        platform=MonitoringPlatform.ELASTICSEARCH,
        enabled=True,
        host="elasticsearch.company.com",
        port=9200,
        username="elastic",
        password="elastic_password",
        index_name="security_events"
    ),
    MonitoringConfig(
        platform=MonitoringPlatform.DATADOG,
        enabled=True,
        api_key="your_datadog_api_key",
        api_token="your_datadog_app_key"
    )
]

# Initialize monitoring manager
manager = MonitoringManager(configs)
```

### Sending Security Events

```python
import asyncio
from compliance_sentinel.monitoring import SecurityEvent, EventType
from compliance_sentinel.core.interfaces import Severity, SecurityCategory

# Create security event
event = SecurityEvent(
    event_id="sec_001",
    source_platform=MonitoringPlatform.SPLUNK,
    event_type=EventType.STATIC_ANALYSIS,
    timestamp=datetime.now(),
    title="Critical Security Issue Detected",
    description="Hardcoded API key found in source code",
    severity=Severity.CRITICAL,
    category=SecurityCategory.HARDCODED_SECRETS,
    file_path="/app/config.py",
    confidence_score=0.95,
    risk_score=8.5,
    tags=["compliance_sentinel", "static_analysis"]
)

# Send to all configured platforms
async def send_event():
    results = await manager.send_security_event(event)
    print(f"Event sent successfully: {results}")

asyncio.run(send_event())
```

### Event Correlation

```python
from compliance_sentinel.monitoring import SecurityEventCorrelator

# Initialize correlator
correlator = SecurityEventCorrelator()

# Correlate events
async def correlate_events():
    events = [...]  # Your security events
    correlations = await correlator.analyze_correlations(events)
    
    for correlation in correlations:
        print(f"Correlation detected: {correlation.rule_name}")
        print(f"Confidence: {correlation.confidence_score:.2f}")
        print(f"Risk Score: {correlation.risk_score:.1f}")
        print(f"Events: {len(correlation.events)}")

asyncio.run(correlate_events())
```

## Platform-Specific Features

### Splunk Integration

**Features:**
- HTTP Event Collector (HEC) support
- Advanced search with SPL (Search Processing Language)
- Real-time alerting and dashboards
- Custom field mapping and indexing

**Configuration:**
```python
splunk_config = MonitoringConfig(
    platform=MonitoringPlatform.SPLUNK,
    host="splunk.company.com",
    port=8089,
    username="admin",
    password="password",
    index_name="security_events",
    use_ssl=True,
    verify_ssl=True
)
```

**Advanced Usage:**
```python
from compliance_sentinel.monitoring import SplunkIntegration

splunk = SplunkIntegration(splunk_config)

# Create custom alert
await splunk.create_alert(
    name="Critical Security Events",
    search_query='index=security_events severity=critical',
    trigger_condition='search count > 5',
    actions=['email', 'webhook']
)

# Search for correlations
correlations = await splunk.search_correlations(
    correlation_query='eval correlation_key=source_ip+"|"+user_id | stats count by correlation_key',
    time_window=timedelta(hours=1)
)
```

### Elasticsearch Integration

**Features:**
- Full-text search with Elasticsearch Query DSL
- Real-time indexing and aggregations
- Kibana dashboard integration
- Watcher alerting support

**Configuration:**
```python
elasticsearch_config = MonitoringConfig(
    platform=MonitoringPlatform.ELASTICSEARCH,
    host="elasticsearch.company.com",
    port=9200,
    username="elastic",
    password="password",
    index_name="security_events",
    use_ssl=True,
    ca_cert_path="/path/to/ca.crt"
)
```

**Advanced Usage:**
```python
from compliance_sentinel.monitoring import ElasticsearchIntegration

es = ElasticsearchIntegration(elasticsearch_config)

# Perform aggregations
agg_query = {
    "severity_stats": {
        "terms": {"field": "severity"},
        "aggs": {
            "avg_confidence": {"avg": {"field": "confidence_score"}}
        }
    }
}

results = await es.aggregate_events(agg_query, timedelta(days=1))

# Create Watcher alert
await es.create_alert(
    name="High Risk Events",
    query={
        "query": {
            "bool": {
                "must": [
                    {"range": {"risk_score": {"gte": 8.0}}},
                    {"term": {"severity": "critical"}}
                ]
            }
        }
    },
    trigger_condition={"compare": {"ctx.payload.hits.total": {"gt": 0}}}
)
```

### Datadog Integration

**Features:**
- Custom events and metrics
- Real-time dashboards and monitoring
- Alert management and notifications
- APM integration for application security

**Configuration:**
```python
datadog_config = MonitoringConfig(
    platform=MonitoringPlatform.DATADOG,
    api_key="your_datadog_api_key",
    api_token="your_datadog_app_key"
)
```

**Advanced Usage:**
```python
from compliance_sentinel.monitoring import DatadogIntegration

datadog = DatadogIntegration(datadog_config)

# Create monitor
await datadog.create_monitor(
    name="Security Events Spike",
    query="sum(last_5m):sum:compliance_sentinel.security_events.count{severity:critical} > 10",
    message="Critical security events spike detected!",
    thresholds={"critical": 10, "warning": 5}
)

# Send dashboard metrics
dashboard_metrics = {
    "severity_distribution": {"critical": 5, "high": 12, "medium": 25},
    "risk_score": 7.8,
    "active_correlations": 3
}

await datadog.send_security_dashboard_metrics(dashboard_metrics)
```

### New Relic Integration

**Features:**
- Custom events via Insights API
- NRQL querying and analysis
- Alert policies and conditions
- Dashboard creation and management

**Configuration:**
```python
newrelic_config = MonitoringConfig(
    platform=MonitoringPlatform.NEWRELIC,
    api_key="your_insights_insert_key",
    api_token="your_rest_api_key",
    custom_fields={"account_id": "your_account_id"}
)
```

**Advanced Usage:**
```python
from compliance_sentinel.monitoring import NewRelicIntegration

newrelic = NewRelicIntegration(newrelic_config)

# Create alert policy
await newrelic.create_alert_policy(
    name="Security Events Alert",
    nrql_condition="SELECT count(*) FROM ComplianceSentinelSecurityEvent WHERE severity = 'critical'",
    threshold=5.0,
    notification_channels=["email", "slack"]
)

# Create dashboard
dashboard_config = {
    "title": "Security Dashboard",
    "widgets": [
        {
            "title": "Security Events by Severity",
            "nrql": "SELECT count(*) FROM ComplianceSentinelSecurityEvent FACET severity TIMESERIES"
        }
    ]
}

await newrelic.create_dashboard(dashboard_config)
```

## Event Correlation Engine

### Built-in Correlation Rules

The system includes several pre-configured correlation rules:

1. **Authentication Brute Force** - Multiple failed login attempts
2. **Privilege Escalation** - Sequence of privilege escalation events
3. **Data Exfiltration** - Pattern indicating data theft
4. **Static-Runtime Correlation** - Links static analysis to runtime events
5. **Malware Detection Chain** - Chain of malware-related events

### Custom Correlation Rules

```python
from compliance_sentinel.monitoring import CorrelationRule, CorrelationEngine

# Create custom rule
custom_rule = CorrelationRule(
    rule_id="api_abuse",
    name="API Abuse Detection",
    description="Detect API abuse patterns",
    event_types=[EventType.AUTHENTICATION_FAILURE, EventType.ACCESS_VIOLATION],
    correlation_fields=["source_ip", "user_agent"],
    time_window=timedelta(minutes=10),
    min_events=3,
    confidence_threshold=0.8,
    risk_multiplier=2.0,
    alert_severity=Severity.HIGH
)

# Add to correlation engine
engine = CorrelationEngine()
engine.add_rule(custom_rule)
```

### Correlation Analysis

```python
async def analyze_security_events():
    # Get events from monitoring platforms
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=1)
    
    all_events = await manager.query_events("*", start_time, end_time)
    
    # Flatten events from all platforms
    events = []
    for platform_events in all_events.values():
        events.extend(platform_events)
    
    # Perform correlation analysis
    correlations = await manager.correlate_events(events)
    
    # Process correlations
    for correlation_group in correlations:
        print(f"Correlation found: {len(correlation_group)} related events")
        
        # Generate incident if high confidence
        if len(correlation_group) >= 3:
            await create_security_incident(correlation_group)
```

## Security Dashboard

### Real-time Dashboard

```python
async def create_security_dashboard():
    dashboard_data = await manager.create_security_dashboard()
    
    print(f"Dashboard Data:")
    print(f"Total Events: {dashboard_data['summary']['total_events']}")
    print(f"Critical Events: {dashboard_data['summary']['critical_events']}")
    print(f"Active Correlations: {dashboard_data['summary']['active_correlations']}")
    
    # Check for alerts
    for alert in dashboard_data['alerts']:
        print(f"ALERT: {alert['message']} (Confidence: {alert.get('confidence', 'N/A')})")
```

### Trend Analysis

```python
async def analyze_security_trends():
    trends = await manager.analyze_security_trends(days=7)
    
    print(f"Security Trends (7 days):")
    print(f"Total Events: {trends['total_events']}")
    print(f"Trend Direction: {trends['trend_analysis']['direction']}")
    print(f"Average Daily Events: {trends['trend_analysis']['avg_daily_events']:.1f}")
    
    # Top security sources
    print("Top Security Sources:")
    for source, count in list(trends['top_sources'].items())[:5]:
        print(f"  {source}: {count} events")
```

## Integration with Static Analysis

### Sending Static Analysis Results

```python
from compliance_sentinel.core.interfaces import SecurityIssue

async def send_static_analysis_results(issues: List[SecurityIssue]):
    # Send static analysis results to monitoring platforms
    success_rates = await manager.send_static_analysis_results(issues)
    
    print("Static Analysis Results Sent:")
    for platform, success_rate in success_rates.items():
        print(f"  {platform}: {success_rate:.1%} success rate")
```

### Correlating Static and Runtime Events

The correlation engine automatically links static analysis findings with runtime security events when they occur in the same files or systems, providing comprehensive security visibility.

## Advanced Configuration

### SSL/TLS Configuration

```python
config = MonitoringConfig(
    platform=MonitoringPlatform.ELASTICSEARCH,
    host="secure-es.company.com",
    port=9200,
    use_ssl=True,
    verify_ssl=True,
    ca_cert_path="/etc/ssl/certs/ca-bundle.crt",
    username="security_user",
    password="secure_password"
)
```

### Custom Field Mapping

```python
config = MonitoringConfig(
    platform=MonitoringPlatform.SPLUNK,
    host="splunk.company.com",
    custom_fields={
        "environment": "production",
        "team": "security",
        "compliance_framework": "SOC2"
    }
)
```

### Performance Tuning

```python
config = MonitoringConfig(
    platform=MonitoringPlatform.ELASTICSEARCH,
    query_timeout=60,  # seconds
    max_results=5000,
    correlation_window_minutes=120,
    correlation_threshold=0.8
)
```

## API Reference

### MonitoringManager

Main class for managing security events across multiple platforms.

```python
class MonitoringManager:
    async def send_security_event(self, event: SecurityEvent) -> Dict[str, bool]
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> Dict[str, List[SecurityEvent]]
    async def correlate_events(self, events: List[SecurityEvent]) -> List[List[SecurityEvent]]
    async def analyze_security_trends(self, days: int = 7) -> Dict[str, Any]
    async def create_security_dashboard(self) -> Dict[str, Any]
    async def send_static_analysis_results(self, issues: List[SecurityIssue]) -> Dict[str, bool]
```

### SecurityEvent

Represents a security event in the monitoring system.

```python
@dataclass
class SecurityEvent:
    event_id: str
    source_platform: MonitoringPlatform
    event_type: EventType
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    category: SecurityCategory
    confidence_score: float = 0.0
    risk_score: float = 0.0
    # ... additional fields
```

### CorrelationEngine

Engine for correlating security events.

```python
class CorrelationEngine:
    async def correlate_events(self, events: List[SecurityEvent]) -> List[CorrelationResult]
    def add_rule(self, rule: CorrelationRule)
    def remove_rule(self, rule_id: str) -> bool
```

## Best Practices

### Security Configuration

1. **Secure Credentials**: Use environment variables or secret management systems
2. **SSL/TLS**: Always use encrypted connections in production
3. **Access Control**: Implement least-privilege access for monitoring accounts
4. **Audit Logging**: Enable audit logging for all monitoring operations

### Performance Optimization

1. **Batch Operations**: Send events in batches when possible
2. **Index Management**: Use appropriate index patterns and retention policies
3. **Query Optimization**: Optimize queries for large datasets
4. **Resource Monitoring**: Monitor resource usage of monitoring integrations

### Correlation Tuning

1. **Rule Refinement**: Regularly review and tune correlation rules
2. **False Positive Reduction**: Adjust confidence thresholds based on environment
3. **Time Windows**: Set appropriate time windows for different event types
4. **Field Selection**: Choose correlation fields that provide meaningful relationships

### Alerting Strategy

1. **Severity-Based Routing**: Route alerts based on severity levels
2. **Escalation Policies**: Implement escalation for unacknowledged alerts
3. **Alert Fatigue**: Avoid over-alerting by tuning thresholds
4. **Context Enrichment**: Include relevant context in alert messages

## Troubleshooting

### Common Issues

**Connection Failures**
- Verify network connectivity and firewall rules
- Check authentication credentials and permissions
- Validate SSL/TLS certificate configuration

**Event Ingestion Issues**
- Check index/database permissions and quotas
- Verify event format and field mappings
- Monitor ingestion rates and throttling

**Correlation Problems**
- Review correlation rule configurations
- Check time window settings and event timestamps
- Validate correlation field values and formats

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger('compliance_sentinel.monitoring').setLevel(logging.DEBUG)
```

### Health Monitoring

```python
async def check_platform_health():
    for platform, integration in manager.integrations.items():
        status = await integration.get_platform_status()
        print(f"{platform.value}: {status['status']}")
```

## Examples

See the `examples/monitoring/` directory for complete examples:

- `examples/monitoring/splunk/` - Splunk integration examples
- `examples/monitoring/elasticsearch/` - Elasticsearch setup and queries
- `examples/monitoring/datadog/` - Datadog dashboard and alerting
- `examples/monitoring/newrelic/` - New Relic custom events and NRQL
- `examples/monitoring/correlation/` - Event correlation examples

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review platform-specific documentation
3. Open an issue on GitHub
4. Consult the main Compliance Sentinel documentation