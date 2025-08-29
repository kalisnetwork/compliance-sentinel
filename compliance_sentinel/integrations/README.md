# Project Management and Ticketing Integrations

This module provides comprehensive project management and ticketing integrations for Compliance Sentinel, enabling automated security ticket creation, tracking, and metrics collection across multiple platforms.

## Supported Platforms

- **Jira** - Enterprise issue tracking and project management
- **Asana** - Team task management and collaboration
- **Trello** - Kanban-style board management
- **ServiceNow** - Enterprise IT service management

## Quick Start

### Basic Configuration

Create a configuration file `ticket-config.yml`:

```yaml
platforms:
  jira:
    enabled: true
    api_url: "https://your-domain.atlassian.net"
    username: "your-email@company.com"
    api_token: "your-api-token"
    project_key: "SEC"
    
  asana:
    enabled: true
    api_token: "your-asana-token"
    workspace_id: "workspace-gid"
    project_key: "project-gid"
    
  trello:
    enabled: true
    api_url: "your-api-key"  # Trello API key
    api_token: "your-api-token"
    board_id: "board-id"
    
  servicenow:
    enabled: true
    api_url: "https://your-instance.service-now.com"
    username: "your-username"
    password: "your-password"

# Ticket creation rules
ticket_rules:
  create_for_severities: ["CRITICAL", "HIGH"]
  create_for_categories: ["HARDCODED_SECRETS", "INJECTION"]
  
  # Assignment rules
  assignee_mapping:
    HARDCODED_SECRETS: "security-team@company.com"
    INJECTION: "backend-team@company.com"
    XSS: "frontend-team@company.com"
  
  # SLA configuration
  sla_hours:
    CRITICAL: 4
    HIGH: 24
    MEDIUM: 72
    LOW: 168
```

### Python Usage

```python
from compliance_sentinel.integrations import TicketManager, TicketConfig
from compliance_sentinel.core.interfaces import SecurityIssue

# Load configuration
configs = [
    TicketConfig(
        platform="jira",
        enabled=True,
        api_url="https://company.atlassian.net",
        username="security@company.com",
        api_token="your-token",
        project_key="SEC"
    )
]

# Initialize ticket manager
ticket_manager = TicketManager(configs)

# Create tickets for security issues
security_issues = [...]  # Your security issues
created_tickets = ticket_manager.create_tickets_for_issues(security_issues)

# Update ticket status
ticket_manager.update_ticket_status("jira_SEC-123", "resolved", "Fixed vulnerability")
```

## Platform-Specific Features

### Jira Integration

**Features:**
- Full Jira REST API v3 support
- Custom field mapping
- Workflow transition management
- JQL search capabilities
- Bulk operations

**Configuration:**
```python
jira_config = TicketConfig(
    platform="jira",
    api_url="https://company.atlassian.net",
    username="user@company.com",
    api_token="api-token",
    project_key="SEC",
    custom_fields={
        "customfield_10001": "Security Team",
        "customfield_10002": "Compliance Sentinel"
    }
)
```

**Advanced Usage:**
```python
from compliance_sentinel.integrations import JiraIntegration

jira = JiraIntegration(jira_config)

# Search for security tickets
jql = 'project = "SEC" AND labels = "security" ORDER BY created DESC'
tickets = jira.search_tickets(jql, max_results=50)

# Add comments
jira.add_comment("SEC-123", "Vulnerability has been patched")

# Bulk update
jira.bulk_update_tickets(["SEC-123", "SEC-124"], {"priority": {"name": "High"}})
```

### Asana Integration

**Features:**
- Task creation and management
- Project and workspace support
- Tag-based labeling
- Team member assignment
- Custom field support

**Configuration:**
```python
asana_config = TicketConfig(
    platform="asana",
    api_token="asana-token",
    workspace_id="workspace-gid",
    project_key="project-gid",
    default_assignee="user-gid"
)
```

**Advanced Usage:**
```python
from compliance_sentinel.integrations import AsanaIntegration

asana = AsanaIntegration(asana_config)

# Get team members
members = asana.get_team_members()

# Create project for security tasks
project_id = asana.create_project("Security Issues Q4 2024")

# Search tasks
tasks = asana.search_tickets(project_id="project-gid", completed=False)
```

### Trello Integration

**Features:**
- Board and list management
- Card creation with labels
- Member assignment
- Due date tracking
- Custom board setup

**Configuration:**
```python
trello_config = TicketConfig(
    platform="trello",
    api_url="your-api-key",
    api_token="your-token",
    board_id="board-id"
)
```

**Advanced Usage:**
```python
from compliance_sentinel.integrations import TrelloIntegration

trello = TrelloIntegration(trello_config)

# Get board info
board_info = trello.get_board_info()

# Get board members
members = trello.get_board_members()

# Search cards
cards = trello.search_tickets(query="security", list_name="open")
```

### ServiceNow Integration

**Features:**
- Incident management
- Assignment group support
- Work notes and comments
- SLA tracking
- Custom templates

**Configuration:**
```python
servicenow_config = TicketConfig(
    platform="servicenow",
    api_url="https://instance.service-now.com",
    username="username",
    password="password",
    custom_fields={
        "assignment_group": "Security Team",
        "category": "Security"
    }
)
```

**Advanced Usage:**
```python
from compliance_sentinel.integrations import ServiceNowIntegration

snow = ServiceNowIntegration(servicenow_config)

# Get assignment groups
groups = snow.get_assignment_groups()

# Create security incident template
template_id = snow.create_security_incident_template()

# Bulk update incidents
results = snow.bulk_update_incidents(
    ["INC0010001", "INC0010002"],
    {"state": "6", "close_code": "Solved (Permanently)"}
)
```

## Security Metrics Dashboard

### Metrics Collection

```python
from compliance_sentinel.integrations import SecurityMetricsDashboard

dashboard = SecurityMetricsDashboard()

# Generate dashboard data
dashboard_data = dashboard.generate_dashboard_data(
    issues=security_issues,
    tickets=security_tickets,
    period_days=30
)

# Generate executive report
exec_report = dashboard.generate_executive_report(
    issues=security_issues,
    tickets=security_tickets,
    period_days=30
)
```

### Available Metrics

**Issue Metrics:**
- Total issues by severity and category
- New vs resolved issues
- Daily trend analysis
- Risk scoring

**Ticket Metrics:**
- Ticket status distribution
- SLA performance and breach rates
- Average resolution times
- Overdue ticket tracking

**Performance Metrics:**
- Team productivity metrics
- Resolution time trends
- Capacity utilization
- Security debt calculation

### Dashboard Components

**Summary Cards:**
- Total Security Issues
- Critical Issues
- Open Tickets
- Overdue Tickets
- Average Resolution Time
- SLA Breach Rate
- Risk Score
- Security Debt

**Charts:**
- Severity distribution (pie chart)
- Category breakdown (bar chart)
- Daily trends (line chart)
- Ticket status (doughnut chart)

**Alerts:**
- Critical issues requiring attention
- SLA breach warnings
- Overdue ticket notifications
- High security debt alerts

## Advanced Configuration

### Ticket Creation Rules

```yaml
ticket_rules:
  # Severity-based rules
  severity_rules:
    CRITICAL:
      create_ticket: true
      sla_hours: 4
      priority: "critical"
      assignee: "security-lead@company.com"
      
    HIGH:
      create_ticket: true
      sla_hours: 24
      priority: "high"
      
    MEDIUM:
      create_ticket: false  # Only create for specific categories
      
  # Category-specific rules
  category_rules:
    HARDCODED_SECRETS:
      always_create: true
      assignee: "security-team@company.com"
      labels: ["security", "secrets", "urgent"]
      
    INJECTION:
      always_create: true
      assignee: "backend-team@company.com"
      labels: ["security", "injection"]
      
  # File-based rules
  file_rules:
    - pattern: "src/auth/*"
      assignee: "auth-team@company.com"
      labels: ["authentication"]
      
    - pattern: "src/payment/*"
      assignee: "payments-team@company.com"
      labels: ["pci-dss", "payments"]
      priority: "high"
```

### Notification Configuration

```yaml
notifications:
  email:
    enabled: true
    smtp_server: "smtp.company.com"
    recipients:
      - "security@company.com"
      - "devops@company.com"
    templates:
      new_ticket: "templates/new_ticket.html"
      sla_breach: "templates/sla_breach.html"
      
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
    channels:
      critical: "#security-alerts"
      high: "#security"
      default: "#dev-notifications"
      
  webhook:
    enabled: true
    endpoints:
      - url: "https://api.company.com/security/webhook"
        events: ["ticket_created", "sla_breach"]
        auth_header: "Bearer your-token"
```

### Integration Workflows

```python
from compliance_sentinel.integrations import TicketManager
from compliance_sentinel.analyzers import ProjectAnalyzer

# Complete workflow example
def security_scan_workflow(project_path: str):
    # 1. Scan project for security issues
    analyzer = ProjectAnalyzer()
    scan_result = analyzer.scan_project(project_path)
    
    # 2. Create tickets for issues
    ticket_manager = TicketManager(configs)
    created_tickets = ticket_manager.create_tickets_for_issues(scan_result['issues'])
    
    # 3. Generate metrics dashboard
    dashboard = SecurityMetricsDashboard()
    dashboard_data = dashboard.generate_dashboard_data(
        issues=scan_result['issues'],
        tickets=list(created_tickets.values())[0],  # Flatten tickets
        period_days=30
    )
    
    # 4. Check for SLA breaches
    all_tickets = []
    for platform_tickets in created_tickets.values():
        all_tickets.extend(platform_tickets)
    
    breached_tickets = ticket_manager.check_sla_breaches(all_tickets)
    
    # 5. Generate executive report
    exec_report = dashboard.generate_executive_report(
        issues=scan_result['issues'],
        tickets=all_tickets
    )
    
    return {
        'scan_result': scan_result,
        'created_tickets': created_tickets,
        'dashboard_data': dashboard_data,
        'sla_breaches': breached_tickets,
        'executive_report': exec_report
    }
```

## API Reference

### TicketManager

Main class for managing tickets across multiple platforms.

```python
class TicketManager:
    def __init__(self, configs: List[TicketConfig])
    def create_tickets_for_issues(self, issues: List[SecurityIssue]) -> Dict[str, List[SecurityTicket]]
    def update_ticket_status(self, ticket_id: str, status: TicketStatus, resolution_notes: str = "") -> bool
    def get_ticket_status(self, ticket_id: str) -> Optional[Dict[str, Any]]
    def sync_ticket_statuses(self, tickets: List[SecurityTicket]) -> List[SecurityTicket]
    def check_sla_breaches(self, tickets: List[SecurityTicket]) -> List[SecurityTicket]
    def get_metrics(self, tickets: List[SecurityTicket]) -> Dict[str, Any]
```

### TicketConfig

Configuration class for platform settings.

```python
@dataclass
class TicketConfig:
    platform: str
    enabled: bool = True
    api_url: str = ""
    api_token: str = ""
    username: str = ""
    password: str = ""
    project_key: str = ""
    board_id: str = ""
    workspace_id: str = ""
    create_tickets_for_severities: List[Severity] = field(default_factory=list)
    create_tickets_for_categories: List[SecurityCategory] = field(default_factory=list)
    default_assignee: str = ""
    assignee_mapping: Dict[SecurityCategory, str] = field(default_factory=dict)
    sla_hours: Dict[Severity, int] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
```

### SecurityTicket

Represents a security ticket in external systems.

```python
@dataclass
class SecurityTicket:
    ticket_id: str
    external_id: str
    platform: str
    security_issue_id: str
    title: str
    description: str
    status: TicketStatus
    priority: TicketPriority
    assignee: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    due_date: Optional[datetime] = None
    sla_hours: int = 24
    
    def is_overdue(self) -> bool
    def time_to_sla_breach(self) -> timedelta
    def to_dict(self) -> Dict[str, Any]
```

## Best Practices

### Security Configuration

1. **API Credentials**: Store API tokens and passwords securely using environment variables or secret management systems
2. **Least Privilege**: Use service accounts with minimal required permissions
3. **Token Rotation**: Regularly rotate API tokens and credentials
4. **Audit Logging**: Enable audit logging for all ticket operations

### Ticket Management

1. **Consistent Labeling**: Use consistent labels and tags across platforms
2. **Clear Descriptions**: Include file paths, line numbers, and remediation steps
3. **Priority Mapping**: Map security severities to appropriate ticket priorities
4. **SLA Alignment**: Set realistic SLAs based on team capacity and severity

### Performance Optimization

1. **Batch Operations**: Use bulk operations when updating multiple tickets
2. **Rate Limiting**: Respect API rate limits and implement backoff strategies
3. **Caching**: Cache frequently accessed data like user mappings and project info
4. **Async Processing**: Use asynchronous processing for large-scale operations

### Monitoring and Alerting

1. **SLA Monitoring**: Set up alerts for SLA breaches and overdue tickets
2. **Integration Health**: Monitor API connectivity and error rates
3. **Metrics Tracking**: Track ticket creation, resolution, and cycle times
4. **Dashboard Updates**: Keep dashboards current with real-time data

## Troubleshooting

### Common Issues

**Authentication Failures**
- Verify API credentials and permissions
- Check token expiration dates
- Ensure correct API endpoints

**Ticket Creation Failures**
- Validate required fields for each platform
- Check project/workspace permissions
- Verify custom field configurations

**Performance Issues**
- Review API rate limits
- Optimize batch operations
- Check network connectivity

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger('compliance_sentinel.integrations').setLevel(logging.DEBUG)
```

### Configuration Validation

```python
from compliance_sentinel.integrations import TicketConfig

# Validate configuration
try:
    config = TicketConfig.from_dict(config_dict)
    # Test connection
    integration = JiraIntegration(config)
    print("Configuration valid")
except Exception as e:
    print(f"Configuration error: {e}")
```

## Examples

See the `examples/integrations/` directory for complete examples:

- `examples/integrations/jira/` - Jira integration examples
- `examples/integrations/asana/` - Asana workflow examples
- `examples/integrations/trello/` - Trello board management
- `examples/integrations/servicenow/` - ServiceNow incident management
- `examples/integrations/dashboards/` - Metrics dashboard examples

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review platform-specific documentation
3. Open an issue on GitHub
4. Consult the main Compliance Sentinel documentation