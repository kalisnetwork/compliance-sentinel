"""Unified ticket management system for security issues."""

from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class TicketStatus(Enum):
    """Ticket status enumeration."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    WONT_FIX = "wont_fix"
    DUPLICATE = "duplicate"


class TicketPriority(Enum):
    """Ticket priority enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TicketConfig:
    """Configuration for ticket creation and management."""
    
    # Platform settings
    platform: str  # jira, asana, trello, servicenow
    enabled: bool = True
    
    # Authentication
    api_url: str = ""
    api_token: str = ""
    username: str = ""
    password: str = ""
    
    # Project/Board settings
    project_key: str = ""
    board_id: str = ""
    workspace_id: str = ""
    
    # Ticket creation rules
    create_tickets_for_severities: List[Severity] = field(default_factory=lambda: [Severity.CRITICAL, Severity.HIGH])
    create_tickets_for_categories: List[SecurityCategory] = field(default_factory=list)
    
    # Ticket assignment
    default_assignee: str = ""
    assignee_mapping: Dict[SecurityCategory, str] = field(default_factory=dict)
    
    # Labels and tags
    default_labels: List[str] = field(default_factory=lambda: ["security", "compliance-sentinel"])
    severity_labels: Dict[Severity, str] = field(default_factory=dict)
    category_labels: Dict[SecurityCategory, str] = field(default_factory=dict)
    
    # SLA and deadlines
    sla_hours: Dict[Severity, int] = field(default_factory=lambda: {
        Severity.CRITICAL: 4,
        Severity.HIGH: 24,
        Severity.MEDIUM: 72,
        Severity.LOW: 168
    })
    
    # Notification settings
    notify_on_creation: bool = True
    notify_on_sla_breach: bool = True
    notification_channels: List[str] = field(default_factory=list)
    
    # Auto-resolution
    auto_resolve_fixed_issues: bool = True
    auto_close_after_days: int = 7
    
    # Custom fields
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityTicket:
    """Represents a security ticket in external system."""
    
    # Ticket identification
    ticket_id: str
    external_id: str
    platform: str
    
    # Security issue reference
    security_issue_id: str
    security_issue: Optional[SecurityIssue] = None
    
    # Ticket details
    title: str
    description: str
    status: TicketStatus
    priority: TicketPriority
    
    # Assignment and ownership
    assignee: str = ""
    reporter: str = ""
    team: str = ""
    
    # Metadata
    labels: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    due_date: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # SLA tracking
    sla_hours: int = 24
    sla_breach: bool = False
    
    # Links and references
    external_url: str = ""
    related_tickets: List[str] = field(default_factory=list)
    
    # Custom fields
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def is_overdue(self) -> bool:
        """Check if ticket is overdue based on SLA."""
        if self.status in [TicketStatus.RESOLVED, TicketStatus.CLOSED]:
            return False
        
        sla_deadline = self.created_at + timedelta(hours=self.sla_hours)
        return datetime.now() > sla_deadline
    
    def time_to_sla_breach(self) -> timedelta:
        """Calculate time remaining until SLA breach."""
        sla_deadline = self.created_at + timedelta(hours=self.sla_hours)
        return sla_deadline - datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ticket to dictionary for serialization."""
        return {
            'ticket_id': self.ticket_id,
            'external_id': self.external_id,
            'platform': self.platform,
            'security_issue_id': self.security_issue_id,
            'title': self.title,
            'description': self.description,
            'status': self.status.value,
            'priority': self.priority.value,
            'assignee': self.assignee,
            'reporter': self.reporter,
            'team': self.team,
            'labels': self.labels,
            'components': self.components,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'sla_hours': self.sla_hours,
            'sla_breach': self.sla_breach,
            'external_url': self.external_url,
            'related_tickets': self.related_tickets,
            'custom_fields': self.custom_fields
        }


class TicketManager:
    """Unified ticket management system."""
    
    def __init__(self, configs: List[TicketConfig]):
        """Initialize ticket manager with platform configurations."""
        self.configs = {config.platform: config for config in configs if config.enabled}
        self.integrations = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize platform integrations
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize platform-specific integrations."""
        for platform, config in self.configs.items():
            try:
                if platform == "jira":
                    from .jira_integration import JiraIntegration
                    self.integrations[platform] = JiraIntegration(config)
                elif platform == "asana":
                    from .asana_integration import AsanaIntegration
                    self.integrations[platform] = AsanaIntegration(config)
                elif platform == "trello":
                    from .trello_integration import TrelloIntegration
                    self.integrations[platform] = TrelloIntegration(config)
                elif platform == "servicenow":
                    from .servicenow_integration import ServiceNowIntegration
                    self.integrations[platform] = ServiceNowIntegration(config)
                else:
                    self.logger.warning(f"Unknown platform: {platform}")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize {platform} integration: {e}")
    
    def create_tickets_for_issues(self, issues: List[SecurityIssue]) -> Dict[str, List[SecurityTicket]]:
        """Create tickets for security issues across all configured platforms."""
        created_tickets = {}
        
        for platform, integration in self.integrations.items():
            config = self.configs[platform]
            platform_tickets = []
            
            for issue in issues:
                if self._should_create_ticket(issue, config):
                    try:
                        ticket = self._create_ticket_for_issue(issue, integration, config)
                        if ticket:
                            platform_tickets.append(ticket)
                            self.logger.info(f"Created {platform} ticket {ticket.external_id} for issue {issue.id}")
                    except Exception as e:
                        self.logger.error(f"Failed to create {platform} ticket for issue {issue.id}: {e}")
            
            created_tickets[platform] = platform_tickets
        
        return created_tickets
    
    def _should_create_ticket(self, issue: SecurityIssue, config: TicketConfig) -> bool:
        """Determine if a ticket should be created for the given issue."""
        # Check severity filter
        if config.create_tickets_for_severities and issue.severity not in config.create_tickets_for_severities:
            return False
        
        # Check category filter
        if config.create_tickets_for_categories and issue.category not in config.create_tickets_for_categories:
            return False
        
        return True
    
    def _create_ticket_for_issue(self, issue: SecurityIssue, integration, config: TicketConfig) -> Optional[SecurityTicket]:
        """Create a ticket for a security issue using the specified integration."""
        
        # Generate ticket details
        title = self._generate_ticket_title(issue)
        description = self._generate_ticket_description(issue)
        priority = self._map_severity_to_priority(issue.severity)
        assignee = self._determine_assignee(issue, config)
        labels = self._generate_labels(issue, config)
        due_date = self._calculate_due_date(issue.severity, config)
        
        # Create ticket via integration
        external_ticket = integration.create_ticket(
            title=title,
            description=description,
            priority=priority.value,
            assignee=assignee,
            labels=labels,
            due_date=due_date,
            custom_fields=config.custom_fields
        )
        
        if not external_ticket:
            return None
        
        # Create internal ticket representation
        ticket = SecurityTicket(
            ticket_id=f"{config.platform}_{external_ticket.get('id', '')}",
            external_id=external_ticket.get('id', ''),
            platform=config.platform,
            security_issue_id=issue.id,
            security_issue=issue,
            title=title,
            description=description,
            status=TicketStatus.OPEN,
            priority=priority,
            assignee=assignee,
            reporter=config.username,
            labels=labels,
            due_date=due_date,
            sla_hours=config.sla_hours.get(issue.severity, 24),
            external_url=external_ticket.get('url', ''),
            custom_fields=config.custom_fields
        )
        
        return ticket
    
    def _generate_ticket_title(self, issue: SecurityIssue) -> str:
        """Generate ticket title from security issue."""
        return f"[{issue.severity.value.upper()}] {issue.description}"
    
    def _generate_ticket_description(self, issue: SecurityIssue) -> str:
        """Generate detailed ticket description from security issue."""
        description = f"""
**Security Issue Details**

**File:** {issue.file_path}:{issue.line_number}
**Severity:** {issue.severity.value}
**Category:** {issue.category.value}
**Rule:** {issue.rule_id}
**Confidence:** {issue.confidence:.2f}

**Description:**
{issue.description}

**Remediation Suggestions:**
"""
        
        for i, suggestion in enumerate(issue.remediation_suggestions, 1):
            description += f"{i}. {suggestion}\n"
        
        description += f"""
**Issue ID:** {issue.id}
**Created:** {issue.created_at.strftime('%Y-%m-%d %H:%M:%S')}

---
*This ticket was automatically created by Compliance Sentinel*
"""
        
        return description.strip()
    
    def _map_severity_to_priority(self, severity: Severity) -> TicketPriority:
        """Map security issue severity to ticket priority."""
        mapping = {
            Severity.CRITICAL: TicketPriority.CRITICAL,
            Severity.HIGH: TicketPriority.HIGH,
            Severity.MEDIUM: TicketPriority.MEDIUM,
            Severity.LOW: TicketPriority.LOW
        }
        return mapping.get(severity, TicketPriority.MEDIUM)
    
    def _determine_assignee(self, issue: SecurityIssue, config: TicketConfig) -> str:
        """Determine ticket assignee based on issue category and configuration."""
        # Check category-specific assignment
        if issue.category in config.assignee_mapping:
            return config.assignee_mapping[issue.category]
        
        # Fall back to default assignee
        return config.default_assignee
    
    def _generate_labels(self, issue: SecurityIssue, config: TicketConfig) -> List[str]:
        """Generate labels for the ticket."""
        labels = config.default_labels.copy()
        
        # Add severity label
        if issue.severity in config.severity_labels:
            labels.append(config.severity_labels[issue.severity])
        else:
            labels.append(f"severity-{issue.severity.value.lower()}")
        
        # Add category label
        if issue.category in config.category_labels:
            labels.append(config.category_labels[issue.category])
        else:
            labels.append(f"category-{issue.category.value.lower()}")
        
        return labels
    
    def _calculate_due_date(self, severity: Severity, config: TicketConfig) -> datetime:
        """Calculate due date based on severity and SLA."""
        sla_hours = config.sla_hours.get(severity, 24)
        return datetime.now() + timedelta(hours=sla_hours)
    
    def update_ticket_status(self, ticket_id: str, status: TicketStatus, resolution_notes: str = "") -> bool:
        """Update ticket status across platforms."""
        platform = ticket_id.split('_')[0]
        
        if platform not in self.integrations:
            self.logger.error(f"No integration found for platform: {platform}")
            return False
        
        try:
            integration = self.integrations[platform]
            external_id = ticket_id.split('_', 1)[1]
            
            success = integration.update_ticket_status(external_id, status.value, resolution_notes)
            
            if success:
                self.logger.info(f"Updated ticket {ticket_id} status to {status.value}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to update ticket {ticket_id}: {e}")
            return False
    
    def get_ticket_status(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Get current ticket status from external platform."""
        platform = ticket_id.split('_')[0]
        
        if platform not in self.integrations:
            return None
        
        try:
            integration = self.integrations[platform]
            external_id = ticket_id.split('_', 1)[1]
            
            return integration.get_ticket(external_id)
            
        except Exception as e:
            self.logger.error(f"Failed to get ticket {ticket_id}: {e}")
            return None
    
    def sync_ticket_statuses(self, tickets: List[SecurityTicket]) -> List[SecurityTicket]:
        """Sync ticket statuses with external platforms."""
        updated_tickets = []
        
        for ticket in tickets:
            try:
                external_ticket = self.get_ticket_status(ticket.ticket_id)
                
                if external_ticket:
                    # Update ticket with external status
                    ticket.status = TicketStatus(external_ticket.get('status', ticket.status.value))
                    ticket.updated_at = datetime.now()
                    
                    if external_ticket.get('resolved_at'):
                        ticket.resolved_at = datetime.fromisoformat(external_ticket['resolved_at'])
                
                updated_tickets.append(ticket)
                
            except Exception as e:
                self.logger.error(f"Failed to sync ticket {ticket.ticket_id}: {e}")
                updated_tickets.append(ticket)  # Keep original if sync fails
        
        return updated_tickets
    
    def check_sla_breaches(self, tickets: List[SecurityTicket]) -> List[SecurityTicket]:
        """Check for SLA breaches and update tickets accordingly."""
        breached_tickets = []
        
        for ticket in tickets:
            if ticket.is_overdue() and not ticket.sla_breach:
                ticket.sla_breach = True
                breached_tickets.append(ticket)
                
                # Notify about SLA breach
                if self.configs[ticket.platform].notify_on_sla_breach:
                    self._notify_sla_breach(ticket)
        
        return breached_tickets
    
    def _notify_sla_breach(self, ticket: SecurityTicket):
        """Send notification about SLA breach."""
        # This would integrate with notification systems
        self.logger.warning(f"SLA breach detected for ticket {ticket.ticket_id}")
    
    def get_metrics(self, tickets: List[SecurityTicket]) -> Dict[str, Any]:
        """Calculate ticket metrics and statistics."""
        total_tickets = len(tickets)
        
        if total_tickets == 0:
            return {
                'total_tickets': 0,
                'by_status': {},
                'by_priority': {},
                'by_platform': {},
                'sla_metrics': {}
            }
        
        # Count by status
        by_status = {}
        for status in TicketStatus:
            by_status[status.value] = len([t for t in tickets if t.status == status])
        
        # Count by priority
        by_priority = {}
        for priority in TicketPriority:
            by_priority[priority.value] = len([t for t in tickets if t.priority == priority])
        
        # Count by platform
        by_platform = {}
        for ticket in tickets:
            by_platform[ticket.platform] = by_platform.get(ticket.platform, 0) + 1
        
        # SLA metrics
        overdue_tickets = [t for t in tickets if t.is_overdue()]
        resolved_tickets = [t for t in tickets if t.status in [TicketStatus.RESOLVED, TicketStatus.CLOSED]]
        
        avg_resolution_time = None
        if resolved_tickets:
            resolution_times = []
            for ticket in resolved_tickets:
                if ticket.resolved_at:
                    resolution_time = (ticket.resolved_at - ticket.created_at).total_seconds() / 3600
                    resolution_times.append(resolution_time)
            
            if resolution_times:
                avg_resolution_time = sum(resolution_times) / len(resolution_times)
        
        sla_metrics = {
            'total_overdue': len(overdue_tickets),
            'sla_breach_rate': len(overdue_tickets) / total_tickets * 100,
            'avg_resolution_time_hours': avg_resolution_time
        }
        
        return {
            'total_tickets': total_tickets,
            'by_status': by_status,
            'by_priority': by_priority,
            'by_platform': by_platform,
            'sla_metrics': sla_metrics
        }