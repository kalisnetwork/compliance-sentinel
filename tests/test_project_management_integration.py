"""Tests for project management and ticketing integrations."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import List

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.integrations.ticket_manager import (
    TicketManager, TicketConfig, SecurityTicket, TicketStatus, TicketPriority
)
from compliance_sentinel.integrations.jira_integration import JiraIntegration
from compliance_sentinel.integrations.asana_integration import AsanaIntegration
from compliance_sentinel.integrations.trello_integration import TrelloIntegration
from compliance_sentinel.integrations.servicenow_integration import ServiceNowIntegration
from compliance_sentinel.integrations.security_metrics import (
    SecurityMetrics, MetricsCollector, SecurityMetricsDashboard
)


class TestTicketManager:
    """Test unified ticket management system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.jira_config = TicketConfig(
            platform="jira",
            enabled=True,
            api_url="https://test.atlassian.net",
            api_token="test_token",
            username="test@example.com",
            project_key="SEC",
            create_tickets_for_severities=[Severity.CRITICAL, Severity.HIGH]
        )
        
        self.asana_config = TicketConfig(
            platform="asana",
            enabled=True,
            api_token="test_asana_token",
            workspace_id="12345",
            project_key="67890"
        )
        
        self.sample_issues = [
            SecurityIssue(
                id="issue_001", severity=Severity.CRITICAL, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="app.py", line_number=10, description="Critical hardcoded secret",
                rule_id="hardcoded_secrets", confidence=0.95, remediation_suggestions=["Use env vars"],
                created_at=datetime.now()
            ),
            SecurityIssue(
                id="issue_002", severity=Severity.HIGH, category=SecurityCategory.INJECTION,
                file_path="db.py", line_number=25, description="SQL injection vulnerability",
                rule_id="sql_injection", confidence=0.9, remediation_suggestions=["Use parameterized queries"],
                created_at=datetime.now()
            ),
            SecurityIssue(
                id="issue_003", severity=Severity.MEDIUM, category=SecurityCategory.XSS,
                file_path="web.py", line_number=15, description="XSS vulnerability",
                rule_id="xss_detection", confidence=0.8, remediation_suggestions=["Sanitize input"],
                created_at=datetime.now()
            )
        ]
    
    def test_ticket_manager_initialization(self):
        """Test ticket manager initialization with multiple platforms."""
        configs = [self.jira_config, self.asana_config]
        
        with patch('compliance_sentinel.integrations.ticket_manager.JiraIntegration'), \
             patch('compliance_sentinel.integrations.ticket_manager.AsanaIntegration'):
            
            manager = TicketManager(configs)
            
            assert len(manager.configs) == 2
            assert "jira" in manager.configs
            assert "asana" in manager.configs
    
    @patch('compliance_sentinel.integrations.ticket_manager.JiraIntegration')
    @patch('compliance_sentinel.integrations.ticket_manager.AsanaIntegration')
    def test_create_tickets_for_issues(self, mock_asana, mock_jira):
        """Test creating tickets for security issues."""
        # Mock integration responses
        mock_jira_instance = Mock()
        mock_jira_instance.create_ticket.return_value = {
            "id": "SEC-123",
            "url": "https://test.atlassian.net/browse/SEC-123"
        }
        mock_jira.return_value = mock_jira_instance
        
        mock_asana_instance = Mock()
        mock_asana_instance.create_ticket.return_value = {
            "id": "1234567890",
            "url": "https://app.asana.com/0/67890/1234567890"
        }
        mock_asana.return_value = mock_asana_instance
        
        configs = [self.jira_config, self.asana_config]
        manager = TicketManager(configs)
        
        # Create tickets for issues
        created_tickets = manager.create_tickets_for_issues(self.sample_issues)
        
        # Should create tickets for critical and high severity issues only
        assert "jira" in created_tickets
        assert "asana" in created_tickets
        assert len(created_tickets["jira"]) == 2  # Critical and High
        assert len(created_tickets["asana"]) == 2  # Critical and High
        
        # Verify ticket creation calls
        assert mock_jira_instance.create_ticket.call_count == 2
        assert mock_asana_instance.create_ticket.call_count == 2
    
    def test_should_create_ticket_filtering(self):
        """Test ticket creation filtering logic."""
        configs = [self.jira_config]
        manager = TicketManager([])  # Empty to avoid integration initialization
        
        # Test severity filtering
        assert manager._should_create_ticket(self.sample_issues[0], self.jira_config) is True  # Critical
        assert manager._should_create_ticket(self.sample_issues[1], self.jira_config) is True  # High
        assert manager._should_create_ticket(self.sample_issues[2], self.jira_config) is False  # Medium
        
        # Test category filtering
        category_config = TicketConfig(
            platform="test",
            create_tickets_for_categories=[SecurityCategory.HARDCODED_SECRETS]
        )
        
        assert manager._should_create_ticket(self.sample_issues[0], category_config) is True  # Hardcoded secrets
        assert manager._should_create_ticket(self.sample_issues[1], category_config) is False  # Injection
    
    def test_ticket_title_and_description_generation(self):
        """Test ticket title and description generation."""
        manager = TicketManager([])
        
        issue = self.sample_issues[0]
        
        title = manager._generate_ticket_title(issue)
        assert "[CRITICAL]" in title
        assert issue.description in title
        
        description = manager._generate_ticket_description(issue)
        assert issue.file_path in description
        assert str(issue.line_number) in description
        assert issue.rule_id in description
        assert str(issue.confidence) in description
        assert issue.remediation_suggestions[0] in description
    
    def test_severity_to_priority_mapping(self):
        """Test severity to priority mapping."""
        manager = TicketManager([])
        
        assert manager._map_severity_to_priority(Severity.CRITICAL) == TicketPriority.CRITICAL
        assert manager._map_severity_to_priority(Severity.HIGH) == TicketPriority.HIGH
        assert manager._map_severity_to_priority(Severity.MEDIUM) == TicketPriority.MEDIUM
        assert manager._map_severity_to_priority(Severity.LOW) == TicketPriority.LOW


class TestJiraIntegration:
    """Test Jira integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = TicketConfig(
            platform="jira",
            api_url="https://test.atlassian.net",
            api_token="test_token",
            username="test@example.com",
            project_key="SEC"
        )
    
    @patch('requests.Session')
    def test_jira_authentication_setup(self, mock_session):
        """Test Jira authentication setup."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"displayName": "Test User"}
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        jira = JiraIntegration(self.config)
        
        # Verify authentication headers were set
        assert 'Authorization' in mock_session_instance.headers.update.call_args[0][0]
        assert 'Basic' in mock_session_instance.headers.update.call_args[0][0]['Authorization']
    
    @patch('requests.Session')
    def test_create_jira_ticket(self, mock_session):
        """Test Jira ticket creation."""
        # Mock authentication validation
        auth_response = Mock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"displayName": "Test User"}
        
        # Mock ticket creation
        create_response = Mock()
        create_response.raise_for_status.return_value = None
        create_response.json.return_value = {
            "key": "SEC-123",
            "id": "10001"
        }
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = auth_response
        mock_session_instance.post.return_value = create_response
        mock_session.return_value = mock_session_instance
        
        jira = JiraIntegration(self.config)
        
        result = jira.create_ticket(
            title="Test Security Issue",
            description="Test description",
            priority="high",
            labels=["security", "critical"]
        )
        
        assert result is not None
        assert result["id"] == "SEC-123"
        assert "browse/SEC-123" in result["url"]
        
        # Verify API call
        mock_session_instance.post.assert_called_once()
        call_args = mock_session_instance.post.call_args
        assert "/rest/api/3/issue" in call_args[0][0]
    
    @patch('requests.Session')
    def test_update_jira_ticket_status(self, mock_session):
        """Test Jira ticket status update."""
        # Mock responses
        auth_response = Mock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"displayName": "Test User"}
        
        transitions_response = Mock()
        transitions_response.raise_for_status.return_value = None
        transitions_response.json.return_value = {
            "transitions": [
                {"id": "31", "name": "Done"}
            ]
        }
        
        update_response = Mock()
        update_response.raise_for_status.return_value = None
        
        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = [auth_response, transitions_response]
        mock_session_instance.post.return_value = update_response
        mock_session.return_value = mock_session_instance
        
        jira = JiraIntegration(self.config)
        
        result = jira.update_ticket_status("SEC-123", "resolved", "Fixed the issue")
        
        assert result is True
        assert mock_session_instance.post.call_count == 1


class TestAsanaIntegration:
    """Test Asana integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = TicketConfig(
            platform="asana",
            api_token="test_asana_token",
            workspace_id="12345",
            project_key="67890"
        )
    
    @patch('requests.Session')
    def test_asana_authentication_setup(self, mock_session):
        """Test Asana authentication setup."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"data": {"name": "Test User"}}
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        asana = AsanaIntegration(self.config)
        
        # Verify authentication headers were set
        assert 'Authorization' in mock_session_instance.headers.update.call_args[0][0]
        assert 'Bearer' in mock_session_instance.headers.update.call_args[0][0]['Authorization']
    
    @patch('requests.Session')
    def test_create_asana_task(self, mock_session):
        """Test Asana task creation."""
        # Mock authentication validation
        auth_response = Mock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"data": {"name": "Test User"}}
        
        workspace_response = Mock()
        workspace_response.raise_for_status.return_value = None
        workspace_response.json.return_value = {"data": {"name": "Test Workspace"}}
        
        # Mock task creation
        create_response = Mock()
        create_response.raise_for_status.return_value = None
        create_response.json.return_value = {
            "data": {
                "gid": "1234567890",
                "name": "Test Security Issue",
                "permalink_url": "https://app.asana.com/0/67890/1234567890"
            }
        }
        
        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = [auth_response, workspace_response]
        mock_session_instance.post.return_value = create_response
        mock_session.return_value = mock_session_instance
        
        asana = AsanaIntegration(self.config)
        
        result = asana.create_ticket(
            title="Test Security Issue",
            description="Test description",
            priority="high"
        )
        
        assert result is not None
        assert result["id"] == "1234567890"
        assert "asana.com" in result["url"]


class TestSecurityMetrics:
    """Test security metrics collection and dashboard."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.sample_issues = [
            SecurityIssue(
                id="metric_001", severity=Severity.CRITICAL, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="app.py", line_number=10, description="Critical issue",
                rule_id="rule1", confidence=0.95, remediation_suggestions=[],
                created_at=datetime.now() - timedelta(days=1)
            ),
            SecurityIssue(
                id="metric_002", severity=Severity.HIGH, category=SecurityCategory.INJECTION,
                file_path="db.py", line_number=25, description="High issue",
                rule_id="rule2", confidence=0.9, remediation_suggestions=[],
                created_at=datetime.now() - timedelta(days=2)
            ),
            SecurityIssue(
                id="metric_003", severity=Severity.MEDIUM, category=SecurityCategory.XSS,
                file_path="web.py", line_number=15, description="Medium issue",
                rule_id="rule3", confidence=0.8, remediation_suggestions=[],
                created_at=datetime.now() - timedelta(days=3)
            )
        ]
        
        self.sample_tickets = [
            SecurityTicket(
                ticket_id="jira_SEC-123", external_id="SEC-123", platform="jira",
                security_issue_id="metric_001", title="Critical Security Issue",
                description="Test description", status=TicketStatus.OPEN,
                priority=TicketPriority.CRITICAL, sla_hours=4,
                created_at=datetime.now() - timedelta(days=1)
            ),
            SecurityTicket(
                ticket_id="jira_SEC-124", external_id="SEC-124", platform="jira",
                security_issue_id="metric_002", title="High Security Issue",
                description="Test description", status=TicketStatus.RESOLVED,
                priority=TicketPriority.HIGH, sla_hours=24,
                created_at=datetime.now() - timedelta(days=2),
                resolved_at=datetime.now() - timedelta(hours=12)
            )
        ]
    
    def test_metrics_collector_basic_metrics(self):
        """Test basic metrics collection."""
        collector = MetricsCollector()
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        metrics = collector.collect_metrics(
            self.sample_issues, self.sample_tickets, start_date, end_date
        )
        
        assert metrics.total_issues == 3
        assert metrics.critical_issues == 1
        assert metrics.high_issues == 1
        assert metrics.medium_issues == 1
        assert metrics.low_issues == 0
        
        assert metrics.total_tickets == 2
        assert metrics.open_tickets == 1
        assert metrics.resolved_tickets == 1
    
    def test_metrics_collector_performance_metrics(self):
        """Test performance metrics calculation."""
        collector = MetricsCollector()
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        metrics = collector.collect_metrics(
            self.sample_issues, self.sample_tickets, start_date, end_date
        )
        
        # Should calculate average resolution time for resolved tickets
        assert metrics.avg_resolution_time_hours > 0
        
        # Should calculate SLA breach rate
        assert 0 <= metrics.sla_breach_rate <= 100
    
    def test_metrics_collector_risk_calculation(self):
        """Test risk metrics calculation."""
        collector = MetricsCollector()
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        metrics = collector.collect_metrics(
            self.sample_issues, self.sample_tickets, start_date, end_date
        )
        
        # Should calculate risk score based on severity and age
        assert metrics.risk_score > 0
        
        # Should calculate security debt
        assert metrics.security_debt_hours > 0
    
    def test_security_metrics_dashboard_generation(self):
        """Test security metrics dashboard generation."""
        dashboard = SecurityMetricsDashboard()
        
        dashboard_data = dashboard.generate_dashboard_data(
            self.sample_issues, self.sample_tickets, period_days=7
        )
        
        # Verify dashboard structure
        assert 'period' in dashboard_data
        assert 'summary_cards' in dashboard_data
        assert 'charts' in dashboard_data
        assert 'alerts' in dashboard_data
        assert 'current_metrics' in dashboard_data
        
        # Verify summary cards
        summary_cards = dashboard_data['summary_cards']
        assert len(summary_cards) > 0
        
        card_titles = [card['title'] for card in summary_cards]
        assert 'Total Security Issues' in card_titles
        assert 'Critical Issues' in card_titles
        assert 'Open Tickets' in card_titles
    
    def test_dashboard_charts_generation(self):
        """Test dashboard charts data generation."""
        dashboard = SecurityMetricsDashboard()
        
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        metrics = dashboard.metrics_collector.collect_metrics(
            self.sample_issues, self.sample_tickets, start_date, end_date
        )
        
        charts_data = dashboard._generate_charts_data(
            metrics, self.sample_issues, self.sample_tickets
        )
        
        # Verify chart types
        assert 'severity_distribution' in charts_data
        assert 'category_distribution' in charts_data
        assert 'daily_trends' in charts_data
        assert 'ticket_status' in charts_data
        
        # Verify chart data structure
        severity_chart = charts_data['severity_distribution']
        assert severity_chart['type'] == 'pie'
        assert 'data' in severity_chart
        assert 'labels' in severity_chart['data']
        assert 'values' in severity_chart['data']
    
    def test_dashboard_alerts_generation(self):
        """Test dashboard alerts generation."""
        dashboard = SecurityMetricsDashboard()
        
        # Create metrics with critical issues to trigger alerts
        metrics = SecurityMetrics(
            start_date=datetime.now() - timedelta(days=7),
            end_date=datetime.now(),
            critical_issues=2,
            overdue_tickets=3,
            sla_breach_rate=25.0
        )
        
        alerts = dashboard._generate_alerts(metrics, self.sample_tickets)
        
        # Should generate alerts for critical issues, overdue tickets, and high SLA breach rate
        assert len(alerts) >= 2
        
        alert_types = [alert['type'] for alert in alerts]
        assert 'error' in alert_types  # Critical issues
        assert 'warning' in alert_types  # Overdue tickets or SLA breach
    
    def test_executive_report_generation(self):
        """Test executive report generation."""
        dashboard = SecurityMetricsDashboard()
        
        report = dashboard.generate_executive_report(
            self.sample_issues, self.sample_tickets, period_days=7
        )
        
        # Verify report structure
        assert 'period' in report
        assert 'executive_summary' in report
        assert 'key_insights' in report
        assert 'recommendations' in report
        assert 'metrics' in report
        
        # Verify executive summary
        exec_summary = report['executive_summary']
        assert 'total_issues' in exec_summary
        assert 'critical_issues' in exec_summary
        assert 'risk_level' in exec_summary
        assert 'sla_performance' in exec_summary
        
        # Verify insights and recommendations are lists
        assert isinstance(report['key_insights'], list)
        assert isinstance(report['recommendations'], list)


class TestSecurityTicket:
    """Test SecurityTicket class functionality."""
    
    def test_ticket_creation(self):
        """Test security ticket creation."""
        ticket = SecurityTicket(
            ticket_id="test_123",
            external_id="123",
            platform="jira",
            security_issue_id="issue_001",
            title="Test Ticket",
            description="Test description",
            status=TicketStatus.OPEN,
            priority=TicketPriority.HIGH,
            sla_hours=24
        )
        
        assert ticket.ticket_id == "test_123"
        assert ticket.status == TicketStatus.OPEN
        assert ticket.priority == TicketPriority.HIGH
        assert ticket.sla_hours == 24
    
    def test_ticket_overdue_calculation(self):
        """Test ticket overdue calculation."""
        # Create overdue ticket
        overdue_ticket = SecurityTicket(
            ticket_id="overdue_123", external_id="123", platform="jira",
            security_issue_id="issue_001", title="Overdue Ticket",
            description="Test", status=TicketStatus.OPEN, priority=TicketPriority.HIGH,
            sla_hours=1, created_at=datetime.now() - timedelta(hours=2)
        )
        
        assert overdue_ticket.is_overdue() is True
        
        # Create non-overdue ticket
        current_ticket = SecurityTicket(
            ticket_id="current_123", external_id="123", platform="jira",
            security_issue_id="issue_001", title="Current Ticket",
            description="Test", status=TicketStatus.OPEN, priority=TicketPriority.HIGH,
            sla_hours=24, created_at=datetime.now()
        )
        
        assert current_ticket.is_overdue() is False
        
        # Resolved tickets should not be overdue
        resolved_ticket = SecurityTicket(
            ticket_id="resolved_123", external_id="123", platform="jira",
            security_issue_id="issue_001", title="Resolved Ticket",
            description="Test", status=TicketStatus.RESOLVED, priority=TicketPriority.HIGH,
            sla_hours=1, created_at=datetime.now() - timedelta(hours=2)
        )
        
        assert resolved_ticket.is_overdue() is False
    
    def test_ticket_serialization(self):
        """Test ticket serialization to dictionary."""
        ticket = SecurityTicket(
            ticket_id="serialize_123",
            external_id="123",
            platform="jira",
            security_issue_id="issue_001",
            title="Serialize Test",
            description="Test description",
            status=TicketStatus.IN_PROGRESS,
            priority=TicketPriority.MEDIUM,
            labels=["security", "test"],
            sla_hours=48
        )
        
        ticket_dict = ticket.to_dict()
        
        assert ticket_dict['ticket_id'] == "serialize_123"
        assert ticket_dict['status'] == "in_progress"
        assert ticket_dict['priority'] == "medium"
        assert ticket_dict['labels'] == ["security", "test"]
        assert ticket_dict['sla_hours'] == 48


if __name__ == "__main__":
    pytest.main([__file__])