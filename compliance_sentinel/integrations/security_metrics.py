"""Security metrics dashboard and data collection for project management visibility."""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import json
import logging
from collections import defaultdict

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from .ticket_manager import SecurityTicket, TicketStatus, TicketPriority


logger = logging.getLogger(__name__)


@dataclass
class SecurityMetrics:
    """Security metrics data structure."""
    
    # Time period
    start_date: datetime
    end_date: datetime
    
    # Issue metrics
    total_issues: int = 0
    new_issues: int = 0
    resolved_issues: int = 0
    
    # Severity breakdown
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    
    # Category breakdown
    issues_by_category: Dict[str, int] = field(default_factory=dict)
    
    # Ticket metrics
    total_tickets: int = 0
    open_tickets: int = 0
    in_progress_tickets: int = 0
    resolved_tickets: int = 0
    overdue_tickets: int = 0
    
    # Performance metrics
    avg_resolution_time_hours: float = 0.0
    sla_breach_rate: float = 0.0
    
    # Trend data
    daily_new_issues: Dict[str, int] = field(default_factory=dict)
    daily_resolved_issues: Dict[str, int] = field(default_factory=dict)
    
    # Risk metrics
    risk_score: float = 0.0
    security_debt_hours: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            'period': {
                'start_date': self.start_date.isoformat(),
                'end_date': self.end_date.isoformat()
            },
            'issues': {
                'total': self.total_issues,
                'new': self.new_issues,
                'resolved': self.resolved_issues,
                'by_severity': {
                    'critical': self.critical_issues,
                    'high': self.high_issues,
                    'medium': self.medium_issues,
                    'low': self.low_issues
                },
                'by_category': self.issues_by_category
            },
            'tickets': {
                'total': self.total_tickets,
                'open': self.open_tickets,
                'in_progress': self.in_progress_tickets,
                'resolved': self.resolved_tickets,
                'overdue': self.overdue_tickets
            },
            'performance': {
                'avg_resolution_time_hours': self.avg_resolution_time_hours,
                'sla_breach_rate': self.sla_breach_rate
            },
            'trends': {
                'daily_new_issues': self.daily_new_issues,
                'daily_resolved_issues': self.daily_resolved_issues
            },
            'risk': {
                'risk_score': self.risk_score,
                'security_debt_hours': self.security_debt_hours
            }
        }


class MetricsCollector:
    """Collects and aggregates security metrics."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self.logger = logging.getLogger(__name__)
    
    def collect_metrics(self, 
                       issues: List[SecurityIssue],
                       tickets: List[SecurityTicket],
                       start_date: datetime,
                       end_date: datetime) -> SecurityMetrics:
        """Collect comprehensive security metrics."""
        
        metrics = SecurityMetrics(start_date=start_date, end_date=end_date)
        
        # Filter issues and tickets by date range
        period_issues = self._filter_issues_by_date(issues, start_date, end_date)
        period_tickets = self._filter_tickets_by_date(tickets, start_date, end_date)
        
        # Calculate issue metrics
        self._calculate_issue_metrics(metrics, period_issues, start_date, end_date)
        
        # Calculate ticket metrics
        self._calculate_ticket_metrics(metrics, period_tickets)
        
        # Calculate performance metrics
        self._calculate_performance_metrics(metrics, period_tickets)
        
        # Calculate trend data
        self._calculate_trend_data(metrics, period_issues, start_date, end_date)
        
        # Calculate risk metrics
        self._calculate_risk_metrics(metrics, period_issues, period_tickets)
        
        return metrics
    
    def _filter_issues_by_date(self, 
                              issues: List[SecurityIssue],
                              start_date: datetime,
                              end_date: datetime) -> List[SecurityIssue]:
        """Filter issues by date range."""
        return [
            issue for issue in issues
            if start_date <= issue.created_at <= end_date
        ]
    
    def _filter_tickets_by_date(self,
                               tickets: List[SecurityTicket],
                               start_date: datetime,
                               end_date: datetime) -> List[SecurityTicket]:
        """Filter tickets by date range."""
        return [
            ticket for ticket in tickets
            if start_date <= ticket.created_at <= end_date
        ]
    
    def _calculate_issue_metrics(self,
                                metrics: SecurityMetrics,
                                issues: List[SecurityIssue],
                                start_date: datetime,
                                end_date: datetime):
        """Calculate issue-related metrics."""
        
        metrics.total_issues = len(issues)
        metrics.new_issues = len(issues)  # All issues in period are "new"
        
        # Count by severity
        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                metrics.critical_issues += 1
            elif issue.severity == Severity.HIGH:
                metrics.high_issues += 1
            elif issue.severity == Severity.MEDIUM:
                metrics.medium_issues += 1
            elif issue.severity == Severity.LOW:
                metrics.low_issues += 1
        
        # Count by category
        for issue in issues:
            category_name = issue.category.value
            metrics.issues_by_category[category_name] = metrics.issues_by_category.get(category_name, 0) + 1
    
    def _calculate_ticket_metrics(self, metrics: SecurityMetrics, tickets: List[SecurityTicket]):
        """Calculate ticket-related metrics."""
        
        metrics.total_tickets = len(tickets)
        
        # Count by status
        for ticket in tickets:
            if ticket.status == TicketStatus.OPEN:
                metrics.open_tickets += 1
            elif ticket.status == TicketStatus.IN_PROGRESS:
                metrics.in_progress_tickets += 1
            elif ticket.status in [TicketStatus.RESOLVED, TicketStatus.CLOSED]:
                metrics.resolved_tickets += 1
            
            # Check for overdue tickets
            if ticket.is_overdue():
                metrics.overdue_tickets += 1
    
    def _calculate_performance_metrics(self, metrics: SecurityMetrics, tickets: List[SecurityTicket]):
        """Calculate performance-related metrics."""
        
        resolved_tickets = [
            ticket for ticket in tickets
            if ticket.status in [TicketStatus.RESOLVED, TicketStatus.CLOSED] and ticket.resolved_at
        ]
        
        # Calculate average resolution time
        if resolved_tickets:
            total_resolution_time = 0
            for ticket in resolved_tickets:
                resolution_time = (ticket.resolved_at - ticket.created_at).total_seconds() / 3600
                total_resolution_time += resolution_time
            
            metrics.avg_resolution_time_hours = total_resolution_time / len(resolved_tickets)
        
        # Calculate SLA breach rate
        if tickets:
            breached_tickets = [ticket for ticket in tickets if ticket.sla_breach]
            metrics.sla_breach_rate = len(breached_tickets) / len(tickets) * 100
    
    def _calculate_trend_data(self,
                             metrics: SecurityMetrics,
                             issues: List[SecurityIssue],
                             start_date: datetime,
                             end_date: datetime):
        """Calculate daily trend data."""
        
        # Initialize daily counters
        current_date = start_date.date()
        end_date_only = end_date.date()
        
        while current_date <= end_date_only:
            date_str = current_date.isoformat()
            metrics.daily_new_issues[date_str] = 0
            metrics.daily_resolved_issues[date_str] = 0
            current_date += timedelta(days=1)
        
        # Count new issues by day
        for issue in issues:
            issue_date = issue.created_at.date().isoformat()
            if issue_date in metrics.daily_new_issues:
                metrics.daily_new_issues[issue_date] += 1
        
        # Note: For resolved issues, we would need additional data about when issues were resolved
        # This would typically come from ticket resolution data or issue status changes
    
    def _calculate_risk_metrics(self,
                               metrics: SecurityMetrics,
                               issues: List[SecurityIssue],
                               tickets: List[SecurityTicket]):
        """Calculate risk-related metrics."""
        
        # Calculate risk score based on severity and age of issues
        total_risk = 0
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1
        }
        
        for issue in issues:
            base_risk = severity_weights.get(issue.severity, 1)
            
            # Increase risk based on age (older issues are riskier)
            age_days = (datetime.now() - issue.created_at).days
            age_multiplier = 1 + (age_days / 30)  # Increase risk by 100% per month
            
            total_risk += base_risk * age_multiplier
        
        metrics.risk_score = total_risk
        
        # Calculate security debt (estimated hours to fix all issues)
        severity_hours = {
            Severity.CRITICAL: 8,   # 1 day
            Severity.HIGH: 4,       # Half day
            Severity.MEDIUM: 2,     # 2 hours
            Severity.LOW: 0.5       # 30 minutes
        }
        
        total_debt = 0
        for issue in issues:
            total_debt += severity_hours.get(issue.severity, 1)
        
        metrics.security_debt_hours = total_debt


class SecurityMetricsDashboard:
    """Security metrics dashboard for project management visibility."""
    
    def __init__(self):
        """Initialize security metrics dashboard."""
        self.logger = logging.getLogger(__name__)
        self.metrics_collector = MetricsCollector()
    
    def generate_dashboard_data(self,
                               issues: List[SecurityIssue],
                               tickets: List[SecurityTicket],
                               period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive dashboard data."""
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Collect current period metrics
        current_metrics = self.metrics_collector.collect_metrics(
            issues, tickets, start_date, end_date
        )
        
        # Collect previous period metrics for comparison
        prev_start_date = start_date - timedelta(days=period_days)
        prev_end_date = start_date
        
        previous_metrics = self.metrics_collector.collect_metrics(
            issues, tickets, prev_start_date, prev_end_date
        )
        
        # Calculate changes
        changes = self._calculate_metric_changes(current_metrics, previous_metrics)
        
        # Generate summary cards
        summary_cards = self._generate_summary_cards(current_metrics, changes)
        
        # Generate charts data
        charts_data = self._generate_charts_data(current_metrics, issues, tickets)
        
        # Generate alerts
        alerts = self._generate_alerts(current_metrics, tickets)
        
        return {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': period_days
            },
            'summary_cards': summary_cards,
            'charts': charts_data,
            'alerts': alerts,
            'current_metrics': current_metrics.to_dict(),
            'previous_metrics': previous_metrics.to_dict(),
            'changes': changes
        }
    
    def _calculate_metric_changes(self,
                                 current: SecurityMetrics,
                                 previous: SecurityMetrics) -> Dict[str, Dict[str, float]]:
        """Calculate percentage changes between periods."""
        
        def safe_percentage_change(current_val: float, previous_val: float) -> float:
            if previous_val == 0:
                return 100.0 if current_val > 0 else 0.0
            return ((current_val - previous_val) / previous_val) * 100
        
        return {
            'issues': {
                'total': safe_percentage_change(current.total_issues, previous.total_issues),
                'critical': safe_percentage_change(current.critical_issues, previous.critical_issues),
                'high': safe_percentage_change(current.high_issues, previous.high_issues)
            },
            'tickets': {
                'total': safe_percentage_change(current.total_tickets, previous.total_tickets),
                'overdue': safe_percentage_change(current.overdue_tickets, previous.overdue_tickets)
            },
            'performance': {
                'resolution_time': safe_percentage_change(
                    current.avg_resolution_time_hours,
                    previous.avg_resolution_time_hours
                ),
                'sla_breach_rate': safe_percentage_change(
                    current.sla_breach_rate,
                    previous.sla_breach_rate
                )
            },
            'risk': {
                'risk_score': safe_percentage_change(current.risk_score, previous.risk_score),
                'security_debt': safe_percentage_change(
                    current.security_debt_hours,
                    previous.security_debt_hours
                )
            }
        }
    
    def _generate_summary_cards(self,
                               metrics: SecurityMetrics,
                               changes: Dict[str, Dict[str, float]]) -> List[Dict[str, Any]]:
        """Generate summary cards for dashboard."""
        
        return [
            {
                'title': 'Total Security Issues',
                'value': metrics.total_issues,
                'change': changes['issues']['total'],
                'trend': 'up' if changes['issues']['total'] > 0 else 'down',
                'color': 'red' if changes['issues']['total'] > 0 else 'green',
                'icon': 'shield-alert'
            },
            {
                'title': 'Critical Issues',
                'value': metrics.critical_issues,
                'change': changes['issues']['critical'],
                'trend': 'up' if changes['issues']['critical'] > 0 else 'down',
                'color': 'red' if metrics.critical_issues > 0 else 'green',
                'icon': 'alert-triangle'
            },
            {
                'title': 'Open Tickets',
                'value': metrics.open_tickets + metrics.in_progress_tickets,
                'change': changes['tickets']['total'],
                'trend': 'up' if changes['tickets']['total'] > 0 else 'down',
                'color': 'orange' if metrics.open_tickets > 0 else 'green',
                'icon': 'ticket'
            },
            {
                'title': 'Overdue Tickets',
                'value': metrics.overdue_tickets,
                'change': changes['tickets']['overdue'],
                'trend': 'up' if changes['tickets']['overdue'] > 0 else 'down',
                'color': 'red' if metrics.overdue_tickets > 0 else 'green',
                'icon': 'clock'
            },
            {
                'title': 'Avg Resolution Time',
                'value': f"{metrics.avg_resolution_time_hours:.1f}h",
                'change': changes['performance']['resolution_time'],
                'trend': 'up' if changes['performance']['resolution_time'] > 0 else 'down',
                'color': 'red' if changes['performance']['resolution_time'] > 0 else 'green',
                'icon': 'timer'
            },
            {
                'title': 'SLA Breach Rate',
                'value': f"{metrics.sla_breach_rate:.1f}%",
                'change': changes['performance']['sla_breach_rate'],
                'trend': 'up' if changes['performance']['sla_breach_rate'] > 0 else 'down',
                'color': 'red' if metrics.sla_breach_rate > 10 else 'green',
                'icon': 'target'
            },
            {
                'title': 'Risk Score',
                'value': f"{metrics.risk_score:.0f}",
                'change': changes['risk']['risk_score'],
                'trend': 'up' if changes['risk']['risk_score'] > 0 else 'down',
                'color': 'red' if metrics.risk_score > 100 else 'orange' if metrics.risk_score > 50 else 'green',
                'icon': 'trending-up'
            },
            {
                'title': 'Security Debt',
                'value': f"{metrics.security_debt_hours:.0f}h",
                'change': changes['risk']['security_debt'],
                'trend': 'up' if changes['risk']['security_debt'] > 0 else 'down',
                'color': 'red' if metrics.security_debt_hours > 40 else 'orange' if metrics.security_debt_hours > 20 else 'green',
                'icon': 'credit-card'
            }
        ]
    
    def _generate_charts_data(self,
                             metrics: SecurityMetrics,
                             issues: List[SecurityIssue],
                             tickets: List[SecurityTicket]) -> Dict[str, Any]:
        """Generate data for dashboard charts."""
        
        return {
            'severity_distribution': {
                'type': 'pie',
                'data': {
                    'labels': ['Critical', 'High', 'Medium', 'Low'],
                    'values': [
                        metrics.critical_issues,
                        metrics.high_issues,
                        metrics.medium_issues,
                        metrics.low_issues
                    ],
                    'colors': ['#dc3545', '#fd7e14', '#ffc107', '#6c757d']
                }
            },
            'category_distribution': {
                'type': 'bar',
                'data': {
                    'labels': list(metrics.issues_by_category.keys()),
                    'values': list(metrics.issues_by_category.values()),
                    'color': '#0d6efd'
                }
            },
            'daily_trends': {
                'type': 'line',
                'data': {
                    'labels': list(metrics.daily_new_issues.keys()),
                    'datasets': [
                        {
                            'label': 'New Issues',
                            'data': list(metrics.daily_new_issues.values()),
                            'color': '#dc3545'
                        },
                        {
                            'label': 'Resolved Issues',
                            'data': list(metrics.daily_resolved_issues.values()),
                            'color': '#28a745'
                        }
                    ]
                }
            },
            'ticket_status': {
                'type': 'doughnut',
                'data': {
                    'labels': ['Open', 'In Progress', 'Resolved'],
                    'values': [
                        metrics.open_tickets,
                        metrics.in_progress_tickets,
                        metrics.resolved_tickets
                    ],
                    'colors': ['#dc3545', '#ffc107', '#28a745']
                }
            }
        }
    
    def _generate_alerts(self,
                        metrics: SecurityMetrics,
                        tickets: List[SecurityTicket]) -> List[Dict[str, Any]]:
        """Generate alerts for dashboard."""
        
        alerts = []
        
        # Critical issues alert
        if metrics.critical_issues > 0:
            alerts.append({
                'type': 'error',
                'title': 'Critical Security Issues',
                'message': f'{metrics.critical_issues} critical security issues require immediate attention',
                'action': 'Review critical issues',
                'priority': 'high'
            })
        
        # Overdue tickets alert
        if metrics.overdue_tickets > 0:
            alerts.append({
                'type': 'warning',
                'title': 'Overdue Tickets',
                'message': f'{metrics.overdue_tickets} tickets are overdue and may breach SLA',
                'action': 'Review overdue tickets',
                'priority': 'medium'
            })
        
        # High SLA breach rate alert
        if metrics.sla_breach_rate > 20:
            alerts.append({
                'type': 'warning',
                'title': 'High SLA Breach Rate',
                'message': f'SLA breach rate is {metrics.sla_breach_rate:.1f}%, exceeding acceptable threshold',
                'action': 'Review team capacity and processes',
                'priority': 'medium'
            })
        
        # High security debt alert
        if metrics.security_debt_hours > 80:
            alerts.append({
                'type': 'info',
                'title': 'High Security Debt',
                'message': f'Security debt is {metrics.security_debt_hours:.0f} hours, consider sprint planning',
                'action': 'Plan security debt reduction',
                'priority': 'low'
            })
        
        return alerts
    
    def generate_executive_report(self,
                                 issues: List[SecurityIssue],
                                 tickets: List[SecurityTicket],
                                 period_days: int = 30) -> Dict[str, Any]:
        """Generate executive summary report."""
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        metrics = self.metrics_collector.collect_metrics(issues, tickets, start_date, end_date)
        
        # Calculate key insights
        insights = []
        
        if metrics.critical_issues > 0:
            insights.append(f"Found {metrics.critical_issues} critical security issues requiring immediate attention")
        
        if metrics.sla_breach_rate > 15:
            insights.append(f"SLA breach rate of {metrics.sla_breach_rate:.1f}% indicates capacity or process issues")
        
        if metrics.security_debt_hours > 40:
            insights.append(f"Security debt of {metrics.security_debt_hours:.0f} hours may impact development velocity")
        
        # Risk assessment
        risk_level = "Low"
        if metrics.risk_score > 100:
            risk_level = "High"
        elif metrics.risk_score > 50:
            risk_level = "Medium"
        
        # Recommendations
        recommendations = []
        
        if metrics.critical_issues > 0:
            recommendations.append("Prioritize resolution of critical security issues")
        
        if metrics.overdue_tickets > metrics.total_tickets * 0.2:
            recommendations.append("Review team capacity and ticket assignment process")
        
        if metrics.avg_resolution_time_hours > 48:
            recommendations.append("Implement automation or additional training to improve resolution times")
        
        return {
            'period': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            'executive_summary': {
                'total_issues': metrics.total_issues,
                'critical_issues': metrics.critical_issues,
                'risk_level': risk_level,
                'risk_score': metrics.risk_score,
                'sla_performance': f"{100 - metrics.sla_breach_rate:.1f}%"
            },
            'key_insights': insights,
            'recommendations': recommendations,
            'metrics': metrics.to_dict()
        }