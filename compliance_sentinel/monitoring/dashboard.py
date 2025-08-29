"""Security dashboard with real-time metrics and visualization."""

import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import logging
from pathlib import Path

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of security metrics."""
    VULNERABILITY_COUNT = "vulnerability_count"
    SEVERITY_DISTRIBUTION = "severity_distribution"
    CATEGORY_DISTRIBUTION = "category_distribution"
    TREND_ANALYSIS = "trend_analysis"
    COMPLIANCE_SCORE = "compliance_score"
    REMEDIATION_RATE = "remediation_rate"
    DETECTION_ACCURACY = "detection_accuracy"
    SCAN_PERFORMANCE = "scan_performance"


@dataclass
class MetricValue:
    """A single metric value with timestamp."""
    value: float
    timestamp: datetime
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    id: str
    title: str
    widget_type: str  # chart, gauge, table, alert_list, etc.
    metric_type: MetricType
    config: Dict[str, Any]
    position: Tuple[int, int]  # (row, column)
    size: Tuple[int, int]      # (width, height)
    refresh_interval: int = 30  # seconds
    enabled: bool = True


@dataclass
class DashboardMetrics:
    """Collection of dashboard metrics."""
    vulnerability_count: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    compliance_score: float
    remediation_rate: float
    scan_coverage: float
    last_scan_time: datetime
    trend_direction: str  # "improving", "stable", "degrading"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'vulnerability_count': self.vulnerability_count,
            'critical_issues': self.critical_issues,
            'high_issues': self.high_issues,
            'medium_issues': self.medium_issues,
            'low_issues': self.low_issues,
            'compliance_score': self.compliance_score,
            'remediation_rate': self.remediation_rate,
            'scan_coverage': self.scan_coverage,
            'last_scan_time': self.last_scan_time.isoformat(),
            'trend_direction': self.trend_direction
        }


class SecurityDashboard:
    """Real-time security dashboard with metrics and visualization."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize security dashboard."""
        self.logger = logging.getLogger(f"{__name__}.dashboard")
        self.widgets: List[DashboardWidget] = []
        self.metrics_history: Dict[MetricType, List[MetricValue]] = {}
        self.current_metrics: DashboardMetrics = None
        self.security_issues: List[SecurityIssue] = []
        
        # Initialize metrics history
        for metric_type in MetricType:
            self.metrics_history[metric_type] = []
        
        if config_path:
            self.load_config(config_path)
        else:
            self._create_default_widgets()
    
    def load_config(self, config_path: str) -> None:
        """Load dashboard configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.widgets = []
            for widget_data in config.get('widgets', []):
                widget = DashboardWidget(
                    id=widget_data['id'],
                    title=widget_data['title'],
                    widget_type=widget_data['widget_type'],
                    metric_type=MetricType(widget_data['metric_type']),
                    config=widget_data.get('config', {}),
                    position=tuple(widget_data['position']),
                    size=tuple(widget_data['size']),
                    refresh_interval=widget_data.get('refresh_interval', 30),
                    enabled=widget_data.get('enabled', True)
                )
                self.widgets.append(widget)
            
            self.logger.info(f"Loaded dashboard configuration from {config_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to load dashboard config: {e}")
            self._create_default_widgets()
    
    def _create_default_widgets(self) -> None:
        """Create default dashboard widgets."""
        default_widgets = [
            DashboardWidget(
                id="vulnerability_overview",
                title="Vulnerability Overview",
                widget_type="gauge",
                metric_type=MetricType.VULNERABILITY_COUNT,
                config={"max_value": 1000, "color_thresholds": [50, 100, 200]},
                position=(0, 0),
                size=(2, 1)
            ),
            DashboardWidget(
                id="severity_distribution",
                title="Severity Distribution",
                widget_type="pie_chart",
                metric_type=MetricType.SEVERITY_DISTRIBUTION,
                config={"colors": ["#28a745", "#ffc107", "#fd7e14", "#dc3545"]},
                position=(0, 2),
                size=(2, 1)
            ),
            DashboardWidget(
                id="compliance_score",
                title="Compliance Score",
                widget_type="gauge",
                metric_type=MetricType.COMPLIANCE_SCORE,
                config={"max_value": 100, "unit": "%", "color_thresholds": [70, 85, 95]},
                position=(1, 0),
                size=(1, 1)
            ),
            DashboardWidget(
                id="trend_analysis",
                title="Security Trend (30 days)",
                widget_type="line_chart",
                metric_type=MetricType.TREND_ANALYSIS,
                config={"time_range": 30, "unit": "days"},
                position=(2, 0),
                size=(4, 2)
            ),
            DashboardWidget(
                id="category_breakdown",
                title="Vulnerability Categories",
                widget_type="bar_chart",
                metric_type=MetricType.CATEGORY_DISTRIBUTION,
                config={"horizontal": True},
                position=(1, 1),
                size=(2, 1)
            ),
            DashboardWidget(
                id="recent_alerts",
                title="Recent Security Alerts",
                widget_type="alert_list",
                metric_type=MetricType.VULNERABILITY_COUNT,
                config={"max_items": 10, "show_resolved": False},
                position=(0, 4),
                size=(2, 2)
            )
        ]
        
        self.widgets = default_widgets
        self.logger.info("Created default dashboard widgets")
    
    def update_security_issues(self, issues: List[SecurityIssue]) -> None:
        """Update dashboard with new security issues."""
        self.security_issues = issues
        self._calculate_metrics()
        self._update_metrics_history()
        self.logger.info(f"Updated dashboard with {len(issues)} security issues")
    
    def _calculate_metrics(self) -> None:
        """Calculate current dashboard metrics from security issues."""
        if not self.security_issues:
            self.current_metrics = DashboardMetrics(
                vulnerability_count=0,
                critical_issues=0,
                high_issues=0,
                medium_issues=0,
                low_issues=0,
                compliance_score=100.0,
                remediation_rate=0.0,
                scan_coverage=0.0,
                last_scan_time=datetime.now(),
                trend_direction="stable"
            )
            return
        
        # Count by severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0
        }
        
        for issue in self.security_issues:
            severity_counts[issue.severity] += 1
        
        # Calculate compliance score (simplified)
        total_issues = len(self.security_issues)
        critical_weight = severity_counts[Severity.CRITICAL] * 10
        high_weight = severity_counts[Severity.HIGH] * 5
        medium_weight = severity_counts[Severity.MEDIUM] * 2
        low_weight = severity_counts[Severity.LOW] * 1
        
        weighted_score = critical_weight + high_weight + medium_weight + low_weight
        max_possible_score = total_issues * 10  # If all were critical
        
        if max_possible_score > 0:
            compliance_score = max(0, 100 - (weighted_score / max_possible_score * 100))
        else:
            compliance_score = 100.0
        
        # Calculate trend direction (simplified - would use historical data)
        trend_direction = self._calculate_trend_direction()
        
        self.current_metrics = DashboardMetrics(
            vulnerability_count=total_issues,
            critical_issues=severity_counts[Severity.CRITICAL],
            high_issues=severity_counts[Severity.HIGH],
            medium_issues=severity_counts[Severity.MEDIUM],
            low_issues=severity_counts[Severity.LOW],
            compliance_score=compliance_score,
            remediation_rate=self._calculate_remediation_rate(),
            scan_coverage=100.0,  # Placeholder
            last_scan_time=datetime.now(),
            trend_direction=trend_direction
        )
    
    def _calculate_trend_direction(self) -> str:
        """Calculate trend direction based on historical data."""
        # Get recent vulnerability counts
        recent_counts = []
        for metric_value in self.metrics_history[MetricType.VULNERABILITY_COUNT][-7:]:  # Last 7 data points
            recent_counts.append(metric_value.value)
        
        if len(recent_counts) < 2:
            return "stable"
        
        # Simple trend calculation
        first_half = sum(recent_counts[:len(recent_counts)//2])
        second_half = sum(recent_counts[len(recent_counts)//2:])
        
        if second_half < first_half * 0.9:  # 10% improvement
            return "improving"
        elif second_half > first_half * 1.1:  # 10% degradation
            return "degrading"
        else:
            return "stable"
    
    def _calculate_remediation_rate(self) -> float:
        """Calculate remediation rate (placeholder implementation)."""
        # This would track resolved vs. new issues over time
        return 75.0  # Placeholder value
    
    def _update_metrics_history(self) -> None:
        """Update metrics history with current values."""
        if not self.current_metrics:
            return
        
        timestamp = datetime.now()
        
        # Update vulnerability count history
        self.metrics_history[MetricType.VULNERABILITY_COUNT].append(
            MetricValue(
                value=self.current_metrics.vulnerability_count,
                timestamp=timestamp
            )
        )
        
        # Update compliance score history
        self.metrics_history[MetricType.COMPLIANCE_SCORE].append(
            MetricValue(
                value=self.current_metrics.compliance_score,
                timestamp=timestamp
            )
        )
        
        # Update remediation rate history
        self.metrics_history[MetricType.REMEDIATION_RATE].append(
            MetricValue(
                value=self.current_metrics.remediation_rate,
                timestamp=timestamp
            )
        )
        
        # Cleanup old data (keep last 30 days)
        cutoff_time = timestamp - timedelta(days=30)
        for metric_type in self.metrics_history:
            self.metrics_history[metric_type] = [
                mv for mv in self.metrics_history[metric_type]
                if mv.timestamp > cutoff_time
            ]
    
    def get_widget_data(self, widget_id: str) -> Dict[str, Any]:
        """Get data for a specific widget."""
        widget = next((w for w in self.widgets if w.id == widget_id), None)
        if not widget or not widget.enabled:
            return {}
        
        if widget.metric_type == MetricType.VULNERABILITY_COUNT:
            return self._get_vulnerability_count_data(widget)
        elif widget.metric_type == MetricType.SEVERITY_DISTRIBUTION:
            return self._get_severity_distribution_data(widget)
        elif widget.metric_type == MetricType.CATEGORY_DISTRIBUTION:
            return self._get_category_distribution_data(widget)
        elif widget.metric_type == MetricType.COMPLIANCE_SCORE:
            return self._get_compliance_score_data(widget)
        elif widget.metric_type == MetricType.TREND_ANALYSIS:
            return self._get_trend_analysis_data(widget)
        else:
            return {}
    
    def _get_vulnerability_count_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Get vulnerability count data for widget."""
        if not self.current_metrics:
            return {"value": 0, "status": "no_data"}
        
        value = self.current_metrics.vulnerability_count
        thresholds = widget.config.get("color_thresholds", [50, 100, 200])
        
        if value <= thresholds[0]:
            status = "good"
        elif value <= thresholds[1]:
            status = "warning"
        elif value <= thresholds[2]:
            status = "danger"
        else:
            status = "critical"
        
        return {
            "value": value,
            "status": status,
            "last_updated": self.current_metrics.last_scan_time.isoformat(),
            "trend": self.current_metrics.trend_direction
        }
    
    def _get_severity_distribution_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Get severity distribution data for widget."""
        if not self.current_metrics:
            return {"data": [], "total": 0}
        
        data = [
            {"label": "Critical", "value": self.current_metrics.critical_issues, "color": "#dc3545"},
            {"label": "High", "value": self.current_metrics.high_issues, "color": "#fd7e14"},
            {"label": "Medium", "value": self.current_metrics.medium_issues, "color": "#ffc107"},
            {"label": "Low", "value": self.current_metrics.low_issues, "color": "#28a745"}
        ]
        
        return {
            "data": data,
            "total": self.current_metrics.vulnerability_count,
            "last_updated": self.current_metrics.last_scan_time.isoformat()
        }
    
    def _get_category_distribution_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Get category distribution data for widget."""
        if not self.security_issues:
            return {"data": [], "total": 0}
        
        # Count by category
        category_counts = {}
        for issue in self.security_issues:
            category = issue.category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Convert to chart data
        data = [
            {"label": category, "value": count}
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return {
            "data": data,
            "total": len(self.security_issues),
            "last_updated": datetime.now().isoformat()
        }
    
    def _get_compliance_score_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Get compliance score data for widget."""
        if not self.current_metrics:
            return {"value": 0, "status": "no_data"}
        
        value = self.current_metrics.compliance_score
        thresholds = widget.config.get("color_thresholds", [70, 85, 95])
        
        if value >= thresholds[2]:
            status = "excellent"
        elif value >= thresholds[1]:
            status = "good"
        elif value >= thresholds[0]:
            status = "warning"
        else:
            status = "critical"
        
        return {
            "value": value,
            "status": status,
            "unit": "%",
            "last_updated": self.current_metrics.last_scan_time.isoformat(),
            "trend": self.current_metrics.trend_direction
        }
    
    def _get_trend_analysis_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Get trend analysis data for widget."""
        time_range = widget.config.get("time_range", 30)  # days
        cutoff_time = datetime.now() - timedelta(days=time_range)
        
        # Get vulnerability count history
        history_data = [
            {
                "timestamp": mv.timestamp.isoformat(),
                "value": mv.value
            }
            for mv in self.metrics_history[MetricType.VULNERABILITY_COUNT]
            if mv.timestamp > cutoff_time
        ]
        
        return {
            "data": history_data,
            "time_range": time_range,
            "unit": "days",
            "last_updated": datetime.now().isoformat()
        }
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get complete dashboard summary."""
        if not self.current_metrics:
            return {"status": "no_data", "widgets": []}
        
        widget_data = {}
        for widget in self.widgets:
            if widget.enabled:
                widget_data[widget.id] = self.get_widget_data(widget.id)
        
        return {
            "status": "active",
            "metrics": self.current_metrics.to_dict(),
            "widgets": widget_data,
            "last_updated": datetime.now().isoformat(),
            "total_widgets": len([w for w in self.widgets if w.enabled])
        }
    
    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format."""
        if format.lower() == "json":
            return json.dumps(self.get_dashboard_summary(), indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def add_widget(self, widget: DashboardWidget) -> None:
        """Add a new widget to the dashboard."""
        self.widgets.append(widget)
        self.logger.info(f"Added widget: {widget.title}")
    
    def remove_widget(self, widget_id: str) -> bool:
        """Remove a widget from the dashboard."""
        for i, widget in enumerate(self.widgets):
            if widget.id == widget_id:
                del self.widgets[i]
                self.logger.info(f"Removed widget: {widget_id}")
                return True
        return False
    
    def get_widget_config(self, widget_id: str) -> Optional[DashboardWidget]:
        """Get widget configuration."""
        return next((w for w in self.widgets if w.id == widget_id), None)


# Global dashboard instance
_global_dashboard: Optional[SecurityDashboard] = None


def get_security_dashboard() -> SecurityDashboard:
    """Get global security dashboard instance."""
    global _global_dashboard
    if _global_dashboard is None:
        _global_dashboard = SecurityDashboard()
    return _global_dashboard


def reset_security_dashboard() -> None:
    """Reset global security dashboard (for testing)."""
    global _global_dashboard
    _global_dashboard = None