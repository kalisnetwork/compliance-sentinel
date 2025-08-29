"""Dashboard generation system for security monitoring visualization."""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import base64
import io

from compliance_sentinel.monitoring.metrics_collector import MetricsCollector, MetricAggregation


logger = logging.getLogger(__name__)


class WidgetType(Enum):
    """Types of dashboard widgets."""
    CHART = "chart"
    METRIC = "metric"
    ALERT = "alert"
    TABLE = "table"
    TEXT = "text"
    GAUGE = "gauge"
    HEATMAP = "heatmap"


class ChartType(Enum):
    """Types of charts."""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    AREA = "area"
    SCATTER = "scatter"
    HISTOGRAM = "histogram"


@dataclass
class Widget:
    """Base dashboard widget."""
    
    widget_id: str
    title: str
    widget_type: WidgetType
    
    # Layout
    position: Dict[str, int] = field(default_factory=lambda: {'x': 0, 'y': 0, 'width': 4, 'height': 3})
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Data
    data: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    description: Optional[str] = None
    refresh_interval: int = 60  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert widget to dictionary."""
        return {
            'widget_id': self.widget_id,
            'title': self.title,
            'type': self.widget_type.value,
            'position': self.position,
            'config': self.config,
            'data': self.data,
            'description': self.description,
            'refresh_interval': self.refresh_interval
        }


@dataclass
class ChartWidget(Widget):
    """Chart widget for data visualization."""
    
    chart_type: ChartType = ChartType.LINE
    
    def __post_init__(self):
        """Initialize chart widget."""
        self.widget_type = WidgetType.CHART
        self.config['chart_type'] = self.chart_type.value


@dataclass
class MetricWidget(Widget):
    """Metric display widget."""
    
    metric_name: str = ""
    aggregation: MetricAggregation = MetricAggregation.AVERAGE
    
    def __post_init__(self):
        """Initialize metric widget."""
        self.widget_type = WidgetType.METRIC
        self.config['metric_name'] = self.metric_name
        self.config['aggregation'] = self.aggregation.value


@dataclass
class AlertWidget(Widget):
    """Alert display widget."""
    
    alert_severity_filter: Optional[str] = None
    max_alerts: int = 10
    
    def __post_init__(self):
        """Initialize alert widget."""
        self.widget_type = WidgetType.ALERT
        self.config['severity_filter'] = self.alert_severity_filter
        self.config['max_alerts'] = self.max_alerts


@dataclass
class Dashboard:
    """Dashboard configuration and layout."""
    
    dashboard_id: str
    title: str
    description: str
    
    # Widgets
    widgets: List[Widget] = field(default_factory=list)
    
    # Layout settings
    grid_size: Dict[str, int] = field(default_factory=lambda: {'columns': 12, 'row_height': 100})
    
    # Refresh settings
    auto_refresh: bool = True
    refresh_interval: int = 30  # seconds
    
    # Access control
    public: bool = False
    allowed_users: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def add_widget(self, widget: Widget):
        """Add widget to dashboard."""
        self.widgets.append(widget)
        self.updated_at = datetime.now()
    
    def remove_widget(self, widget_id: str) -> bool:
        """Remove widget from dashboard."""
        for i, widget in enumerate(self.widgets):
            if widget.widget_id == widget_id:
                del self.widgets[i]
                self.updated_at = datetime.now()
                return True
        return False
    
    def get_widget(self, widget_id: str) -> Optional[Widget]:
        """Get widget by ID."""
        for widget in self.widgets:
            if widget.widget_id == widget_id:
                return widget
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard to dictionary."""
        return {
            'dashboard_id': self.dashboard_id,
            'title': self.title,
            'description': self.description,
            'widgets': [widget.to_dict() for widget in self.widgets],
            'grid_size': self.grid_size,
            'auto_refresh': self.auto_refresh,
            'refresh_interval': self.refresh_interval,
            'public': self.public,
            'allowed_users': self.allowed_users,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class DashboardGenerator:
    """Dashboard generation and management system."""
    
    def __init__(self, metrics_collector: Optional[MetricsCollector] = None):
        """Initialize dashboard generator."""
        self.metrics_collector = metrics_collector
        self.logger = logging.getLogger(__name__)
        
        # Dashboard storage
        self.dashboards = {}
        
        # Widget data cache
        self.widget_data_cache = {}
        self.cache_ttl = 60  # seconds
        
        # Template dashboards
        self.dashboard_templates = {}
        
        # Load default templates
        self._load_default_templates()
    
    def _load_default_templates(self):
        """Load default dashboard templates."""
        
        # Security overview dashboard
        security_dashboard = self._create_security_overview_dashboard()
        self.dashboard_templates['security_overview'] = security_dashboard
        
        # System monitoring dashboard
        system_dashboard = self._create_system_monitoring_dashboard()
        self.dashboard_templates['system_monitoring'] = system_dashboard
        
        # Compliance dashboard
        compliance_dashboard = self._create_compliance_dashboard()
        self.dashboard_templates['compliance'] = compliance_dashboard
    
    def _create_security_overview_dashboard(self) -> Dashboard:
        """Create security overview dashboard template."""
        
        dashboard = Dashboard(
            dashboard_id="security_overview",
            title="Security Overview",
            description="High-level security metrics and alerts"
        )
        
        # Vulnerability count chart
        vuln_chart = ChartWidget(
            widget_id="vulnerability_chart",
            title="Vulnerabilities by Severity",
            chart_type=ChartType.BAR,
            position={'x': 0, 'y': 0, 'width': 6, 'height': 4}
        )
        dashboard.add_widget(vuln_chart)
        
        # Critical vulnerabilities metric
        critical_metric = MetricWidget(
            widget_id="critical_vulns",
            title="Critical Vulnerabilities",
            metric_name="security.vulnerabilities.critical",
            position={'x': 6, 'y': 0, 'width': 3, 'height': 2}
        )
        dashboard.add_widget(critical_metric)
        
        # Compliance score gauge
        compliance_gauge = Widget(
            widget_id="compliance_score",
            title="Compliance Score",
            widget_type=WidgetType.GAUGE,
            position={'x': 9, 'y': 0, 'width': 3, 'height': 2}
        )
        dashboard.add_widget(compliance_gauge)
        
        # Recent alerts
        alerts_widget = AlertWidget(
            widget_id="recent_alerts",
            title="Recent Security Alerts",
            max_alerts=5,
            position={'x': 6, 'y': 2, 'width': 6, 'height': 4}
        )
        dashboard.add_widget(alerts_widget)
        
        # Analysis timeline
        timeline_chart = ChartWidget(
            widget_id="analysis_timeline",
            title="Security Analysis Timeline",
            chart_type=ChartType.LINE,
            position={'x': 0, 'y': 4, 'width': 12, 'height': 3}
        )
        dashboard.add_widget(timeline_chart)
        
        return dashboard
    
    def _create_system_monitoring_dashboard(self) -> Dashboard:
        """Create system monitoring dashboard template."""
        
        dashboard = Dashboard(
            dashboard_id="system_monitoring",
            title="System Monitoring",
            description="System performance and resource utilization"
        )
        
        # CPU usage chart
        cpu_chart = ChartWidget(
            widget_id="cpu_usage",
            title="CPU Usage",
            chart_type=ChartType.LINE,
            position={'x': 0, 'y': 0, 'width': 6, 'height': 3}
        )
        dashboard.add_widget(cpu_chart)
        
        # Memory usage chart
        memory_chart = ChartWidget(
            widget_id="memory_usage",
            title="Memory Usage",
            chart_type=ChartType.LINE,
            position={'x': 6, 'y': 0, 'width': 6, 'height': 3}
        )
        dashboard.add_widget(memory_chart)
        
        # Disk usage gauge
        disk_gauge = Widget(
            widget_id="disk_usage",
            title="Disk Usage",
            widget_type=WidgetType.GAUGE,
            position={'x': 0, 'y': 3, 'width': 3, 'height': 2}
        )
        dashboard.add_widget(disk_gauge)
        
        # Network I/O chart
        network_chart = ChartWidget(
            widget_id="network_io",
            title="Network I/O",
            chart_type=ChartType.AREA,
            position={'x': 3, 'y': 3, 'width': 6, 'height': 3}
        )
        dashboard.add_widget(network_chart)
        
        # Process count metric
        process_metric = MetricWidget(
            widget_id="process_count",
            title="Active Processes",
            metric_name="system.process.count",
            position={'x': 9, 'y': 3, 'width': 3, 'height': 2}
        )
        dashboard.add_widget(process_metric)
        
        return dashboard
    
    def _create_compliance_dashboard(self) -> Dashboard:
        """Create compliance monitoring dashboard template."""
        
        dashboard = Dashboard(
            dashboard_id="compliance",
            title="Compliance Monitoring",
            description="Regulatory compliance status and violations"
        )
        
        # Compliance score by framework
        compliance_chart = ChartWidget(
            widget_id="compliance_by_framework",
            title="Compliance Score by Framework",
            chart_type=ChartType.BAR,
            position={'x': 0, 'y': 0, 'width': 8, 'height': 4}
        )
        dashboard.add_widget(compliance_chart)
        
        # Overall compliance score
        overall_score = Widget(
            widget_id="overall_compliance",
            title="Overall Compliance",
            widget_type=WidgetType.GAUGE,
            position={'x': 8, 'y': 0, 'width': 4, 'height': 4}
        )
        dashboard.add_widget(overall_score)
        
        # Violations by category
        violations_chart = ChartWidget(
            widget_id="violations_by_category",
            title="Violations by Category",
            chart_type=ChartType.PIE,
            position={'x': 0, 'y': 4, 'width': 6, 'height': 4}
        )
        dashboard.add_widget(violations_chart)
        
        # Recent violations table
        violations_table = Widget(
            widget_id="recent_violations",
            title="Recent Violations",
            widget_type=WidgetType.TABLE,
            position={'x': 6, 'y': 4, 'width': 6, 'height': 4}
        )
        dashboard.add_widget(violations_table)
        
        return dashboard
    
    def create_dashboard(self, dashboard_id: str, title: str, description: str = "") -> Dashboard:
        """Create new dashboard."""
        
        dashboard = Dashboard(
            dashboard_id=dashboard_id,
            title=title,
            description=description
        )
        
        self.dashboards[dashboard_id] = dashboard
        self.logger.info(f"Created dashboard: {dashboard_id}")
        
        return dashboard
    
    def create_dashboard_from_template(self, template_name: str, dashboard_id: str, 
                                     title: Optional[str] = None) -> Optional[Dashboard]:
        """Create dashboard from template."""
        
        if template_name not in self.dashboard_templates:
            self.logger.error(f"Template not found: {template_name}")
            return None
        
        template = self.dashboard_templates[template_name]
        
        # Create new dashboard based on template
        dashboard = Dashboard(
            dashboard_id=dashboard_id,
            title=title or template.title,
            description=template.description,
            widgets=template.widgets.copy(),
            grid_size=template.grid_size.copy(),
            auto_refresh=template.auto_refresh,
            refresh_interval=template.refresh_interval
        )
        
        self.dashboards[dashboard_id] = dashboard
        self.logger.info(f"Created dashboard from template {template_name}: {dashboard_id}")
        
        return dashboard
    
    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get dashboard by ID."""
        return self.dashboards.get(dashboard_id)
    
    def list_dashboards(self) -> List[str]:
        """List all dashboard IDs."""
        return list(self.dashboards.keys())
    
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete dashboard."""
        if dashboard_id in self.dashboards:
            del self.dashboards[dashboard_id]
            self.logger.info(f"Deleted dashboard: {dashboard_id}")
            return True
        return False
    
    def update_widget_data(self, dashboard_id: str, widget_id: str) -> bool:
        """Update widget data from metrics collector."""
        
        dashboard = self.get_dashboard(dashboard_id)
        if not dashboard:
            return False
        
        widget = dashboard.get_widget(widget_id)
        if not widget:
            return False
        
        # Check cache
        cache_key = f"{dashboard_id}_{widget_id}"
        if cache_key in self.widget_data_cache:
            cached_data, timestamp = self.widget_data_cache[cache_key]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                widget.data = cached_data
                return True
        
        # Generate new data based on widget type
        try:
            if widget.widget_type == WidgetType.CHART:
                widget.data = self._generate_chart_data(widget)
            elif widget.widget_type == WidgetType.METRIC:
                widget.data = self._generate_metric_data(widget)
            elif widget.widget_type == WidgetType.ALERT:
                widget.data = self._generate_alert_data(widget)
            elif widget.widget_type == WidgetType.GAUGE:
                widget.data = self._generate_gauge_data(widget)
            elif widget.widget_type == WidgetType.TABLE:
                widget.data = self._generate_table_data(widget)
            
            # Cache the data
            self.widget_data_cache[cache_key] = (widget.data.copy(), datetime.now())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating widget data for {widget_id}: {e}")
            return False
    
    def _generate_chart_data(self, widget: Widget) -> Dict[str, Any]:
        """Generate chart data for widget."""
        
        if not self.metrics_collector:
            return {'labels': [], 'datasets': []}
        
        # Get metric history based on chart type
        chart_type = widget.config.get('chart_type', 'line')
        
        if chart_type == 'bar':
            # Vulnerability counts by severity
            return {
                'labels': ['Critical', 'High', 'Medium', 'Low'],
                'datasets': [{
                    'label': 'Vulnerabilities',
                    'data': [
                        len(self.metrics_collector.get_metric_history('security.vulnerabilities.critical', 1)),
                        len(self.metrics_collector.get_metric_history('security.vulnerabilities.high', 1)),
                        len(self.metrics_collector.get_metric_history('security.vulnerabilities.medium', 1)),
                        len(self.metrics_collector.get_metric_history('security.vulnerabilities.low', 1))
                    ],
                    'backgroundColor': ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }]
            }
        
        elif chart_type == 'line':
            # Time series data
            history = self.metrics_collector.get_metric_history('system.cpu.usage', 50)
            
            return {
                'labels': [h.timestamp.strftime('%H:%M') for h in history],
                'datasets': [{
                    'label': 'CPU Usage %',
                    'data': [h.value for h in history],
                    'borderColor': '#007bff',
                    'fill': False
                }]
            }
        
        elif chart_type == 'pie':
            # Compliance violations by category
            return {
                'labels': ['Authentication', 'Encryption', 'Input Validation', 'Access Control'],
                'datasets': [{
                    'data': [25, 15, 30, 20],
                    'backgroundColor': ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }]
            }
        
        return {'labels': [], 'datasets': []}
    
    def _generate_metric_data(self, widget: Widget) -> Dict[str, Any]:
        """Generate metric data for widget."""
        
        if not self.metrics_collector:
            return {'value': 0, 'unit': '', 'trend': 'stable'}
        
        metric_name = widget.config.get('metric_name', '')
        aggregation = MetricAggregation(widget.config.get('aggregation', 'average'))
        
        # Get current value
        current_value = self.metrics_collector.get_aggregated_metric(
            metric_name, aggregation, timedelta(minutes=5)
        )
        
        # Get previous value for trend
        previous_value = self.metrics_collector.get_aggregated_metric(
            metric_name, aggregation, timedelta(minutes=10)
        )
        
        # Calculate trend
        trend = 'stable'
        if current_value is not None and previous_value is not None:
            if current_value > previous_value * 1.1:
                trend = 'up'
            elif current_value < previous_value * 0.9:
                trend = 'down'
        
        return {
            'value': current_value or 0,
            'unit': self._get_metric_unit(metric_name),
            'trend': trend,
            'change': ((current_value or 0) - (previous_value or 0)) if previous_value else 0
        }
    
    def _generate_alert_data(self, widget: Widget) -> Dict[str, Any]:
        """Generate alert data for widget."""
        
        # Mock alert data - would integrate with AlertManager
        alerts = [
            {
                'id': 'alert_1',
                'title': 'Critical SQL Injection Vulnerability',
                'severity': 'critical',
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            },
            {
                'id': 'alert_2',
                'title': 'High Memory Usage Detected',
                'severity': 'high',
                'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
                'status': 'acknowledged'
            }
        ]
        
        max_alerts = widget.config.get('max_alerts', 10)
        severity_filter = widget.config.get('severity_filter')
        
        if severity_filter:
            alerts = [a for a in alerts if a['severity'] == severity_filter]
        
        return {
            'alerts': alerts[:max_alerts],
            'total_count': len(alerts)
        }
    
    def _generate_gauge_data(self, widget: Widget) -> Dict[str, Any]:
        """Generate gauge data for widget."""
        
        if not self.metrics_collector:
            return {'value': 0, 'min': 0, 'max': 100, 'unit': '%'}
        
        # Get compliance score or similar gauge metric
        value = 85.5  # Mock value
        
        return {
            'value': value,
            'min': 0,
            'max': 100,
            'unit': '%',
            'thresholds': [
                {'value': 70, 'color': '#dc3545'},  # Red
                {'value': 85, 'color': '#ffc107'},  # Yellow
                {'value': 95, 'color': '#28a745'}   # Green
            ]
        }
    
    def _generate_table_data(self, widget: Widget) -> Dict[str, Any]:
        """Generate table data for widget."""
        
        # Mock table data - would integrate with actual data sources
        return {
            'columns': [
                {'key': 'timestamp', 'title': 'Time'},
                {'key': 'violation', 'title': 'Violation'},
                {'key': 'severity', 'title': 'Severity'},
                {'key': 'status', 'title': 'Status'}
            ],
            'rows': [
                {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    'violation': 'Hardcoded API Key',
                    'severity': 'High',
                    'status': 'Open'
                },
                {
                    'timestamp': (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M'),
                    'violation': 'Weak Encryption',
                    'severity': 'Medium',
                    'status': 'Resolved'
                }
            ]
        }
    
    def _get_metric_unit(self, metric_name: str) -> str:
        """Get unit for metric."""
        
        unit_mapping = {
            'cpu': '%',
            'memory': '%',
            'disk': '%',
            'bytes': 'B',
            'seconds': 's',
            'count': '',
            'rate': '/s'
        }
        
        for key, unit in unit_mapping.items():
            if key in metric_name.lower():
                return unit
        
        return ''
    
    def refresh_dashboard(self, dashboard_id: str) -> bool:
        """Refresh all widgets in dashboard."""
        
        dashboard = self.get_dashboard(dashboard_id)
        if not dashboard:
            return False
        
        success_count = 0
        
        for widget in dashboard.widgets:
            if self.update_widget_data(dashboard_id, widget.widget_id):
                success_count += 1
        
        self.logger.info(f"Refreshed {success_count}/{len(dashboard.widgets)} widgets in dashboard {dashboard_id}")
        
        return success_count > 0
    
    def export_dashboard(self, dashboard_id: str, format_type: str = 'json') -> Optional[str]:
        """Export dashboard configuration."""
        
        dashboard = self.get_dashboard(dashboard_id)
        if not dashboard:
            return None
        
        if format_type == 'json':
            return json.dumps(dashboard.to_dict(), indent=2)
        
        elif format_type == 'html':
            return self._generate_html_dashboard(dashboard)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _generate_html_dashboard(self, dashboard: Dashboard) -> str:
        """Generate HTML representation of dashboard."""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{dashboard.title}</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .dashboard {{ max-width: 1200px; margin: 0 auto; }}
                .dashboard-header {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .dashboard-title {{ margin: 0; color: #333; }}
                .dashboard-description {{ color: #666; margin-top: 5px; }}
                .widget-grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 20px; }}
                .widget {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .widget-title {{ margin: 0 0 15px 0; color: #333; font-size: 16px; font-weight: bold; }}
                .metric-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
                .metric-unit {{ font-size: 16px; color: #666; }}
                .alert {{ padding: 10px; margin: 5px 0; border-radius: 4px; }}
                .alert-critical {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
                .alert-high {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
                .table {{ width: 100%; border-collapse: collapse; }}
                .table th, .table td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                .table th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="dashboard">
                <div class="dashboard-header">
                    <h1 class="dashboard-title">{dashboard.title}</h1>
                    <p class="dashboard-description">{dashboard.description}</p>
                </div>
                
                <div class="widget-grid">
        """
        
        for widget in dashboard.widgets:
            pos = widget.position
            html += f"""
                    <div class="widget" style="grid-column: span {pos['width']}; grid-row: span {pos['height']};">
                        <h3 class="widget-title">{widget.title}</h3>
                        {self._generate_widget_html(widget)}
                    </div>
            """
        
        html += """
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_widget_html(self, widget: Widget) -> str:
        """Generate HTML for individual widget."""
        
        if widget.widget_type == WidgetType.METRIC:
            data = widget.data
            return f"""
                <div class="metric-value">{data.get('value', 0)}</div>
                <span class="metric-unit">{data.get('unit', '')}</span>
            """
        
        elif widget.widget_type == WidgetType.ALERT:
            data = widget.data
            html = ""
            for alert in data.get('alerts', []):
                severity_class = f"alert-{alert['severity']}"
                html += f"""
                    <div class="alert {severity_class}">
                        <strong>{alert['title']}</strong><br>
                        <small>{alert['timestamp']} - {alert['status']}</small>
                    </div>
                """
            return html
        
        elif widget.widget_type == WidgetType.TABLE:
            data = widget.data
            html = '<table class="table"><thead><tr>'
            
            for col in data.get('columns', []):
                html += f'<th>{col["title"]}</th>'
            
            html += '</tr></thead><tbody>'
            
            for row in data.get('rows', []):
                html += '<tr>'
                for col in data.get('columns', []):
                    html += f'<td>{row.get(col["key"], "")}</td>'
                html += '</tr>'
            
            html += '</tbody></table>'
            return html
        
        elif widget.widget_type == WidgetType.CHART:
            return '<div>Chart visualization would be rendered here with JavaScript charting library</div>'
        
        elif widget.widget_type == WidgetType.GAUGE:
            data = widget.data
            return f"""
                <div style="text-align: center;">
                    <div class="metric-value">{data.get('value', 0)}</div>
                    <span class="metric-unit">{data.get('unit', '')}</span>
                    <div>Gauge visualization would be rendered here</div>
                </div>
            """
        
        return '<div>Widget content</div>'
    
    def get_dashboard_templates(self) -> List[str]:
        """Get list of available dashboard templates."""
        return list(self.dashboard_templates.keys())


# Utility functions

def create_dashboard_generator(metrics_collector: Optional[MetricsCollector] = None) -> DashboardGenerator:
    """Create dashboard generator instance."""
    return DashboardGenerator(metrics_collector)


def create_security_dashboard(generator: DashboardGenerator, dashboard_id: str) -> Dashboard:
    """Create security overview dashboard."""
    return generator.create_dashboard_from_template('security_overview', dashboard_id)


def create_system_dashboard(generator: DashboardGenerator, dashboard_id: str) -> Dashboard:
    """Create system monitoring dashboard."""
    return generator.create_dashboard_from_template('system_monitoring', dashboard_id)


def create_compliance_dashboard(generator: DashboardGenerator, dashboard_id: str) -> Dashboard:
    """Create compliance monitoring dashboard."""
    return generator.create_dashboard_from_template('compliance', dashboard_id)