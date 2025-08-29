"""Monitoring tool integration and correlation for Compliance Sentinel."""

from .splunk_integration import SplunkIntegration
from .elasticsearch_integration import ElasticsearchIntegration
from .datadog_integration import DatadogIntegration
from .newrelic_integration import NewRelicIntegration
from .event_correlator import SecurityEventCorrelator, CorrelationEngine
from .monitoring_manager import MonitoringManager, MonitoringConfig

# Real-time monitoring and alerting
from .real_time_monitor import (
    RealTimeMonitor, MonitoringEvent, MonitoringRule,
    EventType, EventSeverity
)
from .alert_manager import (
    AlertManager, Alert, AlertChannel, AlertSeverity, AlertStatus,
    EmailChannel, SlackChannel
)
from .metrics_collector import (
    MetricsCollector, Metric, MetricType, MetricAggregation,
    SystemMetrics, SecurityMetrics, PerformanceMetrics, Timer
)
from .dashboard_generator import (
    DashboardGenerator, Dashboard, Widget, WidgetType,
    ChartWidget, MetricWidget, AlertWidget, GaugeWidget, ChartType
)

__all__ = [
    'SplunkIntegration',
    'ElasticsearchIntegration',
    'DatadogIntegration',
    'NewRelicIntegration',
    'SecurityEventCorrelator',
    'CorrelationEngine',
    'MonitoringManager',
    'MonitoringConfig',
    # Real-time monitoring
    'RealTimeMonitor',
    'MonitoringEvent',
    'MonitoringRule',
    'EventType',
    'EventSeverity',
    # Alert management
    'AlertManager',
    'Alert',
    'AlertChannel',
    'AlertSeverity',
    'AlertStatus',
    'EmailChannel',
    'SlackChannel',
    # Metrics collection
    'MetricsCollector',
    'Metric',
    'MetricType',
    'MetricAggregation',
    'SystemMetrics',
    'SecurityMetrics',
    'PerformanceMetrics',
    'Timer',
    # Dashboard generation
    'DashboardGenerator',
    'Dashboard',
    'Widget',
    'WidgetType',
    'ChartWidget',
    'MetricWidget',
    'AlertWidget',
    'GaugeWidget',
    'ChartType'
]