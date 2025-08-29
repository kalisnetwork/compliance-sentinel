"""Integrated monitoring system that combines all monitoring components."""

import logging
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from compliance_sentinel.monitoring.real_time_monitor import (
    RealTimeMonitor, MonitoringConfig, MonitoringEvent, EventType, EventSeverity
)
from compliance_sentinel.monitoring.alert_manager import (
    AlertManager, Alert, AlertSeverity, 
    EmailChannel, SlackChannel, WebhookChannel, SMSChannel
)
from compliance_sentinel.monitoring.metrics_collector import (
    MetricsCollector, Metric, MetricType
)
from compliance_sentinel.monitoring.dashboard_generator import (
    DashboardGenerator, Dashboard
)
from compliance_sentinel.core.interfaces import SecurityIssue


logger = logging.getLogger(__name__)


@dataclass
class MonitoringSystemConfig:
    """Configuration for the integrated monitoring system."""
    
    # Real-time monitoring
    enable_real_time_monitoring: bool = True
    monitoring_config: Optional[MonitoringConfig] = None
    
    # Metrics collection
    enable_metrics_collection: bool = True
    metrics_collection_interval: int = 60
    
    # Alert management
    enable_alerting: bool = True
    alert_channels: Dict[str, Dict[str, Any]] = None
    
    # Dashboard generation
    enable_dashboards: bool = True
    auto_create_default_dashboards: bool = True
    
    # System settings
    log_level: str = "INFO"
    health_check_interval: int = 300  # 5 minutes
    
    def __post_init__(self):
        """Initialize default values."""
        if self.alert_channels is None:
            self.alert_channels = {}
        
        if self.monitoring_config is None:
            self.monitoring_config = MonitoringConfig()


class MonitoringSystem:
    """Integrated monitoring system for Compliance Sentinel."""
    
    def __init__(self, config: Optional[MonitoringSystemConfig] = None):
        """Initialize monitoring system."""
        self.config = config or MonitoringSystemConfig()
        self.logger = logging.getLogger(__name__)
        
        # Set logging level
        logging.getLogger().setLevel(getattr(logging, self.config.log_level.upper()))
        
        # Initialize components
        self.real_time_monitor = None
        self.alert_manager = None
        self.metrics_collector = None
        self.dashboard_generator = None
        
        # System state
        self.is_running = False
        self.health_check_thread = None
        
        # Statistics
        self.system_stats = {
            'start_time': None,
            'uptime_seconds': 0,
            'events_processed': 0,
            'alerts_sent': 0,
            'metrics_collected': 0,
            'health_checks_completed': 0,
            'errors': 0
        }
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize monitoring system components."""
        
        try:
            # Initialize metrics collector
            if self.config.enable_metrics_collection:
                self.metrics_collector = MetricsCollector(
                    collection_interval=self.config.metrics_collection_interval
                )
                self.logger.info("Metrics collector initialized")
            
            # Initialize real-time monitor
            if self.config.enable_real_time_monitoring:
                self.real_time_monitor = RealTimeMonitor(self.config.monitoring_config)
                
                # Connect to metrics collector
                if self.metrics_collector:
                    self.real_time_monitor.add_event_handler(
                        EventType.VULNERABILITY_DETECTED,
                        self._handle_security_event
                    )
                
                self.logger.info("Real-time monitor initialized")
            
            # Initialize alert manager
            if self.config.enable_alerting:
                self.alert_manager = AlertManager()
                
                # Configure alert channels
                self._configure_alert_channels()
                
                # Connect to real-time monitor
                if self.real_time_monitor:
                    self.real_time_monitor.add_event_handler(
                        EventType.VULNERABILITY_DETECTED,
                        self._handle_alert_event
                    )
                    self.real_time_monitor.add_event_handler(
                        EventType.COMPLIANCE_VIOLATION,
                        self._handle_alert_event
                    )
                    self.real_time_monitor.add_event_handler(
                        EventType.SYSTEM_ERROR,
                        self._handle_alert_event
                    )
                
                self.logger.info("Alert manager initialized")
            
            # Initialize dashboard generator
            if self.config.enable_dashboards:
                self.dashboard_generator = DashboardGenerator(self.metrics_collector)
                
                # Create default dashboards
                if self.config.auto_create_default_dashboards:
                    self._create_default_dashboards()
                
                self.logger.info("Dashboard generator initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing monitoring system: {e}")
            raise
    
    def _configure_alert_channels(self):
        """Configure alert channels."""
        
        if not self.alert_manager:
            return
        
        for channel_id, channel_config in self.config.alert_channels.items():
            channel_type = channel_config.get('type', '').lower()
            
            try:
                if channel_type == 'email':
                    channel = EmailChannel(channel_id, channel_config)
                elif channel_type == 'slack':
                    channel = SlackChannel(channel_id, channel_config)
                elif channel_type == 'webhook':
                    channel = WebhookChannel(channel_id, channel_config)
                elif channel_type == 'sms':
                    channel = SMSChannel(channel_id, channel_config)
                else:
                    self.logger.warning(f"Unknown alert channel type: {channel_type}")
                    continue
                
                self.alert_manager.add_channel(channel)
                self.logger.info(f"Configured alert channel: {channel_id} ({channel_type})\")
                \n            except Exception as e:\n                self.logger.error(f\"Error configuring alert channel {channel_id}: {e}\")
    \n    def _create_default_dashboards(self):\n        \"\"\"Create default dashboards.\"\"\"\n        \n        if not self.dashboard_generator:\n            return\n        \n        try:\n            # Security overview dashboard\n            self.dashboard_generator.create_dashboard_from_template(\n                'security_overview', \n                'default_security',\n                'Security Overview'\n            )\n            \n            # System monitoring dashboard\n            self.dashboard_generator.create_dashboard_from_template(\n                'system_monitoring',\n                'default_system',\n                'System Monitoring'\n            )\n            \n            # Compliance dashboard\n            self.dashboard_generator.create_dashboard_from_template(\n                'compliance',\n                'default_compliance',\n                'Compliance Status'\n            )\n            \n            self.logger.info(\"Created default dashboards\")
            \n        except Exception as e:\n            self.logger.error(f\"Error creating default dashboards: {e}\")
    \n    def _handle_security_event(self, event: MonitoringEvent):\n        \"\"\"Handle security events for metrics collection.\"\"\"\n        \n        if not self.metrics_collector:\n            return\n        \n        try:\n            # Record security metrics\n            if event.data and 'issue_id' in event.data:\n                self.metrics_collector.record_counter(\n                    f\"security.vulnerabilities.{event.severity.value}\",\n                    tags={\n                        'rule_id': event.data.get('rule_id', 'unknown'),\n                        'category': event.data.get('category', 'unknown')\n                    }\n                )\n            \n            self.system_stats['events_processed'] += 1\n            \n        except Exception as e:\n            self.logger.error(f\"Error handling security event: {e}\")
            self.system_stats['errors'] += 1\n    \n    def _handle_alert_event(self, event: MonitoringEvent):\n        \"\"\"Handle events that should trigger alerts.\"\"\"\n        \n        if not self.alert_manager:\n            return\n        \n        try:\n            # Create alert from event\n            alert = self.alert_manager.create_alert_from_event(\n                event, \n                list(self.config.alert_channels.keys())\n            )\n            \n            # Send alert\n            self.alert_manager.send_alert(alert)\n            \n            self.system_stats['alerts_sent'] += 1\n            \n        except Exception as e:\n            self.logger.error(f\"Error handling alert event: {e}\")
            self.system_stats['errors'] += 1\n    \n    def start(self):\n        \"\"\"Start the monitoring system.\"\"\"\n        \n        if self.is_running:\n            self.logger.warning(\"Monitoring system is already running\")
            return\n        \n        self.logger.info(\"Starting monitoring system\")
        self.is_running = True\n        self.system_stats['start_time'] = datetime.now()\n        \n        try:\n            # Start metrics collector\n            if self.metrics_collector:\n                self.metrics_collector.start_collection()\n            \n            # Start real-time monitor\n            if self.real_time_monitor:\n                self.real_time_monitor.start()\n            \n            # Start alert manager\n            if self.alert_manager:\n                self.alert_manager.start()\n            \n            # Start health check thread\n            self.health_check_thread = threading.Thread(\n                target=self._health_check_loop,\n                name=\"MonitoringHealthCheck\",\n                daemon=True\n            )\n            self.health_check_thread.start()\n            \n            self.logger.info(\"Monitoring system started successfully\")
            \n        except Exception as e:\n            self.logger.error(f\"Error starting monitoring system: {e}\")
            self.stop()\n            raise\n    \n    def stop(self):\n        \"\"\"Stop the monitoring system.\"\"\"\n        \n        if not self.is_running:\n            return\n        \n        self.logger.info(\"Stopping monitoring system\")
        self.is_running = False\n        \n        try:\n            # Stop components\n            if self.alert_manager:\n                self.alert_manager.stop()\n            \n            if self.real_time_monitor:\n                self.real_time_monitor.stop()\n            \n            if self.metrics_collector:\n                self.metrics_collector.stop_collection()\n            \n            # Wait for health check thread\n            if self.health_check_thread and self.health_check_thread.is_alive():\n                self.health_check_thread.join(timeout=5)\n            \n            self.logger.info(\"Monitoring system stopped\")
            \n        except Exception as e:\n            self.logger.error(f\"Error stopping monitoring system: {e}\")
    \n    def _health_check_loop(self):\n        \"\"\"Health check loop for monitoring system components.\"\"\"\n        \n        while self.is_running:\n            try:\n                # Update uptime\n                if self.system_stats['start_time']:\n                    self.system_stats['uptime_seconds'] = (\n                        datetime.now() - self.system_stats['start_time']\n                    ).total_seconds()\n                \n                # Check component health\n                health_status = self.get_health_status()\n                \n                # Log health status if there are issues\n                if not health_status['healthy']:\n                    self.logger.warning(f\"Health check failed: {health_status['issues']}\")
                \n                self.system_stats['health_checks_completed'] += 1\n                \n                # Sleep until next check\n                time.sleep(self.config.health_check_interval)\n                \n            except Exception as e:\n                self.logger.error(f\"Error in health check loop: {e}\")
                self.system_stats['errors'] += 1\n                time.sleep(self.config.health_check_interval)\n    \n    def emit_security_issue(self, issue: SecurityIssue) -> bool:\n        \"\"\"Emit security issue to monitoring system.\"\"\"\n        \n        if not self.real_time_monitor:\n            return False\n        \n        return self.real_time_monitor.emit_security_issue(issue)\n    \n    def emit_event(self, event: MonitoringEvent) -> bool:\n        \"\"\"Emit monitoring event.\"\"\"\n        \n        if not self.real_time_monitor:\n            return False\n        \n        return self.real_time_monitor.emit_event(event)\n    \n    def record_metric(self, metric: Metric):\n        \"\"\"Record metric.\"\"\"\n        \n        if self.metrics_collector:\n            self.metrics_collector.record_metric(metric)\n            self.system_stats['metrics_collected'] += 1\n    \n    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:\n        \"\"\"Get dashboard by ID.\"\"\"\n        \n        if not self.dashboard_generator:\n            return None\n        \n        return self.dashboard_generator.get_dashboard(dashboard_id)\n    \n    def refresh_dashboard(self, dashboard_id: str) -> bool:\n        \"\"\"Refresh dashboard data.\"\"\"\n        \n        if not self.dashboard_generator:\n            return False\n        \n        return self.dashboard_generator.refresh_dashboard(dashboard_id)\n    \n    def get_recent_events(self, limit: int = 100) -> List[MonitoringEvent]:\n        \"\"\"Get recent monitoring events.\"\"\"\n        \n        if not self.real_time_monitor:\n            return []\n        \n        return self.real_time_monitor.get_recent_events(limit=limit)\n    \n    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:\n        \"\"\"Get recent alerts.\"\"\"\n        \n        if not self.alert_manager:\n            return []\n        \n        return self.alert_manager.get_alerts(limit=limit)\n    \n    def get_system_stats(self) -> Dict[str, Any]:\n        \"\"\"Get system statistics.\"\"\"\n        \n        stats = self.system_stats.copy()\n        \n        # Add component stats\n        if self.real_time_monitor:\n            stats['monitoring'] = self.real_time_monitor.get_monitoring_stats()\n        \n        if self.alert_manager:\n            stats['alerting'] = self.alert_manager.get_alert_stats()\n        \n        if self.metrics_collector:\n            stats['metrics'] = self.metrics_collector.get_collection_stats()\n        \n        return stats\n    \n    def get_health_status(self) -> Dict[str, Any]:\n        \"\"\"Get health status of monitoring system.\"\"\"\n        \n        health = {\n            'healthy': True,\n            'issues': [],\n            'components': {}\n        }\n        \n        # Check real-time monitor\n        if self.real_time_monitor:\n            monitor_stats = self.real_time_monitor.get_monitoring_stats()\n            health['components']['real_time_monitor'] = {\n                'running': monitor_stats['is_running'],\n                'queue_size': monitor_stats['queue_size'],\n                'errors': monitor_stats['processing_stats']['errors']\n            }\n            \n            if not monitor_stats['is_running']:\n                health['healthy'] = False\n                health['issues'].append('Real-time monitor not running')\n        \n        # Check alert manager\n        if self.alert_manager:\n            alert_stats = self.alert_manager.get_alert_stats()\n            health['components']['alert_manager'] = {\n                'running': alert_stats['is_running'],\n                'queue_size': alert_stats['queue_size'],\n                'channels': alert_stats['channels_configured']\n            }\n            \n            if not alert_stats['is_running']:\n                health['healthy'] = False\n                health['issues'].append('Alert manager not running')\n        \n        # Check metrics collector\n        if self.metrics_collector:\n            metrics_stats = self.metrics_collector.get_collection_stats()\n            health['components']['metrics_collector'] = {\n                'running': metrics_stats['is_running'],\n                'metrics_stored': metrics_stats['metrics_stored'],\n                'errors': metrics_stats['collection_stats']['collections_failed']\n            }\n            \n            if not metrics_stats['is_running']:\n                health['healthy'] = False\n                health['issues'].append('Metrics collector not running')\n        \n        # Check dashboard generator\n        if self.dashboard_generator:\n            dashboards = self.dashboard_generator.list_dashboards()\n            health['components']['dashboard_generator'] = {\n                'dashboards_count': len(dashboards)\n            }\n        \n        return health\n    \n    def create_dashboard(self, dashboard_id: str, title: str, description: str = \"\") -> Optional[Dashboard]:\n        \"\"\"Create new dashboard.\"\"\"\n        \n        if not self.dashboard_generator:\n            return None\n        \n        return self.dashboard_generator.create_dashboard(dashboard_id, title, description)\n    \n    def export_dashboard(self, dashboard_id: str, format_type: str = 'json') -> Optional[str]:\n        \"\"\"Export dashboard.\"\"\"\n        \n        if not self.dashboard_generator:\n            return None\n        \n        return self.dashboard_generator.export_dashboard(dashboard_id, format_type)\n    \n    def acknowledge_alert(self, alert_id: str) -> bool:\n        \"\"\"Acknowledge alert.\"\"\"\n        \n        if not self.alert_manager:\n            return False\n        \n        return self.alert_manager.acknowledge_alert(alert_id)\n    \n    def resolve_alert(self, alert_id: str) -> bool:\n        \"\"\"Resolve alert.\"\"\"\n        \n        if not self.alert_manager:\n            return False\n        \n        return self.alert_manager.resolve_alert(alert_id)\n\n\n# Utility functions\n\ndef create_monitoring_system(config: Optional[MonitoringSystemConfig] = None) -> MonitoringSystem:\n    \"\"\"Create monitoring system instance.\"\"\"\n    return MonitoringSystem(config)\n\n\ndef create_default_monitoring_config() -> MonitoringSystemConfig:\n    \"\"\"Create default monitoring configuration.\"\"\"\n    return MonitoringSystemConfig(\n        enable_real_time_monitoring=True,\n        enable_metrics_collection=True,\n        enable_alerting=True,\n        enable_dashboards=True,\n        auto_create_default_dashboards=True,\n        metrics_collection_interval=60,\n        health_check_interval=300,\n        log_level=\"INFO\"\n    )\n\n\ndef create_email_alert_config(smtp_server: str, username: str, password: str, \n                             from_email: str, to_emails: List[str]) -> Dict[str, Any]:\n    \"\"\"Create email alert channel configuration.\"\"\"\n    return {\n        'type': 'email',\n        'smtp_server': smtp_server,\n        'username': username,\n        'password': password,\n        'from_email': from_email,\n        'to_emails': to_emails,\n        'enabled': True\n    }\n\n\ndef create_slack_alert_config(webhook_url: str, channel: str = '#alerts') -> Dict[str, Any]:\n    \"\"\"Create Slack alert channel configuration.\"\"\"\n    return {\n        'type': 'slack',\n        'webhook_url': webhook_url,\n        'channel': channel,\n        'enabled': True\n    }\n\n\ndef create_webhook_alert_config(webhook_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:\n    \"\"\"Create webhook alert channel configuration.\"\"\"\n    return {\n        'type': 'webhook',\n        'webhook_url': webhook_url,\n        'headers': headers or {'Content-Type': 'application/json'},\n        'enabled': True\n    }"