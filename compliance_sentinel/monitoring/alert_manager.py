"""Alert management system with multiple notification channels."""

import asyncio
import logging
import json
import smtplib
import requests
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from abc import ABC, abstractmethod
import threading
import queue

from compliance_sentinel.monitoring.real_time_monitor import MonitoringEvent, EventSeverity


logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """Represents an alert to be sent."""
    
    alert_id: str
    title: str
    message: str
    severity: AlertSeverity
    
    # Alert details
    source_event: Optional[MonitoringEvent] = None
    channels: List[str] = field(default_factory=list)
    
    # Status tracking
    status: AlertStatus = AlertStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    sent_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Retry logic
    retry_count: int = 0
    max_retries: int = 3
    
    # Additional data
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'message': self.message,
            'severity': self.severity.value,
            'channels': self.channels,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'metadata': self.metadata
        }


class AlertChannel(ABC):
    """Abstract base class for alert channels."""
    
    def __init__(self, channel_id: str, name: str, config: Dict[str, Any]):
        """Initialize alert channel."""
        self.channel_id = channel_id
        self.name = name
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', True)
    
    @abstractmethod
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert through this channel."""
        pass
    
    def is_enabled(self) -> bool:
        """Check if channel is enabled."""
        return self.enabled
    
    def supports_severity(self, severity: AlertSeverity) -> bool:
        """Check if channel supports the given severity level."""
        min_severity = self.config.get('min_severity', 'info')
        
        severity_levels = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        
        return severity_levels.get(severity.value, 1) >= severity_levels.get(min_severity, 1)


class EmailChannel(AlertChannel):
    """Email alert channel."""
    
    def __init__(self, channel_id: str, config: Dict[str, Any]):
        """Initialize email channel."""
        super().__init__(channel_id, "Email", config)
        
        # Email configuration
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_email = config.get('from_email', 'alerts@compliance-sentinel.com')
        self.to_emails = config.get('to_emails', [])
        self.use_tls = config.get('use_tls', True)
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert via email."""
        
        if not self.to_emails:
            self.logger.error("No recipient emails configured")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {alert.alert_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert {alert.alert_id}: {e}")
            return False
    
    def _create_email_body(self, alert: Alert) -> str:
        """Create HTML email body."""
        
        severity_colors = {
            AlertSeverity.CRITICAL: '#dc3545',
            AlertSeverity.HIGH: '#fd7e14',
            AlertSeverity.MEDIUM: '#ffc107',
            AlertSeverity.LOW: '#6c757d',
            AlertSeverity.INFO: '#17a2b8'
        }
        
        color = severity_colors.get(alert.severity, '#6c757d')
        
        html = f"""
        <html>
        <body>
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background-color: {color}; color: white; padding: 20px; text-align: center;">
                    <h1 style="margin: 0;">{alert.severity.value.upper()} ALERT</h1>
                </div>
                
                <div style="padding: 20px; border: 1px solid #ddd;">
                    <h2 style="color: {color}; margin-top: 0;">{alert.title}</h2>
                    
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <p style="margin: 0; white-space: pre-wrap;">{alert.message}</p>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Alert ID:</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{alert.alert_id}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Severity:</td>
                            <td style="padding: 8px; border: 1px solid #ddd; color: {color}; font-weight: bold;">{alert.severity.value.upper()}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Created:</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d;">
                    <p>This alert was generated by Compliance Sentinel</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html


class SlackChannel(AlertChannel):
    """Slack alert channel."""
    
    def __init__(self, channel_id: str, config: Dict[str, Any]):
        """Initialize Slack channel."""
        super().__init__(channel_id, "Slack", config)
        
        self.webhook_url = config.get('webhook_url')
        self.channel = config.get('channel', '#alerts')
        self.username = config.get('username', 'Compliance Sentinel')
        self.icon_emoji = config.get('icon_emoji', ':warning:')
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to Slack."""
        
        if not self.webhook_url:
            self.logger.error("No Slack webhook URL configured")
            return False
        
        try:
            # Create Slack message
            payload = self._create_slack_payload(alert)
            
            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info(f"Slack alert sent: {alert.alert_id}")
                return True
            else:
                self.logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert {alert.alert_id}: {e}")
            return False
    
    def _create_slack_payload(self, alert: Alert) -> Dict[str, Any]:
        """Create Slack message payload."""
        
        # Severity colors for Slack
        severity_colors = {
            AlertSeverity.CRITICAL: 'danger',
            AlertSeverity.HIGH: 'warning',
            AlertSeverity.MEDIUM: 'warning',
            AlertSeverity.LOW: 'good',
            AlertSeverity.INFO: 'good'
        }
        
        color = severity_colors.get(alert.severity, 'good')
        
        # Create attachment
        attachment = {
            'color': color,
            'title': alert.title,
            'text': alert.message,
            'fields': [
                {
                    'title': 'Severity',
                    'value': alert.severity.value.upper(),
                    'short': True
                },
                {
                    'title': 'Alert ID',
                    'value': alert.alert_id,
                    'short': True
                },
                {
                    'title': 'Created',
                    'value': alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'short': True
                }
            ],
            'footer': 'Compliance Sentinel',
            'ts': int(alert.created_at.timestamp())
        }
        
        return {
            'channel': self.channel,
            'username': self.username,
            'icon_emoji': self.icon_emoji,
            'attachments': [attachment]
        }


class AlertManager:
    """Main alert management system."""
    
    def __init__(self):
        """Initialize alert manager."""
        self.logger = logging.getLogger(__name__)
        
        # Alert channels
        self.channels = {}
        
        # Alert queue and processing
        self.alert_queue = queue.Queue()
        self.alert_history = []
        self.max_history_size = 1000
        
        # Processing state
        self.is_running = False
        self.worker_thread = None
        
        # Statistics
        self.stats = {
            'alerts_sent': 0,
            'alerts_failed': 0,
            'channels_configured': 0
        }
    
    def add_channel(self, channel: AlertChannel):
        """Add alert channel."""
        self.channels[channel.channel_id] = channel
        self.stats['channels_configured'] = len(self.channels)
        self.logger.info(f"Added alert channel: {channel.channel_id} ({channel.name})")
    
    def send_alert(self, alert: Alert) -> bool:
        """Queue alert for sending."""
        
        try:
            self.alert_queue.put_nowait(alert)
            return True
            
        except queue.Full:
            self.logger.error(f"Alert queue full, dropping alert: {alert.alert_id}")
            return False
    
    def start(self):
        """Start alert processing."""
        
        if self.is_running:
            self.logger.warning("Alert manager is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting alert manager")
        
        # Start worker thread
        self.worker_thread = threading.Thread(
            target=self._worker_thread,
            name="AlertWorker",
            daemon=True
        )
        self.worker_thread.start()
    
    def stop(self):
        """Stop alert processing."""
        
        if not self.is_running:
            return
        
        self.logger.info("Stopping alert manager")
        self.is_running = False
        
        # Wait for worker thread
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
    
    def _worker_thread(self):
        """Worker thread for processing alerts."""
        
        while self.is_running:
            try:
                # Get alert from queue
                alert = self.alert_queue.get(timeout=1)
                
                # Process alert
                asyncio.run(self._process_alert(alert))
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in alert worker thread: {e}")
    
    async def _process_alert(self, alert: Alert):
        """Process individual alert."""
        
        try:
            # Add to history
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_history_size:
                self.alert_history.pop(0)
            
            # Send to configured channels
            success_count = 0
            
            for channel_id in alert.channels:
                if channel_id in self.channels:
                    channel = self.channels[channel_id]
                    
                    # Check if channel is enabled and supports severity
                    if channel.is_enabled() and channel.supports_severity(alert.severity):
                        try:
                            success = await channel.send_alert(alert)
                            if success:
                                success_count += 1
                        except Exception as e:
                            self.logger.error(f"Error sending alert via {channel_id}: {e}")
                else:
                    self.logger.warning(f"Alert channel not found: {channel_id}")
            
            # Update alert status
            if success_count > 0:
                alert.status = AlertStatus.SENT
                alert.sent_at = datetime.now()
                self.stats['alerts_sent'] += 1
            else:
                alert.status = AlertStatus.FAILED
                self.stats['alerts_failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Error processing alert {alert.alert_id}: {e}")
            alert.status = AlertStatus.FAILED
            self.stats['alerts_failed'] += 1
    
    def get_alerts(self, 
                   status: Optional[AlertStatus] = None,
                   severity: Optional[AlertSeverity] = None,
                   limit: int = 100) -> List[Alert]:
        """Get alerts with filtering."""
        
        alerts = self.alert_history.copy()
        
        # Apply filters
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        # Sort by creation time (newest first) and limit
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        
        # Count alerts by status\n        status_counts = {}\n        for status in AlertStatus:\n            status_counts[status.value] = len([a for a in self.alert_history if a.status == status])\n        \n        # Count alerts by severity\n        severity_counts = {}\n        for severity in AlertSeverity:\n            severity_counts[severity.value] = len([a for a in self.alert_history if a.severity == severity])\n        \n        return {\n            'total_alerts': len(self.alert_history),\n            'queue_size': self.alert_queue.qsize(),\n            'channels_configured': len(self.channels),\n            'is_running': self.is_running,\n            'status_counts': status_counts,\n            'severity_counts': severity_counts,\n            'stats': self.stats.copy()\n        }\n\n\n# Utility functions\n\ndef create_email_channel(channel_id: str, config: Dict[str, Any]) -> EmailChannel:\n    \"\"\"Create email alert channel.\"\"\"\n    return EmailChannel(channel_id, config)\n\n\ndef create_slack_channel(channel_id: str, config: Dict[str, Any]) -> SlackChannel:\n    \"\"\"Create Slack alert channel.\"\"\"\n    return SlackChannel(channel_id, config)\n\n\ndef create_webhook_channel(channel_id: str, config: Dict[str, Any]) -> WebhookChannel:\n    \"\"\"Create webhook alert channel.\"\"\"\n    return WebhookChannel(channel_id, config)\n\n\ndef create_sms_channel(channel_id: str, config: Dict[str, Any]) -> SMSChannel:\n    \"\"\"Create SMS alert channel.\"\"\"\n    return SMSChannel(channel_id, config)\n