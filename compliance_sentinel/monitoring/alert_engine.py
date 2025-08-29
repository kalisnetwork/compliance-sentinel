"""Multi-channel alert engine for security notifications."""

import json
import smtplib
import requests
from typing import List, Dict, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
import asyncio
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from email.mime.text import MIMEText as MimeText
    from email.mime.multipart import MIMEMultipart as MimeMultipart
except ImportError:
    # Fallback for different Python versions
    MimeText = None
    MimeMultipart = None

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class AlertChannel(Enum):
    """Supported alert channels."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    TEAMS = "teams"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class AlertRule:
    """Configuration for alert routing and escalation."""
    id: str
    name: str
    severity_threshold: AlertSeverity
    channels: List[AlertChannel]
    escalation_delay: timedelta
    escalation_channels: List[AlertChannel]
    conditions: Dict[str, Any]
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class Alert:
    """Security alert with routing information."""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    timestamp: datetime
    metadata: Dict[str, Any]
    channels: List[AlertChannel]
    escalated: bool = False
    acknowledged: bool = False
    resolved: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
            'channels': [c.value for c in self.channels],
            'escalated': self.escalated,
            'acknowledged': self.acknowledged,
            'resolved': self.resolved
        }


@dataclass
class ChannelConfig:
    """Configuration for alert channels."""
    channel: AlertChannel
    config: Dict[str, Any]
    enabled: bool = True
    rate_limit: Optional[int] = None  # Max alerts per hour
    
    @classmethod
    def email_config(cls, smtp_host: str, smtp_port: int, username: str, 
                    password: str, from_email: str, to_emails: List[str]) -> 'ChannelConfig':
        """Create email channel configuration."""
        return cls(
            channel=AlertChannel.EMAIL,
            config={
                'smtp_host': smtp_host,
                'smtp_port': smtp_port,
                'username': username,
                'password': password,
                'from_email': from_email,
                'to_emails': to_emails,
                'use_tls': True
            }
        )
    
    @classmethod
    def slack_config(cls, webhook_url: str, channel: str = None) -> 'ChannelConfig':
        """Create Slack channel configuration."""
        return cls(
            channel=AlertChannel.SLACK,
            config={
                'webhook_url': webhook_url,
                'channel': channel,
                'username': 'Compliance Sentinel',
                'icon_emoji': ':warning:'
            }
        )
    
    @classmethod
    def webhook_config(cls, url: str, headers: Dict[str, str] = None) -> 'ChannelConfig':
        """Create webhook channel configuration."""
        return cls(
            channel=AlertChannel.WEBHOOK,
            config={
                'url': url,
                'headers': headers or {},
                'method': 'POST',
                'timeout': 30
            }
        )


class AlertEngine:
    """Multi-channel alert engine with escalation and rate limiting."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize alert engine."""
        self.logger = logging.getLogger(f"{__name__}.alert_engine")
        self.channels: Dict[AlertChannel, ChannelConfig] = {}
        self.rules: List[AlertRule] = []
        self.alert_history: List[Alert] = []
        self.rate_limits: Dict[AlertChannel, List[datetime]] = {}
        
        if config_path:
            self.load_config(config_path)
    
    def add_channel(self, channel_config: ChannelConfig) -> None:
        """Add alert channel configuration."""
        self.channels[channel_config.channel] = channel_config
        self.rate_limits[channel_config.channel] = []
        self.logger.info(f"Added alert channel: {channel_config.channel.value}")
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add alert routing rule."""
        self.rules.append(rule)
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def load_config(self, config_path: str) -> None:
        """Load configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Load channels
            for channel_data in config.get('channels', []):
                channel_type = AlertChannel(channel_data['type'])
                channel_config = ChannelConfig(
                    channel=channel_type,
                    config=channel_data['config'],
                    enabled=channel_data.get('enabled', True),
                    rate_limit=channel_data.get('rate_limit')
                )
                self.add_channel(channel_config)
            
            # Load rules
            for rule_data in config.get('rules', []):
                rule = AlertRule(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    severity_threshold=AlertSeverity(rule_data['severity_threshold']),
                    channels=[AlertChannel(c) for c in rule_data['channels']],
                    escalation_delay=timedelta(minutes=rule_data.get('escalation_delay_minutes', 30)),
                    escalation_channels=[AlertChannel(c) for c in rule_data.get('escalation_channels', [])],
                    conditions=rule_data.get('conditions', {}),
                    enabled=rule_data.get('enabled', True)
                )
                self.add_rule(rule)
            
            self.logger.info(f"Loaded configuration from {config_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_path}: {e}")
    
    def create_alert_from_security_issue(self, issue: SecurityIssue) -> Alert:
        """Create alert from security issue."""
        # Map security severity to alert severity
        severity_map = {
            Severity.LOW: AlertSeverity.LOW,
            Severity.MEDIUM: AlertSeverity.MEDIUM,
            Severity.HIGH: AlertSeverity.HIGH,
            Severity.CRITICAL: AlertSeverity.CRITICAL
        }
        
        alert = Alert(
            id=f"alert_{issue.id}_{int(datetime.now().timestamp())}",
            title=f"Security Issue: {issue.category.value}",
            description=issue.description,
            severity=severity_map.get(issue.severity, AlertSeverity.MEDIUM),
            source=f"file:{issue.file_path}:{issue.line_number}",
            timestamp=datetime.now(),
            metadata={
                'issue_id': issue.id,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'rule_id': issue.rule_id,
                'confidence': issue.confidence,
                'category': issue.category.value,
                'remediation_suggestions': issue.remediation_suggestions
            },
            channels=self._determine_channels(severity_map.get(issue.severity, AlertSeverity.MEDIUM))
        )
        
        return alert
    
    def _determine_channels(self, severity: AlertSeverity) -> List[AlertChannel]:
        """Determine which channels to use based on severity and rules."""
        channels = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check severity threshold
            severity_levels = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, 
                             AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
            
            if severity_levels.index(severity) >= severity_levels.index(rule.severity_threshold):
                channels.extend(rule.channels)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_channels = []
        for channel in channels:
            if channel not in seen:
                seen.add(channel)
                unique_channels.append(channel)
        
        return unique_channels
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert through configured channels."""
        success = True
        
        for channel in alert.channels:
            if channel not in self.channels:
                self.logger.warning(f"Channel {channel.value} not configured")
                continue
            
            channel_config = self.channels[channel]
            if not channel_config.enabled:
                continue
            
            # Check rate limits
            if not self._check_rate_limit(channel, channel_config.rate_limit):
                self.logger.warning(f"Rate limit exceeded for channel {channel.value}")
                continue
            
            try:
                if channel == AlertChannel.EMAIL:
                    await self._send_email_alert(alert, channel_config)
                elif channel == AlertChannel.SLACK:
                    await self._send_slack_alert(alert, channel_config)
                elif channel == AlertChannel.WEBHOOK:
                    await self._send_webhook_alert(alert, channel_config)
                elif channel == AlertChannel.SMS:
                    await self._send_sms_alert(alert, channel_config)
                elif channel == AlertChannel.TEAMS:
                    await self._send_teams_alert(alert, channel_config)
                
                self._record_rate_limit(channel)
                self.logger.info(f"Alert {alert.id} sent via {channel.value}")
            
            except Exception as e:
                self.logger.error(f"Failed to send alert via {channel.value}: {e}")
                success = False
        
        # Store alert in history
        self.alert_history.append(alert)
        
        return success
    
    def _check_rate_limit(self, channel: AlertChannel, rate_limit: Optional[int]) -> bool:
        """Check if channel is within rate limits."""
        if rate_limit is None:
            return True
        
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        # Clean old entries
        self.rate_limits[channel] = [
            timestamp for timestamp in self.rate_limits[channel]
            if timestamp > hour_ago
        ]
        
        return len(self.rate_limits[channel]) < rate_limit
    
    def _record_rate_limit(self, channel: AlertChannel) -> None:
        """Record alert for rate limiting."""
        self.rate_limits[channel].append(datetime.now())
    
    async def _send_email_alert(self, alert: Alert, config: ChannelConfig) -> None:
        """Send alert via email."""
        if not MimeText or not MimeMultipart:
            raise Exception("Email functionality not available - missing email libraries")
        
        smtp_config = config.config
        
        # Create message
        msg = MimeMultipart()
        msg['From'] = smtp_config['from_email']
        msg['To'] = ', '.join(smtp_config['to_emails'])
        msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
        
        # Create HTML body
        html_body = f"""
        <html>
        <body>
            <h2>Security Alert</h2>
            <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
            <p><strong>Source:</strong> {alert.source}</p>
            <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Description:</strong></p>
            <p>{alert.description}</p>
            
            <h3>Metadata</h3>
            <ul>
        """
        
        for key, value in alert.metadata.items():
            html_body += f"<li><strong>{key}:</strong> {value}</li>"
        
        html_body += """
            </ul>
        </body>
        </html>
        """
        
        msg.attach(MimeText(html_body, 'html'))
        
        # Send email
        with smtplib.SMTP(smtp_config['smtp_host'], smtp_config['smtp_port']) as server:
            if smtp_config.get('use_tls', True):
                server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            server.send_message(msg)
    
    async def _send_slack_alert(self, alert: Alert, config: ChannelConfig) -> None:
        """Send alert via Slack webhook."""
        slack_config = config.config
        
        # Create Slack message
        color_map = {
            AlertSeverity.LOW: "#36a64f",      # Green
            AlertSeverity.MEDIUM: "#ff9500",   # Orange
            AlertSeverity.HIGH: "#ff0000",     # Red
            AlertSeverity.CRITICAL: "#8B0000", # Dark Red
            AlertSeverity.EMERGENCY: "#4B0082" # Indigo
        }
        
        payload = {
            "username": slack_config.get('username', 'Compliance Sentinel'),
            "icon_emoji": slack_config.get('icon_emoji', ':warning:'),
            "attachments": [{
                "color": color_map.get(alert.severity, "#ff9500"),
                "title": alert.title,
                "text": alert.description,
                "fields": [
                    {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                    {"title": "Source", "value": alert.source, "short": True},
                    {"title": "Time", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), "short": True}
                ],
                "footer": "Compliance Sentinel",
                "ts": int(alert.timestamp.timestamp())
            }]
        }
        
        if slack_config.get('channel'):
            payload['channel'] = slack_config['channel']
        
        if aiohttp:
            async with aiohttp.ClientSession() as session:
                async with session.post(slack_config['webhook_url'], json=payload) as response:
                    if response.status != 200:
                        raise Exception(f"Slack webhook returned status {response.status}")
        else:
            # Fallback to requests for synchronous operation
            import requests
            response = requests.post(slack_config['webhook_url'], json=payload)
            if response.status_code != 200:
                raise Exception(f"Slack webhook returned status {response.status_code}")
    
    async def _send_webhook_alert(self, alert: Alert, config: ChannelConfig) -> None:
        """Send alert via generic webhook."""
        webhook_config = config.config
        
        payload = alert.to_dict()
        headers = webhook_config.get('headers', {})
        headers.setdefault('Content-Type', 'application/json')
        
        if aiohttp:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=webhook_config.get('method', 'POST'),
                    url=webhook_config['url'],
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=webhook_config.get('timeout', 30))
                ) as response:
                    if response.status >= 400:
                        raise Exception(f"Webhook returned status {response.status}")
        else:
            # Fallback to requests
            import requests
            response = requests.request(
                method=webhook_config.get('method', 'POST'),
                url=webhook_config['url'],
                json=payload,
                headers=headers,
                timeout=webhook_config.get('timeout', 30)
            )
            if response.status_code >= 400:
                raise Exception(f"Webhook returned status {response.status_code}")
    
    async def _send_sms_alert(self, alert: Alert, config: ChannelConfig) -> None:
        """Send alert via SMS (placeholder - requires SMS service integration)."""
        # This would integrate with services like Twilio, AWS SNS, etc.
        self.logger.info(f"SMS alert would be sent: {alert.title}")
    
    async def _send_teams_alert(self, alert: Alert, config: ChannelConfig) -> None:
        """Send alert via Microsoft Teams webhook."""
        teams_config = config.config
        
        # Create Teams message card
        color_map = {
            AlertSeverity.LOW: "00FF00",      # Green
            AlertSeverity.MEDIUM: "FFA500",   # Orange
            AlertSeverity.HIGH: "FF0000",     # Red
            AlertSeverity.CRITICAL: "8B0000", # Dark Red
            AlertSeverity.EMERGENCY: "4B0082" # Indigo
        }
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(alert.severity, "FFA500"),
            "summary": alert.title,
            "sections": [{
                "activityTitle": alert.title,
                "activitySubtitle": f"Severity: {alert.severity.value.upper()}",
                "text": alert.description,
                "facts": [
                    {"name": "Source", "value": alert.source},
                    {"name": "Time", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')},
                    {"name": "Alert ID", "value": alert.id}
                ]
            }]
        }
        
        if aiohttp:
            async with aiohttp.ClientSession() as session:
                async with session.post(teams_config['webhook_url'], json=payload) as response:
                    if response.status != 200:
                        raise Exception(f"Teams webhook returned status {response.status}")
        else:
            # Fallback to requests
            import requests
            response = requests.post(teams_config['webhook_url'], json=payload)
            if response.status_code != 200:
                raise Exception(f"Teams webhook returned status {response.status_code}")
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        for alert in self.alert_history:
            if alert.id == alert_id:
                alert.acknowledged = True
                alert.metadata['acknowledged_by'] = user
                alert.metadata['acknowledged_at'] = datetime.now().isoformat()
                self.logger.info(f"Alert {alert_id} acknowledged by {user}")
                return True
        return False
    
    def resolve_alert(self, alert_id: str, user: str, resolution: str) -> bool:
        """Resolve an alert."""
        for alert in self.alert_history:
            if alert.id == alert_id:
                alert.resolved = True
                alert.metadata['resolved_by'] = user
                alert.metadata['resolved_at'] = datetime.now().isoformat()
                alert.metadata['resolution'] = resolution
                self.logger.info(f"Alert {alert_id} resolved by {user}")
                return True
        return False
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        return [alert for alert in self.alert_history if not alert.resolved]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        total_alerts = len(self.alert_history)
        active_alerts = len(self.get_active_alerts())
        
        severity_counts = {}
        for severity in AlertSeverity:
            severity_counts[severity.value] = sum(
                1 for alert in self.alert_history 
                if alert.severity == severity
            )
        
        return {
            'total_alerts': total_alerts,
            'active_alerts': active_alerts,
            'resolved_alerts': total_alerts - active_alerts,
            'severity_breakdown': severity_counts,
            'channels_configured': len(self.channels),
            'rules_configured': len(self.rules)
        }


# Global alert engine instance
_global_alert_engine: Optional[AlertEngine] = None


def get_alert_engine() -> AlertEngine:
    """Get global alert engine instance."""
    global _global_alert_engine
    if _global_alert_engine is None:
        _global_alert_engine = AlertEngine()
    return _global_alert_engine


def reset_alert_engine() -> None:
    """Reset global alert engine (for testing)."""
    global _global_alert_engine
    _global_alert_engine = None