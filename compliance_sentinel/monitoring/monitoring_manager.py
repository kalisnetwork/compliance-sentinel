"""Unified monitoring manager for security event correlation and analysis."""

from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import logging
import asyncio

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class MonitoringPlatform(Enum):
    """Supported monitoring platforms."""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    DATADOG = "datadog"
    NEWRELIC = "newrelic"


class EventType(Enum):
    """Security event types."""
    STATIC_ANALYSIS = "static_analysis"
    RUNTIME_DETECTION = "runtime_detection"
    NETWORK_ANOMALY = "network_anomaly"
    ACCESS_VIOLATION = "access_violation"
    MALWARE_DETECTION = "malware_detection"
    DATA_EXFILTRATION = "data_exfiltration"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class MonitoringConfig:
    """Configuration for monitoring integrations."""
    
    # Platform settings
    platform: MonitoringPlatform
    enabled: bool = True
    
    # Connection settings
    host: str = ""
    port: int = 443
    username: str = ""
    password: str = ""
    api_key: str = ""
    api_token: str = ""
    
    # SSL/TLS settings
    use_ssl: bool = True
    verify_ssl: bool = True
    ca_cert_path: str = ""
    
    # Index/Database settings
    index_name: str = "compliance_sentinel"
    database_name: str = "security_events"
    
    # Query settings
    query_timeout: int = 30
    max_results: int = 1000
    
    # Event correlation settings
    correlation_window_minutes: int = 60
    correlation_threshold: float = 0.7
    
    # Alerting settings
    alert_on_correlation: bool = True
    alert_threshold: int = 5
    
    # Custom fields
    custom_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvent:
    """Represents a security event from monitoring systems."""
    
    # Event identification
    event_id: str
    source_platform: MonitoringPlatform
    event_type: EventType
    
    # Event details
    title: str
    description: str
    severity: Severity
    category: SecurityCategory
    
    # Timing
    timestamp: datetime
    detection_time: datetime = field(default_factory=datetime.now)
    
    # Source information
    source_ip: str = ""
    destination_ip: str = ""
    hostname: str = ""
    user_agent: str = ""
    user_id: str = ""
    
    # Technical details
    file_path: str = ""
    process_name: str = ""
    command_line: str = ""
    network_protocol: str = ""
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Correlation
    correlation_id: str = ""
    related_events: List[str] = field(default_factory=list)
    
    # Analysis
    confidence_score: float = 0.0
    risk_score: float = 0.0
    false_positive_probability: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'event_id': self.event_id,
            'source_platform': self.source_platform.value,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'detection_time': self.detection_time.isoformat(),
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category.value,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'hostname': self.hostname,
            'user_agent': self.user_agent,
            'user_id': self.user_id,
            'file_path': self.file_path,
            'process_name': self.process_name,
            'command_line': self.command_line,
            'network_protocol': self.network_protocol,
            'tags': self.tags,
            'raw_data': self.raw_data,
            'correlation_id': self.correlation_id,
            'related_events': self.related_events,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'false_positive_probability': self.false_positive_probability
        }


class MonitoringManager:
    """Unified monitoring manager for security event correlation."""
    
    def __init__(self, configs: List[MonitoringConfig]):
        """Initialize monitoring manager with platform configurations."""
        self.configs = {config.platform: config for config in configs if config.enabled}
        self.integrations = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize platform integrations
        self._initialize_integrations()
        
        # Initialize event correlator
        from .event_correlator import SecurityEventCorrelator
        self.correlator = SecurityEventCorrelator()
    
    def _initialize_integrations(self):
        """Initialize platform-specific integrations."""
        for platform, config in self.configs.items():
            try:
                if platform == MonitoringPlatform.SPLUNK:
                    from .splunk_integration import SplunkIntegration
                    self.integrations[platform] = SplunkIntegration(config)
                elif platform == MonitoringPlatform.ELASTICSEARCH:
                    from .elasticsearch_integration import ElasticsearchIntegration
                    self.integrations[platform] = ElasticsearchIntegration(config)
                elif platform == MonitoringPlatform.DATADOG:
                    from .datadog_integration import DatadogIntegration
                    self.integrations[platform] = DatadogIntegration(config)
                elif platform == MonitoringPlatform.NEWRELIC:
                    from .newrelic_integration import NewRelicIntegration
                    self.integrations[platform] = NewRelicIntegration(config)
                else:
                    self.logger.warning(f"Unknown monitoring platform: {platform}")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize {platform.value} integration: {e}")
    
    async def send_security_event(self, event: SecurityEvent) -> Dict[str, bool]:
        """Send security event to all configured monitoring platforms."""
        results = {}
        
        tasks = []
        for platform, integration in self.integrations.items():
            task = asyncio.create_task(
                self._send_event_to_platform(integration, event, platform)
            )
            tasks.append((platform, task))
        
        # Wait for all tasks to complete
        for platform, task in tasks:
            try:
                success = await task
                results[platform.value] = success
            except Exception as e:
                self.logger.error(f"Failed to send event to {platform.value}: {e}")
                results[platform.value] = False
        
        return results
    
    async def _send_event_to_platform(self, integration, event: SecurityEvent, platform: MonitoringPlatform) -> bool:
        """Send event to specific platform."""
        try:
            return await integration.send_event(event)
        except Exception as e:
            self.logger.error(f"Error sending event to {platform.value}: {e}")
            return False
    
    async def query_events(self, 
                          query: str,
                          start_time: datetime,
                          end_time: datetime,
                          platforms: Optional[List[MonitoringPlatform]] = None) -> Dict[str, List[SecurityEvent]]:
        """Query security events from monitoring platforms."""
        
        if platforms is None:
            platforms = list(self.integrations.keys())
        
        results = {}
        tasks = []
        
        for platform in platforms:
            if platform in self.integrations:
                integration = self.integrations[platform]
                task = asyncio.create_task(
                    integration.query_events(query, start_time, end_time)
                )
                tasks.append((platform, task))
        
        # Wait for all queries to complete
        for platform, task in tasks:
            try:
                events = await task
                results[platform.value] = events
            except Exception as e:
                self.logger.error(f"Failed to query events from {platform.value}: {e}")
                results[platform.value] = []
        
        return results
    
    async def correlate_events(self, 
                              events: List[SecurityEvent],
                              correlation_window: timedelta = None) -> List[List[SecurityEvent]]:
        """Correlate security events across platforms."""
        
        if correlation_window is None:
            correlation_window = timedelta(minutes=60)
        
        return await self.correlator.correlate_events(events, correlation_window)
    
    async def analyze_security_trends(self, 
                                    days: int = 7) -> Dict[str, Any]:
        """Analyze security trends across all platforms."""
        
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        # Query events from all platforms
        all_events = []
        for platform, integration in self.integrations.items():
            try:
                events = await integration.query_events("*", start_time, end_time)
                all_events.extend(events)
            except Exception as e:
                self.logger.error(f"Failed to get events from {platform.value}: {e}")
        
        # Analyze trends
        trends = self._analyze_event_trends(all_events, days)
        
        return trends
    
    def _analyze_event_trends(self, events: List[SecurityEvent], days: int) -> Dict[str, Any]:
        """Analyze trends in security events."""
        
        if not events:
            return {
                'total_events': 0,
                'daily_counts': {},
                'severity_distribution': {},
                'category_distribution': {},
                'top_sources': {},
                'trend_analysis': {}
            }
        
        # Count events by day
        daily_counts = {}
        severity_counts = {severity.value: 0 for severity in Severity}
        category_counts = {}
        source_counts = {}
        
        for event in events:
            # Daily counts
            day_key = event.timestamp.date().isoformat()
            daily_counts[day_key] = daily_counts.get(day_key, 0) + 1
            
            # Severity distribution
            severity_counts[event.severity.value] += 1
            
            # Category distribution
            category_key = event.category.value
            category_counts[category_key] = category_counts.get(category_key, 0) + 1
            
            # Source distribution
            source_key = event.source_ip or event.hostname or "unknown"
            source_counts[source_key] = source_counts.get(source_key, 0) + 1
        
        # Calculate trends
        daily_values = list(daily_counts.values())
        if len(daily_values) > 1:
            trend_direction = "increasing" if daily_values[-1] > daily_values[0] else "decreasing"
            avg_daily = sum(daily_values) / len(daily_values)
        else:
            trend_direction = "stable"
            avg_daily = daily_values[0] if daily_values else 0
        
        # Top sources
        top_sources = dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        return {
            'total_events': len(events),
            'daily_counts': daily_counts,
            'severity_distribution': severity_counts,
            'category_distribution': category_counts,
            'top_sources': top_sources,
            'trend_analysis': {
                'direction': trend_direction,
                'avg_daily_events': avg_daily,
                'peak_day': max(daily_counts.items(), key=lambda x: x[1]) if daily_counts else None
            }
        }
    
    async def create_security_dashboard(self) -> Dict[str, Any]:
        """Create comprehensive security dashboard data."""
        
        # Get recent events (last 24 hours)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        dashboard_data = {
            'timestamp': end_time.isoformat(),
            'platforms': {},
            'summary': {
                'total_events': 0,
                'critical_events': 0,
                'high_events': 0,
                'active_correlations': 0
            },
            'alerts': [],
            'trends': {}
        }
        
        # Collect data from each platform
        all_events = []
        
        for platform, integration in self.integrations.items():
            try:
                # Get platform status
                status = await integration.get_platform_status()
                
                # Get recent events
                events = await integration.query_events("*", start_time, end_time)
                all_events.extend(events)
                
                # Platform-specific metrics
                platform_data = {
                    'status': status,
                    'event_count': len(events),
                    'last_event': events[-1].timestamp.isoformat() if events else None,
                    'critical_count': len([e for e in events if e.severity == Severity.CRITICAL]),
                    'high_count': len([e for e in events if e.severity == Severity.HIGH])
                }
                
                dashboard_data['platforms'][platform.value] = platform_data
                
            except Exception as e:
                self.logger.error(f"Failed to get dashboard data from {platform.value}: {e}")
                dashboard_data['platforms'][platform.value] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        # Update summary
        dashboard_data['summary']['total_events'] = len(all_events)
        dashboard_data['summary']['critical_events'] = len([e for e in all_events if e.severity == Severity.CRITICAL])
        dashboard_data['summary']['high_events'] = len([e for e in all_events if e.severity == Severity.HIGH])
        
        # Correlate events
        try:
            correlations = await self.correlate_events(all_events)
            dashboard_data['summary']['active_correlations'] = len(correlations)
            
            # Generate alerts for high-confidence correlations
            for correlation in correlations:
                if len(correlation) >= 3:  # Multiple related events
                    avg_confidence = sum(e.confidence_score for e in correlation) / len(correlation)
                    if avg_confidence > 0.8:
                        dashboard_data['alerts'].append({
                            'type': 'correlation',
                            'severity': 'high',
                            'message': f'High-confidence correlation detected: {len(correlation)} related events',
                            'event_ids': [e.event_id for e in correlation],
                            'confidence': avg_confidence
                        })
        
        except Exception as e:
            self.logger.error(f"Failed to correlate events for dashboard: {e}")
        
        # Get trends
        try:
            trends = await self.analyze_security_trends(days=7)
            dashboard_data['trends'] = trends
        except Exception as e:
            self.logger.error(f"Failed to analyze trends for dashboard: {e}")
        
        return dashboard_data
    
    async def send_static_analysis_results(self, issues: List[SecurityIssue]) -> Dict[str, bool]:
        """Send static analysis results to monitoring platforms."""
        
        results = {}
        
        for issue in issues:
            # Convert security issue to security event
            event = SecurityEvent(
                event_id=f"static_{issue.id}",
                source_platform=MonitoringPlatform.SPLUNK,  # Default platform
                event_type=EventType.STATIC_ANALYSIS,
                timestamp=issue.created_at,
                title=f"Static Analysis: {issue.description}",
                description=issue.description,
                severity=issue.severity,
                category=issue.category,
                file_path=issue.file_path,
                tags=["static_analysis", issue.rule_id],
                confidence_score=issue.confidence,
                raw_data={
                    'rule_id': issue.rule_id,
                    'line_number': issue.line_number,
                    'remediation_suggestions': issue.remediation_suggestions
                }
            )
            
            # Send to all platforms
            platform_results = await self.send_security_event(event)
            
            # Aggregate results
            for platform, success in platform_results.items():
                if platform not in results:
                    results[platform] = []
                results[platform].append(success)
        
        # Convert to success rates
        success_rates = {}
        for platform, successes in results.items():
            success_rate = sum(successes) / len(successes) if successes else 0
            success_rates[platform] = success_rate
        
        return success_rates
    
    async def shutdown(self):
        """Gracefully shutdown all monitoring integrations."""
        
        for platform, integration in self.integrations.items():
            try:
                if hasattr(integration, 'close'):
                    await integration.close()
                self.logger.info(f"Closed {platform.value} integration")
            except Exception as e:
                self.logger.error(f"Error closing {platform.value} integration: {e}")


def create_security_event_from_issue(issue: SecurityIssue) -> SecurityEvent:
    """Create a SecurityEvent from a SecurityIssue."""
    
    return SecurityEvent(
        event_id=f"static_{issue.id}",
        source_platform=MonitoringPlatform.SPLUNK,  # Default
        event_type=EventType.STATIC_ANALYSIS,
        timestamp=issue.created_at,
        title=f"Security Issue: {issue.description}",
        description=issue.description,
        severity=issue.severity,
        category=issue.category,
        file_path=issue.file_path,
        tags=["compliance_sentinel", "static_analysis", issue.rule_id],
        confidence_score=issue.confidence,
        raw_data={
            'rule_id': issue.rule_id,
            'line_number': issue.line_number,
            'remediation_suggestions': issue.remediation_suggestions,
            'file_path': issue.file_path
        }
    )