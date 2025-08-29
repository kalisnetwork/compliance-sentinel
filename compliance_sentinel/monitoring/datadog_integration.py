"""Datadog integration for security metrics and alerting."""

import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import aiohttp

from .monitoring_manager import MonitoringConfig, SecurityEvent, EventType, MonitoringPlatform
from compliance_sentinel.core.interfaces import Severity, SecurityCategory


logger = logging.getLogger(__name__)


class DatadogIntegration:
    """Datadog integration for security metrics and monitoring."""
    
    def __init__(self, config: MonitoringConfig):
        """Initialize Datadog integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.api_base_url = "https://api.datadoghq.com/api/v1"
        
        # Initialize session
        asyncio.create_task(self._initialize_session())
    
    async def _initialize_session(self):
        """Initialize HTTP session with authentication."""
        
        headers = {
            'DD-API-KEY': self.config.api_key,
            'DD-APPLICATION-KEY': self.config.api_token,
            'Content-Type': 'application/json'
        }
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config.query_timeout)
        )
        
        # Test connection
        await self._test_connection()
    
    async def _test_connection(self):
        """Test Datadog API connection."""
        
        try:
            async with self.session.get(f"{self.api_base_url}/validate") as response:
                response.raise_for_status()
                
                result = await response.json()
                
                if result.get('valid'):
                    self.logger.info("Successfully connected to Datadog API")
                else:
                    raise Exception("Invalid Datadog API credentials")
                    
        except Exception as e:
            self.logger.error(f"Failed to connect to Datadog: {e}")
            raise
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to Datadog as an event."""
        
        try:
            # Prepare Datadog event
            dd_event = {
                "title": event.title,
                "text": event.description,
                "date_happened": int(event.timestamp.timestamp()),
                "priority": self._map_severity_to_priority(event.severity),
                "alert_type": self._map_severity_to_alert_type(event.severity),
                "source_type_name": "compliance_sentinel",
                "host": event.hostname or "compliance_sentinel",
                "tags": [
                    f"event_type:{event.event_type.value}",
                    f"severity:{event.severity.value}",
                    f"category:{event.category.value}",
                    f"source_platform:{event.source_platform.value}"
                ] + event.tags
            }
            
            # Add additional context
            if event.source_ip:
                dd_event["tags"].append(f"source_ip:{event.source_ip}")
            
            if event.user_id:
                dd_event["tags"].append(f"user_id:{event.user_id}")
            
            if event.file_path:
                dd_event["tags"].append(f"file_path:{event.file_path}")
            
            # Send event
            async with self.session.post(
                f"{self.api_base_url}/events",
                json=dd_event
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                if result.get('status') == 'ok':
                    self.logger.debug(f"Successfully sent event {event.event_id} to Datadog")
                    
                    # Also send as custom metric
                    await self._send_security_metrics(event)
                    
                    return True
                else:
                    self.logger.error(f"Datadog rejected event {event.event_id}: {result}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to send event {event.event_id} to Datadog: {e}")
            return False
    
    async def _send_security_metrics(self, event: SecurityEvent):
        """Send security metrics to Datadog."""
        
        try:
            current_time = int(datetime.now().timestamp())
            
            # Prepare metrics
            metrics = [
                {
                    "metric": "compliance_sentinel.security_events.count",
                    "points": [[current_time, 1]],
                    "tags": [
                        f"event_type:{event.event_type.value}",
                        f"severity:{event.severity.value}",
                        f"category:{event.category.value}"
                    ]
                },
                {
                    "metric": "compliance_sentinel.security_events.confidence_score",
                    "points": [[current_time, event.confidence_score]],
                    "tags": [
                        f"event_type:{event.event_type.value}",
                        f"severity:{event.severity.value}"
                    ]
                },
                {
                    "metric": "compliance_sentinel.security_events.risk_score",
                    "points": [[current_time, event.risk_score]],
                    "tags": [
                        f"event_type:{event.event_type.value}",
                        f"severity:{event.severity.value}"
                    ]
                }
            ]
            
            # Send metrics
            async with self.session.post(
                f"{self.api_base_url}/series",
                json={"series": metrics}
            ) as response:
                response.raise_for_status()
                
        except Exception as e:
            self.logger.error(f"Failed to send security metrics to Datadog: {e}")
    
    async def query_events(self, 
                          query: str,
                          start_time: datetime,
                          end_time: datetime) -> List[SecurityEvent]:
        """Query security events from Datadog (limited functionality)."""
        
        try:
            # Datadog events API has limited querying capabilities
            # We'll search for events with our source type
            
            params = {
                'start': int(start_time.timestamp()),
                'end': int(end_time.timestamp()),
                'sources': 'compliance_sentinel'
            }
            
            if query != "*":
                params['tags'] = query
            
            async with self.session.get(
                f"{self.api_base_url}/events",
                params=params
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                # Convert Datadog events to SecurityEvent objects
                events = []
                for dd_event in result.get('events', []):
                    try:
                        event = self._convert_dd_event_to_security_event(dd_event)
                        if event:
                            events.append(event)
                    except Exception as e:
                        self.logger.error(f"Failed to convert Datadog event: {e}")
                
                return events
                
        except Exception as e:
            self.logger.error(f"Failed to query events from Datadog: {e}")
            return []
    
    def _convert_dd_event_to_security_event(self, dd_event: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Convert Datadog event to SecurityEvent."""
        
        try:
            # Extract tags
            tags = dd_event.get('tags', [])
            tag_dict = {}
            
            for tag in tags:
                if ':' in tag:
                    key, value = tag.split(':', 1)
                    tag_dict[key] = value
            
            # Map Datadog event to SecurityEvent
            event = SecurityEvent(
                event_id=str(dd_event.get('id', '')),
                source_platform=MonitoringPlatform.DATADOG,
                event_type=EventType(tag_dict.get('event_type', 'static_analysis')),
                timestamp=datetime.fromtimestamp(dd_event.get('date_happened', 0)),
                title=dd_event.get('title', ''),
                description=dd_event.get('text', ''),
                severity=Severity(tag_dict.get('severity', 'medium')),
                category=SecurityCategory(tag_dict.get('category', 'input_validation')),
                hostname=dd_event.get('host', ''),
                source_ip=tag_dict.get('source_ip', ''),
                user_id=tag_dict.get('user_id', ''),
                file_path=tag_dict.get('file_path', ''),
                tags=[tag for tag in tags if ':' not in tag],
                raw_data=dd_event
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"Failed to convert Datadog event to SecurityEvent: {e}")
            return None
    
    async def create_monitor(self, 
                           name: str,
                           query: str,
                           message: str,
                           thresholds: Dict[str, float]) -> bool:
        """Create a Datadog monitor for security metrics."""
        
        try:
            monitor_config = {
                "name": name,
                "type": "metric alert",
                "query": query,
                "message": message,
                "tags": ["compliance_sentinel", "security"],
                "options": {
                    "thresholds": thresholds,
                    "notify_audit": True,
                    "require_full_window": False,
                    "notify_no_data": True,
                    "no_data_timeframe": 20
                }
            }
            
            async with self.session.post(
                f"{self.api_base_url}/monitor",
                json=monitor_config
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                self.logger.info(f"Successfully created Datadog monitor: {name} (ID: {result.get('id')})")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to create Datadog monitor {name}: {e}")
            return False
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get Datadog platform status."""
        
        try:
            # Get service summary
            async with self.session.get(f"{self.api_base_url}/service_summary") as response:
                response.raise_for_status()
                
                summary = await response.json()
                
                # Get recent metrics
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=1)
                
                metrics_query = {
                    'query': 'compliance_sentinel.security_events.count{*}',
                    'from': int(start_time.timestamp()),
                    'to': int(end_time.timestamp())
                }
                
                async with self.session.get(
                    f"{self.api_base_url}/query",
                    params=metrics_query
                ) as metrics_response:
                    
                    if metrics_response.status == 200:
                        metrics_data = await metrics_response.json()
                        event_count = len(metrics_data.get('series', []))
                    else:
                        event_count = 0
                    
                    return {
                        'status': 'healthy',
                        'service_summary': summary,
                        'recent_events': event_count,
                        'last_check': datetime.now().isoformat()
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get Datadog platform status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    async def send_security_dashboard_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send aggregated security metrics to Datadog dashboard."""
        
        try:
            current_time = int(datetime.now().timestamp())
            
            # Prepare dashboard metrics
            dd_metrics = []
            
            # Total events by severity
            for severity, count in metrics.get('severity_distribution', {}).items():
                dd_metrics.append({
                    "metric": "compliance_sentinel.events.by_severity",
                    "points": [[current_time, count]],
                    "tags": [f"severity:{severity}"]
                })
            
            # Events by category
            for category, count in metrics.get('category_distribution', {}).items():
                dd_metrics.append({
                    "metric": "compliance_sentinel.events.by_category",
                    "points": [[current_time, count]],
                    "tags": [f"category:{category}"]
                })
            
            # Risk metrics
            if 'risk_score' in metrics:
                dd_metrics.append({
                    "metric": "compliance_sentinel.risk_score",
                    "points": [[current_time, metrics['risk_score']]]
                })
            
            # Correlation metrics
            if 'active_correlations' in metrics:
                dd_metrics.append({
                    "metric": "compliance_sentinel.correlations.active",
                    "points": [[current_time, metrics['active_correlations']]]
                })
            
            # Send all metrics
            async with self.session.post(
                f"{self.api_base_url}/series",
                json={"series": dd_metrics}
            ) as response:
                response.raise_for_status()
                
                self.logger.info("Successfully sent security dashboard metrics to Datadog")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to send dashboard metrics to Datadog: {e}")
            return False
    
    def _map_severity_to_priority(self, severity: Severity) -> str:
        """Map security severity to Datadog priority."""
        mapping = {
            Severity.CRITICAL: "high",
            Severity.HIGH: "normal",
            Severity.MEDIUM: "low",
            Severity.LOW: "low"
        }
        return mapping.get(severity, "normal")
    
    def _map_severity_to_alert_type(self, severity: Severity) -> str:
        """Map security severity to Datadog alert type."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info"
        }
        return mapping.get(severity, "info")
    
    async def close(self):
        """Close Datadog session."""
        if self.session:
            await self.session.close()
            self.logger.info("Closed Datadog session")