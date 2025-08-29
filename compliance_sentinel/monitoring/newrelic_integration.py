"""New Relic integration for application security monitoring."""

import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import aiohttp

from .monitoring_manager import MonitoringConfig, SecurityEvent, EventType, MonitoringPlatform
from compliance_sentinel.core.interfaces import Severity, SecurityCategory


logger = logging.getLogger(__name__)


class NewRelicIntegration:
    """New Relic integration for application security monitoring."""
    
    def __init__(self, config: MonitoringConfig):
        """Initialize New Relic integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.insights_api_url = "https://insights-api.newrelic.com/v1"
        self.api_base_url = "https://api.newrelic.com/v2"
        
        # Initialize session
        asyncio.create_task(self._initialize_session())
    
    async def _initialize_session(self):
        """Initialize HTTP session with authentication."""
        
        headers = {
            'X-Insert-Key': self.config.api_key,  # For Insights API
            'X-Api-Key': self.config.api_token,   # For REST API
            'Content-Type': 'application/json'
        }
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config.query_timeout)
        )
        
        # Test connection
        await self._test_connection()
    
    async def _test_connection(self):
        """Test New Relic API connection."""
        
        try:
            # Test REST API connection
            async with self.session.get(f"{self.api_base_url}/applications.json") as response:
                if response.status == 200:
                    self.logger.info("Successfully connected to New Relic API")
                elif response.status == 403:
                    raise Exception("Invalid New Relic API key")
                else:
                    response.raise_for_status()
                    
        except Exception as e:
            self.logger.error(f"Failed to connect to New Relic: {e}")
            raise
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to New Relic as a custom event."""
        
        try:
            # Prepare New Relic custom event
            nr_event = {
                "eventType": "ComplianceSentinelSecurityEvent",
                "timestamp": int(event.timestamp.timestamp() * 1000),  # Milliseconds
                "eventId": event.event_id,
                "title": event.title,
                "description": event.description,
                "severity": event.severity.value,
                "category": event.category.value,
                "eventType_custom": event.event_type.value,
                "sourcePlatform": event.source_platform.value,
                "confidenceScore": event.confidence_score,
                "riskScore": event.risk_score,
                "falsePositiveProbability": event.false_positive_probability
            }
            
            # Add optional fields
            if event.hostname:
                nr_event["hostname"] = event.hostname
            
            if event.source_ip:
                nr_event["sourceIp"] = event.source_ip
            
            if event.destination_ip:
                nr_event["destinationIp"] = event.destination_ip
            
            if event.user_id:
                nr_event["userId"] = event.user_id
            
            if event.file_path:
                nr_event["filePath"] = event.file_path
            
            if event.process_name:
                nr_event["processName"] = event.process_name
            
            if event.network_protocol:
                nr_event["networkProtocol"] = event.network_protocol
            
            if event.correlation_id:
                nr_event["correlationId"] = event.correlation_id
            
            # Add tags as attributes
            for i, tag in enumerate(event.tags[:10]):  # Limit to 10 tags
                nr_event[f"tag{i+1}"] = tag
            
            # Send to New Relic Insights
            account_id = self.config.custom_fields.get('account_id', '1')
            
            async with self.session.post(
                f"{self.insights_api_url}/accounts/{account_id}/events",
                json=[nr_event]  # Events must be in an array
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                if result.get('success'):
                    self.logger.debug(f"Successfully sent event {event.event_id} to New Relic")
                    
                    # Also send as custom metrics
                    await self._send_security_metrics(event)
                    
                    return True
                else:
                    self.logger.error(f"New Relic rejected event {event.event_id}: {result}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to send event {event.event_id} to New Relic: {e}")
            return False
    
    async def _send_security_metrics(self, event: SecurityEvent):
        """Send security metrics to New Relic as custom metrics."""
        
        try:
            account_id = self.config.custom_fields.get('account_id', '1')
            
            # Prepare custom metrics
            metrics = [
                {
                    "eventType": "ComplianceSentinelMetrics",
                    "timestamp": int(datetime.now().timestamp() * 1000),
                    "metricName": "security_events_count",
                    "metricValue": 1,
                    "severity": event.severity.value,
                    "category": event.category.value,
                    "eventType_custom": event.event_type.value
                },
                {
                    "eventType": "ComplianceSentinelMetrics",
                    "timestamp": int(datetime.now().timestamp() * 1000),
                    "metricName": "confidence_score",
                    "metricValue": event.confidence_score,
                    "severity": event.severity.value,
                    "eventType_custom": event.event_type.value
                },
                {
                    "eventType": "ComplianceSentinelMetrics",
                    "timestamp": int(datetime.now().timestamp() * 1000),
                    "metricName": "risk_score",
                    "metricValue": event.risk_score,
                    "severity": event.severity.value,
                    "eventType_custom": event.event_type.value
                }
            ]
            
            # Send metrics
            async with self.session.post(
                f"{self.insights_api_url}/accounts/{account_id}/events",
                json=metrics
            ) as response:
                response.raise_for_status()
                
        except Exception as e:
            self.logger.error(f"Failed to send security metrics to New Relic: {e}")
    
    async def query_events(self, 
                          query: str,
                          start_time: datetime,
                          end_time: datetime) -> List[SecurityEvent]:
        """Query security events from New Relic using NRQL."""
        
        try:
            account_id = self.config.custom_fields.get('account_id', '1')
            
            # Build NRQL query
            if query == "*":
                nrql_query = f"""
                SELECT * FROM ComplianceSentinelSecurityEvent 
                WHERE timestamp >= {int(start_time.timestamp() * 1000)} 
                AND timestamp <= {int(end_time.timestamp() * 1000)}
                LIMIT {self.config.max_results}
                """
            else:
                # Simple text search in description
                nrql_query = f"""
                SELECT * FROM ComplianceSentinelSecurityEvent 
                WHERE timestamp >= {int(start_time.timestamp() * 1000)} 
                AND timestamp <= {int(end_time.timestamp() * 1000)}
                AND description LIKE '%{query}%'
                LIMIT {self.config.max_results}
                """
            
            # Execute NRQL query
            params = {'nrql': nrql_query}
            
            async with self.session.get(
                f"{self.insights_api_url}/accounts/{account_id}/query",
                params=params
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                # Convert New Relic results to SecurityEvent objects
                events = []
                for nr_event in result.get('results', []):
                    try:
                        event = self._convert_nr_event_to_security_event(nr_event)
                        if event:
                            events.append(event)
                    except Exception as e:
                        self.logger.error(f"Failed to convert New Relic event: {e}")
                
                return events
                
        except Exception as e:
            self.logger.error(f"Failed to query events from New Relic: {e}")
            return []
    
    def _convert_nr_event_to_security_event(self, nr_event: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Convert New Relic event to SecurityEvent."""
        
        try:
            # Extract tags from tag attributes
            tags = []
            for key, value in nr_event.items():
                if key.startswith('tag') and value:
                    tags.append(value)
            
            # Map New Relic event to SecurityEvent
            event = SecurityEvent(
                event_id=nr_event.get('eventId', ''),
                source_platform=MonitoringPlatform.NEWRELIC,
                event_type=EventType(nr_event.get('eventType_custom', 'static_analysis')),
                timestamp=datetime.fromtimestamp(nr_event.get('timestamp', 0) / 1000),
                title=nr_event.get('title', ''),
                description=nr_event.get('description', ''),
                severity=Severity(nr_event.get('severity', 'medium')),
                category=SecurityCategory(nr_event.get('category', 'input_validation')),
                hostname=nr_event.get('hostname', ''),
                source_ip=nr_event.get('sourceIp', ''),
                destination_ip=nr_event.get('destinationIp', ''),
                user_id=nr_event.get('userId', ''),
                file_path=nr_event.get('filePath', ''),
                process_name=nr_event.get('processName', ''),
                network_protocol=nr_event.get('networkProtocol', ''),
                correlation_id=nr_event.get('correlationId', ''),
                tags=tags,
                confidence_score=float(nr_event.get('confidenceScore', 0.0)),
                risk_score=float(nr_event.get('riskScore', 0.0)),
                false_positive_probability=float(nr_event.get('falsePositiveProbability', 0.0)),
                raw_data=nr_event
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"Failed to convert New Relic event to SecurityEvent: {e}")
            return None
    
    async def create_alert_policy(self, 
                                 name: str,
                                 nrql_condition: str,
                                 threshold: float,
                                 notification_channels: List[str]) -> bool:
        """Create a New Relic alert policy for security events."""
        
        try:
            # Create alert policy
            policy_data = {
                "policy": {
                    "name": name,
                    "incident_preference": "PER_CONDITION"
                }
            }
            
            async with self.session.post(
                f"{self.api_base_url}/alerts_policies.json",
                json=policy_data
            ) as response:
                response.raise_for_status()
                
                policy_result = await response.json()
                policy_id = policy_result['policy']['id']
            
            # Create NRQL condition
            condition_data = {
                "nrql_condition": {
                    "name": f"{name} Condition",
                    "enabled": True,
                    "nrql": {
                        "query": nrql_condition,
                        "since_value": "3"
                    },
                    "terms": [
                        {
                            "threshold": threshold,
                            "time_function": "all",
                            "operator": "above"
                        }
                    ],
                    "value_function": "single_value"
                }
            }
            
            async with self.session.post(
                f"{self.api_base_url}/alerts_nrql_conditions/policies/{policy_id}.json",
                json=condition_data
            ) as response:
                response.raise_for_status()
                
                self.logger.info(f"Successfully created New Relic alert policy: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to create New Relic alert policy {name}: {e}")
            return False
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get New Relic platform status."""
        
        try:
            # Get applications
            async with self.session.get(f"{self.api_base_url}/applications.json") as response:
                response.raise_for_status()
                
                apps_data = await response.json()
                
                # Get recent security events count
                account_id = self.config.custom_fields.get('account_id', '1')
                
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=1)
                
                nrql_query = f"""
                SELECT count(*) FROM ComplianceSentinelSecurityEvent 
                WHERE timestamp >= {int(start_time.timestamp() * 1000)}
                """
                
                params = {'nrql': nrql_query}
                
                async with self.session.get(
                    f"{self.insights_api_url}/accounts/{account_id}/query",
                    params=params
                ) as metrics_response:
                    
                    if metrics_response.status == 200:
                        metrics_data = await metrics_response.json()
                        event_count = metrics_data.get('results', [{}])[0].get('count', 0)
                    else:
                        event_count = 0
                    
                    return {
                        'status': 'healthy',
                        'applications_count': len(apps_data.get('applications', [])),
                        'recent_events': event_count,
                        'account_id': account_id,
                        'last_check': datetime.now().isoformat()
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get New Relic platform status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    async def send_security_dashboard_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send aggregated security metrics to New Relic."""
        
        try:
            account_id = self.config.custom_fields.get('account_id', '1')
            current_time = int(datetime.now().timestamp() * 1000)
            
            # Prepare dashboard metrics
            nr_metrics = []
            
            # Total events by severity
            for severity, count in metrics.get('severity_distribution', {}).items():
                nr_metrics.append({
                    "eventType": "ComplianceSentinelDashboard",
                    "timestamp": current_time,
                    "metricName": "events_by_severity",
                    "metricValue": count,
                    "severity": severity
                })
            
            # Events by category
            for category, count in metrics.get('category_distribution', {}).items():
                nr_metrics.append({
                    "eventType": "ComplianceSentinelDashboard",
                    "timestamp": current_time,
                    "metricName": "events_by_category",
                    "metricValue": count,
                    "category": category
                })
            
            # Risk metrics
            if 'risk_score' in metrics:
                nr_metrics.append({
                    "eventType": "ComplianceSentinelDashboard",
                    "timestamp": current_time,
                    "metricName": "overall_risk_score",
                    "metricValue": metrics['risk_score']
                })
            
            # Correlation metrics
            if 'active_correlations' in metrics:
                nr_metrics.append({
                    "eventType": "ComplianceSentinelDashboard",
                    "timestamp": current_time,
                    "metricName": "active_correlations",
                    "metricValue": metrics['active_correlations']
                })
            
            # Send all metrics
            async with self.session.post(
                f"{self.insights_api_url}/accounts/{account_id}/events",
                json=nr_metrics
            ) as response:
                response.raise_for_status()
                
                self.logger.info("Successfully sent security dashboard metrics to New Relic")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to send dashboard metrics to New Relic: {e}")
            return False
    
    async def create_dashboard(self, dashboard_config: Dict[str, Any]) -> bool:
        """Create a New Relic dashboard for security metrics."""
        
        try:
            async with self.session.post(
                f"{self.api_base_url}/dashboards.json",
                json={"dashboard": dashboard_config}
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                dashboard_id = result['dashboard']['id']
                
                self.logger.info(f"Successfully created New Relic dashboard: {dashboard_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to create New Relic dashboard: {e}")
            return False
    
    async def close(self):
        """Close New Relic session."""
        if self.session:
            await self.session.close()
            self.logger.info("Closed New Relic session")