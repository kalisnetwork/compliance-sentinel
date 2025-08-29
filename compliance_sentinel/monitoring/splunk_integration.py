"""Splunk integration for security event correlation and analysis."""

import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import aiohttp
import ssl

from .monitoring_manager import MonitoringConfig, SecurityEvent, EventType, MonitoringPlatform
from compliance_sentinel.core.interfaces import Severity, SecurityCategory


logger = logging.getLogger(__name__)


class SplunkIntegration:
    """Splunk integration for security event management."""
    
    def __init__(self, config: MonitoringConfig):
        """Initialize Splunk integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.base_url = f"{'https' if config.use_ssl else 'http'}://{config.host}:{config.port}"
        
        # Initialize session
        asyncio.create_task(self._initialize_session())
    
    async def _initialize_session(self):
        """Initialize HTTP session with authentication."""
        
        # SSL context
        ssl_context = None
        if self.config.use_ssl:
            ssl_context = ssl.create_default_context()
            if not self.config.verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            elif self.config.ca_cert_path:
                ssl_context.load_verify_locations(self.config.ca_cert_path)
        
        # Create session
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.config.query_timeout)
        )
        
        # Authenticate
        await self._authenticate()
    
    async def _authenticate(self):
        """Authenticate with Splunk."""
        
        auth_data = {
            'username': self.config.username,
            'password': self.config.password,
            'output_mode': 'json'
        }
        
        try:
            async with self.session.post(
                f"{self.base_url}/services/auth/login",
                data=auth_data
            ) as response:
                response.raise_for_status()
                
                auth_result = await response.json()
                session_key = auth_result['sessionKey']
                
                # Set session key for future requests
                self.session.headers.update({
                    'Authorization': f'Splunk {session_key}',
                    'Content-Type': 'application/json'
                })
                
                self.logger.info("Successfully authenticated with Splunk")
                
        except Exception as e:
            self.logger.error(f"Failed to authenticate with Splunk: {e}")
            raise
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to Splunk."""
        
        try:
            # Prepare event data for Splunk
            splunk_event = {
                'time': event.timestamp.timestamp(),
                'host': event.hostname or 'compliance_sentinel',
                'source': 'compliance_sentinel',
                'sourcetype': f'security:{event.event_type.value}',
                'index': self.config.index_name,
                'event': {
                    'event_id': event.event_id,
                    'title': event.title,
                    'description': event.description,
                    'severity': event.severity.value,
                    'category': event.category.value,
                    'event_type': event.event_type.value,
                    'source_ip': event.source_ip,
                    'destination_ip': event.destination_ip,
                    'hostname': event.hostname,
                    'user_id': event.user_id,
                    'file_path': event.file_path,
                    'process_name': event.process_name,
                    'command_line': event.command_line,
                    'network_protocol': event.network_protocol,
                    'tags': event.tags,
                    'confidence_score': event.confidence_score,
                    'risk_score': event.risk_score,
                    'correlation_id': event.correlation_id,
                    'related_events': event.related_events,
                    'raw_data': event.raw_data
                }
            }
            
            # Send to Splunk HTTP Event Collector (HEC)
            async with self.session.post(
                f"{self.base_url}/services/collector/event",
                json=splunk_event
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                if result.get('text') == 'Success':
                    self.logger.debug(f"Successfully sent event {event.event_id} to Splunk")
                    return True
                else:
                    self.logger.error(f"Splunk rejected event {event.event_id}: {result}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to send event {event.event_id} to Splunk: {e}")
            return False
    
    async def query_events(self, 
                          query: str,
                          start_time: datetime,
                          end_time: datetime) -> List[SecurityEvent]:
        """Query security events from Splunk."""
        
        try:
            # Build Splunk search query
            time_range = f"earliest={start_time.timestamp()} latest={end_time.timestamp()}"
            
            if query == "*":
                search_query = f"search index={self.config.index_name} source=compliance_sentinel {time_range}"
            else:
                search_query = f"search index={self.config.index_name} source=compliance_sentinel {query} {time_range}"
            
            # Create search job
            search_data = {
                'search': search_query,
                'output_mode': 'json',
                'count': self.config.max_results
            }
            
            async with self.session.post(
                f"{self.base_url}/services/search/jobs",
                data=search_data
            ) as response:
                response.raise_for_status()
                
                job_result = await response.json()
                job_id = job_result['sid']
            
            # Wait for search to complete
            await self._wait_for_search_completion(job_id)
            
            # Get search results
            async with self.session.get(
                f"{self.base_url}/services/search/jobs/{job_id}/results",
                params={'output_mode': 'json'}
            ) as response:
                response.raise_for_status()
                
                results = await response.json()
                
                # Convert Splunk results to SecurityEvent objects
                events = []
                for result in results.get('results', []):
                    try:
                        event = self._convert_splunk_result_to_event(result)
                        if event:
                            events.append(event)
                    except Exception as e:
                        self.logger.error(f"Failed to convert Splunk result to event: {e}")
                
                return events
                
        except Exception as e:
            self.logger.error(f"Failed to query events from Splunk: {e}")
            return []
    
    async def _wait_for_search_completion(self, job_id: str, max_wait: int = 60):
        """Wait for Splunk search job to complete."""
        
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < max_wait:
            try:
                async with self.session.get(
                    f"{self.base_url}/services/search/jobs/{job_id}",
                    params={'output_mode': 'json'}
                ) as response:
                    response.raise_for_status()
                    
                    job_status = await response.json()
                    
                    if job_status['entry'][0]['content']['isDone']:
                        return
                    
                    await asyncio.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error checking Splunk search job status: {e}")
                break
        
        raise TimeoutError(f"Splunk search job {job_id} did not complete within {max_wait} seconds")
    
    def _convert_splunk_result_to_event(self, result: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Convert Splunk search result to SecurityEvent."""
        
        try:
            # Extract event data from Splunk result
            raw_event = result.get('_raw', {})
            
            if isinstance(raw_event, str):
                # Parse JSON string
                raw_event = json.loads(raw_event)
            
            event_data = raw_event.get('event', raw_event)
            
            # Map Splunk fields to SecurityEvent
            event = SecurityEvent(
                event_id=event_data.get('event_id', result.get('_cd', '')),
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType(event_data.get('event_type', 'static_analysis')),
                timestamp=datetime.fromtimestamp(float(result.get('_time', 0))),
                title=event_data.get('title', ''),
                description=event_data.get('description', ''),
                severity=Severity(event_data.get('severity', 'medium')),
                category=SecurityCategory(event_data.get('category', 'input_validation')),
                source_ip=event_data.get('source_ip', ''),
                destination_ip=event_data.get('destination_ip', ''),
                hostname=event_data.get('hostname', result.get('host', '')),
                user_id=event_data.get('user_id', ''),
                file_path=event_data.get('file_path', ''),
                process_name=event_data.get('process_name', ''),
                command_line=event_data.get('command_line', ''),
                network_protocol=event_data.get('network_protocol', ''),
                tags=event_data.get('tags', []),
                confidence_score=float(event_data.get('confidence_score', 0.0)),
                risk_score=float(event_data.get('risk_score', 0.0)),
                correlation_id=event_data.get('correlation_id', ''),
                related_events=event_data.get('related_events', []),
                raw_data=event_data.get('raw_data', {})
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"Failed to convert Splunk result to SecurityEvent: {e}")
            return None
    
    async def create_alert(self, 
                          name: str,
                          search_query: str,
                          trigger_condition: str,
                          actions: List[str]) -> bool:
        """Create a Splunk alert for security events."""
        
        try:
            alert_data = {
                'name': name,
                'search': search_query,
                'cron_schedule': '*/5 * * * *',  # Every 5 minutes
                'actions': ','.join(actions),
                'alert.track': '1',
                'alert.condition': trigger_condition,
                'output_mode': 'json'
            }
            
            async with self.session.post(
                f"{self.base_url}/services/saved/searches",
                data=alert_data
            ) as response:
                response.raise_for_status()
                
                self.logger.info(f"Successfully created Splunk alert: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to create Splunk alert {name}: {e}")
            return False
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get Splunk platform status and health."""
        
        try:
            # Get server info
            async with self.session.get(
                f"{self.base_url}/services/server/info",
                params={'output_mode': 'json'}
            ) as response:
                response.raise_for_status()
                
                server_info = await response.json()
                
                # Get index info
                async with self.session.get(
                    f"{self.base_url}/services/data/indexes/{self.config.index_name}",
                    params={'output_mode': 'json'}
                ) as index_response:
                    index_response.raise_for_status()
                    
                    index_info = await index_response.json()
                    
                    return {
                        'status': 'healthy',
                        'version': server_info['entry'][0]['content'].get('version', 'unknown'),
                        'server_name': server_info['entry'][0]['content'].get('serverName', 'unknown'),
                        'index_size': index_info['entry'][0]['content'].get('currentDBSizeMB', 0),
                        'last_check': datetime.now().isoformat()
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get Splunk platform status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    async def search_correlations(self, 
                                 correlation_query: str,
                                 time_window: timedelta) -> List[Dict[str, Any]]:
        """Search for event correlations in Splunk."""
        
        try:
            end_time = datetime.now()
            start_time = end_time - time_window
            
            # Build correlation search query
            search_query = f"""
            search index={self.config.index_name} source=compliance_sentinel 
            earliest={start_time.timestamp()} latest={end_time.timestamp()}
            | {correlation_query}
            | stats count by correlation_id, event_type, severity
            | where count > 1
            """
            
            # Execute search
            search_data = {
                'search': search_query,
                'output_mode': 'json',
                'count': 100
            }
            
            async with self.session.post(
                f"{self.base_url}/services/search/jobs",
                data=search_data
            ) as response:
                response.raise_for_status()
                
                job_result = await response.json()
                job_id = job_result['sid']
            
            # Wait for completion and get results
            await self._wait_for_search_completion(job_id)
            
            async with self.session.get(
                f"{self.base_url}/services/search/jobs/{job_id}/results",
                params={'output_mode': 'json'}
            ) as response:
                response.raise_for_status()
                
                results = await response.json()
                return results.get('results', [])
                
        except Exception as e:
            self.logger.error(f"Failed to search correlations in Splunk: {e}")
            return []
    
    async def close(self):
        """Close Splunk session."""
        if self.session:
            await self.session.close()
            self.logger.info("Closed Splunk session")