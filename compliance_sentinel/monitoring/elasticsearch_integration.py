"""Elasticsearch integration for security log aggregation and search."""

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


class ElasticsearchIntegration:
    """Elasticsearch integration for security event management."""
    
    def __init__(self, config: MonitoringConfig):
        """Initialize Elasticsearch integration."""
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
        
        # Authentication
        auth = None
        if self.config.username and self.config.password:
            auth = aiohttp.BasicAuth(self.config.username, self.config.password)
        
        # Create session
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        self.session = aiohttp.ClientSession(
            connector=connector,
            auth=auth,
            timeout=aiohttp.ClientTimeout(total=self.config.query_timeout),
            headers={'Content-Type': 'application/json'}
        )
        
        # Test connection
        await self._test_connection()
    
    async def _test_connection(self):
        """Test Elasticsearch connection."""
        
        try:
            async with self.session.get(f"{self.base_url}/") as response:
                response.raise_for_status()
                
                cluster_info = await response.json()
                self.logger.info(f"Connected to Elasticsearch cluster: {cluster_info.get('cluster_name', 'unknown')}")
                
                # Ensure index exists
                await self._ensure_index_exists()
                
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            raise
    
    async def _ensure_index_exists(self):
        """Ensure the security events index exists with proper mapping."""
        
        index_name = self.config.index_name
        
        # Check if index exists
        async with self.session.head(f"{self.base_url}/{index_name}") as response:
            if response.status == 200:
                return  # Index already exists
        
        # Create index with mapping
        index_mapping = {
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "source_platform": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "detection_time": {"type": "date"},
                    "title": {"type": "text", "analyzer": "standard"},
                    "description": {"type": "text", "analyzer": "standard"},
                    "severity": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "hostname": {"type": "keyword"},
                    "user_agent": {"type": "text"},
                    "user_id": {"type": "keyword"},
                    "file_path": {"type": "keyword"},
                    "process_name": {"type": "keyword"},
                    "command_line": {"type": "text"},
                    "network_protocol": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "correlation_id": {"type": "keyword"},
                    "related_events": {"type": "keyword"},
                    "confidence_score": {"type": "float"},
                    "risk_score": {"type": "float"},
                    "false_positive_probability": {"type": "float"},
                    "raw_data": {"type": "object", "enabled": False}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.lifecycle.name": "security_events_policy",
                "index.lifecycle.rollover_alias": f"{index_name}_alias"
            }
        }
        
        try:
            async with self.session.put(
                f"{self.base_url}/{index_name}",
                json=index_mapping
            ) as response:
                response.raise_for_status()
                
                self.logger.info(f"Created Elasticsearch index: {index_name}")
                
        except Exception as e:
            self.logger.error(f"Failed to create Elasticsearch index: {e}")
            raise
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to Elasticsearch."""
        
        try:
            # Prepare event document
            doc = {
                "event_id": event.event_id,
                "source_platform": event.source_platform.value,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "detection_time": event.detection_time.isoformat(),
                "title": event.title,
                "description": event.description,
                "severity": event.severity.value,
                "category": event.category.value,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "hostname": event.hostname,
                "user_agent": event.user_agent,
                "user_id": event.user_id,
                "file_path": event.file_path,
                "process_name": event.process_name,
                "command_line": event.command_line,
                "network_protocol": event.network_protocol,
                "tags": event.tags,
                "correlation_id": event.correlation_id,
                "related_events": event.related_events,
                "confidence_score": event.confidence_score,
                "risk_score": event.risk_score,
                "false_positive_probability": event.false_positive_probability,
                "raw_data": event.raw_data
            }
            
            # Index document
            async with self.session.post(
                f"{self.base_url}/{self.config.index_name}/_doc/{event.event_id}",
                json=doc
            ) as response:
                response.raise_for_status()
                
                result = await response.json()
                
                if result.get('result') in ['created', 'updated']:
                    self.logger.debug(f"Successfully indexed event {event.event_id} in Elasticsearch")
                    return True
                else:
                    self.logger.error(f"Elasticsearch indexing failed for event {event.event_id}: {result}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to send event {event.event_id} to Elasticsearch: {e}")
            return False
    
    async def query_events(self, 
                          query: str,
                          start_time: datetime,
                          end_time: datetime) -> List[SecurityEvent]:
        """Query security events from Elasticsearch."""
        
        try:
            # Build Elasticsearch query
            if query == "*":
                es_query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": self.config.max_results
                }
            else:
                # Parse query string and build appropriate Elasticsearch query
                es_query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                },
                                {
                                    "query_string": {
                                        "query": query,
                                        "default_field": "description"
                                    }
                                }
                            ]
                        }
                    },
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": self.config.max_results
                }
            
            # Execute search
            async with self.session.post(
                f"{self.base_url}/{self.config.index_name}/_search",
                json=es_query
            ) as response:
                response.raise_for_status()
                
                results = await response.json()
                
                # Convert Elasticsearch hits to SecurityEvent objects
                events = []
                for hit in results.get('hits', {}).get('hits', []):
                    try:
                        event = self._convert_es_hit_to_event(hit)
                        if event:
                            events.append(event)
                    except Exception as e:
                        self.logger.error(f"Failed to convert Elasticsearch hit to event: {e}")
                
                return events
                
        except Exception as e:
            self.logger.error(f"Failed to query events from Elasticsearch: {e}")
            return []
    
    def _convert_es_hit_to_event(self, hit: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Convert Elasticsearch hit to SecurityEvent."""
        
        try:
            source = hit['_source']
            
            event = SecurityEvent(
                event_id=source.get('event_id', hit['_id']),
                source_platform=MonitoringPlatform.ELASTICSEARCH,
                event_type=EventType(source.get('event_type', 'static_analysis')),
                timestamp=datetime.fromisoformat(source.get('timestamp', datetime.now().isoformat())),
                detection_time=datetime.fromisoformat(source.get('detection_time', datetime.now().isoformat())),
                title=source.get('title', ''),
                description=source.get('description', ''),
                severity=Severity(source.get('severity', 'medium')),
                category=SecurityCategory(source.get('category', 'input_validation')),
                source_ip=source.get('source_ip', ''),
                destination_ip=source.get('destination_ip', ''),
                hostname=source.get('hostname', ''),
                user_agent=source.get('user_agent', ''),
                user_id=source.get('user_id', ''),
                file_path=source.get('file_path', ''),
                process_name=source.get('process_name', ''),
                command_line=source.get('command_line', ''),
                network_protocol=source.get('network_protocol', ''),
                tags=source.get('tags', []),
                correlation_id=source.get('correlation_id', ''),
                related_events=source.get('related_events', []),
                confidence_score=float(source.get('confidence_score', 0.0)),
                risk_score=float(source.get('risk_score', 0.0)),
                false_positive_probability=float(source.get('false_positive_probability', 0.0)),
                raw_data=source.get('raw_data', {})
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"Failed to convert Elasticsearch hit to SecurityEvent: {e}")
            return None
    
    async def create_alert(self, 
                          name: str,
                          query: Dict[str, Any],
                          trigger_condition: Dict[str, Any]) -> bool:
        """Create an Elasticsearch Watcher alert."""
        
        try:
            watcher_config = {
                "trigger": {
                    "schedule": {
                        "interval": "5m"
                    }
                },
                "input": {
                    "search": {
                        "request": {
                            "search_type": "query_then_fetch",
                            "indices": [self.config.index_name],
                            "body": query
                        }
                    }
                },
                "condition": trigger_condition,
                "actions": {
                    "log_action": {
                        "logging": {
                            "text": f"Security alert triggered: {name}"
                        }
                    }
                }
            }
            
            async with self.session.put(
                f"{self.base_url}/_watcher/watch/{name}",
                json=watcher_config
            ) as response:
                response.raise_for_status()
                
                self.logger.info(f"Successfully created Elasticsearch watcher: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to create Elasticsearch watcher {name}: {e}")
            return False
    
    async def get_platform_status(self) -> Dict[str, Any]:
        """Get Elasticsearch platform status and health."""
        
        try:
            # Get cluster health
            async with self.session.get(f"{self.base_url}/_cluster/health") as response:
                response.raise_for_status()
                
                health = await response.json()
                
                # Get index stats
                async with self.session.get(
                    f"{self.base_url}/{self.config.index_name}/_stats"
                ) as stats_response:
                    stats_response.raise_for_status()
                    
                    stats = await stats_response.json()
                    index_stats = stats['indices'][self.config.index_name]
                    
                    return {
                        'status': health['status'],
                        'cluster_name': health['cluster_name'],
                        'number_of_nodes': health['number_of_nodes'],
                        'active_shards': health['active_shards'],
                        'index_size_bytes': index_stats['total']['store']['size_in_bytes'],
                        'document_count': index_stats['total']['docs']['count'],
                        'last_check': datetime.now().isoformat()
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get Elasticsearch platform status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    async def aggregate_events(self, 
                              aggregation_query: Dict[str, Any],
                              time_window: timedelta) -> Dict[str, Any]:
        """Perform aggregations on security events."""
        
        try:
            end_time = datetime.now()
            start_time = end_time - time_window
            
            # Build aggregation query with time filter
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                "aggs": aggregation_query,
                "size": 0  # Only return aggregations, not documents
            }
            
            async with self.session.post(
                f"{self.base_url}/{self.config.index_name}/_search",
                json=query
            ) as response:
                response.raise_for_status()
                
                results = await response.json()
                return results.get('aggregations', {})
                
        except Exception as e:
            self.logger.error(f"Failed to perform aggregation in Elasticsearch: {e}")
            return {}
    
    async def search_correlations(self, 
                                 correlation_fields: List[str],
                                 time_window: timedelta) -> List[Dict[str, Any]]:
        """Search for event correlations using aggregations."""
        
        try:
            # Build correlation aggregation
            agg_query = {
                "correlations": {
                    "terms": {
                        "script": {
                            "source": " + '_' + ".join([f"doc['{field}'].value" for field in correlation_fields])
                        },
                        "min_doc_count": 2  # At least 2 events to be considered a correlation
                    },
                    "aggs": {
                        "events": {
                            "top_hits": {
                                "size": 10,
                                "_source": ["event_id", "title", "severity", "timestamp"]
                            }
                        }
                    }
                }
            }
            
            correlations = await self.aggregate_events(agg_query, time_window)
            
            # Process correlation results
            correlation_groups = []
            for bucket in correlations.get('correlations', {}).get('buckets', []):
                if bucket['doc_count'] >= 2:
                    correlation_groups.append({
                        'correlation_key': bucket['key'],
                        'event_count': bucket['doc_count'],
                        'events': [hit['_source'] for hit in bucket['events']['hits']['hits']]
                    })
            
            return correlation_groups
            
        except Exception as e:
            self.logger.error(f"Failed to search correlations in Elasticsearch: {e}")
            return []
    
    async def close(self):
        """Close Elasticsearch session."""
        if self.session:
            await self.session.close()
            self.logger.info("Closed Elasticsearch session")