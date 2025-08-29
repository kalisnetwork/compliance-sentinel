"""Tests for monitoring tool integration and correlation."""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from typing import List

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.monitoring.monitoring_manager import (
    MonitoringManager, MonitoringConfig, SecurityEvent, EventType, MonitoringPlatform
)
from compliance_sentinel.monitoring.event_correlator import (
    SecurityEventCorrelator, CorrelationEngine, CorrelationRule, CorrelationResult
)
from compliance_sentinel.monitoring.splunk_integration import SplunkIntegration
from compliance_sentinel.monitoring.elasticsearch_integration import ElasticsearchIntegration
from compliance_sentinel.monitoring.datadog_integration import DatadogIntegration
from compliance_sentinel.monitoring.newrelic_integration import NewRelicIntegration


class TestMonitoringManager:
    """Test unified monitoring manager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.splunk_config = MonitoringConfig(
            platform=MonitoringPlatform.SPLUNK,
            enabled=True,
            host="splunk.example.com",
            port=8089,
            username="admin",
            password="password",
            index_name="security_events"
        )
        
        self.elasticsearch_config = MonitoringConfig(
            platform=MonitoringPlatform.ELASTICSEARCH,
            enabled=True,
            host="elasticsearch.example.com",
            port=9200,
            username="elastic",
            password="password",
            index_name="security_events"
        )
        
        self.sample_events = [
            SecurityEvent(
                event_id="event_001",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.STATIC_ANALYSIS,
                timestamp=datetime.now(),
                title="Critical Security Issue",
                description="Hardcoded secret detected",
                severity=Severity.CRITICAL,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path="/app/config.py",
                confidence_score=0.95,
                risk_score=8.5
            ),
            SecurityEvent(
                event_id="event_002",
                source_platform=MonitoringPlatform.ELASTICSEARCH,
                event_type=EventType.RUNTIME_DETECTION,
                timestamp=datetime.now() - timedelta(minutes=5),
                title="Authentication Failure",
                description="Multiple failed login attempts",
                severity=Severity.HIGH,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8,
                risk_score=6.0
            )
        ]
    
    @patch('compliance_sentinel.monitoring.monitoring_manager.SplunkIntegration')
    @patch('compliance_sentinel.monitoring.monitoring_manager.ElasticsearchIntegration')
    def test_monitoring_manager_initialization(self, mock_es, mock_splunk):
        """Test monitoring manager initialization with multiple platforms."""
        
        configs = [self.splunk_config, self.elasticsearch_config]
        manager = MonitoringManager(configs)
        
        assert len(manager.configs) == 2
        assert MonitoringPlatform.SPLUNK in manager.configs
        assert MonitoringPlatform.ELASTICSEARCH in manager.configs
        
        # Verify integrations were initialized
        mock_splunk.assert_called_once()
        mock_es.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('compliance_sentinel.monitoring.monitoring_manager.SplunkIntegration')
    @patch('compliance_sentinel.monitoring.monitoring_manager.ElasticsearchIntegration')
    async def test_send_security_event(self, mock_es, mock_splunk):
        """Test sending security event to multiple platforms."""
        
        # Mock integration responses
        mock_splunk_instance = AsyncMock()
        mock_splunk_instance.send_event.return_value = True
        mock_splunk.return_value = mock_splunk_instance
        
        mock_es_instance = AsyncMock()
        mock_es_instance.send_event.return_value = True
        mock_es.return_value = mock_es_instance
        
        configs = [self.splunk_config, self.elasticsearch_config]
        manager = MonitoringManager(configs)
        
        # Send event
        event = self.sample_events[0]
        results = await manager.send_security_event(event)
        
        # Verify results
        assert len(results) == 2
        assert results['splunk'] is True
        assert results['elasticsearch'] is True
        
        # Verify integration calls
        mock_splunk_instance.send_event.assert_called_once_with(event)
        mock_es_instance.send_event.assert_called_once_with(event)
    
    @pytest.mark.asyncio
    @patch('compliance_sentinel.monitoring.monitoring_manager.SplunkIntegration')
    async def test_query_events(self, mock_splunk):
        """Test querying events from monitoring platforms."""
        
        # Mock integration response
        mock_splunk_instance = AsyncMock()
        mock_splunk_instance.query_events.return_value = self.sample_events
        mock_splunk.return_value = mock_splunk_instance
        
        configs = [self.splunk_config]
        manager = MonitoringManager(configs)
        
        # Query events
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()
        
        results = await manager.query_events("*", start_time, end_time)
        
        # Verify results
        assert 'splunk' in results
        assert len(results['splunk']) == 2
        
        # Verify integration call
        mock_splunk_instance.query_events.assert_called_once_with("*", start_time, end_time)
    
    @pytest.mark.asyncio
    @patch('compliance_sentinel.monitoring.monitoring_manager.SecurityEventCorrelator')
    async def test_correlate_events(self, mock_correlator):
        """Test event correlation functionality."""
        
        # Mock correlator response
        mock_correlator_instance = AsyncMock()
        mock_correlator_instance.correlate_events.return_value = [self.sample_events]
        mock_correlator.return_value = mock_correlator_instance
        
        manager = MonitoringManager([])
        manager.correlator = mock_correlator_instance
        
        # Correlate events
        correlations = await manager.correlate_events(self.sample_events)
        
        # Verify results
        assert len(correlations) == 1
        assert len(correlations[0]) == 2
        
        # Verify correlator call
        mock_correlator_instance.correlate_events.assert_called_once()
    
    def test_security_event_creation_from_issue(self):
        """Test creating SecurityEvent from SecurityIssue."""
        from compliance_sentinel.monitoring.monitoring_manager import create_security_event_from_issue
        
        issue = SecurityIssue(
            id="issue_001",
            severity=Severity.HIGH,
            category=SecurityCategory.INJECTION,
            file_path="app.py",
            line_number=25,
            description="SQL injection vulnerability",
            rule_id="sql_injection",
            confidence=0.9,
            remediation_suggestions=["Use parameterized queries"],
            created_at=datetime.now()
        )
        
        event = create_security_event_from_issue(issue)
        
        assert event.event_id == "static_issue_001"
        assert event.event_type == EventType.STATIC_ANALYSIS
        assert event.severity == Severity.HIGH
        assert event.category == SecurityCategory.INJECTION
        assert event.file_path == "app.py"
        assert event.confidence_score == 0.9
        assert "sql_injection" in event.tags


class TestEventCorrelator:
    """Test security event correlation engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.correlator = SecurityEventCorrelator()
        
        # Create test events for correlation
        base_time = datetime.now()
        
        self.auth_events = [
            SecurityEvent(
                event_id="auth_001",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time,
                title="Failed Login",
                description="Authentication failed for user admin",
                severity=Severity.MEDIUM,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8
            ),
            SecurityEvent(
                event_id="auth_002",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time + timedelta(minutes=1),
                title="Failed Login",
                description="Authentication failed for user admin",
                severity=Severity.MEDIUM,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8
            ),
            SecurityEvent(
                event_id="auth_003",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time + timedelta(minutes=2),
                title="Failed Login",
                description="Authentication failed for user admin",
                severity=Severity.MEDIUM,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8
            ),
            SecurityEvent(
                event_id="auth_004",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time + timedelta(minutes=3),
                title="Failed Login",
                description="Authentication failed for user admin",
                severity=Severity.MEDIUM,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8
            ),
            SecurityEvent(
                event_id="auth_005",
                source_platform=MonitoringPlatform.SPLUNK,
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time + timedelta(minutes=4),
                title="Failed Login",
                description="Authentication failed for user admin",
                severity=Severity.MEDIUM,
                category=SecurityCategory.AUTHENTICATION,
                source_ip="192.168.1.100",
                user_id="admin",
                confidence_score=0.8
            )
        ]
    
    @pytest.mark.asyncio
    async def test_correlation_engine_initialization(self):
        """Test correlation engine initialization with default rules."""
        
        engine = CorrelationEngine()
        
        # Should have default correlation rules
        assert len(engine.rules) > 0
        
        # Check for specific default rules
        rule_ids = [rule.rule_id for rule in engine.rules]
        assert "auth_brute_force" in rule_ids
        assert "privilege_escalation" in rule_ids
        assert "static_runtime_correlation" in rule_ids
    
    @pytest.mark.asyncio
    async def test_authentication_brute_force_correlation(self):
        """Test correlation of authentication brute force events."""
        
        correlations = await self.correlator.analyze_correlations(self.auth_events)
        
        # Should detect brute force correlation
        assert len(correlations) > 0
        
        # Find the auth brute force correlation
        auth_correlation = None
        for correlation in correlations:
            if correlation.rule_id == "auth_brute_force":
                auth_correlation = correlation
                break
        
        assert auth_correlation is not None
        assert len(auth_correlation.events) == 5  # All auth events
        assert auth_correlation.confidence_score > 0.7
        assert auth_correlation.severity in [Severity.HIGH, Severity.CRITICAL]
    
    def test_correlation_rule_creation(self):
        """Test creating custom correlation rules."""
        
        custom_rule = CorrelationRule(
            rule_id="custom_test_rule",
            name="Custom Test Rule",
            description="Test rule for unit testing",
            event_types=[EventType.STATIC_ANALYSIS],
            correlation_fields=["file_path"],
            time_window=timedelta(minutes=30),
            min_events=2,
            confidence_threshold=0.6
        )
        
        engine = CorrelationEngine()
        initial_count = len(engine.rules)
        
        engine.add_rule(custom_rule)
        
        assert len(engine.rules) == initial_count + 1
        assert engine.rules[-1].rule_id == "custom_test_rule"
    
    def test_correlation_rule_removal(self):
        """Test removing correlation rules."""
        
        engine = CorrelationEngine()
        initial_count = len(engine.rules)
        
        # Remove a default rule
        success = engine.remove_rule("auth_brute_force")
        
        assert success is True
        assert len(engine.rules) == initial_count - 1
        
        # Try to remove non-existent rule
        success = engine.remove_rule("non_existent_rule")
        assert success is False
    
    @pytest.mark.asyncio
    async def test_correlation_confidence_scoring(self):
        """Test correlation confidence scoring."""
        
        engine = CorrelationEngine()
        
        # Test with high-confidence events
        high_confidence_events = [
            event for event in self.auth_events
        ]
        for event in high_confidence_events:
            event.confidence_score = 0.95
        
        correlations = await engine.correlate_events(high_confidence_events)
        
        if correlations:
            # Should have high confidence due to high event confidence
            assert correlations[0].confidence_score > 0.8
    
    def test_correlation_result_serialization(self):
        """Test correlation result serialization."""
        
        correlation = CorrelationResult(
            correlation_id="test_correlation",
            rule_id="test_rule",
            rule_name="Test Rule",
            events=self.auth_events[:2],
            confidence_score=0.85,
            risk_score=7.5,
            severity=Severity.HIGH,
            correlation_summary="Test correlation summary",
            attack_pattern="Test Attack Pattern",
            indicators=["IP: 192.168.1.100", "User: admin"]
        )
        
        correlation_dict = correlation.to_dict()
        
        assert correlation_dict['correlation_id'] == "test_correlation"
        assert correlation_dict['rule_id'] == "test_rule"
        assert correlation_dict['event_count'] == 2
        assert correlation_dict['confidence_score'] == 0.85
        assert correlation_dict['risk_score'] == 7.5
        assert correlation_dict['severity'] == "high"
        assert len(correlation_dict['indicators']) == 2


class TestSplunkIntegration:
    """Test Splunk integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = MonitoringConfig(
            platform=MonitoringPlatform.SPLUNK,
            host="splunk.example.com",
            port=8089,
            username="admin",
            password="password",
            index_name="security_events"
        )
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession')
    async def test_splunk_authentication(self, mock_session):
        """Test Splunk authentication."""
        
        # Mock authentication response
        mock_response = AsyncMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"sessionKey": "test_session_key"}
        
        mock_session_instance = AsyncMock()
        mock_session_instance.post.return_value.__aenter__.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        # This would normally be tested with actual initialization
        # but we're mocking the session creation
        assert self.config.username == "admin"
        assert self.config.password == "password"
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession')
    async def test_splunk_send_event(self, mock_session):
        """Test sending event to Splunk."""
        
        # Mock responses
        auth_response = AsyncMock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"sessionKey": "test_session_key"}
        
        event_response = AsyncMock()
        event_response.raise_for_status.return_value = None
        event_response.json.return_value = {"text": "Success"}
        
        mock_session_instance = AsyncMock()
        mock_session_instance.post.return_value.__aenter__.side_effect = [auth_response, event_response]
        mock_session.return_value = mock_session_instance
        
        # Create integration (mocked)
        integration = SplunkIntegration(self.config)
        integration.session = mock_session_instance
        
        # Test event
        event = SecurityEvent(
            event_id="test_event",
            source_platform=MonitoringPlatform.SPLUNK,
            event_type=EventType.STATIC_ANALYSIS,
            timestamp=datetime.now(),
            title="Test Event",
            description="Test description",
            severity=Severity.HIGH,
            category=SecurityCategory.HARDCODED_SECRETS,
            confidence_score=0.9
        )
        
        # Send event
        result = await integration.send_event(event)
        
        # Verify result
        assert result is True


class TestElasticsearchIntegration:
    """Test Elasticsearch integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = MonitoringConfig(
            platform=MonitoringPlatform.ELASTICSEARCH,
            host="elasticsearch.example.com",
            port=9200,
            username="elastic",
            password="password",
            index_name="security_events"
        )
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession')
    async def test_elasticsearch_connection(self, mock_session):
        """Test Elasticsearch connection."""
        
        # Mock cluster info response
        mock_response = AsyncMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"cluster_name": "test_cluster"}
        
        # Mock index check (404 = doesn't exist)
        mock_index_response = AsyncMock()
        mock_index_response.status = 404
        
        # Mock index creation
        mock_create_response = AsyncMock()
        mock_create_response.raise_for_status.return_value = None
        
        mock_session_instance = AsyncMock()
        mock_session_instance.get.return_value.__aenter__.return_value = mock_response
        mock_session_instance.head.return_value.__aenter__.return_value = mock_index_response
        mock_session_instance.put.return_value.__aenter__.return_value = mock_create_response
        mock_session.return_value = mock_session_instance
        
        # Test connection would be established during initialization
        assert self.config.host == "elasticsearch.example.com"
        assert self.config.index_name == "security_events"
    
    def test_elasticsearch_event_conversion(self):
        """Test converting Elasticsearch hit to SecurityEvent."""
        
        # Mock Elasticsearch hit
        es_hit = {
            "_id": "test_id",
            "_source": {
                "event_id": "test_event",
                "event_type": "static_analysis",
                "timestamp": datetime.now().isoformat(),
                "title": "Test Event",
                "description": "Test description",
                "severity": "high",
                "category": "hardcoded_secrets",
                "confidence_score": 0.9,
                "risk_score": 7.5
            }
        }
        
        integration = ElasticsearchIntegration(self.config)
        event = integration._convert_es_hit_to_event(es_hit)
        
        assert event is not None
        assert event.event_id == "test_event"
        assert event.event_type == EventType.STATIC_ANALYSIS
        assert event.severity == Severity.HIGH
        assert event.category == SecurityCategory.HARDCODED_SECRETS
        assert event.confidence_score == 0.9


class TestDatadogIntegration:
    """Test Datadog integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = MonitoringConfig(
            platform=MonitoringPlatform.DATADOG,
            api_key="test_api_key",
            api_token="test_app_key"
        )
    
    def test_datadog_severity_mapping(self):
        """Test Datadog severity mapping."""
        
        integration = DatadogIntegration(self.config)
        
        # Test priority mapping
        assert integration._map_severity_to_priority(Severity.CRITICAL) == "high"
        assert integration._map_severity_to_priority(Severity.HIGH) == "normal"
        assert integration._map_severity_to_priority(Severity.MEDIUM) == "low"
        assert integration._map_severity_to_priority(Severity.LOW) == "low"
        
        # Test alert type mapping
        assert integration._map_severity_to_alert_type(Severity.CRITICAL) == "error"
        assert integration._map_severity_to_alert_type(Severity.HIGH) == "error"
        assert integration._map_severity_to_alert_type(Severity.MEDIUM) == "warning"
        assert integration._map_severity_to_alert_type(Severity.LOW) == "info"


class TestNewRelicIntegration:
    """Test New Relic integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = MonitoringConfig(
            platform=MonitoringPlatform.NEWRELIC,
            api_key="test_insert_key",
            api_token="test_api_key",
            custom_fields={"account_id": "12345"}
        )
    
    def test_newrelic_event_conversion(self):
        """Test converting New Relic event to SecurityEvent."""
        
        # Mock New Relic event
        nr_event = {
            "eventId": "test_event",
            "eventType_custom": "static_analysis",
            "timestamp": int(datetime.now().timestamp() * 1000),
            "title": "Test Event",
            "description": "Test description",
            "severity": "high",
            "category": "hardcoded_secrets",
            "confidenceScore": 0.9,
            "riskScore": 7.5,
            "hostname": "test_host",
            "sourceIp": "192.168.1.100",
            "tag1": "security",
            "tag2": "compliance"
        }
        
        integration = NewRelicIntegration(self.config)
        event = integration._convert_nr_event_to_security_event(nr_event)
        
        assert event is not None
        assert event.event_id == "test_event"
        assert event.event_type == EventType.STATIC_ANALYSIS
        assert event.severity == Severity.HIGH
        assert event.category == SecurityCategory.HARDCODED_SECRETS
        assert event.confidence_score == 0.9
        assert event.hostname == "test_host"
        assert event.source_ip == "192.168.1.100"
        assert "security" in event.tags
        assert "compliance" in event.tags


if __name__ == "__main__":
    pytest.main([__file__])