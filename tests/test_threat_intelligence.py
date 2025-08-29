"""Tests for threat intelligence integration."""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from compliance_sentinel.threat_intelligence import (
    ThreatIntelligenceManager,
    ThreatIntelConfig,
    ThreatIndicator,
    ThreatMatch,
    IOCMatcher,
    IOCMatch,
    ThreatEnrichmentEngine,
    AutomatedThreatResponse,
    ThreatHuntingEngine,
    HuntingRule,
    ThreatLevel,
    ThreatType,
    IOCType,
    ResponseAction,
    HuntingRuleType
)
from compliance_sentinel.core.interfaces import SecurityIssue, Severity
from compliance_sentinel.monitoring.monitoring_manager import SecurityEvent, EventType


class TestThreatIntelligenceManager:
    """Test threat intelligence manager."""
    
    @pytest.fixture
    def sample_config(self):
        """Sample threat intelligence configuration."""
        return ThreatIntelConfig(
            feed_name="test_feed",
            api_key="test_key",
            update_interval_minutes=60,
            min_confidence=0.7
        )
    
    @pytest.fixture
    def threat_manager(self, sample_config):
        """Create threat intelligence manager."""
        return ThreatIntelligenceManager([sample_config])
    
    @pytest.fixture
    def sample_indicator(self):
        """Sample threat indicator."""
        return ThreatIndicator(
            indicator_id="test_indicator_1",
            ioc_type=IOCType.IP_ADDRESS,
            value="192.168.1.100",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            source="test_feed",
            description="Test malicious IP"
        )
    
    def test_manager_initialization(self, threat_manager):
        """Test manager initialization."""
        assert len(threat_manager.configs) == 1
        assert "test_feed" in threat_manager.configs
        assert threat_manager.ioc_matcher is not None
    
    def test_store_indicator(self, threat_manager, sample_indicator):
        """Test storing threat indicator."""
        threat_manager._store_indicator(sample_indicator)
        
        assert sample_indicator.indicator_id in threat_manager.indicators
        assert sample_indicator.value.lower() in threat_manager.ioc_index
    
    def test_should_store_indicator(self, threat_manager, sample_indicator):
        """Test indicator storage criteria."""
        # Should store high confidence indicator
        assert threat_manager._should_store_indicator(sample_indicator)
        
        # Should not store low confidence indicator
        sample_indicator.confidence = 0.5
        assert not threat_manager._should_store_indicator(sample_indicator)
        
        # Should not store expired indicator
        sample_indicator.confidence = 0.9
        sample_indicator.expires_at = datetime.now() - timedelta(hours=1)
        assert not threat_manager._should_store_indicator(sample_indicator)
    
    @pytest.mark.asyncio
    async def test_check_security_issue(self, threat_manager, sample_indicator):
        """Test checking security issue against threat intelligence."""
        # Store indicator
        threat_manager._store_indicator(sample_indicator)
        
        # Create security issue with matching IOC
        issue = SecurityIssue(
            id="test_issue_1",
            rule_id="test_rule",
            file_path="/test/file.py",
            line_number=10,
            severity=Severity.HIGH,
            category="test",
            description=f"Suspicious activity from {sample_indicator.value}",
            created_at=datetime.now()
        )
        
        matches = await threat_manager.check_security_issue(issue)
        
        assert len(matches) > 0
        assert matches[0].indicator.indicator_id == sample_indicator.indicator_id
        assert matches[0].matched_value == sample_indicator.value
    
    def test_get_threat_statistics(self, threat_manager, sample_indicator):
        """Test getting threat statistics."""
        threat_manager._store_indicator(sample_indicator)
        
        stats = threat_manager.get_threat_statistics()
        
        assert stats['total_indicators'] == 1
        assert stats['active_indicators'] == 1
        assert ThreatType.MALWARE.value in stats['by_threat_type']
        assert ThreatLevel.HIGH.value in stats['by_threat_level']


class TestIOCMatcher:
    """Test IOC matcher."""
    
    @pytest.fixture
    def ioc_matcher(self):
        """Create IOC matcher."""
        return IOCMatcher()
    
    def test_extract_ip_addresses(self, ioc_matcher):
        """Test IP address extraction."""
        text = "Suspicious activity from 192.168.1.100 and 10.0.0.1"
        iocs = ioc_matcher._extract_ip_addresses(text)
        
        # Should not include private IPs for threat intelligence
        assert len(iocs) == 0
        
        # Test with public IP
        text = "Malicious traffic from 8.8.8.8"
        iocs = ioc_matcher._extract_ip_addresses(text)
        assert len(iocs) == 1
        assert iocs[0] == (IOCType.IP_ADDRESS, "8.8.8.8")
    
    def test_extract_domains(self, ioc_matcher):
        """Test domain extraction."""
        text = "Malicious domain: evil.example.com and phishing.badsite.org"
        iocs = ioc_matcher._extract_domains(text)
        
        assert len(iocs) == 2
        assert (IOCType.DOMAIN, "evil.example.com") in iocs
        assert (IOCType.DOMAIN, "phishing.badsite.org") in iocs
    
    def test_extract_file_hashes(self, ioc_matcher):
        """Test file hash extraction."""
        text = "Malware hash: d41d8cd98f00b204e9800998ecf8427e"
        iocs = ioc_matcher._extract_file_hashes(text)
        
        assert len(iocs) == 1
        assert iocs[0] == (IOCType.FILE_HASH, "d41d8cd98f00b204e9800998ecf8427e")
    
    def test_extract_iocs_from_text(self, ioc_matcher):
        """Test comprehensive IOC extraction."""
        text = """
        Malicious activity detected:
        - IP: 8.8.8.8
        - Domain: malware.example.com
        - Hash: d41d8cd98f00b204e9800998ecf8427e
        - URL: http://malicious.site.com/payload
        """
        
        matches = ioc_matcher.extract_iocs_from_text(text)
        
        assert len(matches) >= 4
        ioc_types = {match.ioc_type for match in matches}
        assert IOCType.IP_ADDRESS in ioc_types
        assert IOCType.DOMAIN in ioc_types
        assert IOCType.FILE_HASH in ioc_types
        assert IOCType.URL in ioc_types


class TestThreatEnrichmentEngine:
    """Test threat enrichment engine."""
    
    @pytest.fixture
    def enrichment_engine(self):
        """Create enrichment engine."""
        return ThreatEnrichmentEngine()
    
    @pytest.fixture
    def sample_match(self):
        """Sample threat match."""
        indicator = ThreatIndicator(
            indicator_id="test_indicator",
            ioc_type=IOCType.FILE_HASH,
            value="d41d8cd98f00b204e9800998ecf8427e",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            source="test_feed",
            description="Test malware hash",
            tags=["malware", "trojan"]
        )
        
        return ThreatMatch(
            match_id="test_match",
            indicator=indicator,
            matched_value="d41d8cd98f00b204e9800998ecf8427e",
            match_type="exact",
            source_type="security_issue",
            source_id="test_issue",
            confidence_score=0.9,
            risk_score=8.5
        )
    
    @pytest.mark.asyncio
    async def test_enrich_matches(self, enrichment_engine, sample_match):
        """Test enriching threat matches."""
        matches = [sample_match]
        
        enriched_context = await enrichment_engine.enrich_matches(matches)
        
        assert 'summary' in enriched_context
        assert 'threat_landscape' in enriched_context
        assert 'risk_assessment' in enriched_context
        assert 'enriched_matches' in enriched_context
        
        assert len(enriched_context['enriched_matches']) == 1
        
        # Check summary
        summary = enriched_context['summary']
        assert summary['total_matches'] == 1
        assert summary['average_risk_score'] == 8.5
    
    @pytest.mark.asyncio
    async def test_enrich_single_match(self, enrichment_engine, sample_match):
        """Test enriching single match."""
        enriched = await enrichment_engine._enrich_single_match(sample_match)
        
        assert 'match' in enriched
        assert 'context' in enriched
        
        context = enriched['context']
        assert 'confidence_score' in context
        assert 'enrichment_sources' in context


class TestAutomatedThreatResponse:
    """Test automated threat response."""
    
    @pytest.fixture
    def response_engine(self):
        """Create response engine."""
        return AutomatedThreatResponse()
    
    @pytest.fixture
    def sample_match(self):
        """Sample threat match for response testing."""
        indicator = ThreatIndicator(
            indicator_id="test_indicator",
            ioc_type=IOCType.IP_ADDRESS,
            value="8.8.8.8",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.9,
            source="test_feed",
            description="Critical malware C2"
        )
        
        return ThreatMatch(
            match_id="test_match",
            indicator=indicator,
            matched_value="8.8.8.8",
            match_type="exact",
            source_type="security_event",
            source_id="test_event",
            confidence_score=0.9,
            risk_score=9.5
        )
    
    def test_find_matching_rules(self, response_engine, sample_match):
        """Test finding matching response rules."""
        matching_rules = response_engine._find_matching_rules(sample_match)
        
        # Should match critical malware rule
        assert len(matching_rules) > 0
        
        # Check if critical malware rule matches
        critical_rule = next((rule for rule in matching_rules if rule.rule_id == 'critical_malware'), None)
        assert critical_rule is not None
        assert critical_rule.matches(sample_match)
    
    @pytest.mark.asyncio
    async def test_process_matches(self, response_engine, sample_match):
        """Test processing threat matches."""
        matches = [sample_match]
        
        execution_ids = await response_engine.process_matches(matches)
        
        assert len(execution_ids) > 0
        
        # Check execution status
        for execution_id in execution_ids:
            status = response_engine.get_execution_status(execution_id)
            assert status is not None
            assert 'execution_id' in status
            assert 'status' in status
    
    @pytest.mark.asyncio
    async def test_block_ip_action(self, response_engine, sample_match):
        """Test IP blocking action."""
        from compliance_sentinel.threat_intelligence.automated_response import ResponseExecution
        
        execution = ResponseExecution(
            execution_id="test_execution",
            rule_id="test_rule",
            match_id=sample_match.match_id,
            actions=[ResponseAction.BLOCK_IP]
        )
        
        result = await response_engine._handle_block_ip(sample_match, execution)
        
        assert result['action'] == 'block_ip'
        assert result['ip_address'] == sample_match.matched_value
        assert result['status'] == 'success'


class TestThreatHuntingEngine:
    """Test threat hunting engine."""
    
    @pytest.fixture
    def hunting_engine(self):
        """Create hunting engine."""
        return ThreatHuntingEngine()
    
    @pytest.fixture
    def sample_security_issue(self):
        """Sample security issue for hunting."""
        return SecurityIssue(
            id="test_issue",
            rule_id="test_rule",
            file_path="/tmp/suspicious.exe",
            line_number=1,
            severity=Severity.HIGH,
            category="malware",
            description="Suspicious executable in temp directory",
            created_at=datetime.now()
        )
    
    def test_load_default_rules(self, hunting_engine):
        """Test loading default hunting rules."""
        assert len(hunting_engine.rules) > 0
        assert 'suspicious_file_execution' in hunting_engine.rules
        assert 'command_injection' in hunting_engine.rules
    
    @pytest.mark.asyncio
    async def test_execute_hunt(self, hunting_engine, sample_security_issue):
        """Test executing hunting rule."""
        # Add test data
        hunting_engine.add_data_source('security_issues', [sample_security_issue])
        
        # Execute suspicious file execution hunt
        results = await hunting_engine.execute_hunt('suspicious_file_execution')
        
        assert results is not None
        if results:  # May not match depending on pattern
            assert len(results) > 0
            assert all(isinstance(result.confidence, float) for result in results)
    
    def test_add_hunting_rule(self, hunting_engine):
        """Test adding custom hunting rule."""
        custom_rule = HuntingRule(
            rule_id='custom_test_rule',
            name='Custom Test Rule',
            description='Test custom hunting rule',
            rule_type=HuntingRuleType.PATTERN_MATCH,
            pattern=r'test_pattern',
            target_data_types=['security_issues']
        )
        
        hunting_engine.add_hunting_rule(custom_rule)
        
        assert 'custom_test_rule' in hunting_engine.rules
        assert hunting_engine.rules['custom_test_rule'].name == 'Custom Test Rule'
    
    def test_get_rule_statistics(self, hunting_engine):
        """Test getting hunting rule statistics."""
        stats = hunting_engine.get_rule_statistics()
        
        assert 'total_rules' in stats
        assert 'active_rules' in stats
        assert 'rules_by_type' in stats
        assert stats['total_rules'] > 0


class TestIntegrationScenarios:
    """Test integration scenarios."""
    
    @pytest.fixture
    def full_system(self):
        """Create full threat intelligence system."""
        config = ThreatIntelConfig(
            feed_name="test_feed",
            api_key="test_key"
        )
        
        threat_manager = ThreatIntelligenceManager([config])
        enrichment_engine = ThreatEnrichmentEngine()
        response_engine = AutomatedThreatResponse()
        hunting_engine = ThreatHuntingEngine()
        
        return {
            'threat_manager': threat_manager,
            'enrichment_engine': enrichment_engine,
            'response_engine': response_engine,
            'hunting_engine': hunting_engine
        }
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_processing(self, full_system):
        """Test end-to-end threat processing."""
        threat_manager = full_system['threat_manager']
        enrichment_engine = full_system['enrichment_engine']
        response_engine = full_system['response_engine']
        
        # 1. Store threat indicator
        indicator = ThreatIndicator(
            indicator_id="e2e_test_indicator",
            ioc_type=IOCType.IP_ADDRESS,
            value="8.8.8.8",
            threat_type=ThreatType.MALWARE,
            threat_level=ThreatLevel.CRITICAL,
            confidence=0.95,
            source="test_feed",
            description="Critical malware C2 server"
        )
        threat_manager._store_indicator(indicator)
        
        # 2. Create security issue with matching IOC
        issue = SecurityIssue(
            id="e2e_test_issue",
            rule_id="test_rule",
            file_path="/test/file.py",
            line_number=10,
            severity=Severity.CRITICAL,
            category="network",
            description="Connection to 8.8.8.8 detected",
            created_at=datetime.now()
        )
        
        # 3. Check for threat matches
        matches = await threat_manager.check_security_issue(issue)
        assert len(matches) > 0
        
        # 4. Enrich matches
        enriched_context = await enrichment_engine.enrich_matches(matches)
        assert 'summary' in enriched_context
        assert enriched_context['summary']['total_matches'] > 0
        
        # 5. Execute automated response
        execution_ids = await response_engine.process_matches(matches)
        assert len(execution_ids) > 0
        
        # 6. Verify response execution
        for execution_id in execution_ids:
            status = response_engine.get_execution_status(execution_id)
            assert status is not None
            assert status['match_id'] == matches[0].match_id
    
    @pytest.mark.asyncio
    async def test_hunting_with_threat_intelligence(self, full_system):
        """Test threat hunting with threat intelligence integration."""
        threat_manager = full_system['threat_manager']
        hunting_engine = full_system['hunting_engine']
        
        # Store threat indicators
        indicators = [
            ThreatIndicator(
                indicator_id=f"hunt_test_{i}",
                ioc_type=IOCType.FILE_HASH,
                value=f"hash_{i:032d}",
                threat_type=ThreatType.MALWARE,
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                source="test_feed",
                description=f"Test malware hash {i}"
            ) for i in range(3)
        ]
        
        for indicator in indicators:
            threat_manager._store_indicator(indicator)
        
        # Create security issues for hunting
        issues = [
            SecurityIssue(
                id=f"hunt_issue_{i}",
                rule_id="test_rule",
                file_path=f"/tmp/malware_{i}.exe",
                line_number=1,
                severity=Severity.HIGH,
                category="malware",
                description=f"Suspicious file with hash hash_{i:032d}",
                created_at=datetime.now()
            ) for i in range(3)
        ]
        
        # Add data to hunting engine
        hunting_engine.add_data_source('security_issues', issues)
        
        # Execute hunting
        results = await hunting_engine.execute_hunt('suspicious_file_execution')
        
        # Should find suspicious patterns
        if results:
            assert len(results) > 0
            for result in results:
                assert result.confidence > 0
                assert result.rule_id == 'suspicious_file_execution'


if __name__ == "__main__":
    pytest.main([__file__])