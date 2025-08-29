"""Comprehensive integration tests for real-time data integration."""

import os
import asyncio
import pytest
import tempfile
import time
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path

from compliance_sentinel.config.dynamic_config import DynamicConfigManager
from compliance_sentinel.providers.vulnerability_provider import NVDVulnerabilityProvider
from compliance_sentinel.providers.compliance_provider import OWASPComplianceProvider
from compliance_sentinel.utils.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from compliance_sentinel.utils.intelligent_cache import IntelligentCache
from compliance_sentinel.sync.data_synchronizer import DataSynchronizer
from compliance_sentinel.monitoring.real_time_metrics import RealTimeMetrics
from compliance_sentinel.utils.resilient_error_handler import ResilientErrorHandler
from compliance_sentinel.testing.production_data_validator import ProductionDataValidator


class TestRealTimeDataIntegration:
    """Integration tests for real-time data integration components."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create config sources for testing
        from compliance_sentinel.config.dynamic_config import EnvironmentConfigSource
        env_source = EnvironmentConfigSource()
        
        self.config_manager = DynamicConfigManager([env_source])
        self.cache = IntelligentCache()
        self.metrics = RealTimeMetrics()
        self.error_handler = ResilientErrorHandler()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_vulnerability_data_fetching_with_fallback(self):
        """Test real vulnerability data fetching with fallback mechanisms."""
        # Configure provider with test settings
        config = {
            "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "timeout": 5,
            "max_retries": 2,
            "circuit_breaker_failure_threshold": 3
        }
        
        provider = NVDVulnerabilityProvider(config, self.cache)
        await provider.initialize(config)
        
        try:
            # Test successful data fetching
            from compliance_sentinel.providers.data_provider import DataRequest
            request = DataRequest(
                request_type="get_recent_vulnerabilities",
                parameters={"days_back": 1, "limit": 5},
                cache_key="test_recent_vulns"
            )
            
            response = await provider._fetch_data(request)
            
            # Should either succeed or use fallback
            assert response.success or response.metadata.get("fallback_used")
            
            if response.success and not response.metadata.get("fallback_used"):
                # If we got real data, verify structure
                assert isinstance(response.data, list)
                if response.data:
                    vuln = response.data[0]
                    assert hasattr(vuln, 'cve_id') or 'cve_id' in vuln
            
        finally:
            await provider.shutdown()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker behavior with external services."""
        # Create circuit breaker with low threshold for testing
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1,
            success_threshold=1,
            timeout=1
        )
        
        circuit_breaker = CircuitBreaker("test_service", config)
        
        # Function that always fails
        async def failing_operation():
            raise Exception("Service unavailable")
        
        # Function that succeeds
        async def successful_operation():
            return "success"
        
        # Trip the circuit breaker
        for _ in range(3):
            try:
                await circuit_breaker.call(failing_operation)
            except:
                pass
        
        # Circuit should be open now
        assert circuit_breaker.get_state().name == "OPEN"
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        
        # Should be in half-open state
        assert circuit_breaker.get_state().name == "HALF_OPEN"
        
        # Successful call should close the circuit
        result = await circuit_breaker.call(successful_operation)
        assert result == "success"
        assert circuit_breaker.get_state().name == "CLOSED"    

    @pytest.mark.asyncio
    async def test_cache_invalidation_behavior(self):
        """Test cache invalidation and refresh behavior."""
        cache = IntelligentCache()
        
        # Set initial data
        cache.set("test_key", "initial_value", ttl=60)
        assert cache.get("test_key") == "initial_value"
        
        # Test pattern-based invalidation
        cache.set("user:123:profile", {"name": "John"}, ttl=60)
        cache.set("user:456:profile", {"name": "Jane"}, ttl=60)
        cache.set("product:789", {"name": "Widget"}, ttl=60)
        
        # Invalidate all user profiles
        invalidated = cache.invalidate_pattern("user:*:profile")
        assert invalidated >= 2
        
        # User profiles should be gone, product should remain
        assert cache.get("user:123:profile") is None
        assert cache.get("user:456:profile") is None
        assert cache.get("product:789") is not None
        
        # Test TTL-based expiration
        cache.set("short_lived", "value", ttl=0.1)  # 100ms
        assert cache.get("short_lived") == "value"
        
        await asyncio.sleep(0.2)  # Wait for expiration
        assert cache.get("short_lived") is None
    
    @pytest.mark.asyncio
    async def test_data_synchronization_workflow(self):
        """Test complete data synchronization workflow."""
        # Mock data source
        mock_data_source = AsyncMock()
        mock_data_source.fetch_data.return_value = [
            {"id": "CVE-2024-001", "severity": "HIGH"},
            {"id": "CVE-2024-002", "severity": "MEDIUM"}
        ]
        
        # Create synchronizer
        sync_config = {
            "sync_interval": 0.1,  # 100ms for testing
            "batch_size": 10,
            "max_retries": 2
        }
        
        synchronizer = DataSynchronizer(sync_config)
        
        # Track updates
        updates_received = []
        
        def update_callback(data):
            updates_received.extend(data)
        
        synchronizer.add_update_callback(update_callback)
        
        # Start synchronization
        await synchronizer.start()
        
        try:
            # Trigger sync
            await synchronizer.sync_data_source("vulnerabilities", mock_data_source.fetch_data)
            
            # Wait for callback
            await asyncio.sleep(0.2)
            
            # Verify data was synchronized
            assert len(updates_received) >= 2
            assert any(item["id"] == "CVE-2024-001" for item in updates_received)
            
        finally:
            await synchronizer.stop()
    
    @pytest.mark.asyncio
    async def test_configuration_hot_reload(self):
        """Test configuration hot-reloading functionality."""
        # Create temporary config file
        config_file = Path(self.temp_dir) / "test_config.json"
        initial_config = {
            "cache_ttl": 300,
            "max_retries": 3,
            "timeout": 30
        }
        
        with open(config_file, 'w') as f:
            import json
            json.dump(initial_config, f)
        
        # Set up file watcher (mock)
        config_manager = DynamicConfigManager()
        
        # Load initial config
        config = config_manager.get_system_config()
        initial_cache_ttl = config.get("cache_ttl", 3600)
        
        # Simulate config change via environment variable
        with patch.dict(os.environ, {"COMPLIANCE_SENTINEL_CACHE_TTL": "600"}):
            config_manager.reload_configuration()
            updated_config = config_manager.get_system_config()
            
            # Should reflect the new value
            assert updated_config.get("cache_ttl") != initial_cache_ttl
    
    @pytest.mark.asyncio
    async def test_error_handling_with_metrics(self):
        """Test error handling integration with metrics collection."""
        metrics = RealTimeMetrics()
        error_handler = ResilientErrorHandler()
        
        # Register error metrics
        metrics.register_metric("service_errors", "counter", "Service error count")
        metrics.register_metric("fallback_usage", "counter", "Fallback usage count")
        
        # Simulate service error
        async def failing_service():
            metrics.increment_counter("service_errors")
            raise Exception("Service failure")
        
        # Handle error with fallback
        from compliance_sentinel.utils.resilient_error_handler import ErrorContext
        context = ErrorContext(
            operation="test_operation",
            service="test_service"
        )
        
        result = await error_handler.execute_with_fallback(
            failing_service,
            context,
            fallback_data={"status": "fallback"}
        )
        
        if result.fallback_used:
            metrics.increment_counter("fallback_usage")
        
        # Verify metrics were recorded
        error_count = metrics.get_metric_value("service_errors")
        assert error_count >= 1
        
        if result.fallback_used:
            fallback_count = metrics.get_metric_value("fallback_usage")
            assert fallback_count >= 1
    
    @pytest.mark.asyncio
    async def test_production_data_validation_integration(self):
        """Test production data validation in integration context."""
        validator = ProductionDataValidator()
        
        # Create test file with potential issues
        test_file = Path(self.temp_dir) / "test_code.py"
        test_content = '''
import os

# This should be flagged in production
API_KEY = "test-api-key-12345"
DATABASE_URL = "postgresql://user:test-password@localhost/db"

def get_config():
    return {
        "api_key": API_KEY,
        "db_url": DATABASE_URL
    }
'''
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Run validation
        issues = validator.validate_file(str(test_file))
        
        # Should detect test data patterns
        assert len(issues) > 0
        
        # Check that issues are properly categorized
        api_key_issues = [issue for issue in issues if "api" in issue.description.lower()]
        password_issues = [issue for issue in issues if "password" in issue.description.lower()]
        
        assert len(api_key_issues) > 0 or len(password_issues) > 0
        
        # Verify recommendations are provided
        for issue in issues:
            assert issue.recommendation
            assert len(issue.recommendation) > 10
    
    @pytest.mark.asyncio
    async def test_end_to_end_vulnerability_workflow(self):
        """Test complete end-to-end vulnerability data workflow."""
        # Set up components
        cache = IntelligentCache()
        metrics = RealTimeMetrics()
        
        # Configure vulnerability provider
        config = {
            "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "timeout": 10,
            "max_retries": 1,
            "circuit_breaker_failure_threshold": 5
        }
        
        provider = NVDVulnerabilityProvider(config, cache)
        await provider.initialize(config)
        
        try:
            # Test the complete workflow
            from compliance_sentinel.providers.data_provider import DataRequest
            
            # 1. Fetch recent vulnerabilities
            request = DataRequest(
                request_type="get_recent_vulnerabilities",
                parameters={"days_back": 1, "limit": 3},
                cache_key="integration_test_vulns"
            )
            
            start_time = time.time()
            response = await provider._fetch_data(request)
            duration = time.time() - start_time
            
            # Record metrics
            metrics.record_metric("vulnerability_fetch_duration", duration * 1000)
            metrics.increment_counter("vulnerability_requests")
            
            if response.success:
                metrics.increment_counter("vulnerability_requests_success")
                
                # 2. Verify data structure
                if response.data:
                    vuln = response.data[0]
                    if hasattr(vuln, 'cve_id'):
                        assert vuln.cve_id.startswith('CVE-')
                    elif isinstance(vuln, dict) and 'cve_id' in vuln:
                        assert vuln['cve_id'].startswith('CVE-')
                
                # 3. Test caching
                cached_response = await provider._fetch_data(request)
                assert cached_response.success
                
            else:
                metrics.increment_counter("vulnerability_requests_failed")
                
                # Should have fallback information
                if response.metadata.get("fallback_used"):
                    metrics.increment_counter("vulnerability_fallback_used")
            
            # 4. Verify metrics were recorded
            request_count = metrics.get_metric_value("vulnerability_requests")
            assert request_count >= 1
            
            fetch_duration = metrics.get_metric_value("vulnerability_fetch_duration")
            assert fetch_duration is not None
            assert fetch_duration > 0
            
        finally:
            await provider.shutdown()
    
    @pytest.mark.asyncio
    async def test_compliance_data_integration(self):
        """Test compliance data integration workflow."""
        cache = IntelligentCache()
        
        # Configure compliance provider
        config = {
            "timeout": 10
        }
        
        provider = OWASPComplianceProvider(config, cache)
        await provider.initialize(config)
        
        try:
            from compliance_sentinel.providers.data_provider import DataRequest
            
            # Test OWASP Top 10 requirements
            request = DataRequest(
                request_type="get_owasp_top_10",
                parameters={},
                cache_key="integration_test_owasp"
            )
            
            response = await provider._fetch_data(request)
            
            # Should succeed (using built-in data)
            assert response.success
            assert isinstance(response.data, list)
            assert len(response.data) > 0
            
            # Verify requirement structure
            requirement = response.data[0]
            assert hasattr(requirement, 'requirement_id') or 'requirement_id' in requirement
            assert hasattr(requirement, 'title') or 'title' in requirement
            
            # Test compliance checking
            check_request = DataRequest(
                request_type="check_compliance",
                parameters={
                    "code_patterns": ["password = 'hardcoded'"],
                    "vulnerabilities": [{"category": "authentication"}]
                },
                cache_key="integration_test_compliance_check"
            )
            
            check_response = await provider._fetch_data(check_request)
            assert check_response.success
            
            # Should return compliance result
            result = check_response.data
            assert hasattr(result, 'framework') or 'framework' in result
            assert hasattr(result, 'overall_score') or 'overall_score' in result
            
        finally:
            await provider.shutdown()


if __name__ == "__main__":
    pytest.main([__file__])