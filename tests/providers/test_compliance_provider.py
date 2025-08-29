"""Tests for compliance data provider."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime
import httpx

from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
from compliance_sentinel.providers.data_provider import DataRequest, DataResponse
from compliance_sentinel.utils.intelligent_cache import IntelligentCache


class TestComplianceDataProvider:
    """Test compliance data provider functionality."""
    
    @pytest.fixture
    def mock_cache_manager(self):
        """Create mock cache manager."""
        return MagicMock(spec=IntelligentCache)
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client."""
        client = AsyncMock(spec=httpx.AsyncClient)
        
        # Default successful response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "framework": "OWASP",
            "version": "4.0",
            "categories": [
                {
                    "id": "A01",
                    "name": "Broken Access Control",
                    "description": "Access control enforces policy...",
                    "requirements": [
                        {
                            "id": "A01.1",
                            "title": "Implement proper access controls",
                            "description": "Ensure that access controls are properly implemented"
                        }
                    ]
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        client.get.return_value = mock_response
        
        return client
    
    @pytest.fixture
    def provider_config(self):
        """Create provider configuration."""
        return {
            "owasp_base_url": "https://owasp.org/api",
            "nist_base_url": "https://csrc.nist.gov/api",
            "pci_base_url": "https://pcisecuritystandards.org/api",
            "request_timeout": 30.0,
            "rate_limit": 50,
            "api_key": None
        }
    
    @pytest.fixture
    def compliance_provider(self, provider_config, mock_cache_manager):
        """Create compliance data provider."""
        return ComplianceDataProvider(
            config=provider_config,
            cache_manager=mock_cache_manager
        )
    
    @pytest.mark.asyncio
    async def test_provider_initialization(self, compliance_provider):
        """Test provider initialization."""
        result = await compliance_provider.initialize()
        assert result is True
        assert compliance_provider.name == "compliance-framework-provider"
    
    @pytest.mark.asyncio
    async def test_health_check(self, compliance_provider, mock_http_client):
        """Test provider health check."""
        compliance_provider.session = mock_http_client
        
        # Mock successful health check response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_http_client.get.return_value = mock_response
        
        result = await compliance_provider.health_check()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, compliance_provider, mock_http_client):
        """Test provider health check failure."""
        compliance_provider.session = mock_http_client
        
        # Mock failed health check
        mock_http_client.get.side_effect = httpx.ConnectError("Connection failed")
        
        result = await compliance_provider.health_check()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_framework_requirements(self, compliance_provider, mock_http_client):
        """Test getting framework requirements."""
        compliance_provider.session = mock_http_client
        
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": "OWASP", "version": "4.0"}
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data is not None
        assert response.provider_name == "compliance-framework-provider"
        
        # Verify HTTP client was called
        mock_http_client.get.assert_called()
    
    @pytest.mark.asyncio
    async def test_check_compliance(self, compliance_provider, mock_http_client):
        """Test compliance checking functionality."""
        compliance_provider.session = mock_http_client
        
        # Mock compliance check response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "compliance_status": "partial",
            "score": 75.5,
            "passed_requirements": 15,
            "total_requirements": 20,
            "failed_requirements": [
                {
                    "id": "A01.1",
                    "title": "Access Control",
                    "reason": "Missing implementation"
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.post.return_value = mock_response
        
        request = DataRequest(
            request_type="check_compliance",
            parameters={
                "framework": "OWASP",
                "version": "4.0",
                "assessment_data": {"controls": ["A01", "A02"]}
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data is not None
        assert response.data["compliance_status"] == "partial"
        assert response.data["score"] == 75.5
    
    @pytest.mark.asyncio
    async def test_get_control_details(self, compliance_provider, mock_http_client):
        """Test getting control details."""
        compliance_provider.session = mock_http_client
        
        # Mock control details response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "control_id": "A01",
            "name": "Broken Access Control",
            "description": "Detailed description of access control requirements",
            "implementation_guidance": "Step-by-step implementation guide",
            "testing_procedures": ["Test 1", "Test 2"],
            "references": ["NIST SP 800-53", "ISO 27001"]
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.get.return_value = mock_response
        
        request = DataRequest(
            request_type="get_control_details",
            parameters={
                "framework": "OWASP",
                "control_id": "A01"
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data is not None
        assert response.data["control_id"] == "A01"
        assert "implementation_guidance" in response.data
    
    @pytest.mark.asyncio
    async def test_get_framework_mapping(self, compliance_provider, mock_http_client):
        """Test getting framework mapping."""
        compliance_provider.session = mock_http_client
        
        # Mock framework mapping response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "source_framework": "OWASP",
            "target_framework": "NIST",
            "mappings": [
                {
                    "source_control": "A01",
                    "target_controls": ["AC-1", "AC-2", "AC-3"],
                    "mapping_strength": "strong"
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.get.return_value = mock_response
        
        request = DataRequest(
            request_type="get_framework_mapping",
            parameters={
                "source_framework": "OWASP",
                "target_framework": "NIST"
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data is not None
        assert response.data["source_framework"] == "OWASP"
        assert response.data["target_framework"] == "NIST"
        assert len(response.data["mappings"]) > 0
    
    @pytest.mark.asyncio
    async def test_caching_integration(self, compliance_provider, mock_http_client, mock_cache_manager):
        """Test caching integration."""
        compliance_provider.session = mock_http_client
        
        # Mock cache miss first, then hit
        mock_cache_manager.get.side_effect = [None, {"data": {"cached": True}}]
        
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": "OWASP", "version": "4.0"}
        )
        
        # First request - should hit external API and cache result
        response1 = await compliance_provider.get_data(request)
        assert response1.success is True
        
        # Verify cache was set
        mock_cache_manager.set.assert_called()
        
        # Second request - should use cache
        response2 = await compliance_provider.get_data(request)
        assert response2.success is True
        assert response2.data == {"cached": True}
    
    @pytest.mark.asyncio
    async def test_multiple_frameworks_support(self, compliance_provider, mock_http_client):
        """Test support for multiple compliance frameworks."""
        compliance_provider.session = mock_http_client
        
        frameworks = ["OWASP", "NIST", "PCI-DSS", "ISO27001", "SOC2"]
        
        for framework in frameworks:
            # Mock framework-specific response
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "framework": framework,
                "version": "latest",
                "requirements": [{"id": f"{framework}-001", "title": f"{framework} requirement"}]
            }
            mock_response.raise_for_status.return_value = None
            mock_http_client.get.return_value = mock_response
            
            request = DataRequest(
                request_type="get_framework_requirements",
                parameters={"framework": framework}
            )
            
            response = await compliance_provider.get_data(request)
            
            assert response.success is True
            assert response.data["framework"] == framework
    
    @pytest.mark.asyncio
    async def test_error_handling(self, compliance_provider, mock_http_client):
        """Test error handling for failed requests."""
        compliance_provider.session = mock_http_client
        
        # Mock HTTP error
        mock_http_client.get.side_effect = httpx.HTTPStatusError(
            "Not found", request=MagicMock(), response=MagicMock(status_code=404)
        )
        
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": "INVALID_FRAMEWORK"}
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is False
        assert response.error is not None
        assert "404" in response.error or "not found" in response.error.lower()
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, compliance_provider, mock_http_client):
        """Test timeout handling."""
        compliance_provider.session = mock_http_client
        
        # Mock timeout
        mock_http_client.get.side_effect = httpx.TimeoutException("Request timeout")
        
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": "OWASP"}
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is False
        assert response.error is not None
        assert "timeout" in response.error.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, compliance_provider, mock_http_client):
        """Test rate limiting functionality."""
        compliance_provider.session = mock_http_client
        compliance_provider.rate_limit = 2  # Very low limit for testing
        
        requests = [
            DataRequest(
                request_type="get_framework_requirements",
                parameters={"framework": f"FRAMEWORK_{i}"}
            )
            for i in range(5)
        ]
        
        # Make multiple requests quickly
        responses = []
        for request in requests:
            response = await compliance_provider.get_data(request)
            responses.append(response)
        
        # All should succeed (rate limiting should delay, not fail)
        assert all(r.success for r in responses)
    
    @pytest.mark.asyncio
    async def test_compliance_assessment(self, compliance_provider, mock_http_client):
        """Test comprehensive compliance assessment."""
        compliance_provider.session = mock_http_client
        
        # Mock assessment response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "assessment_id": "assess-123",
            "framework": "OWASP",
            "version": "4.0",
            "overall_score": 82.5,
            "maturity_level": "Level 3",
            "category_scores": {
                "A01": 90.0,
                "A02": 75.0,
                "A03": 80.0
            },
            "recommendations": [
                {
                    "category": "A02",
                    "priority": "high",
                    "recommendation": "Implement cryptographic failures prevention"
                }
            ],
            "assessment_date": "2023-12-01T10:00:00Z"
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.post.return_value = mock_response
        
        request = DataRequest(
            request_type="perform_assessment",
            parameters={
                "framework": "OWASP",
                "version": "4.0",
                "evidence": {
                    "A01": {"implemented": True, "evidence": "Access control documentation"},
                    "A02": {"implemented": False, "evidence": "No crypto implementation"}
                }
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data["overall_score"] == 82.5
        assert response.data["maturity_level"] == "Level 3"
        assert len(response.data["recommendations"]) > 0
    
    @pytest.mark.asyncio
    async def test_control_implementation_guidance(self, compliance_provider, mock_http_client):
        """Test getting control implementation guidance."""
        compliance_provider.session = mock_http_client
        
        # Mock implementation guidance response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "control_id": "A01",
            "framework": "OWASP",
            "implementation_steps": [
                {
                    "step": 1,
                    "title": "Design access control architecture",
                    "description": "Define access control requirements and architecture",
                    "deliverables": ["Access control policy", "Architecture diagram"]
                },
                {
                    "step": 2,
                    "title": "Implement access controls",
                    "description": "Implement the designed access controls",
                    "deliverables": ["Code implementation", "Configuration files"]
                }
            ],
            "testing_guidance": {
                "test_cases": ["Test unauthorized access", "Test privilege escalation"],
                "tools": ["OWASP ZAP", "Burp Suite"]
            },
            "common_pitfalls": [
                "Overly permissive default permissions",
                "Lack of regular access reviews"
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.get.return_value = mock_response
        
        request = DataRequest(
            request_type="get_implementation_guidance",
            parameters={
                "framework": "OWASP",
                "control_id": "A01"
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert len(response.data["implementation_steps"]) == 2
        assert "testing_guidance" in response.data
        assert "common_pitfalls" in response.data
    
    @pytest.mark.asyncio
    async def test_compliance_gap_analysis(self, compliance_provider, mock_http_client):
        """Test compliance gap analysis functionality."""
        compliance_provider.session = mock_http_client
        
        # Mock gap analysis response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "analysis_id": "gap-456",
            "framework": "NIST",
            "current_maturity": "Level 2",
            "target_maturity": "Level 4",
            "gaps": [
                {
                    "control_family": "Access Control",
                    "current_score": 60.0,
                    "target_score": 90.0,
                    "gap_size": 30.0,
                    "priority": "high",
                    "effort_estimate": "6 months"
                }
            ],
            "roadmap": [
                {
                    "phase": 1,
                    "duration": "3 months",
                    "controls": ["AC-1", "AC-2"],
                    "expected_improvement": 15.0
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_http_client.post.return_value = mock_response
        
        request = DataRequest(
            request_type="perform_gap_analysis",
            parameters={
                "framework": "NIST",
                "current_state": {"AC": 60.0, "AU": 70.0},
                "target_state": {"AC": 90.0, "AU": 85.0}
            }
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is True
        assert response.data["current_maturity"] == "Level 2"
        assert response.data["target_maturity"] == "Level 4"
        assert len(response.data["gaps"]) > 0
        assert len(response.data["roadmap"]) > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, compliance_provider, mock_http_client):
        """Test handling concurrent requests."""
        compliance_provider.session = mock_http_client
        
        requests = [
            DataRequest(
                request_type="get_framework_requirements",
                parameters={"framework": f"FRAMEWORK_{i}"}
            )
            for i in range(10)
        ]
        
        # Execute requests concurrently
        tasks = [compliance_provider.get_data(req) for req in requests]
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        assert len(responses) == 10
        assert all(r.success for r in responses)
    
    @pytest.mark.asyncio
    async def test_invalid_request_type(self, compliance_provider):
        """Test handling of invalid request types."""
        request = DataRequest(
            request_type="invalid_request_type",
            parameters={"param": "value"}
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is False
        assert response.error is not None
        assert "unsupported" in response.error.lower() or "invalid" in response.error.lower()
    
    @pytest.mark.asyncio
    async def test_missing_parameters(self, compliance_provider):
        """Test handling of missing required parameters."""
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={}  # Missing framework parameter
        )
        
        response = await compliance_provider.get_data(request)
        
        assert response.success is False
        assert response.error is not None
        assert "required" in response.error.lower() or "missing" in response.error.lower()
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, compliance_provider, mock_http_client):
        """Test that metrics are collected during operations."""
        compliance_provider.session = mock_http_client
        
        with patch('compliance_sentinel.monitoring.real_time_metrics.get_metrics') as mock_metrics:
            mock_metrics_instance = MagicMock()
            mock_metrics.return_value = mock_metrics_instance
            
            request = DataRequest(
                request_type="get_framework_requirements",
                parameters={"framework": "OWASP"}
            )
            
            await compliance_provider.get_data(request)
            
            # Verify metrics were recorded
            assert mock_metrics_instance.increment_counter.called
            assert mock_metrics_instance.record_timer.called
    
    def test_provider_configuration(self, compliance_provider):
        """Test provider configuration properties."""
        assert compliance_provider.owasp_base_url == "https://owasp.org/api"
        assert compliance_provider.nist_base_url == "https://csrc.nist.gov/api"
        assert compliance_provider.pci_base_url == "https://pcisecuritystandards.org/api"
        assert compliance_provider.request_timeout == 30.0
        assert compliance_provider.rate_limit == 50
    
    @pytest.mark.asyncio
    async def test_provider_cleanup(self, compliance_provider, mock_http_client):
        """Test provider cleanup and resource management."""
        compliance_provider.session = mock_http_client
        
        # Perform some operations
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": "OWASP"}
        )
        await compliance_provider.get_data(request)
        
        # Cleanup
        await compliance_provider.cleanup()
        
        # Verify HTTP client was closed
        mock_http_client.aclose.assert_called()


class TestComplianceDataTransformation:
    """Test compliance data transformation and normalization."""
    
    def test_owasp_data_transformation(self):
        """Test transformation of OWASP data format."""
        from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
        
        raw_owasp_data = {
            "id": "A01",
            "name": "Broken Access Control",
            "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
            "risk_factors": {
                "prevalence": "Common",
                "detectability": "Average",
                "technical_impact": "Severe"
            }
        }
        
        transformed = ComplianceDataProvider._transform_owasp_control(raw_owasp_data)
        
        assert transformed["control_id"] == "A01"
        assert transformed["title"] == "Broken Access Control"
        assert transformed["description"] == raw_owasp_data["description"]
        assert "risk_assessment" in transformed
    
    def test_nist_data_transformation(self):
        """Test transformation of NIST data format."""
        from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
        
        raw_nist_data = {
            "control_id": "AC-1",
            "control_name": "Access Control Policy and Procedures",
            "control_text": "The organization develops, documents, and disseminates...",
            "control_enhancements": [
                {
                    "enhancement_id": "AC-1(1)",
                    "enhancement_text": "Review and update procedures"
                }
            ]
        }
        
        transformed = ComplianceDataProvider._transform_nist_control(raw_nist_data)
        
        assert transformed["control_id"] == "AC-1"
        assert transformed["title"] == "Access Control Policy and Procedures"
        assert transformed["description"] == raw_nist_data["control_text"]
        assert "enhancements" in transformed
        assert len(transformed["enhancements"]) == 1
    
    def test_pci_data_transformation(self):
        """Test transformation of PCI-DSS data format."""
        from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
        
        raw_pci_data = {
            "requirement": "1.1",
            "title": "Establish and implement firewall and router configuration standards",
            "description": "Firewalls and routers are key components of the architecture...",
            "testing_procedures": [
                "1.1.a Examine firewall and router configuration standards",
                "1.1.b Interview personnel"
            ]
        }
        
        transformed = ComplianceDataProvider._transform_pci_requirement(raw_pci_data)
        
        assert transformed["control_id"] == "1.1"
        assert transformed["title"] == raw_pci_data["title"]
        assert transformed["description"] == raw_pci_data["description"]
        assert "testing_procedures" in transformed
        assert len(transformed["testing_procedures"]) == 2


class TestComplianceFrameworkSupport:
    """Test support for different compliance frameworks."""
    
    @pytest.fixture
    def frameworks_config(self):
        """Configuration for multiple frameworks."""
        return {
            "OWASP": {
                "base_url": "https://owasp.org/api",
                "version": "4.0",
                "supported_versions": ["3.0", "4.0"]
            },
            "NIST": {
                "base_url": "https://csrc.nist.gov/api",
                "version": "SP800-53r5",
                "supported_versions": ["SP800-53r4", "SP800-53r5"]
            },
            "PCI-DSS": {
                "base_url": "https://pcisecuritystandards.org/api",
                "version": "4.0",
                "supported_versions": ["3.2.1", "4.0"]
            },
            "ISO27001": {
                "base_url": "https://iso.org/api",
                "version": "2022",
                "supported_versions": ["2013", "2022"]
            },
            "SOC2": {
                "base_url": "https://aicpa.org/api",
                "version": "2017",
                "supported_versions": ["2017"]
            }
        }
    
    def test_framework_detection(self, frameworks_config):
        """Test automatic framework detection."""
        from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
        
        for framework_name in frameworks_config.keys():
            detected = ComplianceDataProvider._detect_framework(framework_name.lower())
            assert detected == framework_name
    
    def test_framework_version_validation(self, frameworks_config):
        """Test framework version validation."""
        from compliance_sentinel.providers.compliance_provider import ComplianceDataProvider
        
        for framework_name, config in frameworks_config.items():
            for version in config["supported_versions"]:
                is_valid = ComplianceDataProvider._validate_framework_version(framework_name, version)
                assert is_valid is True
            
            # Test invalid version
            is_valid = ComplianceDataProvider._validate_framework_version(framework_name, "invalid_version")
            assert is_valid is False


if __name__ == "__main__":
    pytest.main([__file__])