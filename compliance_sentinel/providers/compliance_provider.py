"""Compliance data provider for real-time compliance framework information."""

import asyncio
import aiohttp
import logging
import time
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlencode

from .data_provider import (
    CachingDataProvider, DataRequest, DataResponse, 
    HealthCheckResult, HealthStatus
)
from ..models.analysis import Severity
from ..utils.circuit_breaker import (
    CircuitBreakerConfig, CircuitBreakerOpenException, 
    get_circuit_breaker, CircuitState
)
from ..utils.resilient_error_handler import (
    get_resilient_error_handler, ErrorContext, handle_service_error
)

logger = logging.getLogger(__name__)


@dataclass
class ComplianceRequirement:
    """Compliance requirement data model."""
    framework: str  # owasp, nist, pci-dss, etc.
    requirement_id: str
    title: str
    description: str
    category: str
    severity: Severity
    test_patterns: List[str] = field(default_factory=list)
    remediation_guidance: str = ""
    last_updated: datetime = field(default_factory=datetime.utcnow)
    source_url: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert requirement to dictionary."""
        return {
            "framework": self.framework,
            "requirement_id": self.requirement_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "test_patterns": self.test_patterns,
            "remediation_guidance": self.remediation_guidance,
            "last_updated": self.last_updated.isoformat(),
            "source_url": self.source_url,
            "tags": self.tags
        }


@dataclass
class ComplianceResult:
    """Result of compliance check."""
    framework: str
    overall_score: float  # 0-100
    passed_requirements: int
    failed_requirements: int
    total_requirements: int
    requirement_results: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def compliance_percentage(self) -> float:
        """Get compliance percentage."""
        if self.total_requirements == 0:
            return 100.0
        return (self.passed_requirements / self.total_requirements) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "framework": self.framework,
            "overall_score": self.overall_score,
            "passed_requirements": self.passed_requirements,
            "failed_requirements": self.failed_requirements,
            "total_requirements": self.total_requirements,
            "compliance_percentage": self.compliance_percentage,
            "requirement_results": self.requirement_results,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat()
        }


class OWASPComplianceProvider(CachingDataProvider):
    """OWASP compliance framework provider."""
    
    def __init__(self, config: Dict[str, Any], cache_manager=None):
        """Initialize OWASP compliance provider."""
        super().__init__("owasp-compliance-provider", config, cache_manager)
        self.base_url = config.get("base_url", "https://owasp.org/api")
        self.timeout = config.get("timeout", 30)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # OWASP Top 10 requirements (hardcoded as fallback)
        self.owasp_top_10_requirements = self._get_owasp_top_10_requirements()
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize OWASP provider."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        logger.info("OWASP compliance provider initialized")
    
    def get_supported_request_types(self) -> List[str]:
        """Get supported request types."""
        return [
            "get_framework_requirements",
            "check_compliance",
            "get_owasp_top_10"
        ]
    
    async def _fetch_data(self, request: DataRequest) -> DataResponse:
        """Fetch compliance data with resilient error handling."""
        start_time = time.time()
        error_handler = get_resilient_error_handler()
        
        # Create error context
        context = ErrorContext(
            operation=request.request_type,
            service="owasp-api",
            request_id=request.cache_key,
            metadata={
                "parameters": request.parameters,
                "priority": request.priority
            }
        )
        
        try:
            # Execute with resilient error handling
            async def fetch_operation():
                if request.request_type == "get_framework_requirements":
                    return await self._get_framework_requirements(request.parameters)
                elif request.request_type == "check_compliance":
                    return await self._check_compliance(request.parameters)
                elif request.request_type == "get_owasp_top_10":
                    return await self._get_owasp_top_10(request.parameters)
                else:
                    raise ValueError(f"Unsupported request type: {request.request_type}")
            
            # Prepare fallback data (OWASP Top 10 requirements)
            fallback_data = self.owasp_top_10_requirements
            
            result = await error_handler.execute_with_fallback(
                fetch_operation,
                context,
                fallback_data
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            if result.success:
                response = DataResponse(
                    success=True,
                    data=result.data,
                    provider_name=self.name,
                    request_duration_ms=duration_ms
                )
                
                # Add fallback information to metadata
                if result.fallback_used:
                    response.metadata["fallback_used"] = True
                    response.metadata["fallback_strategy"] = result.fallback_strategy.value
                    response.metadata["warnings"] = result.warnings
                
                return response
            else:
                return DataResponse(
                    success=False,
                    error_message=result.error_message,
                    provider_name=self.name,
                    request_duration_ms=duration_ms,
                    metadata={"retry_count": result.retry_count}
                )
            
        except Exception as e:
            # Final fallback - handle any unexpected errors
            duration_ms = (time.time() - start_time) * 1000
            
            # Try to get fallback data from error handler
            fallback_result = await handle_service_error(
                "owasp-api",
                request.request_type,
                e,
                fallback_data=self.owasp_top_10_requirements,
                request_id=request.cache_key
            )
            
            if fallback_result.success:
                return DataResponse(
                    success=True,
                    data=fallback_result.data,
                    provider_name=f"{self.name}-fallback",
                    request_duration_ms=duration_ms,
                    metadata={
                        "fallback_used": True,
                        "fallback_strategy": fallback_result.fallback_strategy.value if fallback_result.fallback_strategy else None,
                        "warnings": fallback_result.warnings
                    }
                )
            
            logger.error(f"Error fetching OWASP compliance data: {e}")
            return DataResponse(
                success=False,
                error_message=str(e),
                provider_name=self.name,
                request_duration_ms=duration_ms
            )
    
    async def _get_framework_requirements(self, params: Dict[str, Any]) -> List[ComplianceRequirement]:
        """Get OWASP framework requirements."""
        framework_version = params.get("version", "2021")
        
        if framework_version == "2021":
            return self.owasp_top_10_requirements
        else:
            # For other versions, return the default set
            return self.owasp_top_10_requirements
    
    async def _check_compliance(self, params: Dict[str, Any]) -> ComplianceResult:
        """Check compliance against OWASP requirements."""
        code_patterns = params.get("code_patterns", [])
        vulnerabilities = params.get("vulnerabilities", [])
        
        requirements = self.owasp_top_10_requirements
        requirement_results = []
        passed_count = 0
        
        for requirement in requirements:
            # Simple compliance check based on patterns and vulnerabilities
            passed = self._check_requirement_compliance(requirement, code_patterns, vulnerabilities)
            
            result = {
                "requirement_id": requirement.requirement_id,
                "title": requirement.title,
                "passed": passed,
                "severity": requirement.severity.value,
                "category": requirement.category
            }
            
            requirement_results.append(result)
            if passed:
                passed_count += 1
        
        overall_score = (passed_count / len(requirements)) * 100 if requirements else 100
        
        return ComplianceResult(
            framework="owasp",
            overall_score=overall_score,
            passed_requirements=passed_count,
            failed_requirements=len(requirements) - passed_count,
            total_requirements=len(requirements),
            requirement_results=requirement_results,
            recommendations=self._generate_recommendations(requirement_results)
        )
    
    async def _get_owasp_top_10(self, params: Dict[str, Any]) -> List[ComplianceRequirement]:
        """Get OWASP Top 10 requirements."""
        return self.owasp_top_10_requirements
    
    def _check_requirement_compliance(
        self, 
        requirement: ComplianceRequirement, 
        code_patterns: List[str], 
        vulnerabilities: List[Dict[str, Any]]
    ) -> bool:
        """Check if code complies with a specific requirement."""
        # This is a simplified compliance check
        # In a real implementation, this would be much more sophisticated
        
        # Check for vulnerability patterns
        for vuln in vulnerabilities:
            vuln_category = vuln.get("category", "").lower()
            req_category = requirement.category.lower()
            
            if req_category in vuln_category or vuln_category in req_category:
                return False  # Found vulnerability in this category
        
        # Check for problematic code patterns
        for pattern in code_patterns:
            for test_pattern in requirement.test_patterns:
                if test_pattern.lower() in pattern.lower():
                    return False  # Found problematic pattern
        
        return True  # No issues found
    
    def _generate_recommendations(self, requirement_results: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on failed requirements."""
        recommendations = []
        
        for result in requirement_results:
            if not result["passed"]:
                req_id = result["requirement_id"]
                title = result["title"]
                recommendations.append(f"Address {req_id}: {title}")
        
        return recommendations
    
    def _get_owasp_top_10_requirements(self) -> List[ComplianceRequirement]:
        """Get OWASP Top 10 2021 requirements."""
        return [
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A01:2021",
                title="Broken Access Control",
                description="Access control enforces policy such that users cannot act outside of their intended permissions",
                category="access_control",
                severity=Severity.HIGH,
                test_patterns=["authorization", "access_control", "permission"],
                remediation_guidance="Implement proper access controls and authorization checks",
                source_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                tags=["access", "authorization", "security"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A02:2021",
                title="Cryptographic Failures",
                description="Failures related to cryptography which often leads to sensitive data exposure",
                category="cryptography",
                severity=Severity.HIGH,
                test_patterns=["encryption", "crypto", "hash", "password"],
                remediation_guidance="Use strong cryptographic algorithms and proper key management",
                source_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                tags=["crypto", "encryption", "data_protection"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A03:2021",
                title="Injection",
                description="An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized",
                category="injection",
                severity=Severity.CRITICAL,
                test_patterns=["sql", "injection", "query", "execute"],
                remediation_guidance="Use parameterized queries and input validation",
                source_url="https://owasp.org/Top10/A03_2021-Injection/",
                tags=["injection", "sql", "input_validation"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A04:2021",
                title="Insecure Design",
                description="Risks related to design flaws and architectural weaknesses",
                category="design",
                severity=Severity.MEDIUM,
                test_patterns=["design", "architecture", "threat_model"],
                remediation_guidance="Implement secure design principles and threat modeling",
                source_url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
                tags=["design", "architecture", "security_by_design"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A05:2021",
                title="Security Misconfiguration",
                description="Security misconfiguration is commonly a result of insecure default configurations",
                category="configuration",
                severity=Severity.MEDIUM,
                test_patterns=["config", "default", "misconfiguration"],
                remediation_guidance="Implement secure configuration management",
                source_url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                tags=["configuration", "defaults", "hardening"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A06:2021",
                title="Vulnerable and Outdated Components",
                description="Components with known vulnerabilities may undermine application defenses",
                category="components",
                severity=Severity.HIGH,
                test_patterns=["dependency", "component", "version", "outdated"],
                remediation_guidance="Keep components updated and scan for vulnerabilities",
                source_url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                tags=["dependencies", "components", "updates"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A07:2021",
                title="Identification and Authentication Failures",
                description="Confirmation of the user's identity, authentication, and session management is critical",
                category="authentication",
                severity=Severity.HIGH,
                test_patterns=["auth", "session", "login", "password"],
                remediation_guidance="Implement strong authentication and session management",
                source_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                tags=["authentication", "session", "identity"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A08:2021",
                title="Software and Data Integrity Failures",
                description="Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations",
                category="integrity",
                severity=Severity.MEDIUM,
                test_patterns=["integrity", "signature", "checksum", "validation"],
                remediation_guidance="Implement integrity checks and secure update mechanisms",
                source_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                tags=["integrity", "validation", "updates"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A09:2021",
                title="Security Logging and Monitoring Failures",
                description="Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response",
                category="logging",
                severity=Severity.MEDIUM,
                test_patterns=["log", "monitor", "audit", "incident"],
                remediation_guidance="Implement comprehensive logging and monitoring",
                source_url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                tags=["logging", "monitoring", "incident_response"]
            ),
            ComplianceRequirement(
                framework="owasp",
                requirement_id="A10:2021",
                title="Server-Side Request Forgery (SSRF)",
                description="SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL",
                category="ssrf",
                severity=Severity.MEDIUM,
                test_patterns=["ssrf", "request", "url", "fetch"],
                remediation_guidance="Validate and sanitize all user-supplied URLs",
                source_url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                tags=["ssrf", "url_validation", "remote_requests"]
            )
        ]
    
    async def health_check(self) -> HealthCheckResult:
        """Check OWASP provider health."""
        start_time = time.time()
        
        try:
            # Since we're using mostly static data, just check if we have requirements
            if self.owasp_top_10_requirements:
                response_time_ms = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    status=HealthStatus.HEALTHY,
                    message=f"OWASP provider ready with {len(self.owasp_top_10_requirements)} requirements",
                    response_time_ms=response_time_ms
                )
            else:
                return HealthCheckResult(
                    status=HealthStatus.UNHEALTHY,
                    message="No OWASP requirements available"
                )
                
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"OWASP provider health check failed: {e}",
                response_time_ms=response_time_ms
            )
    
    async def shutdown(self) -> None:
        """Shutdown OWASP provider."""
        if self.session:
            await self.session.close()
            self.session = None
        await super().shutdown()


class NISTComplianceProvider(CachingDataProvider):
    """NIST Cybersecurity Framework compliance provider."""
    
    def __init__(self, config: Dict[str, Any], cache_manager=None):
        """Initialize NIST compliance provider."""
        super().__init__("nist-compliance-provider", config, cache_manager)
        self.timeout = config.get("timeout", 30)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # NIST CSF requirements (simplified)
        self.nist_requirements = self._get_nist_requirements()
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize NIST provider."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        logger.info("NIST compliance provider initialized")
    
    def get_supported_request_types(self) -> List[str]:
        """Get supported request types."""
        return [
            "get_framework_requirements",
            "check_compliance"
        ]
    
    async def _fetch_data(self, request: DataRequest) -> DataResponse:
        """Fetch NIST compliance data."""
        start_time = time.time()
        
        try:
            if request.request_type == "get_framework_requirements":
                data = await self._get_framework_requirements(request.parameters)
            elif request.request_type == "check_compliance":
                data = await self._check_compliance(request.parameters)
            else:
                raise ValueError(f"Unsupported request type: {request.request_type}")
            
            duration_ms = (time.time() - start_time) * 1000
            
            return DataResponse(
                success=True,
                data=data,
                provider_name=self.name,
                request_duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Error fetching NIST compliance data: {e}")
            
            return DataResponse(
                success=False,
                error_message=str(e),
                provider_name=self.name,
                request_duration_ms=duration_ms
            )
    
    async def _get_framework_requirements(self, params: Dict[str, Any]) -> List[ComplianceRequirement]:
        """Get NIST framework requirements."""
        return self.nist_requirements
    
    async def _check_compliance(self, params: Dict[str, Any]) -> ComplianceResult:
        """Check compliance against NIST requirements."""
        code_patterns = params.get("code_patterns", [])
        vulnerabilities = params.get("vulnerabilities", [])
        
        requirements = self.nist_requirements
        requirement_results = []
        passed_count = 0
        
        for requirement in requirements:
            # Simplified compliance check
            passed = self._check_requirement_compliance(requirement, code_patterns, vulnerabilities)
            
            result = {
                "requirement_id": requirement.requirement_id,
                "title": requirement.title,
                "passed": passed,
                "severity": requirement.severity.value,
                "category": requirement.category
            }
            
            requirement_results.append(result)
            if passed:
                passed_count += 1
        
        overall_score = (passed_count / len(requirements)) * 100 if requirements else 100
        
        return ComplianceResult(
            framework="nist",
            overall_score=overall_score,
            passed_requirements=passed_count,
            failed_requirements=len(requirements) - passed_count,
            total_requirements=len(requirements),
            requirement_results=requirement_results,
            recommendations=self._generate_recommendations(requirement_results)
        )
    
    def _check_requirement_compliance(
        self, 
        requirement: ComplianceRequirement, 
        code_patterns: List[str], 
        vulnerabilities: List[Dict[str, Any]]
    ) -> bool:
        """Check if code complies with a NIST requirement."""
        # Simplified compliance check
        for vuln in vulnerabilities:
            if requirement.category.lower() in vuln.get("category", "").lower():
                return False
        
        for pattern in code_patterns:
            for test_pattern in requirement.test_patterns:
                if test_pattern.lower() in pattern.lower():
                    return False
        
        return True
    
    def _generate_recommendations(self, requirement_results: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on failed requirements."""
        recommendations = []
        
        for result in requirement_results:
            if not result["passed"]:
                req_id = result["requirement_id"]
                title = result["title"]
                recommendations.append(f"Address NIST {req_id}: {title}")
        
        return recommendations
    
    def _get_nist_requirements(self) -> List[ComplianceRequirement]:
        """Get NIST Cybersecurity Framework requirements (simplified)."""
        return [
            ComplianceRequirement(
                framework="nist",
                requirement_id="ID.AM-1",
                title="Physical devices and systems within the organization are inventoried",
                description="Maintain an inventory of physical devices and systems",
                category="identify",
                severity=Severity.MEDIUM,
                test_patterns=["inventory", "asset", "device"],
                remediation_guidance="Implement asset inventory management",
                tags=["asset_management", "inventory"]
            ),
            ComplianceRequirement(
                framework="nist",
                requirement_id="PR.AC-1",
                title="Identities and credentials are issued, managed, verified, revoked, and audited",
                description="Manage user identities and credentials throughout their lifecycle",
                category="protect",
                severity=Severity.HIGH,
                test_patterns=["credential", "identity", "user", "auth"],
                remediation_guidance="Implement proper identity and credential management",
                tags=["identity", "credentials", "access_control"]
            ),
            ComplianceRequirement(
                framework="nist",
                requirement_id="DE.CM-1",
                title="The network is monitored to detect potential cybersecurity events",
                description="Monitor network traffic for security events",
                category="detect",
                severity=Severity.MEDIUM,
                test_patterns=["monitor", "network", "traffic", "detect"],
                remediation_guidance="Implement network monitoring and detection",
                tags=["monitoring", "detection", "network"]
            ),
            ComplianceRequirement(
                framework="nist",
                requirement_id="RS.RP-1",
                title="Response plan is executed during or after an incident",
                description="Execute incident response procedures",
                category="respond",
                severity=Severity.MEDIUM,
                test_patterns=["incident", "response", "plan", "execute"],
                remediation_guidance="Develop and test incident response procedures",
                tags=["incident_response", "procedures"]
            ),
            ComplianceRequirement(
                framework="nist",
                requirement_id="RC.RP-1",
                title="Recovery plan is executed during or after a cybersecurity incident",
                description="Execute recovery procedures to restore systems",
                category="recover",
                severity=Severity.MEDIUM,
                test_patterns=["recovery", "restore", "backup", "continuity"],
                remediation_guidance="Implement recovery and business continuity procedures",
                tags=["recovery", "business_continuity", "backup"]
            )
        ]
    
    async def health_check(self) -> HealthCheckResult:
        """Check NIST provider health."""
        start_time = time.time()
        
        try:
            if self.nist_requirements:
                response_time_ms = (time.time() - start_time) * 1000
                return HealthCheckResult(
                    status=HealthStatus.HEALTHY,
                    message=f"NIST provider ready with {len(self.nist_requirements)} requirements",
                    response_time_ms=response_time_ms
                )
            else:
                return HealthCheckResult(
                    status=HealthStatus.UNHEALTHY,
                    message="No NIST requirements available"
                )
                
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"NIST provider health check failed: {e}",
                response_time_ms=response_time_ms
            )
    
    async def shutdown(self) -> None:
        """Shutdown NIST provider."""
        if self.session:
            await self.session.close()
            self.session = None
        await super().shutdown()


class ComplianceDataProvider:
    """Main compliance data provider that aggregates multiple frameworks."""
    
    def __init__(self, config: Dict[str, Any], cache_manager=None):
        """Initialize compliance data provider."""
        self.config = config
        self.cache_manager = cache_manager
        self.providers: List[CachingDataProvider] = []
        
        # Initialize OWASP provider
        owasp_config = config.get("owasp", {})
        if owasp_config.get("enabled", True):
            self.providers.append(OWASPComplianceProvider(owasp_config, cache_manager))
        
        # Initialize NIST provider
        nist_config = config.get("nist", {})
        if nist_config.get("enabled", True):
            self.providers.append(NISTComplianceProvider(nist_config, cache_manager))
    
    async def initialize(self) -> None:
        """Initialize all compliance providers."""
        for provider in self.providers:
            await provider.initialize(provider.config)
    
    async def get_framework_requirements(self, framework: str) -> List[ComplianceRequirement]:
        """Get requirements for a specific compliance framework."""
        request = DataRequest(
            request_type="get_framework_requirements",
            parameters={"framework": framework},
            cache_key=f"requirements_{framework}"
        )
        
        for provider in self.providers:
            if framework.lower() in provider.name.lower():
                try:
                    response = await provider.get_data(request)
                    if response.is_success and response.data:
                        return response.data
                except Exception as e:
                    logger.warning(f"Error getting requirements from {provider.name}: {e}")
        
        return []
    
    async def check_compliance(self, code_patterns: List[str], framework: str) -> ComplianceResult:
        """Check code compliance against framework."""
        request = DataRequest(
            request_type="check_compliance",
            parameters={
                "code_patterns": code_patterns,
                "framework": framework,
                "vulnerabilities": []
            },
            cache_key=f"compliance_{framework}_{len(code_patterns)}"
        )
        
        for provider in self.providers:
            if framework.lower() in provider.name.lower():
                try:
                    response = await provider.get_data(request)
                    if response.is_success and response.data:
                        return response.data
                except Exception as e:
                    logger.warning(f"Error checking compliance with {provider.name}: {e}")
        
        # Return empty result if no provider found
        return ComplianceResult(
            framework=framework,
            overall_score=0.0,
            passed_requirements=0,
            failed_requirements=0,
            total_requirements=0
        )
    
    async def shutdown(self) -> None:
        """Shutdown all providers."""
        for provider in self.providers:
            await provider.shutdown()