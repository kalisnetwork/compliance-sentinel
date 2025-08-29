"""Mock external services for testing."""

import json
import time
from typing import Dict, Any, List, Optional
from unittest.mock import Mock, MagicMock
from dataclasses import dataclass, field
import asyncio
import random


@dataclass
class MockVulnerability:
    """Mock vulnerability data."""
    cve_id: str
    package_name: str
    current_version: str
    fixed_version: Optional[str]
    severity: str
    description: str
    advisory_url: str
    cwe_id: Optional[str] = None
    published_date: str = "2024-01-01"
    modified_date: str = "2024-01-01"


@dataclass
class MockAnalysisResult:
    """Mock analysis result from external tools."""
    tool_name: str
    issues: List[Dict[str, Any]]
    execution_time: float
    success: bool
    error_message: Optional[str] = None


class MockNVDService:
    """Mock National Vulnerability Database service."""
    
    def __init__(self):
        """Initialize mock NVD service."""
        self.vulnerabilities = self._create_mock_vulnerabilities()
        self.request_count = 0
        self.rate_limit_requests = 50
        self.rate_limit_window = 60
        self.request_times = []
        
    def _create_mock_vulnerabilities(self) -> List[MockVulnerability]:
        """Create mock vulnerability data."""
        return [
            MockVulnerability(
                cve_id="CVE-2021-44228",
                package_name="log4j-core",
                current_version="2.14.1",
                fixed_version="2.15.0",
                severity="critical",
                description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                cwe_id="CWE-502"
            ),
            MockVulnerability(
                cve_id="CVE-2022-22965",
                package_name="spring-core",
                current_version="5.3.17",
                fixed_version="5.3.18",
                severity="critical",
                description="Spring Framework RCE via Data Binding on JDK 9+",
                advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                cwe_id="CWE-94"
            ),
            MockVulnerability(
                cve_id="CVE-2021-23337",
                package_name="lodash",
                current_version="4.17.20",
                fixed_version="4.17.21",
                severity="high",
                description="Command injection in lodash",
                advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                cwe_id="CWE-78"
            ),
            MockVulnerability(
                cve_id="CVE-2022-0778",
                package_name="openssl",
                current_version="1.1.1m",
                fixed_version="1.1.1n",
                severity="high",
                description="Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
                advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
                cwe_id="CWE-835"
            ),
            MockVulnerability(
                cve_id="CVE-2021-3807",
                package_name="ansi-regex",
                current_version="5.0.0",
                fixed_version="5.0.1",
                severity="medium",
                description="Regular expression denial of service (ReDoS)",
                advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-3807",
                cwe_id="CWE-1333"
            )
        ]
    
    async def search_vulnerabilities(self, package_name: str, version: str) -> List[MockVulnerability]:
        """Mock vulnerability search."""
        await self._simulate_network_delay()
        self._check_rate_limit()
        
        # Find vulnerabilities for the package
        results = []
        for vuln in self.vulnerabilities:
            if vuln.package_name == package_name:
                # Simple version comparison (in real implementation would be more sophisticated)
                if self._is_vulnerable_version(version, vuln.current_version, vuln.fixed_version):
                    results.append(vuln)
        
        return results
    
    async def get_vulnerability_details(self, cve_id: str) -> Optional[MockVulnerability]:
        """Mock vulnerability details lookup."""
        await self._simulate_network_delay()
        self._check_rate_limit()
        
        for vuln in self.vulnerabilities:
            if vuln.cve_id == cve_id:
                return vuln
        
        return None
    
    def _simulate_network_delay(self) -> None:
        """Simulate network delay."""
        delay = random.uniform(0.1, 0.5)  # 100-500ms delay
        time.sleep(delay)
    
    def _check_rate_limit(self) -> None:
        """Check rate limiting."""
        current_time = time.time()
        self.request_times.append(current_time)
        
        # Remove old requests outside the window
        cutoff_time = current_time - self.rate_limit_window
        self.request_times = [t for t in self.request_times if t > cutoff_time]
        
        if len(self.request_times) > self.rate_limit_requests:
            raise Exception("Rate limit exceeded")
        
        self.request_count += 1
    
    def _is_vulnerable_version(self, current: str, vulnerable: str, fixed: Optional[str]) -> bool:
        """Simple version comparison for mock purposes."""
        if not fixed:
            return current == vulnerable
        
        # Simplified version comparison
        try:
            current_parts = [int(x) for x in current.split('.')]
            fixed_parts = [int(x) for x in fixed.split('.')]
            
            for i in range(min(len(current_parts), len(fixed_parts))):
                if current_parts[i] < fixed_parts[i]:
                    return True
                elif current_parts[i] > fixed_parts[i]:
                    return False
            
            return len(current_parts) < len(fixed_parts)
        except ValueError:
            return current == vulnerable


class MockBanditService:
    """Mock Bandit static analysis service."""
    
    def __init__(self):
        """Initialize mock Bandit service."""
        self.execution_count = 0
        
    async def analyze_file(self, file_path: str, file_content: str) -> MockAnalysisResult:
        """Mock Bandit analysis."""
        await self._simulate_analysis_time()
        self.execution_count += 1
        
        issues = []
        
        # Mock issue detection based on content patterns
        if "password" in file_content.lower() and "=" in file_content:
            issues.append({
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "filename": file_path,
                "line_number": self._find_line_number(file_content, "password"),
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password",
                "line_range": [1, 1]
            })
        
        if "eval(" in file_content:
            issues.append({
                "test_id": "B307",
                "test_name": "blacklist",
                "filename": file_path,
                "line_number": self._find_line_number(file_content, "eval("),
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "Use of possibly insecure function - consider using safer ast.literal_eval.",
                "line_range": [1, 1]
            })
        
        if "subprocess.call" in file_content and "shell=True" in file_content:
            issues.append({
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "filename": file_path,
                "line_number": self._find_line_number(file_content, "subprocess.call"),
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "subprocess call with shell=True identified, security issue.",
                "line_range": [1, 1]
            })
        
        return MockAnalysisResult(
            tool_name="bandit",
            issues=issues,
            execution_time=random.uniform(0.5, 2.0),
            success=True
        )
    
    def _simulate_analysis_time(self) -> None:
        """Simulate analysis processing time."""
        delay = random.uniform(0.2, 1.0)  # 200ms-1s delay
        time.sleep(delay)
    
    def _find_line_number(self, content: str, pattern: str) -> int:
        """Find line number of pattern in content."""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 1


class MockSemgrepService:
    """Mock Semgrep static analysis service."""
    
    def __init__(self):
        """Initialize mock Semgrep service."""
        self.execution_count = 0
        self.custom_rules = []
    
    async def analyze_file(self, file_path: str, file_content: str, rules: List[str] = None) -> MockAnalysisResult:
        """Mock Semgrep analysis."""
        await self._simulate_analysis_time()
        self.execution_count += 1
        
        issues = []
        
        # Mock SQL injection detection
        if any(pattern in file_content for pattern in ["f\"SELECT", "f'SELECT", ".format(", "% "]):
            issues.append({
                "check_id": "python.lang.security.audit.sql-injection.sql-injection-format-string",
                "path": file_path,
                "start": {"line": self._find_line_number(file_content, "SELECT"), "col": 1},
                "end": {"line": self._find_line_number(file_content, "SELECT"), "col": 50},
                "message": "Detected SQL statement that is tainted by user-input. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.",
                "severity": "ERROR",
                "metadata": {
                    "category": "security",
                    "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "owasp": "A03:2021 - Injection"
                }
            })
        
        # Mock XSS detection
        if "render_template_string" in file_content:
            issues.append({
                "check_id": "python.flask.security.xss.audit.template-string",
                "path": file_path,
                "start": {"line": self._find_line_number(file_content, "render_template_string"), "col": 1},
                "end": {"line": self._find_line_number(file_content, "render_template_string"), "col": 30},
                "message": "Detected user input used in template string. This could lead to XSS if user input is not properly sanitized.",
                "severity": "WARNING",
                "metadata": {
                    "category": "security",
                    "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "owasp": "A03:2021 - Injection"
                }
            })
        
        return MockAnalysisResult(
            tool_name="semgrep",
            issues=issues,
            execution_time=random.uniform(1.0, 3.0),
            success=True
        )
    
    def _simulate_analysis_time(self) -> None:
        """Simulate analysis processing time."""
        delay = random.uniform(0.5, 1.5)  # 500ms-1.5s delay
        time.sleep(delay)
    
    def _find_line_number(self, content: str, pattern: str) -> int:
        """Find line number of pattern in content."""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 1


class MockSafetyService:
    """Mock Safety dependency scanner service."""
    
    def __init__(self):
        """Initialize mock Safety service."""
        self.execution_count = 0
        self.vulnerability_db = self._create_vulnerability_db()
    
    def _create_vulnerability_db(self) -> Dict[str, List[MockVulnerability]]:
        """Create mock vulnerability database."""
        return {
            "django": [
                MockVulnerability(
                    cve_id="CVE-2021-35042",
                    package_name="django",
                    current_version="3.2.4",
                    fixed_version="3.2.5",
                    severity="high",
                    description="Django SQL injection vulnerability",
                    advisory_url="https://www.djangoproject.com/weblog/2021/jul/01/security-releases/"
                )
            ],
            "requests": [
                MockVulnerability(
                    cve_id="CVE-2018-18074",
                    package_name="requests",
                    current_version="2.19.1",
                    fixed_version="2.20.0",
                    severity="medium",
                    description="Requests HTTP header injection",
                    advisory_url="https://github.com/psf/requests/pull/4718"
                )
            ],
            "pyyaml": [
                MockVulnerability(
                    cve_id="CVE-2020-1747",
                    package_name="pyyaml",
                    current_version="5.3.0",
                    fixed_version="5.3.1",
                    severity="critical",
                    description="PyYAML arbitrary code execution",
                    advisory_url="https://github.com/yaml/pyyaml/pull/386"
                )
            ]
        }
    
    async def scan_requirements(self, requirements_content: str) -> List[MockVulnerability]:
        """Mock requirements scanning."""
        await self._simulate_scan_time()
        self.execution_count += 1
        
        vulnerabilities = []
        lines = requirements_content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package==version format
            if '==' in line:
                package, version = line.split('==', 1)
                package = package.strip()
                version = version.strip()
                
                if package in self.vulnerability_db:
                    for vuln in self.vulnerability_db[package]:
                        if self._is_vulnerable_version(version, vuln.current_version, vuln.fixed_version):
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _simulate_scan_time(self) -> None:
        """Simulate scanning time."""
        delay = random.uniform(0.3, 1.0)  # 300ms-1s delay
        time.sleep(delay)
    
    def _is_vulnerable_version(self, current: str, vulnerable: str, fixed: Optional[str]) -> bool:
        """Simple version comparison."""
        if not fixed:
            return current == vulnerable
        
        try:
            current_parts = [int(x) for x in current.split('.')]
            fixed_parts = [int(x) for x in fixed.split('.')]
            
            for i in range(min(len(current_parts), len(fixed_parts))):
                if current_parts[i] < fixed_parts[i]:
                    return True
                elif current_parts[i] > fixed_parts[i]:
                    return False
            
            return len(current_parts) < len(fixed_parts)
        except ValueError:
            return current == vulnerable


class MockServiceManager:
    """Manages all mock external services."""
    
    def __init__(self):
        """Initialize mock service manager."""
        self.nvd_service = MockNVDService()
        self.bandit_service = MockBanditService()
        self.semgrep_service = MockSemgrepService()
        self.safety_service = MockSafetyService()
        
        # Service availability simulation
        self.service_availability = {
            "nvd": True,
            "bandit": True,
            "semgrep": True,
            "safety": True
        }
        
        # Error simulation
        self.error_rates = {
            "nvd": 0.0,      # 0% error rate by default
            "bandit": 0.0,
            "semgrep": 0.0,
            "safety": 0.0
        }
    
    def set_service_availability(self, service: str, available: bool) -> None:
        """Set service availability for testing."""
        if service in self.service_availability:
            self.service_availability[service] = available
    
    def set_error_rate(self, service: str, error_rate: float) -> None:
        """Set error rate for service (0.0 to 1.0)."""
        if service in self.error_rates:
            self.error_rates[service] = max(0.0, min(1.0, error_rate))
    
    def simulate_service_error(self, service: str) -> bool:
        """Check if service should simulate an error."""
        if not self.service_availability.get(service, True):
            return True
        
        error_rate = self.error_rates.get(service, 0.0)
        return random.random() < error_rate
    
    async def get_nvd_vulnerabilities(self, package: str, version: str) -> List[MockVulnerability]:
        """Get vulnerabilities from mock NVD service."""
        if self.simulate_service_error("nvd"):
            raise Exception("NVD service unavailable")
        
        return await self.nvd_service.search_vulnerabilities(package, version)
    
    async def run_bandit_analysis(self, file_path: str, content: str) -> MockAnalysisResult:
        """Run mock Bandit analysis."""
        if self.simulate_service_error("bandit"):
            return MockAnalysisResult(
                tool_name="bandit",
                issues=[],
                execution_time=0.0,
                success=False,
                error_message="Bandit analysis failed"
            )
        
        return await self.bandit_service.analyze_file(file_path, content)
    
    async def run_semgrep_analysis(self, file_path: str, content: str) -> MockAnalysisResult:
        """Run mock Semgrep analysis."""
        if self.simulate_service_error("semgrep"):
            return MockAnalysisResult(
                tool_name="semgrep",
                issues=[],
                execution_time=0.0,
                success=False,
                error_message="Semgrep analysis failed"
            )
        
        return await self.semgrep_service.analyze_file(file_path, content)
    
    async def run_safety_scan(self, requirements_content: str) -> List[MockVulnerability]:
        """Run mock Safety dependency scan."""
        if self.simulate_service_error("safety"):
            raise Exception("Safety service unavailable")
        
        return await self.safety_service.scan_requirements(requirements_content)
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """Get statistics for all mock services."""
        return {
            "nvd": {
                "requests": self.nvd_service.request_count,
                "vulnerabilities": len(self.nvd_service.vulnerabilities)
            },
            "bandit": {
                "executions": self.bandit_service.execution_count
            },
            "semgrep": {
                "executions": self.semgrep_service.execution_count
            },
            "safety": {
                "executions": self.safety_service.execution_count,
                "packages_in_db": len(self.safety_service.vulnerability_db)
            }
        }
    
    def reset_statistics(self) -> None:
        """Reset all service statistics."""
        self.nvd_service.request_count = 0
        self.nvd_service.request_times = []
        self.bandit_service.execution_count = 0
        self.semgrep_service.execution_count = 0
        self.safety_service.execution_count = 0


# Global mock service manager for tests
_mock_service_manager = MockServiceManager()


def get_mock_service_manager() -> MockServiceManager:
    """Get the global mock service manager."""
    return _mock_service_manager


def create_mock_patches() -> Dict[str, Mock]:
    """Create mock patches for external services."""
    patches = {}
    
    # Mock HTTP requests
    patches['requests.get'] = Mock()
    patches['requests.post'] = Mock()
    patches['aiohttp.ClientSession.get'] = Mock()
    patches['aiohttp.ClientSession.post'] = Mock()
    
    # Mock subprocess calls
    patches['subprocess.run'] = Mock()
    patches['subprocess.Popen'] = Mock()
    
    # Mock file system operations for external tools
    patches['os.path.exists'] = Mock(return_value=True)
    patches['shutil.which'] = Mock(return_value='/usr/bin/bandit')
    
    return patches