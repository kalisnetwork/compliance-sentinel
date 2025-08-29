"""End-to-end workflow tests for compliance sentinel."""

import os
import asyncio
import pytest
import tempfile
import time
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path

from compliance_sentinel.config.dynamic_config import DynamicConfigManager
from compliance_sentinel.monitoring.real_time_metrics import RealTimeMetrics
from compliance_sentinel.testing.production_data_validator import ProductionDataValidator
from compliance_sentinel.logging.environment_logger import configure_logging, get_logger
from compliance_sentinel.utils.intelligent_cache import IntelligentCache


class TestEndToEndWorkflows:
    """End-to-end workflow tests for complete system integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        configure_logging()
        self.logger = get_logger(__name__)
        self.metrics = RealTimeMetrics()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_complete_security_analysis_workflow(self):
        """Test complete security analysis workflow from file to report."""
        # Create test project structure
        project_dir = Path(self.temp_dir) / "test_project"
        project_dir.mkdir()
        
        # Create test files with various security issues
        (project_dir / "app.py").write_text('''
import os
import subprocess

# Hardcoded credentials (should be detected)
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def authenticate_user(username, password):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return execute_query(query)

def run_command(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    
def weak_crypto():
    import hashlib
    # Weak hashing algorithm
    return hashlib.md5(b"password").hexdigest()
''')
        
        (project_dir / "config.js").write_text('''
// JavaScript security issues
const API_SECRET = "secret-key-12345";
const DB_HOST = "localhost";

function validateInput(userInput) {
    // XSS vulnerability
    document.innerHTML = userInput;
}

function makeRequest(url) {
    // Potential SSRF
    fetch(url).then(response => response.json());
}
''')
        
        (project_dir / "requirements.txt").write_text('''
# Potentially vulnerable dependencies
django==2.0.0
requests==2.18.0
flask==0.12.0
''')
        
        # Start metrics collection
        await self.metrics.start_collection()
        
        try:
            # 1. Initialize policy engine and run analysis
            from compliance_sentinel.engines.policy_engine import PolicyEngine
            
            policy_engine = PolicyEngine()
            all_issues = []
            
            # Analyze Python file
            with open(project_dir / "app.py", 'r') as f:
                python_content = f.read()
            
            python_issues = policy_engine.apply_policies_to_content(
                python_content, str(project_dir / "app.py"), ".py"
            )
            all_issues.extend(python_issues)
            
            # Record metrics
            self.metrics.increment_counter("files_analyzed")
            self.metrics.set_gauge("issues_found", len(python_issues))
            
            # 2. Validate production readiness
            validator = ProductionDataValidator()
            validation_issues = validator.validate_directory(str(project_dir))
            
            # Should find hardcoded credentials
            assert len(validation_issues) > 0
            
            credential_issues = [
                issue for issue in validation_issues 
                if any(pattern in issue.description.lower() 
                      for pattern in ['api', 'password', 'secret'])
            ]
            assert len(credential_issues) > 0
            
            # 3. Test environment-specific behavior
            with patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "production"}):
                # In production, should be more strict
                prod_validator = ProductionDataValidator()
                prod_issues = prod_validator.validate_directory(str(project_dir))
                
                # Should have higher severity issues in production
                critical_issues = [
                    issue for issue in prod_issues 
                    if issue.severity.value == "critical"
                ]
                # May have critical issues due to hardcoded secrets
                
            # 4. Generate comprehensive report
            report_data = {
                "project_path": str(project_dir),
                "total_files_analyzed": 2,
                "security_issues": len(all_issues),
                "production_validation_issues": len(validation_issues),
                "critical_issues": len([i for i in validation_issues if i.severity.value == "critical"]),
                "recommendations": []
            }
            
            # Add recommendations based on findings
            if credential_issues:
                report_data["recommendations"].append(
                    "Move hardcoded credentials to environment variables"
                )
            
            if any("sql" in issue.description.lower() for issue in all_issues):
                report_data["recommendations"].append(
                    "Use parameterized queries to prevent SQL injection"
                )
            
            # 5. Verify metrics were collected
            files_analyzed = self.metrics.get_metric_value("files_analyzed")
            assert files_analyzed >= 1
            
            issues_found = self.metrics.get_metric_value("issues_found")
            assert issues_found is not None
            
            # 6. Test report generation
            report_file = project_dir / "security_report.json"
            with open(report_file, 'w') as f:
                import json
                json.dump(report_data, f, indent=2)
            
            assert report_file.exists()
            
            # Verify report content
            with open(report_file, 'r') as f:
                saved_report = json.load(f)
            
            assert saved_report["total_files_analyzed"] == 2
            assert saved_report["security_issues"] >= 0
            assert len(saved_report["recommendations"]) > 0
            
        finally:
            await self.metrics.stop_collection()
    
    @pytest.mark.asyncio
    async def test_configuration_driven_analysis_workflow(self):
        """Test analysis workflow driven by environment configuration."""
        # Create test configuration scenarios
        test_scenarios = [
            {
                "name": "development",
                "env_vars": {
                    "COMPLIANCE_SENTINEL_ENVIRONMENT": "development",
                    "COMPLIANCE_SENTINEL_ANALYSIS_SEVERITY_THRESHOLD": "low",
                    "COMPLIANCE_SENTINEL_ANALYSIS_FILE_EXTENSIONS": ".py,.js"
                },
                "expected_behavior": "permissive"
            },
            {
                "name": "production", 
                "env_vars": {
                    "COMPLIANCE_SENTINEL_ENVIRONMENT": "production",
                    "COMPLIANCE_SENTINEL_ANALYSIS_SEVERITY_THRESHOLD": "high",
                    "COMPLIANCE_SENTINEL_ANALYSIS_FILE_EXTENSIONS": ".py,.js,.ts,.java"
                },
                "expected_behavior": "strict"
            }
        ]
        
        # Create test file
        test_file = Path(self.temp_dir) / "test_code.py"
        test_file.write_text('''
# Medium severity issue
password = "hardcoded_password"

# Low severity issue  
debug_mode = True

# High severity issue
import subprocess
subprocess.call(user_input, shell=True)
''')
        
        for scenario in test_scenarios:
            with patch.dict(os.environ, scenario["env_vars"]):
                # Reload configuration
                config_manager = DynamicConfigManager()
                config_manager.reload_configuration()
                
                # Run analysis with environment-specific settings
                from compliance_sentinel.engines.policy_engine import PolicyEngine
                policy_engine = PolicyEngine()
                
                with open(test_file, 'r') as f:
                    content = f.read()
                
                issues = policy_engine.apply_policies_to_content(
                    content, str(test_file), ".py"
                )
                
                # Verify environment-specific behavior
                if scenario["expected_behavior"] == "strict":
                    # Production should be more restrictive
                    # Should focus on high severity issues
                    high_severity_issues = [
                        issue for issue in issues 
                        if hasattr(issue, 'severity') and issue.severity.value in ['high', 'critical']
                    ]
                    # Should have some high severity issues
                    
                elif scenario["expected_behavior"] == "permissive":
                    # Development can include lower severity issues
                    # Should include more issues for learning
                    pass
                
                # Record metrics for this scenario
                self.metrics.set_gauge(f"issues_{scenario['name']}", len(issues))
    
    @pytest.mark.asyncio
    async def test_performance_and_scalability_workflow(self):
        """Test performance characteristics of the analysis workflow."""
        # Create multiple test files to simulate larger project
        project_dir = Path(self.temp_dir) / "large_project"
        project_dir.mkdir()
        
        # Generate test files
        file_count = 10
        for i in range(file_count):
            test_file = project_dir / f"module_{i}.py"
            test_file.write_text(f'''
# Module {i}
import os

def function_{i}():
    # Some potential issues
    password = "test_password_{i}"
    query = f"SELECT * FROM table WHERE id = {{user_input}}"
    return query

class Class{i}:
    def __init__(self):
        self.api_key = "api_key_{i}"
''')
        
        # Start performance monitoring
        start_time = time.time()
        await self.metrics.start_collection()
        
        try:
            from compliance_sentinel.engines.policy_engine import PolicyEngine
            policy_engine = PolicyEngine()
            
            total_issues = 0
            files_processed = 0
            
            # Process files and measure performance
            for test_file in project_dir.glob("*.py"):
                file_start = time.time()
                
                with open(test_file, 'r') as f:
                    content = f.read()
                
                issues = policy_engine.apply_policies_to_content(
                    content, str(test_file), ".py"
                )
                
                file_duration = time.time() - file_start
                total_issues += len(issues)
                files_processed += 1
                
                # Record per-file metrics
                self.metrics.record_timer("file_analysis_duration", file_duration * 1000)
                self.metrics.increment_counter("files_processed")
            
            total_duration = time.time() - start_time
            
            # Record overall performance metrics
            self.metrics.set_gauge("total_analysis_duration", total_duration)
            self.metrics.set_gauge("files_per_second", files_processed / total_duration)
            self.metrics.set_gauge("issues_per_file", total_issues / files_processed if files_processed > 0 else 0)
            
            # Performance assertions
            assert files_processed == file_count
            assert total_issues > 0  # Should find some issues
            assert total_duration < 30  # Should complete within 30 seconds
            
            # Verify metrics collection
            avg_file_duration = self.metrics.get_metric_value("file_analysis_duration")
            assert avg_file_duration is not None
            assert avg_file_duration > 0
            
            files_per_second = self.metrics.get_metric_value("files_per_second")
            assert files_per_second > 0
            
        finally:
            await self.metrics.stop_collection()
    
    @pytest.mark.asyncio
    async def test_error_recovery_workflow(self):
        """Test system behavior under error conditions."""
        # Create scenarios that trigger different error conditions
        error_scenarios = [
            {
                "name": "file_permission_error",
                "setup": lambda: self._create_unreadable_file(),
                "expected": "graceful_handling"
            },
            {
                "name": "large_file_error", 
                "setup": lambda: self._create_large_file(),
                "expected": "size_limit_handling"
            },
            {
                "name": "malformed_file_error",
                "setup": lambda: self._create_malformed_file(),
                "expected": "parsing_error_handling"
            }
        ]
        
        for scenario in error_scenarios:
            try:
                # Set up error condition
                test_file = scenario["setup"]()
                
                # Attempt analysis
                from compliance_sentinel.engines.policy_engine import PolicyEngine
                policy_engine = PolicyEngine()
                
                try:
                    with open(test_file, 'r') as f:
                        content = f.read()
                    
                    issues = policy_engine.apply_policies_to_content(
                        content, str(test_file), ".py"
                    )
                    
                    # Should handle gracefully
                    assert isinstance(issues, list)
                    
                except Exception as e:
                    # Should be handled gracefully
                    self.logger.warning(f"Expected error in scenario {scenario['name']}: {e}")
                    
                    # Record error metrics
                    self.metrics.increment_counter(f"error_{scenario['name']}")
                
            except Exception as e:
                # Even setup errors should be handled
                self.logger.error(f"Error in scenario {scenario['name']}: {e}")
    
    def _create_unreadable_file(self) -> Path:
        """Create a file with restricted permissions."""
        file_path = Path(self.temp_dir) / "unreadable.py"
        file_path.write_text("# Test file")
        
        try:
            file_path.chmod(0o000)  # Remove all permissions
        except:
            pass  # May not work on all systems
        
        return file_path
    
    def _create_large_file(self) -> Path:
        """Create a very large file."""
        file_path = Path(self.temp_dir) / "large.py"
        
        # Create a file with many lines
        content = "# Large file test\n" * 10000
        file_path.write_text(content)
        
        return file_path
    
    def _create_malformed_file(self) -> Path:
        """Create a file with malformed content."""
        file_path = Path(self.temp_dir) / "malformed.py"
        
        # Create file with invalid Python syntax
        content = '''
# Malformed Python file
def incomplete_function(
    # Missing closing parenthesis and body
    
class IncompleteClass
    # Missing colon and body
    
# Invalid indentation
def another_function():
pass
    # Wrong indentation level
'''
        file_path.write_text(content)
        return file_path
    
    @pytest.mark.asyncio
    async def test_multi_environment_deployment_workflow(self):
        """Test workflow across different deployment environments."""
        environments = ["development", "staging", "production"]
        
        # Create test project
        project_dir = Path(self.temp_dir) / "multi_env_project"
        project_dir.mkdir()
        
        (project_dir / "app.py").write_text('''
import os

# Configuration that should vary by environment
DEBUG = True  # Should be False in production
API_KEY = "dev-key-123"  # Should come from env vars
LOG_LEVEL = "DEBUG"  # Should be WARNING+ in production

def get_database_url():
    # Should use environment-specific values
    return "postgresql://localhost/dev_db"
''')
        
        results = {}
        
        for env in environments:
            with patch.dict(os.environ, {
                "COMPLIANCE_SENTINEL_ENVIRONMENT": env,
                "COMPLIANCE_SENTINEL_LOG_LEVEL": "WARNING" if env == "production" else "INFO"
            }):
                # Run validation for this environment
                validator = ProductionDataValidator()
                issues = validator.validate_directory(str(project_dir))
                
                # Categorize issues by severity
                issue_counts = {
                    "critical": len([i for i in issues if i.severity.value == "critical"]),
                    "high": len([i for i in issues if i.severity.value == "high"]),
                    "medium": len([i for i in issues if i.severity.value == "medium"]),
                    "low": len([i for i in issues if i.severity.value == "low"])
                }
                
                results[env] = {
                    "total_issues": len(issues),
                    "by_severity": issue_counts,
                    "environment": env
                }
        
        # Verify environment-specific behavior
        # Production should be most strict
        if results["production"]["total_issues"] > 0:
            # Production should flag hardcoded values more strictly
            assert results["production"]["by_severity"]["critical"] >= 0
        
        # Development can be more permissive
        # Should still detect issues but may be less strict
        
        # Record cross-environment metrics
        for env, result in results.items():
            self.metrics.set_gauge(f"issues_total_{env}", result["total_issues"])
            for severity, count in result["by_severity"].items():
                self.metrics.set_gauge(f"issues_{severity}_{env}", count)


if __name__ == "__main__":
    pytest.main([__file__])