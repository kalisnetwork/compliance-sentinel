"""End-to-end integration tests for the complete Compliance Sentinel workflow."""

import pytest
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import patch

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.models.analysis import AnalysisType


class TestEndToEndWorkflow:
    """Integration tests for complete workflow scenarios."""
    
    @pytest.fixture
    def realistic_vulnerable_code(self):
        """Realistic vulnerable Python code with multiple security issues."""
        return '''
import os
import subprocess
import sqlite3
import hashlib
import random
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secrets (Critical)
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key"

# Weak cryptography (High)
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# SQL Injection vulnerability (Critical)
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

# Command injection (Critical)
def process_file(filename):
    os.system(f"cat {filename}")
    subprocess.call(f"ls -la {filename}", shell=True)

# XSS vulnerability (High)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Path traversal (High)
def read_file(filename):
    with open(f"/data/{filename}", 'r') as f:
        return f.read()

# Weak random (Medium)
def generate_token():
    return str(random.random())

# Insecure deserialization (High)
import pickle
def load_data(data):
    return pickle.loads(data)

# Debug mode enabled (Medium)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
'''
    
    @pytest.fixture
    def vulnerable_requirements(self):
        """Requirements file with known vulnerable dependencies."""
        return '''
# Web framework with known vulnerabilities
django==2.0.0
flask==0.12.0

# HTTP library with vulnerabilities
requests==2.18.0

# YAML parser with vulnerabilities
pyyaml==3.12

# Crypto library with issues
cryptography==2.0.0

# Development dependencies
pytest==3.0.0
'''
    
    @pytest.fixture
    def security_policy_md(self):
        """Sample security policy in markdown format."""
        return '''
# Security Policy for Test Project

## Core Security Principles

1. **No Hardcoded Secrets**: All secrets must be loaded from environment variables
2. **Strong Cryptography**: Use only approved cryptographic algorithms
3. **Input Validation**: All user inputs must be validated and sanitized

## Security Rules

### Rule 1: Credential Management
**Policy**: Never hardcode sensitive credentials in source code.

**Requirements**:
- All secrets must be loaded from environment variables
- Use secure secret management systems
- Never log sensitive information

**Code Patterns to Detect**:
- Hardcoded passwords, API keys, database connections
- Secrets in configuration files

### Rule 2: Cryptographic Security
**Policy**: Use only approved cryptographic algorithms.

**Requirements**:
- Use strong encryption algorithms (AES-256, RSA-2048+)
- Use secure hashing for passwords (bcrypt, scrypt, Argon2)
- Never use MD5 or SHA1 for passwords

**Code Patterns to Detect**:
- Weak encryption algorithms (DES, MD5, SHA1 for passwords)
- Hardcoded encryption keys

### Rule 3: Input Validation
**Policy**: All user inputs must be properly validated.

**Requirements**:
- Validate input types, formats, and ranges
- Use parameterized queries for database operations
- Sanitize inputs to prevent injection attacks

**Code Patterns to Detect**:
- SQL injection vulnerabilities
- Command injection possibilities
- XSS vulnerabilities
'''
    
    @pytest.fixture
    def test_project(self, realistic_vulnerable_code, vulnerable_requirements, security_policy_md):
        """Create a complete test project with vulnerable code and policies."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Create main vulnerable file
            main_file = project_path / "app.py"
            main_file.write_text(realistic_vulnerable_code)
            
            # Create requirements file
            req_file = project_path / "requirements.txt"
            req_file.write_text(vulnerable_requirements)
            
            # Create Kiro steering directory and security policy
            kiro_dir = project_path / ".kiro" / "steering"
            kiro_dir.mkdir(parents=True)
            
            policy_file = kiro_dir / "security.md"
            policy_file.write_text(security_policy_md)
            
            # Create a clean utility file
            utils_file = project_path / "utils.py"
            utils_file.write_text('''
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def safe_function(data: str) -> str:
    """A safe utility function."""
    if not isinstance(data, str):
        raise ValueError("Input must be a string")
    
    return data.strip().lower()

def get_config_value(key: str) -> Optional[str]:
    """Safely get configuration from environment."""
    return os.environ.get(key)

def log_event(message: str) -> None:
    """Safely log an event."""
    logger.info("Event: %s", message)
''')
            
            yield project_path
    
    @pytest.mark.asyncio
    async def test_comprehensive_project_analysis(self, test_project):
        """Test comprehensive analysis of a realistic project."""
        # Configure agent for comprehensive analysis
        config = SystemConfiguration()
        config.hooks_enabled = False
        config.ide_feedback_enabled = True
        config.summary_reports_enabled = True
        config.analysis_timeout = 60
        config.file_patterns = ['*.py']
        config.excluded_directories = ['.git', '__pycache__', '.pytest_cache']
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Analyze the entire project
            result = await agent.analyze_project(str(test_project))
            
            # Verify analysis completed successfully
            assert result.success, f"Analysis failed: {result.error_message}"
            
            # Should find multiple files
            assert len(result.file_paths) >= 2  # app.py and utils.py
            
            # Should find security issues
            assert result.total_issues > 0, "Expected to find security issues in vulnerable code"
            
            # Should find critical issues (hardcoded secrets, SQL injection, command injection)
            assert result.critical_issues > 0, "Expected to find critical security issues"
            
            # Should find high severity issues
            assert result.high_issues > 0, "Expected to find high severity issues"
            
            # Should detect dependency vulnerabilities
            assert result.dependency_vulnerabilities > 0, "Expected to find vulnerable dependencies"
            
            # Should have blocking issues
            assert result.has_blocking_issues, "Expected blocking issues for critical/high severity"
            
            # Should generate feedback
            assert result.feedback_generated, "Expected feedback to be generated"
            
            # Analysis should complete in reasonable time
            assert result.analysis_duration_ms < 30000, "Analysis took too long"
            
            print(f"Analysis Results:")
            print(f"  Files analyzed: {len(result.file_paths)}")
            print(f"  Total issues: {result.total_issues}")
            print(f"  Critical: {result.critical_issues}")
            print(f"  High: {result.high_issues}")
            print(f"  Medium: {result.medium_issues}")
            print(f"  Low: {result.low_issues}")
            print(f"  Policy violations: {result.policy_violations}")
            print(f"  Dependency vulnerabilities: {result.dependency_vulnerabilities}")
            print(f"  Duration: {result.analysis_duration_ms:.2f}ms")
    
    @pytest.mark.asyncio
    async def test_single_file_analysis_workflow(self, test_project):
        """Test analyzing a single vulnerable file."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        config.ide_feedback_enabled = True
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Analyze just the main vulnerable file
            app_file = str(test_project / "app.py")
            result = await agent.analyze_files([app_file], AnalysisType.SECURITY_SCAN)
            
            assert result.success
            assert len(result.file_paths) == 1
            assert result.total_issues > 0
            
            # Should find multiple types of issues
            severity_breakdown = result.severity_breakdown
            assert sum(severity_breakdown.values()) == result.total_issues
            
            print(f"Single file analysis:")
            print(f"  File: {app_file}")
            print(f"  Issues found: {result.total_issues}")
            print(f"  Severity breakdown: {severity_breakdown}")
    
    @pytest.mark.asyncio
    async def test_clean_file_analysis(self, test_project):
        """Test analyzing a clean file with no vulnerabilities."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Analyze the clean utils file
            utils_file = str(test_project / "utils.py")
            result = await agent.analyze_files([utils_file])
            
            assert result.success
            assert len(result.file_paths) == 1
            
            # Should find few or no issues in clean code
            assert result.critical_issues == 0, "Clean file should not have critical issues"
            assert result.high_issues == 0, "Clean file should not have high severity issues"
            
            print(f"Clean file analysis:")
            print(f"  File: {utils_file}")
            print(f"  Issues found: {result.total_issues}")
            print(f"  Has blocking issues: {result.has_blocking_issues}")
    
    @pytest.mark.asyncio
    async def test_dependency_only_analysis(self, test_project):
        """Test analyzing only dependency files."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Analyze just the requirements file
            req_file = str(test_project / "requirements.txt")
            result = await agent.analyze_files([req_file])
            
            assert result.success
            assert len(result.file_paths) == 1
            
            # Should find dependency vulnerabilities
            assert result.dependency_vulnerabilities > 0, "Expected to find vulnerable dependencies"
            
            print(f"Dependency analysis:")
            print(f"  File: {req_file}")
            print(f"  Dependency vulnerabilities: {result.dependency_vulnerabilities}")
            print(f"  Total issues: {result.total_issues}")
    
    @pytest.mark.asyncio
    async def test_workflow_performance_metrics(self, test_project):
        """Test workflow performance tracking."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Run multiple analyses to test metrics
            files_to_analyze = [
                str(test_project / "app.py"),
                str(test_project / "utils.py"),
                str(test_project / "requirements.txt")
            ]
            
            results = []
            for file_path in files_to_analyze:
                result = await agent.analyze_files([file_path])
                results.append(result)
            
            # Check that all analyses succeeded
            assert all(r.success for r in results)
            
            # Get workflow metrics
            metrics = agent.get_workflow_metrics()
            
            assert metrics['total_analyses'] == 3
            assert metrics['successful_analyses'] == 3
            assert metrics['failed_analyses'] == 0
            assert metrics['success_rate'] == 1.0
            assert metrics['total_files_analyzed'] == 3
            assert metrics['average_duration_ms'] > 0
            
            print(f"Workflow metrics:")
            print(f"  Total analyses: {metrics['total_analyses']}")
            print(f"  Success rate: {metrics['success_rate']:.2%}")
            print(f"  Average duration: {metrics['average_duration_ms']:.2f}ms")
            print(f"  Total issues found: {metrics['total_issues_found']}")
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis_workflow(self, test_project):
        """Test concurrent analysis of multiple files."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Start concurrent analyses
            tasks = [
                agent.analyze_files([str(test_project / "app.py")]),
                agent.analyze_files([str(test_project / "utils.py")]),
                agent.analyze_files([str(test_project / "requirements.txt")])
            ]
            
            # Wait for all to complete
            results = await asyncio.gather(*tasks)
            
            # All should succeed
            assert all(r.success for r in results)
            assert len(results) == 3
            
            # Check system status during concurrent execution
            status = agent.get_system_status()
            assert status['agent_running'] is True
            
            print(f"Concurrent analysis completed:")
            print(f"  Results: {len(results)}")
            print(f"  All successful: {all(r.success for r in results)}")
    
    @pytest.mark.asyncio
    async def test_error_recovery_workflow(self, test_project):
        """Test error handling and recovery in workflow."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Try to analyze a non-existent file
            result = await agent.analyze_files(["/nonexistent/file.py"])
            
            # Should handle error gracefully
            assert not result.success
            assert result.error_message is not None
            assert result.total_issues == 0
            
            # Agent should still be functional after error
            status = agent.get_system_status()
            assert status['agent_running'] is True
            
            # Should be able to run successful analysis after error
            good_result = await agent.analyze_files([str(test_project / "utils.py")])
            assert good_result.success
            
            print(f"Error recovery test:")
            print(f"  Error handled gracefully: {result.error_message}")
            print(f"  Agent still functional: {status['agent_running']}")
            print(f"  Subsequent analysis successful: {good_result.success}")
    
    @pytest.mark.asyncio
    async def test_system_status_reporting(self, test_project):
        """Test comprehensive system status reporting."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        config.ide_feedback_enabled = True
        config.summary_reports_enabled = True
        
        agent = ComplianceAgent(config)
        
        async with agent:
            # Run an analysis to populate metrics
            await agent.analyze_files([str(test_project / "app.py")])
            
            # Get system status
            status = agent.get_system_status()
            
            # Verify status structure
            assert 'agent_running' in status
            assert 'components' in status
            assert 'metrics' in status
            assert 'configuration' in status
            
            # Verify component status
            components = status['components']
            assert components['analysis_coordinator'] is True
            assert components['policy_engine'] is True
            assert components['feedback_engine'] is True
            assert components['dependency_scanner'] is True
            assert components['hook_manager'] is False  # Disabled
            
            # Verify configuration
            config_status = status['configuration']
            assert config_status['hooks_enabled'] is False
            assert config_status['ide_feedback_enabled'] is True
            assert config_status['summary_reports_enabled'] is True
            
            print(f"System status:")
            print(f"  Agent running: {status['agent_running']}")
            print(f"  Components active: {sum(components.values())}/{len(components)}")
            print(f"  Metrics: {status['metrics']['total_analyses']} analyses")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])