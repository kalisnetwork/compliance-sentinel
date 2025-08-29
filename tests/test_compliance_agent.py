"""Tests for the main ComplianceAgent workflow integration."""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typing import List

from compliance_sentinel.core.compliance_agent import ComplianceAgent, AnalysisWorkflowResult
from compliance_sentinel.models.analysis import AnalysisType, SecurityIssue, Severity
from compliance_sentinel.models.config import SystemConfiguration


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Python code for testing."""
    return '''
import os
import subprocess

def unsafe_function(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    # Command injection vulnerability
    os.system(f"echo {user_input}")
    
    # Hardcoded secret
    api_key = "sk-1234567890abcdef"
    
    # Weak random
    import random
    token = random.random()
    
    return query

def another_function():
    # Path traversal
    filename = input("Enter filename: ")
    with open(f"/data/{filename}", 'r') as f:
        return f.read()
'''


@pytest.fixture
def sample_requirements_txt():
    """Sample requirements.txt with vulnerable dependencies."""
    return '''
django==2.0.0
requests==2.18.0
pyyaml==3.12
'''


@pytest.fixture
def temp_project_dir(sample_vulnerable_code, sample_requirements_txt):
    """Create a temporary project directory with test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create Python file with vulnerabilities
        python_file = temp_path / "vulnerable.py"
        python_file.write_text(sample_vulnerable_code)
        
        # Create requirements file
        req_file = temp_path / "requirements.txt"
        req_file.write_text(sample_requirements_txt)
        
        # Create a clean file
        clean_file = temp_path / "clean.py"
        clean_file.write_text('''
def safe_function():
    """A safe function with no vulnerabilities."""
    return "Hello, World!"
''')
        
        yield temp_path


@pytest.fixture
def mock_config():
    """Mock system configuration."""
    config = SystemConfiguration()
    config.hooks_enabled = False  # Disable hooks for testing
    config.ide_feedback_enabled = True
    config.summary_reports_enabled = True
    config.analysis_timeout = 30
    return config


class TestComplianceAgent:
    """Test cases for ComplianceAgent."""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_config):
        """Test agent initialization."""
        agent = ComplianceAgent(mock_config)
        
        assert agent.config == mock_config
        assert agent.analysis_coordinator is not None
        assert agent.policy_engine is not None
        assert agent.feedback_engine is not None
        assert agent.dependency_scanner is not None
        assert not agent.is_running
        assert agent.hook_manager is None  # Disabled in config
    
    @pytest.mark.asyncio
    async def test_agent_start_stop(self, mock_config):
        """Test agent start and stop lifecycle."""
        agent = ComplianceAgent(mock_config)
        
        # Test start
        await agent.start()
        assert agent.is_running
        
        # Test stop
        await agent.stop()
        assert not agent.is_running
    
    @pytest.mark.asyncio
    async def test_context_manager(self, mock_config):
        """Test agent as async context manager."""
        async with ComplianceAgent(mock_config) as agent:
            assert agent.is_running
        
        assert not agent.is_running
    
    @pytest.mark.asyncio
    async def test_analyze_single_file(self, temp_project_dir, mock_config):
        """Test analyzing a single file."""
        agent = ComplianceAgent(mock_config)
        
        # Mock the analysis components
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[
                SecurityIssue(
                    rule_id="B608",
                    title="Hardcoded SQL query",
                    description="SQL query contains hardcoded values",
                    severity=Severity.HIGH,
                    file_path=str(temp_project_dir / "vulnerable.py"),
                    line_number=6,
                    column_number=1,
                    code_snippet="query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
                    remediation="Use parameterized queries",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    confidence="high"
                )
            ])
            
            with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                mock_feedback.return_value = True
                
                async with agent:
                    result = await agent.analyze_files([str(temp_project_dir / "vulnerable.py")])
                
                assert result.success
                assert result.total_issues == 1
                assert result.high_issues == 1
                assert result.feedback_generated
                assert len(result.file_paths) == 1
    
    @pytest.mark.asyncio
    async def test_analyze_multiple_files(self, temp_project_dir, mock_config):
        """Test analyzing multiple files."""
        agent = ComplianceAgent(mock_config)
        
        file_paths = [
            str(temp_project_dir / "vulnerable.py"),
            str(temp_project_dir / "clean.py")
        ]
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[
                SecurityIssue(
                    rule_id="B101",
                    title="Test issue",
                    description="Test description",
                    severity=Severity.MEDIUM,
                    file_path=str(temp_project_dir / "vulnerable.py"),
                    line_number=1,
                    column_number=1,
                    code_snippet="test",
                    remediation="Fix it",
                    references=[],
                    confidence="medium"
                )
            ])
            
            with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                mock_feedback.return_value = True
                
                async with agent:
                    result = await agent.analyze_files(file_paths)
                
                assert result.success
                assert result.total_issues == 1
                assert result.medium_issues == 1
                assert len(result.file_paths) == 2
    
    @pytest.mark.asyncio
    async def test_dependency_analysis(self, temp_project_dir, mock_config):
        """Test dependency vulnerability analysis."""
        agent = ComplianceAgent(mock_config)
        
        # Mock dependency scanner
        mock_vulnerability = Mock()
        mock_vulnerability.cve_id = "CVE-2021-1234"
        mock_vulnerability.vulnerability_id = "VULN-1234"
        mock_vulnerability.package_name = "django"
        mock_vulnerability.current_version = "2.0.0"
        mock_vulnerability.fixed_version = "2.2.0"
        mock_vulnerability.description = "Test vulnerability"
        mock_vulnerability.severity = Severity.HIGH
        mock_vulnerability.file_path = str(temp_project_dir / "requirements.txt")
        mock_vulnerability.advisory_url = "https://example.com/advisory"
        mock_vulnerability.cwe_id = "CWE-79"
        
        with patch.object(agent.dependency_scanner, 'scan_dependencies') as mock_scan:
            mock_scan.return_value = [mock_vulnerability]
            
            with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_sast:
                mock_sast.return_value = Mock(issues=[])
                
                with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                    mock_feedback.return_value = True
                    
                    async with agent:
                        result = await agent.analyze_files([str(temp_project_dir / "requirements.txt")])
                    
                    assert result.success
                    assert result.dependency_vulnerabilities == 1
                    assert result.total_issues == 1
                    assert result.high_issues == 1
    
    @pytest.mark.asyncio
    async def test_policy_application(self, temp_project_dir, mock_config):
        """Test policy rule application."""
        agent = ComplianceAgent(mock_config)
        
        # Mock policy violations
        policy_violation = SecurityIssue(
            rule_id="POLICY-001",
            title="Policy violation",
            description="Code violates security policy",
            severity=Severity.CRITICAL,
            file_path=str(temp_project_dir / "vulnerable.py"),
            line_number=10,
            column_number=1,
            code_snippet="api_key = \"sk-1234567890abcdef\"",
            remediation="Remove hardcoded secrets",
            references=[],
            confidence="high"
        )
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[])
            
            with patch.object(agent.policy_engine, 'apply_policies_to_file') as mock_policy:
                mock_policy.return_value = [policy_violation]
                
                with patch.object(agent.policy_engine, 'apply_global_policies') as mock_global:
                    mock_global.return_value = []
                    
                    with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                        mock_feedback.return_value = True
                        
                        async with agent:
                            result = await agent.analyze_files([str(temp_project_dir / "vulnerable.py")])
                        
                        assert result.success
                        assert result.policy_violations == 1
                        assert result.critical_issues == 1
                        assert result.has_blocking_issues
    
    @pytest.mark.asyncio
    async def test_issue_deduplication(self, temp_project_dir, mock_config):
        """Test that duplicate issues are properly deduplicated."""
        agent = ComplianceAgent(mock_config)
        
        # Create duplicate issues
        issue1 = SecurityIssue(
            rule_id="B101",
            title="Test issue",
            description="Test description",
            severity=Severity.HIGH,
            file_path=str(temp_project_dir / "vulnerable.py"),
            line_number=5,
            column_number=1,
            code_snippet="test",
            remediation="Fix it",
            references=[],
            confidence="high"
        )
        
        issue2 = SecurityIssue(
            rule_id="B101",  # Same rule, file, and line
            title="Test issue duplicate",
            description="Different description",
            severity=Severity.MEDIUM,
            file_path=str(temp_project_dir / "vulnerable.py"),
            line_number=5,
            column_number=1,
            code_snippet="test",
            remediation="Fix it differently",
            references=[],
            confidence="medium"
        )
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[issue1, issue2])
            
            with patch.object(agent.policy_engine, 'apply_policies_to_file') as mock_policy:
                mock_policy.return_value = []
                
                with patch.object(agent.policy_engine, 'apply_global_policies') as mock_global:
                    mock_global.return_value = []
                    
                    with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                        mock_feedback.return_value = True
                        
                        async with agent:
                            result = await agent.analyze_files([str(temp_project_dir / "vulnerable.py")])
                        
                        # Should only have 1 issue after deduplication
                        assert result.success
                        assert result.total_issues == 1
                        assert result.high_issues == 1  # Should keep the higher severity
    
    @pytest.mark.asyncio
    async def test_analyze_project(self, temp_project_dir, mock_config):
        """Test analyzing entire project."""
        agent = ComplianceAgent(mock_config)
        
        # Update config to include Python files
        mock_config.file_patterns = ['*.py']
        mock_config.excluded_directories = ['.git', '__pycache__']
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[
                SecurityIssue(
                    rule_id="B101",
                    title="Test issue",
                    description="Test description",
                    severity=Severity.LOW,
                    file_path=str(temp_project_dir / "vulnerable.py"),
                    line_number=1,
                    column_number=1,
                    code_snippet="test",
                    remediation="Fix it",
                    references=[],
                    confidence="low"
                )
            ])
            
            with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                mock_feedback.return_value = True
                
                async with agent:
                    result = await agent.analyze_project(str(temp_project_dir))
                
                assert result.success
                assert result.total_issues == 1
                assert result.low_issues == 1
                # Should find both Python files
                assert len(result.file_paths) == 2
    
    @pytest.mark.asyncio
    async def test_error_handling(self, temp_project_dir, mock_config):
        """Test error handling in analysis workflow."""
        agent = ComplianceAgent(mock_config)
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.side_effect = Exception("Analysis failed")
            
            async with agent:
                result = await agent.analyze_files([str(temp_project_dir / "vulnerable.py")])
            
            assert not result.success
            assert result.error_message == "Analysis failed"
            assert result.total_issues == 0
    
    @pytest.mark.asyncio
    async def test_workflow_metrics(self, temp_project_dir, mock_config):
        """Test workflow metrics tracking."""
        agent = ComplianceAgent(mock_config)
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            mock_scan.return_value = Mock(issues=[])
            
            with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                mock_feedback.return_value = True
                
                async with agent:
                    # Run multiple analyses
                    await agent.analyze_files([str(temp_project_dir / "clean.py")])
                    await agent.analyze_files([str(temp_project_dir / "vulnerable.py")])
                
                metrics = agent.get_workflow_metrics()
                
                assert metrics['total_analyses'] == 2
                assert metrics['successful_analyses'] == 2
                assert metrics['failed_analyses'] == 0
                assert metrics['success_rate'] == 1.0
                assert metrics['total_files_analyzed'] == 2
    
    @pytest.mark.asyncio
    async def test_system_status(self, mock_config):
        """Test system status reporting."""
        agent = ComplianceAgent(mock_config)
        
        async with agent:
            status = agent.get_system_status()
            
            assert status['agent_running'] is True
            assert status['components']['analysis_coordinator'] is True
            assert status['components']['policy_engine'] is True
            assert status['components']['feedback_engine'] is True
            assert status['components']['dependency_scanner'] is True
            assert status['components']['hook_manager'] is False  # Disabled
            assert 'metrics' in status
            assert 'configuration' in status
    
    @pytest.mark.asyncio
    async def test_concurrent_analyses(self, temp_project_dir, mock_config):
        """Test handling concurrent analysis requests."""
        agent = ComplianceAgent(mock_config)
        
        with patch.object(agent.analysis_coordinator, 'run_comprehensive_scan') as mock_scan:
            # Add delay to simulate real analysis
            async def delayed_scan(*args, **kwargs):
                await asyncio.sleep(0.1)
                return Mock(issues=[])
            
            mock_scan.side_effect = delayed_scan
            
            with patch.object(agent.feedback_engine, 'generate_ide_feedback') as mock_feedback:
                mock_feedback.return_value = True
                
                async with agent:
                    # Start multiple concurrent analyses
                    tasks = [
                        agent.analyze_files([str(temp_project_dir / "clean.py")]),
                        agent.analyze_files([str(temp_project_dir / "vulnerable.py")]),
                        agent.analyze_files([str(temp_project_dir / "requirements.txt")])
                    ]
                    
                    results = await asyncio.gather(*tasks)
                    
                    # All should succeed
                    assert all(result.success for result in results)
                    assert len(results) == 3
                    
                    # Check metrics
                    metrics = agent.get_workflow_metrics()
                    assert metrics['total_analyses'] == 3
    
    def test_workflow_result_properties(self):
        """Test AnalysisWorkflowResult properties."""
        result = AnalysisWorkflowResult(
            request_id="test",
            file_paths=["test.py"],
            total_issues=5,
            critical_issues=1,
            high_issues=2,
            medium_issues=1,
            low_issues=1,
            policy_violations=2,
            dependency_vulnerabilities=1,
            analysis_duration_ms=100.0,
            feedback_generated=True,
            success=True
        )
        
        assert result.has_blocking_issues is True  # Has critical and high
        
        severity_breakdown = result.severity_breakdown
        assert severity_breakdown['critical'] == 1
        assert severity_breakdown['high'] == 2
        assert severity_breakdown['medium'] == 1
        assert severity_breakdown['low'] == 1
        
        # Test with no blocking issues
        result_safe = AnalysisWorkflowResult(
            request_id="test",
            file_paths=["test.py"],
            total_issues=2,
            critical_issues=0,
            high_issues=0,
            medium_issues=1,
            low_issues=1,
            policy_violations=0,
            dependency_vulnerabilities=0,
            analysis_duration_ms=50.0,
            feedback_generated=False,
            success=True
        )
        
        assert result_safe.has_blocking_issues is False


if __name__ == "__main__":
    pytest.main([__file__])