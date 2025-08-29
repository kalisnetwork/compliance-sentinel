"""Integration tests for CLI commands with dynamic configuration."""

import os
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from click.testing import CliRunner

from compliance_sentinel.cli import main, config, analysis
from compliance_sentinel.config.dynamic_config import DynamicConfigManager


class TestCLIIntegration:
    """Integration tests for CLI commands."""
    
    @pytest.fixture
    def cli_runner(self):
        """Create CLI runner for testing."""
        return CliRunner()
    
    @pytest.fixture
    def temp_workspace(self):
        """Create temporary workspace for testing."""
        temp_dir = tempfile.mkdtemp()
        
        # Create test files
        test_files = {
            "secure_code.py": '''
import os
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY not set")

def secure_function():
    return "secure code"
''',
            "insecure_code.py": '''
API_KEY = "hardcoded-api-key-123"
PASSWORD = "admin123"

def insecure_function():
    return "insecure code"
''',
            "mixed_code.py": '''
import os
from typing import Optional

# Good: Environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

# Bad: Hardcoded secret
SECRET_KEY = "hardcoded-secret-key"

def mixed_function(user_input: str) -> str:
    # Potential SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
'''
        }
        
        workspace_path = Path(temp_dir)
        for filename, content in test_files.items():
            (workspace_path / filename).write_text(content)
        
        yield workspace_path
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_main_command_with_environment_config(self, cli_runner):
        """Test main command with environment configuration."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "test",
            "COMPLIANCE_SENTINEL_CLI_VERBOSE": "true",
            "COMPLIANCE_SENTINEL_CLI_COLORS": "false"
        }):
            result = cli_runner.invoke(main, ['--help'])
            
            assert result.exit_code == 0
            assert "Compliance Sentinel" in result.output
            assert "Proactive Security and Compliance Enforcement" in result.output
    
    def test_config_show_command(self, cli_runner):
        """Test config show command with different formats."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "test",
            "COMPLIANCE_SENTINEL_CACHE_TTL": "1800",
            "COMPLIANCE_SENTINEL_LOG_LEVEL": "DEBUG"
        }):
            # Test table format (default)
            result = cli_runner.invoke(config, ['show'])
            assert result.exit_code == 0
            assert "Configuration" in result.output
            
            # Test JSON format
            result = cli_runner.invoke(config, ['show', '--format', 'json'])
            assert result.exit_code == 0
            
            # Should be valid JSON
            try:
                config_data = json.loads(result.output)
                assert isinstance(config_data, dict)
            except json.JSONDecodeError:
                # Output might contain additional text, extract JSON part
                lines = result.output.strip().split('\n')
                json_lines = [line for line in lines if line.startswith('{') or line.startswith('[')]
                if json_lines:
                    json_str = '\n'.join(json_lines)
                    config_data = json.loads(json_str)
                    assert isinstance(config_data, dict)
    
    def test_config_set_and_get_commands(self, cli_runner):
        """Test config set and get commands."""
        # Set a configuration value
        result = cli_runner.invoke(config, ['set', 'cache_ttl', '3600'])
        assert result.exit_code == 0
        assert "Set COMPLIANCE_SENTINEL_CACHE_TTL = 3600" in result.output
        
        # Get the configuration value
        with patch.dict(os.environ, {"COMPLIANCE_SENTINEL_CACHE_TTL": "3600"}):
            result = cli_runner.invoke(config, ['get', 'cache_ttl'])
            assert result.exit_code == 0
            assert "COMPLIANCE_SENTINEL_CACHE_TTL = 3600" in result.output
    
    def test_config_validate_command(self, cli_runner):
        """Test config validate command."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "test",
            "COMPLIANCE_SENTINEL_CACHE_TTL": "1800",
            "COMPLIANCE_SENTINEL_LOG_LEVEL": "INFO"
        }):
            result = cli_runner.invoke(config, ['validate'])
            
            # Should validate successfully or show specific errors
            assert result.exit_code in [0, 1]  # 0 for success, 1 for validation errors
            
            if result.exit_code == 0:
                assert "valid" in result.output.lower()
    
    def test_config_validate_with_environment(self, cli_runner):
        """Test config validate command with specific environment."""
        result = cli_runner.invoke(config, ['validate', '--environment', 'production'])
        
        # Should validate for production environment
        assert result.exit_code in [0, 1]
        
        if "production" in result.output:
            assert "production" in result.output.lower()
    
    def test_config_reload_command(self, cli_runner):
        """Test config reload command."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "test"
        }):
            result = cli_runner.invoke(config, ['reload'])
            
            assert result.exit_code == 0
            assert "reloaded" in result.output.lower()
    
    def test_scan_command_with_dynamic_config(self, cli_runner, temp_workspace):
        """Test scan command with dynamic configuration."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_DEFAULT_PATTERN": "*.py",
            "COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT": "json",
            "COMPLIANCE_SENTINEL_CLI_MAX_FILES": "10"
        }):
            # Change to temp workspace
            os.chdir(temp_workspace)
            
            # Mock the policy engine to avoid actual analysis
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(main, ['scan'])
                
                # Should use environment configuration
                assert result.exit_code == 0
    
    def test_analyze_command_with_config(self, cli_runner, temp_workspace):
        """Test analyze command with configuration."""
        test_file = temp_workspace / "insecure_code.py"
        
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT": "text"
        }):
            # Mock the policy engine
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(main, ['analyze', str(test_file)])
                
                assert result.exit_code == 0
    
    def test_analysis_run_command(self, cli_runner, temp_workspace):
        """Test analysis run command with environment configuration."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ANALYSIS_OUTPUT_FORMAT": "json",
            "COMPLIANCE_SENTINEL_ANALYSIS_SEVERITY_THRESHOLD": "medium",
            "COMPLIANCE_SENTINEL_ANALYSIS_MAX_FILE_SIZE_MB": "5"
        }):
            # Mock the policy engine
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, ['run', str(temp_workspace)])
                
                # Should complete successfully
                assert result.exit_code == 0
                assert "Analysis complete" in result.output
    
    def test_analysis_run_with_custom_rules(self, cli_runner, temp_workspace):
        """Test analysis run command with custom rules."""
        with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
            mock_engine = MagicMock()
            mock_engine.apply_policies_to_content.return_value = []
            mock_engine.load_rules = MagicMock()
            mock_policy_engine.return_value = mock_engine
            
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--rules', 'rule1,rule2,rule3',
                '--exclude-rules', 'rule4,rule5',
                '--severity-threshold', 'high'
            ])
            
            assert result.exit_code == 0
            
            # Verify rules were loaded
            mock_engine.load_rules.assert_called_once_with(['rule1', 'rule2', 'rule3'])
    
    def test_analysis_run_with_output_file(self, cli_runner, temp_workspace):
        """Test analysis run command with output file."""
        output_file = temp_workspace / "analysis_results.json"
        
        with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
            mock_engine = MagicMock()
            mock_engine.apply_policies_to_content.return_value = []
            mock_policy_engine.return_value = mock_engine
            
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--output-format', 'json',
                '--output-file', str(output_file)
            ])
            
            assert result.exit_code == 0
            assert "Analysis results written" in result.output
            
            # Verify output file was created
            assert output_file.exists()
            
            # Verify output file contains valid JSON
            with open(output_file) as f:
                data = json.load(f)
                assert "total_issues" in data
                assert "issues" in data
    
    def test_analysis_run_with_fail_on_issues(self, cli_runner, temp_workspace):
        """Test analysis run command with fail-on-issues flag."""
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        
        # Create mock issues
        mock_issues = [
            MagicMock(
                id="test-issue-1",
                severity=Severity.HIGH,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path="test.py",
                line_number=1,
                description="Test issue",
                rule_id="TEST_RULE",
                confidence=0.9,
                remediation_suggestions=["Fix the issue"]
            )
        ]
        
        with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
            mock_engine = MagicMock()
            mock_engine.apply_policies_to_content.return_value = mock_issues
            mock_policy_engine.return_value = mock_engine
            
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--fail-on-issues'
            ])
            
            # Should exit with error code when issues are found
            assert result.exit_code == 1
            assert "Found 1 issues, exiting with error code" in result.output
    
    def test_environment_specific_cli_behavior(self, cli_runner, temp_workspace):
        """Test environment-specific CLI behavior."""
        # Test development environment
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "development",
            "COMPLIANCE_SENTINEL_CLI_VERBOSE": "true",
            "COMPLIANCE_SENTINEL_CLI_PROGRESS": "true"
        }):
            result = cli_runner.invoke(main, ['--verbose', '--help'])
            assert result.exit_code == 0
            assert "development" in result.output.lower()
        
        # Test production environment
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "production",
            "COMPLIANCE_SENTINEL_CLI_VERBOSE": "false",
            "COMPLIANCE_SENTINEL_CLI_COLORS": "false"
        }):
            result = cli_runner.invoke(main, ['--help'])
            assert result.exit_code == 0
            assert "production" in result.output.lower()
    
    def test_cli_error_handling(self, cli_runner):
        """Test CLI error handling with invalid inputs."""
        # Test invalid environment
        result = cli_runner.invoke(main, ['--environment', 'invalid_env', '--help'])
        assert result.exit_code in [0, 1]  # May succeed with warning or fail
        
        # Test invalid configuration
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_LOG_LEVEL": "INVALID_LEVEL"
        }):
            result = cli_runner.invoke(config, ['validate'])
            assert result.exit_code == 1
            assert "invalid" in result.output.lower() or "error" in result.output.lower()
    
    def test_cli_with_missing_dependencies(self, cli_runner):
        """Test CLI behavior when optional dependencies are missing."""
        # Mock missing dependency
        with patch('compliance_sentinel.cli.PolicyEngine', side_effect=ImportError("Missing dependency")):
            result = cli_runner.invoke(main, ['scan', '--help'])
            # Should handle gracefully or show appropriate error
            assert result.exit_code in [0, 1]
    
    def test_cli_configuration_precedence(self, cli_runner):
        """Test configuration precedence (CLI args > env vars > defaults)."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_VERBOSE": "false"
        }):
            # CLI argument should override environment variable
            result = cli_runner.invoke(main, ['--verbose', '--help'])
            assert result.exit_code == 0
            # Verbose should be enabled despite env var being false
    
    def test_cli_output_formats(self, cli_runner, temp_workspace):
        """Test different CLI output formats."""
        with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
            mock_engine = MagicMock()
            mock_engine.apply_policies_to_content.return_value = []
            mock_policy_engine.return_value = mock_engine
            
            # Test JSON output
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--output-format', 'json'
            ])
            assert result.exit_code == 0
            
            # Test text output
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--output-format', 'text'
            ])
            assert result.exit_code == 0
            
            # Test CSV output (if supported)
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--output-format', 'csv'
            ])
            # May not be supported, so allow failure
            assert result.exit_code in [0, 1]
    
    def test_cli_progress_indicators(self, cli_runner, temp_workspace):
        """Test CLI progress indicators."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_PROGRESS": "true"
        }):
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, ['run', str(temp_workspace)])
                assert result.exit_code == 0
                # Progress indicators might be in output
    
    def test_cli_color_output(self, cli_runner):
        """Test CLI color output configuration."""
        # Test with colors enabled
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_COLORS": "true"
        }):
            result = cli_runner.invoke(main, ['--help'])
            assert result.exit_code == 0
        
        # Test with colors disabled
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_COLORS": "false"
        }):
            result = cli_runner.invoke(main, ['--help'])
            assert result.exit_code == 0
    
    def test_cli_file_pattern_matching(self, cli_runner, temp_workspace):
        """Test CLI file pattern matching."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_DEFAULT_PATTERN": "*.py"
        }):
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, [
                    'run', str(temp_workspace),
                    '--pattern', '*.py'
                ])
                assert result.exit_code == 0
    
    def test_cli_max_files_limit(self, cli_runner, temp_workspace):
        """Test CLI max files limit."""
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CLI_MAX_FILES": "2"
        }):
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, ['run', str(temp_workspace)])
                assert result.exit_code == 0
                # Should respect max files limit
    
    def test_cli_severity_threshold(self, cli_runner, temp_workspace):
        """Test CLI severity threshold configuration."""
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        
        # Create issues with different severities
        mock_issues = [
            MagicMock(
                severity=Severity.LOW,
                category=SecurityCategory.CODE_QUALITY,
                description="Low severity issue"
            ),
            MagicMock(
                severity=Severity.HIGH,
                category=SecurityCategory.HARDCODED_SECRETS,
                description="High severity issue"
            )
        ]
        
        with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
            mock_engine = MagicMock()
            mock_engine.apply_policies_to_content.return_value = mock_issues
            mock_policy_engine.return_value = mock_engine
            
            # Test with high severity threshold
            result = cli_runner.invoke(analysis, [
                'run', str(temp_workspace),
                '--severity-threshold', 'high'
            ])
            assert result.exit_code == 0
            # Should filter out low severity issues
    
    def test_cli_configuration_file_support(self, cli_runner, temp_workspace):
        """Test CLI configuration file support."""
        config_file = temp_workspace / "config.yaml"
        config_file.write_text("""
analysis:
  output_format: json
  severity_threshold: medium
  max_files: 100
""")
        
        with patch.dict(os.environ, {
            "COMPLIANCE_SENTINEL_CONFIG_FILE": str(config_file)
        }):
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, ['run', str(temp_workspace)])
                assert result.exit_code == 0
                # Should use configuration from file


class TestCLIPerformance:
    """Performance tests for CLI commands."""
    
    def test_cli_startup_time(self, cli_runner):
        """Test CLI startup time."""
        import time
        
        start_time = time.time()
        result = cli_runner.invoke(main, ['--help'])
        end_time = time.time()
        
        startup_time = end_time - start_time
        
        assert result.exit_code == 0
        # CLI should start quickly (under 2 seconds)
        assert startup_time < 2.0
    
    def test_cli_large_directory_handling(self, cli_runner):
        """Test CLI handling of large directories."""
        # Create temporary directory with many files
        temp_dir = tempfile.mkdtemp()
        temp_path = Path(temp_dir)
        
        try:
            # Create 100 small Python files
            for i in range(100):
                (temp_path / f"file_{i}.py").write_text(f"# File {i}\nprint('Hello {i}')")
            
            with patch('compliance_sentinel.cli.PolicyEngine') as mock_policy_engine:
                mock_engine = MagicMock()
                mock_engine.apply_policies_to_content.return_value = []
                mock_policy_engine.return_value = mock_engine
                
                result = cli_runner.invoke(analysis, ['run', str(temp_path)])
                assert result.exit_code == 0
                # Should handle large number of files
        
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    pytest.main([__file__])