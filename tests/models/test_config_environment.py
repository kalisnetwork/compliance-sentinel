"""Tests for environment-aware configuration models."""

import os
import json
import pytest
from unittest.mock import patch

from compliance_sentinel.models.config import (
    SystemConfiguration,
    HookSettings,
    MCPServerConfig,
    AnalysisConfig,
    FeedbackConfig,
    _get_env_var
)
from compliance_sentinel.core.interfaces import Severity


class TestEnvironmentVariableHelper:
    """Test the environment variable helper function."""
    
    def setup_method(self):
        """Set up test environment."""
        # Clear any existing test environment variables
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_get_env_var_string(self):
        """Test getting string environment variable."""
        os.environ["COMPLIANCE_SENTINEL_TEST_STRING"] = "test_value"
        
        result = _get_env_var("test_string", "default")
        assert result == "test_value"
    
    def test_get_env_var_default(self):
        """Test getting default value when env var not set."""
        result = _get_env_var("missing_var", "default_value")
        assert result == "default_value"
    
    def test_get_env_var_boolean(self):
        """Test getting boolean environment variable."""
        test_cases = [
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
            ("off", False)
        ]
        
        for env_value, expected in test_cases:
            os.environ["COMPLIANCE_SENTINEL_TEST_BOOL"] = env_value
            result = _get_env_var("test_bool", False, bool)
            assert result == expected, f"Failed for {env_value}"
    
    def test_get_env_var_integer(self):
        """Test getting integer environment variable."""
        os.environ["COMPLIANCE_SENTINEL_TEST_INT"] = "42"
        
        result = _get_env_var("test_int", 0, int)
        assert result == 42
    
    def test_get_env_var_float(self):
        """Test getting float environment variable."""
        os.environ["COMPLIANCE_SENTINEL_TEST_FLOAT"] = "3.14"
        
        result = _get_env_var("test_float", 0.0, float)
        assert result == 3.14
    
    def test_get_env_var_list_json(self):
        """Test getting list from JSON environment variable."""
        os.environ["COMPLIANCE_SENTINEL_TEST_LIST"] = '["item1", "item2", "item3"]'
        
        result = _get_env_var("test_list", [], list)
        assert result == ["item1", "item2", "item3"]
    
    def test_get_env_var_list_comma_separated(self):
        """Test getting list from comma-separated environment variable."""
        os.environ["COMPLIANCE_SENTINEL_TEST_LIST"] = "item1,item2,item3"
        
        result = _get_env_var("test_list", [], list)
        assert result == ["item1", "item2", "item3"]
    
    def test_get_env_var_dict(self):
        """Test getting dictionary from JSON environment variable."""
        test_dict = {"key1": "value1", "key2": 42}
        os.environ["COMPLIANCE_SENTINEL_TEST_DICT"] = json.dumps(test_dict)
        
        result = _get_env_var("test_dict", {}, dict)
        assert result == test_dict
    
    def test_get_env_var_invalid_type(self):
        """Test handling invalid type conversion."""
        os.environ["COMPLIANCE_SENTINEL_TEST_INVALID"] = "not_a_number"
        
        with pytest.raises(ValueError, match="Invalid value"):
            _get_env_var("test_invalid", 0, int)


class TestSystemConfiguration:
    """Test SystemConfiguration with environment variables."""
    
    def setup_method(self):
        """Set up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_default_configuration(self):
        """Test default configuration values."""
        config = SystemConfiguration()
        
        assert config.python_version == "3.11"
        assert config.analysis_tools == ["bandit", "semgrep"]
        assert config.mcp_server_url == "http://localhost:8000"
        assert config.cache_ttl == 3600
        assert config.max_concurrent_analyses == 5
        assert config.severity_threshold == Severity.MEDIUM
        assert config.enable_external_intelligence is True
        assert config.analysis_timeout == 300
    
    def test_environment_override(self):
        """Test configuration override from environment variables."""
        os.environ["COMPLIANCE_SENTINEL_PYTHON_VERSION"] = "3.12"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_TOOLS"] = '["bandit", "semgrep", "safety"]'
        os.environ["COMPLIANCE_SENTINEL_MCP_SERVER_URL"] = "https://api.example.com"
        os.environ["COMPLIANCE_SENTINEL_CACHE_TTL"] = "7200"
        os.environ["COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES"] = "10"
        os.environ["COMPLIANCE_SENTINEL_SEVERITY_THRESHOLD"] = "high"
        os.environ["COMPLIANCE_SENTINEL_ENABLE_EXTERNAL_INTELLIGENCE"] = "false"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_TIMEOUT"] = "600"
        
        config = SystemConfiguration()
        
        assert config.python_version == "3.12"
        assert config.analysis_tools == ["bandit", "semgrep", "safety"]
        assert config.mcp_server_url == "https://api.example.com"
        assert config.cache_ttl == 7200
        assert config.max_concurrent_analyses == 10
        assert config.severity_threshold == Severity.HIGH
        assert config.enable_external_intelligence is False
        assert config.analysis_timeout == 600
    
    def test_validation_errors(self):
        """Test configuration validation errors."""
        os.environ["COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES"] = "0"
        
        with pytest.raises(ValueError, match="max_concurrent_analyses must be at least 1"):
            SystemConfiguration()
    
    def test_from_environment_custom_prefix(self):
        """Test creating configuration with custom environment prefix."""
        os.environ["CUSTOM_PREFIX_PYTHON_VERSION"] = "3.10"
        os.environ["CUSTOM_PREFIX_CACHE_TTL"] = "1800"
        
        config = SystemConfiguration.from_environment("CUSTOM_PREFIX_")
        
        assert config.python_version == "3.10"
        assert config.cache_ttl == 1800
    
    def test_to_dict(self):
        """Test converting configuration to dictionary."""
        config = SystemConfiguration()
        config_dict = config.to_dict()
        
        assert isinstance(config_dict, dict)
        assert config_dict["python_version"] == "3.11"
        assert config_dict["severity_threshold"] == "medium"
        assert isinstance(config_dict["analysis_tools"], list)
    
    def test_from_dict(self):
        """Test creating configuration from dictionary."""
        config_dict = {
            "python_version": "3.12",
            "analysis_tools": ["bandit"],
            "cache_ttl": 1800,
            "severity_threshold": "high"
        }
        
        config = SystemConfiguration.from_dict(config_dict)
        
        assert config.python_version == "3.12"
        assert config.analysis_tools == ["bandit"]
        assert config.cache_ttl == 1800
        assert config.severity_threshold == Severity.HIGH
    
    def test_get_secure_defaults(self):
        """Test getting secure default values."""
        config = SystemConfiguration()
        defaults = config.get_secure_defaults()
        
        assert defaults["max_concurrent_analyses"] == 3  # Conservative
        assert defaults["severity_threshold"] == "high"  # Stricter
        assert defaults["enable_external_intelligence"] is False  # Disabled for security
        assert defaults["hooks_enabled"] is False  # Disabled for security


class TestHookSettings:
    """Test HookSettings with environment variables."""
    
    def setup_method(self):
        """Set up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_default_hook_settings(self):
        """Test default hook settings."""
        settings = HookSettings()
        
        assert settings.enabled_file_patterns == ["*.py", "*.js", "*.ts"]
        assert "node_modules" in settings.excluded_directories
        assert settings.analysis_timeout == 60
        assert settings.async_processing is True
        assert settings.batch_size == 10
        assert settings.debounce_delay == 0.5
    
    def test_environment_override_hook_settings(self):
        """Test hook settings override from environment."""
        os.environ["COMPLIANCE_SENTINEL_HOOK_FILE_PATTERNS"] = '["*.py", "*.java"]'
        os.environ["COMPLIANCE_SENTINEL_HOOK_EXCLUDED_DIRS"] = '["build", "dist"]'
        os.environ["COMPLIANCE_SENTINEL_HOOK_ANALYSIS_TIMEOUT"] = "120"
        os.environ["COMPLIANCE_SENTINEL_HOOK_ASYNC_PROCESSING"] = "false"
        os.environ["COMPLIANCE_SENTINEL_HOOK_BATCH_SIZE"] = "20"
        os.environ["COMPLIANCE_SENTINEL_HOOK_DEBOUNCE_DELAY"] = "1.0"
        
        settings = HookSettings()
        
        assert settings.enabled_file_patterns == ["*.py", "*.java"]
        assert settings.excluded_directories == ["build", "dist"]
        assert settings.analysis_timeout == 120
        assert settings.async_processing is False
        assert settings.batch_size == 20
        assert settings.debounce_delay == 1.0
    
    def test_hook_settings_validation(self):
        """Test hook settings validation."""
        os.environ["COMPLIANCE_SENTINEL_HOOK_ANALYSIS_TIMEOUT"] = "5"
        
        with pytest.raises(ValueError, match="analysis_timeout must be at least 10 seconds"):
            HookSettings()


class TestMCPServerConfig:
    """Test MCPServerConfig with environment variables."""
    
    def setup_method(self):
        """Set up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_default_mcp_config(self):
        """Test default MCP server configuration."""
        config = MCPServerConfig()
        
        assert config.host == "localhost"
        assert config.port == 8000
        assert config.workers == 4
        assert config.enable_cors is True
        assert config.api_key_required is False
        assert config.rate_limit_requests == 100
        assert config.cache_enabled is True
    
    def test_environment_override_mcp_config(self):
        """Test MCP config override from environment."""
        os.environ["COMPLIANCE_SENTINEL_MCP_HOST"] = "0.0.0.0"
        os.environ["COMPLIANCE_SENTINEL_MCP_PORT"] = "9000"
        os.environ["COMPLIANCE_SENTINEL_MCP_WORKERS"] = "8"
        os.environ["COMPLIANCE_SENTINEL_MCP_ENABLE_CORS"] = "false"
        os.environ["COMPLIANCE_SENTINEL_MCP_API_KEY_REQUIRED"] = "true"
        os.environ["COMPLIANCE_SENTINEL_MCP_RATE_LIMIT_REQUESTS"] = "200"
        
        config = MCPServerConfig()
        
        assert config.host == "0.0.0.0"
        assert config.port == 9000
        assert config.workers == 8
        assert config.enable_cors is False
        assert config.api_key_required is True
        assert config.rate_limit_requests == 200
    
    def test_mcp_config_validation(self):
        """Test MCP configuration validation."""
        os.environ["COMPLIANCE_SENTINEL_MCP_PORT"] = "99999"
        
        with pytest.raises(ValueError, match="port must be between 1 and 65535"):
            MCPServerConfig()
    
    def test_external_apis_validation(self):
        """Test external APIs URL validation."""
        os.environ["COMPLIANCE_SENTINEL_MCP_EXTERNAL_APIS"] = '{"invalid": "not-a-url"}'
        
        with pytest.raises(ValueError, match="must have a valid HTTP/HTTPS URL"):
            MCPServerConfig()


class TestAnalysisConfig:
    """Test AnalysisConfig with environment variables."""
    
    def setup_method(self):
        """Set up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_default_analysis_config(self):
        """Test default analysis configuration."""
        config = AnalysisConfig()
        
        assert config.enable_bandit is True
        assert config.enable_semgrep is True
        assert config.enable_dependency_check is True
        assert config.dependency_check_timeout == 120
        assert config.include_test_files is False
        assert config.max_file_size_mb == 10
    
    def test_environment_override_analysis_config(self):
        """Test analysis config override from environment."""
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_ENABLE_BANDIT"] = "false"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_DEPENDENCY_TIMEOUT"] = "180"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_INCLUDE_TEST_FILES"] = "true"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_MAX_FILE_SIZE_MB"] = "20"
        
        config = AnalysisConfig()
        
        assert config.enable_bandit is False
        assert config.dependency_check_timeout == 180
        assert config.include_test_files is True
        assert config.max_file_size_mb == 20
    
    def test_analysis_config_validation(self):
        """Test analysis configuration validation."""
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_ENABLE_BANDIT"] = "false"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_ENABLE_SEMGREP"] = "false"
        os.environ["COMPLIANCE_SENTINEL_ANALYSIS_ENABLE_DEPENDENCY_CHECK"] = "false"
        
        with pytest.raises(ValueError, match="At least one analysis tool must be enabled"):
            AnalysisConfig()


class TestFeedbackConfig:
    """Test FeedbackConfig with environment variables."""
    
    def setup_method(self):
        """Set up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("COMPLIANCE_SENTINEL_"):
                del os.environ[key]
    
    def test_default_feedback_config(self):
        """Test default feedback configuration."""
        config = FeedbackConfig()
        
        assert config.include_code_examples is True
        assert config.include_documentation_links is True
        assert config.max_suggestions_per_issue == 3
        assert config.enable_auto_fix_suggestions is True
        assert config.group_similar_issues is True
        assert "#FFA500" in config.severity_colors.values()
    
    def test_environment_override_feedback_config(self):
        """Test feedback config override from environment."""
        os.environ["COMPLIANCE_SENTINEL_FEEDBACK_INCLUDE_CODE_EXAMPLES"] = "false"
        os.environ["COMPLIANCE_SENTINEL_FEEDBACK_MAX_SUGGESTIONS"] = "5"
        os.environ["COMPLIANCE_SENTINEL_FEEDBACK_ENABLE_AUTO_FIX"] = "false"
        
        config = FeedbackConfig()
        
        assert config.include_code_examples is False
        assert config.max_suggestions_per_issue == 5
        assert config.enable_auto_fix_suggestions is False
    
    def test_feedback_config_validation(self):
        """Test feedback configuration validation."""
        os.environ["COMPLIANCE_SENTINEL_FEEDBACK_MAX_SUGGESTIONS"] = "0"
        
        with pytest.raises(ValueError, match="max_suggestions_per_issue must be at least 1"):
            FeedbackConfig()
    
    def test_severity_colors_validation(self):
        """Test severity colors validation."""
        os.environ["COMPLIANCE_SENTINEL_FEEDBACK_SEVERITY_COLORS"] = '{"low": "invalid-color"}'
        
        with pytest.raises(ValueError, match="Invalid color format"):
            FeedbackConfig()