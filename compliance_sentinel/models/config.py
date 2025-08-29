"""Configuration data models for the Compliance Sentinel system."""

import os
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from compliance_sentinel.core.interfaces import Severity


def _get_env_var(key: str, default: Any, var_type: type = str) -> Any:
    """Get environment variable with type conversion and default fallback."""
    env_key = f"COMPLIANCE_SENTINEL_{key.upper()}"
    value = os.getenv(env_key)
    
    if value is None:
        return default
    
    try:
        if var_type == bool:
            return value.lower() in ('true', '1', 'yes', 'on')
        elif var_type == int:
            return int(value)
        elif var_type == float:
            return float(value)
        elif var_type == list:
            # Try to parse as JSON array, fallback to comma-separated
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return [item.strip() for item in value.split(',') if item.strip()]
        elif var_type == dict:
            return json.loads(value)
        else:
            return value
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid value for {env_key}: {value}. Error: {e}")


@dataclass
class SystemConfiguration:
    """Main system configuration settings with environment variable support."""
    python_version: str = field(default_factory=lambda: _get_env_var("python_version", "3.11"))
    analysis_tools: List[str] = field(default_factory=lambda: _get_env_var("analysis_tools", ["bandit", "semgrep"], list))
    mcp_server_url: str = field(default_factory=lambda: _get_env_var("mcp_server_url", "http://localhost:8000"))
    cache_ttl: int = field(default_factory=lambda: _get_env_var("cache_ttl", 3600, int))
    max_concurrent_analyses: int = field(default_factory=lambda: _get_env_var("max_concurrent_analyses", 5, int))
    severity_threshold: Severity = field(default_factory=lambda: Severity(_get_env_var("severity_threshold", "medium")))
    enable_external_intelligence: bool = field(default_factory=lambda: _get_env_var("enable_external_intelligence", True, bool))
    analysis_timeout: int = field(default_factory=lambda: _get_env_var("analysis_timeout", 300, int))  # 5 minutes
    hooks_enabled: bool = field(default_factory=lambda: _get_env_var("hooks_enabled", True, bool))
    ide_feedback_enabled: bool = field(default_factory=lambda: _get_env_var("ide_feedback_enabled", True, bool))
    summary_reports_enabled: bool = field(default_factory=lambda: _get_env_var("summary_reports_enabled", True, bool))
    file_patterns: List[str] = field(default_factory=lambda: _get_env_var("file_patterns", ["*.py", "*.js", "*.ts", "*.java"], list))
    excluded_directories: List[str] = field(default_factory=lambda: _get_env_var("excluded_directories", ["node_modules", ".git", "__pycache__"], list))
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_configuration()
    
    def _validate_configuration(self) -> None:
        """Validate configuration values."""
        errors = []
        
        if self.max_concurrent_analyses < 1:
            errors.append("max_concurrent_analyses must be at least 1")
        
        if self.cache_ttl < 0:
            errors.append("cache_ttl must be non-negative")
        
        if self.analysis_timeout < 30:
            errors.append("analysis_timeout must be at least 30 seconds")
        
        if not self.analysis_tools:
            errors.append("at least one analysis tool must be specified")
        
        if not self.mcp_server_url.startswith(('http://', 'https://')):
            errors.append("mcp_server_url must be a valid HTTP/HTTPS URL")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    @classmethod
    def from_environment(cls, prefix: str = "COMPLIANCE_SENTINEL_") -> 'SystemConfiguration':
        """Create configuration from environment variables with custom prefix."""
        # Temporarily change the prefix for this instance
        original_get_env = globals()['_get_env_var']
        
        def custom_get_env(key: str, default: Any, var_type: type = str) -> Any:
            env_key = f"{prefix}{key.upper()}"
            value = os.getenv(env_key)
            
            if value is None:
                return default
            
            try:
                if var_type == bool:
                    return value.lower() in ('true', '1', 'yes', 'on')
                elif var_type == int:
                    return int(value)
                elif var_type == float:
                    return float(value)
                elif var_type == list:
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        return [item.strip() for item in value.split(',') if item.strip()]
                elif var_type == dict:
                    return json.loads(value)
                else:
                    return value
            except (ValueError, json.JSONDecodeError) as e:
                raise ValueError(f"Invalid value for {env_key}: {value}. Error: {e}")
        
        # Use custom environment variable getter
        globals()['_get_env_var'] = custom_get_env
        try:
            return cls()
        finally:
            # Restore original function
            globals()['_get_env_var'] = original_get_env
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'python_version': self.python_version,
            'analysis_tools': self.analysis_tools,
            'mcp_server_url': self.mcp_server_url,
            'cache_ttl': self.cache_ttl,
            'max_concurrent_analyses': self.max_concurrent_analyses,
            'severity_threshold': self.severity_threshold.value,
            'enable_external_intelligence': self.enable_external_intelligence,
            'analysis_timeout': self.analysis_timeout,
            'hooks_enabled': self.hooks_enabled,
            'ide_feedback_enabled': self.ide_feedback_enabled,
            'summary_reports_enabled': self.summary_reports_enabled,
            'file_patterns': self.file_patterns,
            'excluded_directories': self.excluded_directories
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SystemConfiguration':
        """Create configuration from dictionary."""
        # Convert severity string back to enum
        if 'severity_threshold' in data and isinstance(data['severity_threshold'], str):
            data['severity_threshold'] = Severity(data['severity_threshold'])
        
        return cls(**data)
    
    def get_secure_defaults(self) -> Dict[str, Any]:
        """Get secure default values for production environments."""
        return {
            'python_version': '3.11',
            'analysis_tools': ['bandit', 'semgrep'],
            'mcp_server_url': 'http://localhost:8000',
            'cache_ttl': 3600,
            'max_concurrent_analyses': 3,  # Conservative for production
            'severity_threshold': 'high',  # Stricter for production
            'enable_external_intelligence': False,  # Disabled by default for security
            'analysis_timeout': 180,  # Shorter timeout for production
            'hooks_enabled': False,  # Disabled by default for security
            'ide_feedback_enabled': True,
            'summary_reports_enabled': True,
            'file_patterns': ['*.py', '*.js', '*.ts', '*.java', '*.go'],
            'excluded_directories': ['node_modules', '.git', '__pycache__', '.venv', 'venv', 'build', 'dist']
        }


@dataclass
class HookSettings:
    """Configuration for Kiro Agent Hook integration with environment variable support."""
    enabled_file_patterns: List[str] = field(default_factory=lambda: _get_env_var("hook_file_patterns", ["*.py", "*.js", "*.ts"], list))
    excluded_directories: List[str] = field(default_factory=lambda: _get_env_var("hook_excluded_dirs", [
        "node_modules", "__pycache__", ".git", ".venv", "venv"
    ], list))
    analysis_timeout: int = field(default_factory=lambda: _get_env_var("hook_analysis_timeout", 60, int))
    async_processing: bool = field(default_factory=lambda: _get_env_var("hook_async_processing", True, bool))
    batch_size: int = field(default_factory=lambda: _get_env_var("hook_batch_size", 10, int))
    debounce_delay: float = field(default_factory=lambda: _get_env_var("hook_debounce_delay", 0.5, float))  # seconds to wait before triggering analysis
    rate_limit_per_second: int = field(default_factory=lambda: _get_env_var("hook_rate_limit_per_second", 10, int))
    rate_limit_burst: int = field(default_factory=lambda: _get_env_var("hook_rate_limit_burst", 20, int))
    
    def __post_init__(self):
        """Validate hook settings."""
        errors = []
        
        if self.analysis_timeout < 10:
            errors.append("analysis_timeout must be at least 10 seconds")
        
        if self.batch_size < 1:
            errors.append("batch_size must be at least 1")
        
        if self.debounce_delay < 0:
            errors.append("debounce_delay must be non-negative")
        
        if self.rate_limit_per_second < 1:
            errors.append("rate_limit_per_second must be at least 1")
        
        if self.rate_limit_burst < 1:
            errors.append("rate_limit_burst must be at least 1")
        
        if not self.enabled_file_patterns:
            errors.append("at least one file pattern must be enabled")
        
        if errors:
            raise ValueError(f"Hook settings validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert hook settings to dictionary."""
        return {
            'enabled_file_patterns': self.enabled_file_patterns,
            'excluded_directories': self.excluded_directories,
            'analysis_timeout': self.analysis_timeout,
            'async_processing': self.async_processing,
            'batch_size': self.batch_size,
            'debounce_delay': self.debounce_delay,
            'rate_limit_per_second': self.rate_limit_per_second,
            'rate_limit_burst': self.rate_limit_burst
        }


@dataclass
class MCPServerConfig:
    """Configuration for the custom MCP server with environment variable support."""
    host: str = field(default_factory=lambda: _get_env_var("mcp_host", "localhost"))
    port: int = field(default_factory=lambda: _get_env_var("mcp_port", 8000, int))
    workers: int = field(default_factory=lambda: _get_env_var("mcp_workers", 4, int))
    enable_cors: bool = field(default_factory=lambda: _get_env_var("mcp_enable_cors", True, bool))
    api_key_required: bool = field(default_factory=lambda: _get_env_var("mcp_api_key_required", False, bool))
    rate_limit_requests: int = field(default_factory=lambda: _get_env_var("mcp_rate_limit_requests", 100, int))  # requests per minute
    rate_limit_window: int = field(default_factory=lambda: _get_env_var("mcp_rate_limit_window", 60, int))  # seconds
    external_apis: Dict[str, str] = field(default_factory=lambda: _get_env_var("mcp_external_apis", {
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "cve": "https://cve.circl.lu/api"
    }, dict))
    cache_enabled: bool = field(default_factory=lambda: _get_env_var("mcp_cache_enabled", True, bool))
    cache_size: int = field(default_factory=lambda: _get_env_var("mcp_cache_size", 1000, int))  # number of cached responses
    
    def __post_init__(self):
        """Validate MCP server configuration."""
        errors = []
        
        if not (1 <= self.port <= 65535):
            errors.append("port must be between 1 and 65535")
        
        if self.workers < 1:
            errors.append("workers must be at least 1")
        
        if self.rate_limit_requests < 1:
            errors.append("rate_limit_requests must be at least 1")
        
        if self.rate_limit_window < 1:
            errors.append("rate_limit_window must be at least 1")
        
        if self.cache_size < 0:
            errors.append("cache_size must be non-negative")
        
        # Validate external API URLs
        for name, url in self.external_apis.items():
            if not url.startswith(('http://', 'https://')):
                errors.append(f"external API '{name}' must have a valid HTTP/HTTPS URL")
        
        if errors:
            raise ValueError(f"MCP server configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert MCP server config to dictionary."""
        return {
            'host': self.host,
            'port': self.port,
            'workers': self.workers,
            'enable_cors': self.enable_cors,
            'api_key_required': self.api_key_required,
            'rate_limit_requests': self.rate_limit_requests,
            'rate_limit_window': self.rate_limit_window,
            'external_apis': self.external_apis,
            'cache_enabled': self.cache_enabled,
            'cache_size': self.cache_size
        }


@dataclass
class AnalysisConfig:
    """Configuration for security analysis behavior with environment variable support."""
    enable_bandit: bool = field(default_factory=lambda: _get_env_var("analysis_enable_bandit", True, bool))
    enable_semgrep: bool = field(default_factory=lambda: _get_env_var("analysis_enable_semgrep", True, bool))
    enable_dependency_check: bool = field(default_factory=lambda: _get_env_var("analysis_enable_dependency_check", True, bool))
    custom_bandit_config: Optional[str] = field(default_factory=lambda: _get_env_var("analysis_bandit_config", None))
    custom_semgrep_rules: List[str] = field(default_factory=lambda: _get_env_var("analysis_semgrep_rules", [], list))
    dependency_check_timeout: int = field(default_factory=lambda: _get_env_var("analysis_dependency_timeout", 120, int))
    include_test_files: bool = field(default_factory=lambda: _get_env_var("analysis_include_test_files", False, bool))
    max_file_size_mb: int = field(default_factory=lambda: _get_env_var("analysis_max_file_size_mb", 10, int))
    
    def __post_init__(self):
        """Validate analysis configuration."""
        errors = []
        
        if not any([self.enable_bandit, self.enable_semgrep, self.enable_dependency_check]):
            errors.append("At least one analysis tool must be enabled")
        
        if self.dependency_check_timeout < 30:
            errors.append("dependency_check_timeout must be at least 30 seconds")
        
        if self.max_file_size_mb < 1:
            errors.append("max_file_size_mb must be at least 1")
        
        if errors:
            raise ValueError(f"Analysis configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis config to dictionary."""
        return {
            'enable_bandit': self.enable_bandit,
            'enable_semgrep': self.enable_semgrep,
            'enable_dependency_check': self.enable_dependency_check,
            'custom_bandit_config': self.custom_bandit_config,
            'custom_semgrep_rules': self.custom_semgrep_rules,
            'dependency_check_timeout': self.dependency_check_timeout,
            'include_test_files': self.include_test_files,
            'max_file_size_mb': self.max_file_size_mb
        }


@dataclass
class FeedbackConfig:
    """Configuration for feedback generation and formatting with environment variable support."""
    include_code_examples: bool = field(default_factory=lambda: _get_env_var("feedback_include_code_examples", True, bool))
    include_documentation_links: bool = field(default_factory=lambda: _get_env_var("feedback_include_doc_links", True, bool))
    max_suggestions_per_issue: int = field(default_factory=lambda: _get_env_var("feedback_max_suggestions", 3, int))
    severity_colors: Dict[str, str] = field(default_factory=lambda: _get_env_var("feedback_severity_colors", {
        "low": "#FFA500",      # Orange
        "medium": "#FF6B35",   # Red-Orange  
        "high": "#FF0000",     # Red
        "critical": "#8B0000"  # Dark Red
    }, dict))
    enable_auto_fix_suggestions: bool = field(default_factory=lambda: _get_env_var("feedback_enable_auto_fix", True, bool))
    group_similar_issues: bool = field(default_factory=lambda: _get_env_var("feedback_group_similar", True, bool))
    
    def __post_init__(self):
        """Validate feedback configuration."""
        errors = []
        
        if self.max_suggestions_per_issue < 1:
            errors.append("max_suggestions_per_issue must be at least 1")
        
        required_severities = {"low", "medium", "high", "critical"}
        if not required_severities.issubset(set(self.severity_colors.keys())):
            errors.append("severity_colors must include all severity levels")
        
        # Validate color format (basic hex color validation)
        for severity, color in self.severity_colors.items():
            if not color.startswith('#') or len(color) != 7:
                errors.append(f"Invalid color format for {severity}: {color}")
        
        if errors:
            raise ValueError(f"Feedback configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert feedback config to dictionary."""
        return {
            'include_code_examples': self.include_code_examples,
            'include_documentation_links': self.include_documentation_links,
            'max_suggestions_per_issue': self.max_suggestions_per_issue,
            'severity_colors': self.severity_colors,
            'enable_auto_fix_suggestions': self.enable_auto_fix_suggestions,
            'group_similar_issues': self.group_similar_issues
        }