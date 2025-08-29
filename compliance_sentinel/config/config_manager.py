"""Configuration management system for Compliance Sentinel."""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging
import os

from compliance_sentinel.models.config import SystemConfiguration, HookSettings
from compliance_sentinel.models.analysis import Severity
from compliance_sentinel.utils.error_handler import get_global_error_handler


logger = logging.getLogger(__name__)


@dataclass
class AnalysisRuleConfig:
    """Configuration for custom analysis rules."""
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool = True
    pattern: Optional[str] = None
    file_patterns: List[str] = field(default_factory=list)
    excluded_patterns: List[str] = field(default_factory=list)
    custom_message: Optional[str] = None
    remediation_guidance: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def validate(self) -> List[str]:
        """Validate rule configuration."""
        errors = []
        
        if not self.rule_id:
            errors.append("Rule ID is required")
        
        if not self.name:
            errors.append("Rule name is required")
        
        if self.severity not in ['critical', 'high', 'medium', 'low', 'info']:
            errors.append(f"Invalid severity: {self.severity}")
        
        if self.pattern and len(self.pattern) < 3:
            errors.append("Pattern must be at least 3 characters")
        
        return errors


@dataclass
class SeverityThresholdConfig:
    """Configuration for severity thresholds."""
    critical_threshold: int = 0  # Block if any critical issues
    high_threshold: int = 5     # Block if more than 5 high issues
    medium_threshold: int = 20  # Block if more than 20 medium issues
    low_threshold: int = 50     # Block if more than 50 low issues
    
    # Scoring system
    critical_score: int = 100
    high_score: int = 25
    medium_score: int = 5
    low_score: int = 1
    max_total_score: int = 200  # Block if total score exceeds this
    
    def calculate_score(self, critical: int, high: int, medium: int, low: int) -> int:
        """Calculate total severity score."""
        return (
            critical * self.critical_score +
            high * self.high_score +
            medium * self.medium_score +
            low * self.low_score
        )
    
    def should_block(self, critical: int, high: int, medium: int, low: int) -> bool:
        """Determine if issues should block based on thresholds."""
        if critical > self.critical_threshold:
            return True
        if high > self.high_threshold:
            return True
        if medium > self.medium_threshold:
            return True
        if low > self.low_threshold:
            return True
        
        total_score = self.calculate_score(critical, high, medium, low)
        return total_score > self.max_total_score


@dataclass
class FilePatternConfig:
    """Configuration for file pattern matching."""
    included_patterns: List[str] = field(default_factory=lambda: [
        '*.py', '*.js', '*.ts', '*.java', '*.go', '*.php', '*.rb', '*.cs',
        '*.cpp', '*.c', '*.h', '*.hpp', '*.scala', '*.kt', '*.swift'
    ])
    excluded_patterns: List[str] = field(default_factory=lambda: [
        '*.pyc', '*.pyo', '*.pyd', '__pycache__/*', '.git/*', 'node_modules/*',
        '.pytest_cache/*', '.coverage', '*.log', '*.tmp'
    ])
    excluded_directories: List[str] = field(default_factory=lambda: [
        '.git', '__pycache__', 'node_modules', '.pytest_cache', 'venv',
        '.venv', 'env', '.env', 'build', 'dist', '.tox', '.coverage'
    ])
    max_file_size_mb: float = 10.0
    binary_file_extensions: List[str] = field(default_factory=lambda: [
        '.exe', '.dll', '.so', '.dylib', '.bin', '.img', '.iso',
        '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'
    ])
    
    def should_include_file(self, file_path: Path) -> bool:
        """Check if file should be included in analysis."""
        file_str = str(file_path)
        file_name = file_path.name
        
        # Check file size
        try:
            if file_path.exists() and file_path.stat().st_size > self.max_file_size_mb * 1024 * 1024:
                return False
        except OSError:
            return False
        
        # Check if binary file
        if any(file_name.endswith(ext) for ext in self.binary_file_extensions):
            return False
        
        # Check excluded directories
        for excluded_dir in self.excluded_directories:
            if excluded_dir in file_path.parts:
                return False
        
        # Check excluded patterns
        for pattern in self.excluded_patterns:
            if file_path.match(pattern):
                return False
        
        # Check included patterns
        for pattern in self.included_patterns:
            if file_path.match(pattern):
                return True
        
        return False


def _get_mcp_env_var(server_name: str, key: str, default: Any, var_type: type = str) -> Any:
    """Get MCP server-specific environment variable."""
    # Try server-specific variable first
    server_env_key = f"COMPLIANCE_SENTINEL_MCP_{server_name.upper().replace('-', '_')}_{key.upper()}"
    value = os.getenv(server_env_key)
    
    # Fall back to generic MCP variable
    if value is None:
        generic_env_key = f"COMPLIANCE_SENTINEL_MCP_{key.upper()}"
        value = os.getenv(generic_env_key)
    
    if value is None:
        return default
    
    try:
        if var_type == bool:
            return value.lower() in ('true', '1', 'yes', 'on')
        elif var_type == int:
            return int(value)
        elif var_type == float:
            return float(value)
        elif var_type == dict:
            return json.loads(value)
        else:
            return value
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid value for MCP config {key}: {value}. Error: {e}")


@dataclass
class MCPServerConfig:
    """Configuration for MCP server connections with environment variable support."""
    server_name: str
    endpoint_url: str
    api_key: Optional[str] = None
    timeout_seconds: int = 30
    max_retries: int = 3
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    enabled: bool = True
    verify_ssl: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Apply environment variable overrides after initialization."""
        if hasattr(self, '_env_applied'):
            return
        
        # Apply environment variable overrides
        self.endpoint_url = _get_mcp_env_var(self.server_name, "endpoint_url", self.endpoint_url)
        self.api_key = _get_mcp_env_var(self.server_name, "api_key", self.api_key)
        self.timeout_seconds = _get_mcp_env_var(self.server_name, "timeout_seconds", self.timeout_seconds, int)
        self.max_retries = _get_mcp_env_var(self.server_name, "max_retries", self.max_retries, int)
        self.rate_limit_requests = _get_mcp_env_var(self.server_name, "rate_limit_requests", self.rate_limit_requests, int)
        self.rate_limit_window = _get_mcp_env_var(self.server_name, "rate_limit_window", self.rate_limit_window, int)
        self.enabled = _get_mcp_env_var(self.server_name, "enabled", self.enabled, bool)
        self.verify_ssl = _get_mcp_env_var(self.server_name, "verify_ssl", self.verify_ssl, bool)
        
        # Handle custom headers
        custom_headers_env = _get_mcp_env_var(self.server_name, "custom_headers", None)
        if custom_headers_env:
            try:
                if isinstance(custom_headers_env, str):
                    self.custom_headers.update(json.loads(custom_headers_env))
                elif isinstance(custom_headers_env, dict):
                    self.custom_headers.update(custom_headers_env)
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Invalid custom headers format for {self.server_name}")
        
        self._env_applied = True
    
    def validate(self) -> List[str]:
        """Validate MCP server configuration."""
        errors = []
        
        if not self.server_name:
            errors.append("Server name is required")
        
        if not self.endpoint_url:
            errors.append("Endpoint URL is required")
        
        if not self.endpoint_url.startswith(('http://', 'https://')):
            errors.append("Endpoint URL must start with http:// or https://")
        
        if self.timeout_seconds <= 0:
            errors.append("Timeout must be positive")
        
        if self.max_retries < 0:
            errors.append("Max retries cannot be negative")
        
        if self.rate_limit_requests <= 0:
            errors.append("Rate limit requests must be positive")
        
        if self.rate_limit_window <= 0:
            errors.append("Rate limit window must be positive")
        
        return errors
    
    @classmethod
    def create_with_defaults(cls, server_name: str, endpoint_url: str, **kwargs) -> 'MCPServerConfig':
        """Create MCP server config with environment-aware defaults."""
        # Get secure defaults based on environment
        environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        
        if environment == "production":
            defaults = {
                "timeout_seconds": 10,  # Shorter timeout for production
                "max_retries": 2,       # Fewer retries for production
                "rate_limit_requests": 50,  # More conservative rate limiting
                "verify_ssl": True,     # Always verify SSL in production
            }
        else:
            defaults = {
                "timeout_seconds": 30,
                "max_retries": 3,
                "rate_limit_requests": 100,
                "verify_ssl": True,
            }
        
        # Merge with provided kwargs
        defaults.update(kwargs)
        
        return cls(
            server_name=server_name,
            endpoint_url=endpoint_url,
            **defaults
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert MCP server config to dictionary."""
        return {
            'server_name': self.server_name,
            'endpoint_url': self.endpoint_url,
            'api_key': self.api_key,
            'timeout_seconds': self.timeout_seconds,
            'max_retries': self.max_retries,
            'rate_limit_requests': self.rate_limit_requests,
            'rate_limit_window': self.rate_limit_window,
            'enabled': self.enabled,
            'verify_ssl': self.verify_ssl,
            'custom_headers': self.custom_headers
        }


@dataclass
class ProjectConfig:
    """Complete project configuration."""
    project_name: str
    version: str = "1.0.0"
    description: str = ""
    
    # Analysis configuration
    file_patterns: FilePatternConfig = field(default_factory=FilePatternConfig)
    severity_thresholds: SeverityThresholdConfig = field(default_factory=SeverityThresholdConfig)
    custom_rules: List[AnalysisRuleConfig] = field(default_factory=list)
    
    # MCP servers
    mcp_servers: List[MCPServerConfig] = field(default_factory=list)
    
    # System settings
    system_config: SystemConfiguration = field(default_factory=SystemConfiguration)
    hook_settings: HookSettings = field(default_factory=HookSettings)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def validate(self) -> List[str]:
        """Validate entire project configuration."""
        errors = []
        
        if not self.project_name:
            errors.append("Project name is required")
        
        # Validate custom rules
        for i, rule in enumerate(self.custom_rules):
            rule_errors = rule.validate()
            for error in rule_errors:
                errors.append(f"Rule {i+1}: {error}")
        
        # Validate MCP servers
        for i, server in enumerate(self.mcp_servers):
            server_errors = server.validate()
            for error in server_errors:
                errors.append(f"MCP Server {i+1}: {error}")
        
        return errors


class ConfigManager:
    """Manages configuration files and settings for Compliance Sentinel."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_dir = config_dir or Path.cwd() / ".compliance-sentinel"
        self.config_dir.mkdir(exist_ok=True)
        
        self.error_handler = get_global_error_handler()
        
        # Configuration file paths
        self.project_config_file = self.config_dir / "config.yaml"
        self.user_config_file = Path.home() / ".compliance-sentinel" / "config.yaml"
        self.local_config_file = Path.cwd() / "compliance-sentinel.yaml"
        
        # Ensure user config directory exists
        self.user_config_file.parent.mkdir(exist_ok=True)
        
        logger.info(f"Configuration manager initialized with config dir: {self.config_dir}")
    
    def load_project_config(self) -> ProjectConfig:
        """Load project configuration with cascading from multiple sources."""
        try:
            # Start with default configuration
            config = ProjectConfig(project_name="default")
            
            # Load user-level configuration
            if self.user_config_file.exists():
                user_config = self._load_config_file(self.user_config_file)
                config = self._merge_configs(config, user_config)
                logger.debug(f"Loaded user config from {self.user_config_file}")
            
            # Load project-level configuration
            if self.project_config_file.exists():
                project_config = self._load_config_file(self.project_config_file)
                config = self._merge_configs(config, project_config)
                logger.debug(f"Loaded project config from {self.project_config_file}")
            
            # Load local configuration (highest priority)
            if self.local_config_file.exists():
                local_config = self._load_config_file(self.local_config_file)
                config = self._merge_configs(config, local_config)
                logger.debug(f"Loaded local config from {self.local_config_file}")
            
            # Update timestamp
            config.updated_at = datetime.utcnow()
            
            # Validate configuration
            errors = config.validate()
            if errors:
                logger.warning(f"Configuration validation errors: {errors}")
            
            return config
            
        except Exception as e:
            logger.error(f"Error loading project configuration: {e}")
            self.error_handler.handle_system_error(e, "config_load")
            return ProjectConfig(project_name="default")
    
    def save_project_config(self, config: ProjectConfig, scope: str = "project") -> bool:
        """Save project configuration to specified scope."""
        try:
            # Choose target file based on scope
            if scope == "user":
                target_file = self.user_config_file
            elif scope == "local":
                target_file = self.local_config_file
            else:
                target_file = self.project_config_file
            
            # Update timestamp
            config.updated_at = datetime.utcnow()
            
            # Validate before saving
            errors = config.validate()
            if errors:
                logger.error(f"Cannot save invalid configuration: {errors}")
                return False
            
            # Convert to dictionary and save
            config_dict = self._config_to_dict(config)
            
            with open(target_file, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            logger.info(f"Saved configuration to {target_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            self.error_handler.handle_system_error(e, "config_save")
            return False
    
    def _load_config_file(self, config_file: Path) -> Dict[str, Any]:
        """Load configuration from a YAML file."""
        try:
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Error loading config file {config_file}: {e}")
            return {}
    
    def _merge_configs(self, base_config: ProjectConfig, override_dict: Dict[str, Any]) -> ProjectConfig:
        """Merge configuration dictionary into base configuration."""
        try:
            # Convert base config to dict
            base_dict = self._config_to_dict(base_config)
            
            # Deep merge dictionaries
            merged_dict = self._deep_merge_dicts(base_dict, override_dict)
            
            # Convert back to ProjectConfig
            return self._dict_to_config(merged_dict)
            
        except Exception as e:
            logger.error(f"Error merging configurations: {e}")
            return base_config
    
    def _deep_merge_dicts(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dicts(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _config_to_dict(self, config: ProjectConfig) -> Dict[str, Any]:
        """Convert ProjectConfig to dictionary."""
        return {
            'project_name': config.project_name,
            'version': config.version,
            'description': config.description,
            'file_patterns': asdict(config.file_patterns),
            'severity_thresholds': asdict(config.severity_thresholds),
            'custom_rules': [asdict(rule) for rule in config.custom_rules],
            'mcp_servers': [asdict(server) for server in config.mcp_servers],
            'system_config': asdict(config.system_config),
            'hook_settings': asdict(config.hook_settings),
            'created_at': config.created_at.isoformat(),
            'updated_at': config.updated_at.isoformat()
        }
    
    def _dict_to_config(self, config_dict: Dict[str, Any]) -> ProjectConfig:
        """Convert dictionary to ProjectConfig."""
        try:
            # Parse timestamps
            created_at = datetime.fromisoformat(config_dict.get('created_at', datetime.utcnow().isoformat()))
            updated_at = datetime.fromisoformat(config_dict.get('updated_at', datetime.utcnow().isoformat()))
            
            # Parse file patterns
            file_patterns_dict = config_dict.get('file_patterns', {})
            file_patterns = FilePatternConfig(**file_patterns_dict)
            
            # Parse severity thresholds
            severity_dict = config_dict.get('severity_thresholds', {})
            severity_thresholds = SeverityThresholdConfig(**severity_dict)
            
            # Parse custom rules
            custom_rules = []
            for rule_dict in config_dict.get('custom_rules', []):
                custom_rules.append(AnalysisRuleConfig(**rule_dict))
            
            # Parse MCP servers
            mcp_servers = []
            for server_dict in config_dict.get('mcp_servers', []):
                mcp_servers.append(MCPServerConfig(**server_dict))
            
            # Parse system config
            system_dict = config_dict.get('system_config', {})
            system_config = SystemConfiguration(**system_dict)
            
            # Parse hook settings
            hook_dict = config_dict.get('hook_settings', {})
            hook_settings = HookSettings(**hook_dict)
            
            return ProjectConfig(
                project_name=config_dict.get('project_name', 'default'),
                version=config_dict.get('version', '1.0.0'),
                description=config_dict.get('description', ''),
                file_patterns=file_patterns,
                severity_thresholds=severity_thresholds,
                custom_rules=custom_rules,
                mcp_servers=mcp_servers,
                system_config=system_config,
                hook_settings=hook_settings,
                created_at=created_at,
                updated_at=updated_at
            )
            
        except Exception as e:
            logger.error(f"Error converting dict to config: {e}")
            return ProjectConfig(project_name="default")
    
    def create_default_config(self, project_name: str) -> ProjectConfig:
        """Create a default configuration for a new project with environment-aware defaults."""
        config = ProjectConfig(
            project_name=project_name,
            description=f"Compliance Sentinel configuration for {project_name}"
        )
        
        # Get environment-specific defaults
        environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        
        # Add default custom rules (can be overridden by environment)
        default_rules = self._get_default_custom_rules(environment)
        config.custom_rules = default_rules
        
        # Add default MCP server configurations (can be overridden by environment)
        default_mcp_servers = self._get_default_mcp_servers(environment)
        config.mcp_servers = default_mcp_servers
        
        return config
    
    def _get_default_custom_rules(self, environment: str) -> List[AnalysisRuleConfig]:
        """Get default custom rules based on environment."""
        rules = []
        
        # Basic rules for all environments
        rules.append(AnalysisRuleConfig(
            rule_id="CUSTOM-001",
            name="No TODO comments in production",
            description="TODO comments should not be present in production code",
            severity="low" if environment == "development" else "medium",
            pattern=r"#\s*TODO|//\s*TODO|/\*\s*TODO",
            file_patterns=["*.py", "*.js", "*.ts", "*.java"],
            custom_message="Remove TODO comments before production deployment",
            remediation_guidance="Complete the TODO item or create a proper issue tracker entry"
        ))
        
        rules.append(AnalysisRuleConfig(
            rule_id="CUSTOM-002",
            name="No debug print statements",
            description="Debug print statements should not be present in production code",
            severity="medium" if environment == "development" else "high",
            pattern=r"print\s*\(.*debug|console\.log\s*\(.*debug",
            file_patterns=["*.py", "*.js", "*.ts"],
            custom_message="Remove debug print statements",
            remediation_guidance="Use proper logging instead of print statements"
        ))
        
        # Production-specific rules
        if environment == "production":
            rules.append(AnalysisRuleConfig(
                rule_id="CUSTOM-003",
                name="No hardcoded credentials",
                description="Credentials should not be hardcoded in source code",
                severity="critical",
                pattern=r"password\s*=\s*[\"'][^\"']+[\"']|api_key\s*=\s*[\"'][^\"']+[\"']",
                file_patterns=["*.py", "*.js", "*.ts", "*.java", "*.go"],
                custom_message="Remove hardcoded credentials",
                remediation_guidance="Use environment variables or secure secret management"
            ))
        
        return rules
    
    def _get_default_mcp_servers(self, environment: str) -> List[MCPServerConfig]:
        """Get default MCP server configurations based on environment."""
        servers = []
        
        # NVD vulnerability database (always included)
        nvd_config = MCPServerConfig.create_with_defaults(
            server_name="nvd-vulnerability-db",
            endpoint_url=os.getenv("COMPLIANCE_SENTINEL_NVD_ENDPOINT", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        )
        servers.append(nvd_config)
        
        # CVE database (optional, based on environment)
        if environment != "production" or os.getenv("COMPLIANCE_SENTINEL_ENABLE_CVE_DB", "false").lower() == "true":
            cve_config = MCPServerConfig.create_with_defaults(
                server_name="cve-database",
                endpoint_url=os.getenv("COMPLIANCE_SENTINEL_CVE_ENDPOINT", "https://cve.circl.lu/api")
            )
            servers.append(cve_config)
        
        # Additional servers from environment
        additional_servers_env = os.getenv("COMPLIANCE_SENTINEL_ADDITIONAL_MCP_SERVERS")
        if additional_servers_env:
            try:
                additional_servers = json.loads(additional_servers_env)
                for server_data in additional_servers:
                    if isinstance(server_data, dict) and "server_name" in server_data and "endpoint_url" in server_data:
                        server_config = MCPServerConfig(**server_data)
                        servers.append(server_config)
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                logger.warning(f"Invalid additional MCP servers configuration: {e}")
        
        return servers
    
    def get_effective_file_patterns(self) -> FilePatternConfig:
        """Get effective file patterns from current configuration."""
        config = self.load_project_config()
        return config.file_patterns
    
    def get_effective_severity_thresholds(self) -> SeverityThresholdConfig:
        """Get effective severity thresholds from current configuration."""
        config = self.load_project_config()
        return config.severity_thresholds
    
    def get_custom_rules(self) -> List[AnalysisRuleConfig]:
        """Get custom analysis rules from current configuration."""
        config = self.load_project_config()
        return [rule for rule in config.custom_rules if rule.enabled]
    
    def get_mcp_servers(self) -> List[MCPServerConfig]:
        """Get MCP server configurations."""
        config = self.load_project_config()
        return [server for server in config.mcp_servers if server.enabled]
    
    def update_severity_thresholds(self, thresholds: SeverityThresholdConfig) -> bool:
        """Update severity thresholds in configuration."""
        try:
            config = self.load_project_config()
            config.severity_thresholds = thresholds
            return self.save_project_config(config)
        except Exception as e:
            logger.error(f"Error updating severity thresholds: {e}")
            return False
    
    def add_custom_rule(self, rule: AnalysisRuleConfig) -> bool:
        """Add a custom analysis rule."""
        try:
            # Validate rule
            errors = rule.validate()
            if errors:
                logger.error(f"Invalid custom rule: {errors}")
                return False
            
            config = self.load_project_config()
            
            # Check for duplicate rule IDs
            existing_ids = {r.rule_id for r in config.custom_rules}
            if rule.rule_id in existing_ids:
                logger.error(f"Rule ID {rule.rule_id} already exists")
                return False
            
            config.custom_rules.append(rule)
            return self.save_project_config(config)
            
        except Exception as e:
            logger.error(f"Error adding custom rule: {e}")
            return False
    
    def remove_custom_rule(self, rule_id: str) -> bool:
        """Remove a custom analysis rule."""
        try:
            config = self.load_project_config()
            original_count = len(config.custom_rules)
            config.custom_rules = [r for r in config.custom_rules if r.rule_id != rule_id]
            
            if len(config.custom_rules) == original_count:
                logger.warning(f"Rule ID {rule_id} not found")
                return False
            
            return self.save_project_config(config)
            
        except Exception as e:
            logger.error(f"Error removing custom rule: {e}")
            return False
    
    def add_mcp_server(self, server: MCPServerConfig) -> bool:
        """Add an MCP server configuration."""
        try:
            # Validate server config
            errors = server.validate()
            if errors:
                logger.error(f"Invalid MCP server config: {errors}")
                return False
            
            config = self.load_project_config()
            
            # Check for duplicate server names
            existing_names = {s.server_name for s in config.mcp_servers}
            if server.server_name in existing_names:
                logger.error(f"MCP server {server.server_name} already exists")
                return False
            
            config.mcp_servers.append(server)
            return self.save_project_config(config)
            
        except Exception as e:
            logger.error(f"Error adding MCP server: {e}")
            return False
    
    def export_config(self, output_file: Path, format: str = "yaml") -> bool:
        """Export current configuration to file."""
        try:
            config = self.load_project_config()
            config_dict = self._config_to_dict(config)
            
            with open(output_file, 'w') as f:
                if format.lower() == 'json':
                    json.dump(config_dict, f, indent=2, default=str)
                else:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, input_file: Path) -> bool:
        """Import configuration from file."""
        try:
            if not input_file.exists():
                logger.error(f"Configuration file {input_file} does not exist")
                return False
            
            config_dict = self._load_config_file(input_file)
            config = self._dict_to_config(config_dict)
            
            # Validate imported configuration
            errors = config.validate()
            if errors:
                logger.error(f"Invalid imported configuration: {errors}")
                return False
            
            return self.save_project_config(config)
            
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            return False