"""Configuration loading and validation utilities."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import asdict

from compliance_sentinel.models.config import (
    SystemConfiguration,
    HookSettings,
    MCPServerConfig,
    AnalysisConfig,
    FeedbackConfig
)


class ConfigLoader:
    """Handles loading and validation of configuration files."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize config loader with optional custom config directory."""
        self.config_dir = config_dir or Path.cwd() / ".kiro" / "compliance-sentinel"
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def load_system_config(self) -> SystemConfiguration:
        """Load system configuration from file or create default."""
        config_file = self.config_dir / "system.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return SystemConfiguration(**config_data)
        else:
            # Create default config file
            default_config = SystemConfiguration()
            self.save_system_config(default_config)
            return default_config
    
    def save_system_config(self, config: SystemConfiguration) -> None:
        """Save system configuration to file."""
        config_file = self.config_dir / "system.yaml"
        config_dict = asdict(config)
        
        # Convert enum to string for YAML serialization
        config_dict['severity_threshold'] = config.severity_threshold.value
        
        with open(config_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def load_hook_settings(self) -> HookSettings:
        """Load hook settings from file or create default."""
        config_file = self.config_dir / "hooks.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return HookSettings(**config_data)
        else:
            default_settings = HookSettings()
            self.save_hook_settings(default_settings)
            return default_settings
    
    def save_hook_settings(self, settings: HookSettings) -> None:
        """Save hook settings to file."""
        config_file = self.config_dir / "hooks.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(asdict(settings), f, default_flow_style=False, indent=2)
    
    def load_mcp_config(self) -> MCPServerConfig:
        """Load MCP server configuration from file or create default."""
        config_file = self.config_dir / "mcp.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return MCPServerConfig(**config_data)
        else:
            default_config = MCPServerConfig()
            self.save_mcp_config(default_config)
            return default_config
    
    def save_mcp_config(self, config: MCPServerConfig) -> None:
        """Save MCP server configuration to file."""
        config_file = self.config_dir / "mcp.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(asdict(config), f, default_flow_style=False, indent=2)
    
    def load_analysis_config(self) -> AnalysisConfig:
        """Load analysis configuration from file or create default."""
        config_file = self.config_dir / "analysis.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return AnalysisConfig(**config_data)
        else:
            default_config = AnalysisConfig()
            self.save_analysis_config(default_config)
            return default_config
    
    def save_analysis_config(self, config: AnalysisConfig) -> None:
        """Save analysis configuration to file."""
        config_file = self.config_dir / "analysis.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(asdict(config), f, default_flow_style=False, indent=2)
    
    def load_feedback_config(self) -> FeedbackConfig:
        """Load feedback configuration from file or create default."""
        config_file = self.config_dir / "feedback.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return FeedbackConfig(**config_data)
        else:
            default_config = FeedbackConfig()
            self.save_feedback_config(default_config)
            return default_config
    
    def save_feedback_config(self, config: FeedbackConfig) -> None:
        """Save feedback configuration to file."""
        config_file = self.config_dir / "feedback.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(asdict(config), f, default_flow_style=False, indent=2)
    
    def load_environment_variables(self) -> Dict[str, str]:
        """Load environment variables from .env file if present."""
        env_file = Path.cwd() / ".env"
        env_vars = {}
        
        if env_file.exists():
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip().strip('"\'')
        
        return env_vars
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate all configuration files and return validation results."""
        results = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        try:
            self.load_system_config()
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"System config error: {e}")
        
        try:
            self.load_hook_settings()
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"Hook settings error: {e}")
        
        try:
            self.load_mcp_config()
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"MCP config error: {e}")
        
        try:
            self.load_analysis_config()
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"Analysis config error: {e}")
        
        try:
            self.load_feedback_config()
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"Feedback config error: {e}")
        
        # Check for required environment variables
        env_vars = self.load_environment_variables()
        if not env_vars.get("COMPLIANCE_SENTINEL_API_KEY"):
            results["warnings"].append("COMPLIANCE_SENTINEL_API_KEY not set in environment")
        
        return results