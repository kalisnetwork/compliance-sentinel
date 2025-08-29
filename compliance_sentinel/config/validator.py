"""Configuration validation utilities."""

import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse
import logging

from compliance_sentinel.config.config_manager import (
    ProjectConfig, AnalysisRuleConfig, SeverityThresholdConfig,
    FilePatternConfig, MCPServerConfig
)


logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates configuration objects and provides detailed error reporting."""
    
    def __init__(self):
        """Initialize validator."""
        self.validation_errors: List[str] = []
        self.validation_warnings: List[str] = []
    
    def validate_project_config(self, config: ProjectConfig) -> Dict[str, Any]:
        """Validate complete project configuration."""
        self.validation_errors.clear()
        self.validation_warnings.clear()
        
        # Validate basic fields
        self._validate_project_basics(config)
        
        # Validate file patterns
        self._validate_file_patterns(config.file_patterns)
        
        # Validate severity thresholds
        self._validate_severity_thresholds(config.severity_thresholds)
        
        # Validate custom rules
        self._validate_custom_rules(config.custom_rules)
        
        # Validate MCP servers
        self._validate_mcp_servers(config.mcp_servers)
        
        return {
            'valid': len(self.validation_errors) == 0,
            'errors': self.validation_errors.copy(),
            'warnings': self.validation_warnings.copy()
        }
    
    def _validate_project_basics(self, config: ProjectConfig) -> None:
        """Validate basic project configuration fields."""
        if not config.project_name:
            self.validation_errors.append("Project name is required")
        elif not re.match(r'^[a-zA-Z0-9_-]+$', config.project_name):
            self.validation_errors.append("Project name can only contain letters, numbers, hyphens, and underscores")
        
        if not config.version:
            self.validation_warnings.append("Project version is not specified")
        elif not re.match(r'^\d+\.\d+\.\d+', config.version):
            self.validation_warnings.append("Project version should follow semantic versioning (e.g., 1.0.0)")
    
    def _validate_file_patterns(self, patterns: FilePatternConfig) -> None:
        """Validate file pattern configuration."""
        if not patterns.included_patterns:
            self.validation_warnings.append("No file patterns specified for inclusion")
        
        # Validate pattern syntax
        for pattern in patterns.included_patterns:
            if not self._is_valid_glob_pattern(pattern):
                self.validation_errors.append(f"Invalid include pattern: {pattern}")
        
        for pattern in patterns.excluded_patterns:
            if not self._is_valid_glob_pattern(pattern):
                self.validation_errors.append(f"Invalid exclude pattern: {pattern}")
        
        # Check for conflicting patterns
        conflicts = set(patterns.included_patterns) & set(patterns.excluded_patterns)
        if conflicts:
            self.validation_warnings.append(f"Conflicting patterns (both included and excluded): {conflicts}")
        
        # Validate file size limit
        if patterns.max_file_size_mb <= 0:
            self.validation_errors.append("Maximum file size must be positive")
        elif patterns.max_file_size_mb > 100:
            self.validation_warnings.append("Maximum file size is very large (>100MB)")
    
    def _validate_severity_thresholds(self, thresholds: SeverityThresholdConfig) -> None:
        """Validate severity threshold configuration."""
        if thresholds.critical_threshold < 0:
            self.validation_errors.append("Critical threshold cannot be negative")
        
        if thresholds.high_threshold < 0:
            self.validation_errors.append("High threshold cannot be negative")
        
        if thresholds.medium_threshold < 0:
            self.validation_errors.append("Medium threshold cannot be negative")
        
        if thresholds.low_threshold < 0:
            self.validation_errors.append("Low threshold cannot be negative")
        
        # Validate scoring system
        if thresholds.critical_score <= 0:
            self.validation_errors.append("Critical score must be positive")
        
        if thresholds.high_score <= 0:
            self.validation_errors.append("High score must be positive")
        
        if thresholds.medium_score <= 0:
            self.validation_errors.append("Medium score must be positive")
        
        if thresholds.low_score <= 0:
            self.validation_errors.append("Low score must be positive")
        
        # Check score hierarchy
        if not (thresholds.critical_score > thresholds.high_score > thresholds.medium_score > thresholds.low_score):
            self.validation_warnings.append("Severity scores should follow hierarchy: critical > high > medium > low")
        
        if thresholds.max_total_score <= 0:
            self.validation_errors.append("Maximum total score must be positive")
    
    def _validate_custom_rules(self, rules: List[AnalysisRuleConfig]) -> None:
        """Validate custom analysis rules."""
        rule_ids = set()
        
        for i, rule in enumerate(rules):
            rule_prefix = f"Rule {i+1}"
            
            # Check for duplicate rule IDs
            if rule.rule_id in rule_ids:
                self.validation_errors.append(f"{rule_prefix}: Duplicate rule ID '{rule.rule_id}'")
            else:
                rule_ids.add(rule.rule_id)
            
            # Validate rule ID format
            if not re.match(r'^[A-Z0-9_-]+$', rule.rule_id):
                self.validation_errors.append(f"{rule_prefix}: Rule ID should contain only uppercase letters, numbers, hyphens, and underscores")
            
            # Validate pattern if provided
            if rule.pattern:
                if not self._is_valid_regex_pattern(rule.pattern):
                    self.validation_errors.append(f"{rule_prefix}: Invalid regex pattern")
            
            # Validate file patterns
            for pattern in rule.file_patterns:
                if not self._is_valid_glob_pattern(pattern):
                    self.validation_errors.append(f"{rule_prefix}: Invalid file pattern '{pattern}'")
            
            # Validate severity
            if rule.severity not in ['critical', 'high', 'medium', 'low', 'info']:
                self.validation_errors.append(f"{rule_prefix}: Invalid severity '{rule.severity}'")
    
    def _validate_mcp_servers(self, servers: List[MCPServerConfig]) -> None:
        """Validate MCP server configurations."""
        server_names = set()
        
        for i, server in enumerate(servers):
            server_prefix = f"MCP Server {i+1}"
            
            # Check for duplicate server names
            if server.server_name in server_names:
                self.validation_errors.append(f"{server_prefix}: Duplicate server name '{server.server_name}'")
            else:
                server_names.add(server.server_name)
            
            # Validate URL
            if not self._is_valid_url(server.endpoint_url):
                self.validation_errors.append(f"{server_prefix}: Invalid endpoint URL")
            
            # Validate timeout
            if server.timeout_seconds <= 0:
                self.validation_errors.append(f"{server_prefix}: Timeout must be positive")
            elif server.timeout_seconds > 300:
                self.validation_warnings.append(f"{server_prefix}: Very long timeout (>5 minutes)")
            
            # Validate retry settings
            if server.max_retries < 0:
                self.validation_errors.append(f"{server_prefix}: Max retries cannot be negative")
            elif server.max_retries > 10:
                self.validation_warnings.append(f"{server_prefix}: Very high retry count (>10)")
            
            # Validate rate limiting
            if server.rate_limit_requests <= 0:
                self.validation_errors.append(f"{server_prefix}: Rate limit requests must be positive")
            
            if server.rate_limit_window <= 0:
                self.validation_errors.append(f"{server_prefix}: Rate limit window must be positive")
    
    def _is_valid_glob_pattern(self, pattern: str) -> bool:
        """Check if a glob pattern is valid."""
        try:
            # Basic validation - check for invalid characters
            invalid_chars = ['<', '>', '|', '"']
            if any(char in pattern for char in invalid_chars):
                return False
            
            # Check for balanced brackets
            if pattern.count('[') != pattern.count(']'):
                return False
            
            if pattern.count('{') != pattern.count('}'):
                return False
            
            return True
        except Exception:
            return False
    
    def _is_valid_regex_pattern(self, pattern: str) -> bool:
        """Check if a regex pattern is valid."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False