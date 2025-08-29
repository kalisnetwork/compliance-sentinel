"""Validation utilities for data models and security checks."""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
from urllib.parse import urlparse
import ipaddress

from compliance_sentinel.core.interfaces import (
    SecurityIssue, 
    PolicyRule, 
    VulnerabilityReport,
    Severity,
    SecurityCategory,
    PolicyCategory
)


class ValidationError(Exception):
    """Custom exception for validation errors."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.format_message())
    
    def format_message(self) -> str:
        """Format the validation error message."""
        if self.field:
            return f"Validation error in field '{self.field}': {self.message}"
        return f"Validation error: {self.message}"


class SecurityValidator:
    """Validates security-related data and configurations."""
    
    # Common security patterns
    SECRET_PATTERNS = [
        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^"\'\s]{8,}',
        r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9]{16,}',
        r'(?i)(secret|token)\s*[=:]\s*["\']?[a-zA-Z0-9]{16,}',
        r'(?i)(access[_-]?key)\s*[=:]\s*["\']?[A-Z0-9]{16,}',
        r'(?i)(private[_-]?key)\s*[=:]\s*["\']?[a-zA-Z0-9+/]{32,}',
    ]
    
    # Weak cryptographic patterns
    WEAK_CRYPTO_PATTERNS = [
        r'(?i)\b(md5|sha1|des|rc4)\b',
        r'(?i)ssl[_-]?verify\s*[=:]\s*(false|0|none)',
        r'(?i)verify\s*[=:]\s*(false|0)',
        r'(?i)random\.random\(\)',
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r'(?i)execute\s*\(\s*["\'][^"\']*%[sd][^"\']*["\']',
        r'(?i)query\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
        r'(?i)cursor\.execute\s*\([^)]*%[sd]',
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'(?i)innerHTML\s*[=:]\s*[^;]*\+',
        r'(?i)document\.write\s*\([^)]*\+',
        r'(?i)eval\s*\([^)]*\+',
    ]
    
    @classmethod
    def validate_security_issue(cls, issue: SecurityIssue) -> List[str]:
        """Validate a SecurityIssue object and return list of errors."""
        errors = []
        
        # Validate required fields
        if not issue.id or not issue.id.strip():
            errors.append("SecurityIssue.id cannot be empty")
        
        if not issue.description or not issue.description.strip():
            errors.append("SecurityIssue.description cannot be empty")
        
        if not issue.file_path or not issue.file_path.strip():
            errors.append("SecurityIssue.file_path cannot be empty")
        
        # Validate file path exists
        if issue.file_path and not Path(issue.file_path).exists():
            errors.append(f"File does not exist: {issue.file_path}")
        
        # Validate line number
        if issue.line_number < 1:
            errors.append("SecurityIssue.line_number must be positive")
        
        # Validate confidence score
        if not (0.0 <= issue.confidence <= 1.0):
            errors.append("SecurityIssue.confidence must be between 0.0 and 1.0")
        
        # Validate rule_id format
        if issue.rule_id and not re.match(r'^[A-Z0-9_-]+$', issue.rule_id):
            errors.append("SecurityIssue.rule_id must contain only uppercase letters, numbers, underscores, and hyphens")
        
        return errors
    
    @classmethod
    def validate_policy_rule(cls, rule: PolicyRule) -> List[str]:
        """Validate a PolicyRule object and return list of errors."""
        errors = []
        
        # Validate required fields
        if not rule.id or not rule.id.strip():
            errors.append("PolicyRule.id cannot be empty")
        
        if not rule.name or not rule.name.strip():
            errors.append("PolicyRule.name cannot be empty")
        
        if not rule.description or not rule.description.strip():
            errors.append("PolicyRule.description cannot be empty")
        
        if not rule.pattern or not rule.pattern.strip():
            errors.append("PolicyRule.pattern cannot be empty")
        
        # Validate pattern is valid regex
        try:
            re.compile(rule.pattern)
        except re.error as e:
            errors.append(f"PolicyRule.pattern is not a valid regex: {e}")
        
        # Validate file types
        for file_type in rule.applicable_file_types:
            if not file_type.startswith('.'):
                errors.append(f"File type must start with dot: {file_type}")
        
        # Validate rule ID format
        if rule.id and not re.match(r'^[A-Z0-9_-]+$', rule.id):
            errors.append("PolicyRule.id must contain only uppercase letters, numbers, underscores, and hyphens")
        
        return errors
    
    @classmethod
    def validate_vulnerability_report(cls, report: VulnerabilityReport) -> List[str]:
        """Validate a VulnerabilityReport object and return list of errors."""
        errors = []
        
        # Validate CVE ID format
        if report.cve_id and not re.match(r'^CVE-\d{4}-\d{4,}$', report.cve_id):
            errors.append("VulnerabilityReport.cve_id must follow CVE-YYYY-NNNN format")
        
        # Validate package name
        if not report.package_name or not report.package_name.strip():
            errors.append("VulnerabilityReport.package_name cannot be empty")
        
        # Validate severity score
        if not (0.0 <= report.severity_score <= 10.0):
            errors.append("VulnerabilityReport.severity_score must be between 0.0 and 10.0")
        
        # Validate affected versions
        if not report.affected_versions:
            errors.append("VulnerabilityReport.affected_versions cannot be empty")
        
        return errors
    
    @classmethod
    def scan_for_hardcoded_secrets(cls, content: str, file_path: str) -> List[SecurityIssue]:
        """Scan content for hardcoded secrets and return security issues."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in cls.SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    issue = SecurityIssue(
                        id=f"HARDCODED_SECRET_{line_num}_{match.start()}",
                        severity=Severity.HIGH,
                        category=SecurityCategory.HARDCODED_SECRETS,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"Potential hardcoded secret detected: {match.group(1)}",
                        rule_id="HARDCODED_SECRETS",
                        confidence=0.8,
                        remediation_suggestions=[
                            "Move secrets to environment variables",
                            "Use a secure secret management system",
                            "Never commit secrets to version control"
                        ],
                        created_at=datetime.utcnow()
                    )
                    issues.append(issue)
        
        return issues
    
    @classmethod
    def scan_for_weak_crypto(cls, content: str, file_path: str) -> List[SecurityIssue]:
        """Scan content for weak cryptographic practices."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in cls.WEAK_CRYPTO_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    issue = SecurityIssue(
                        id=f"WEAK_CRYPTO_{line_num}_{match.start()}",
                        severity=Severity.HIGH,
                        category=SecurityCategory.INSECURE_CRYPTO,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"Weak cryptographic practice detected: {match.group()}",
                        rule_id="WEAK_CRYPTO",
                        confidence=0.9,
                        remediation_suggestions=[
                            "Use strong encryption algorithms (AES-256, RSA-2048+)",
                            "Enable SSL/TLS certificate verification",
                            "Use cryptographically secure random number generators"
                        ],
                        created_at=datetime.utcnow()
                    )
                    issues.append(issue)
        
        return issues
    
    @classmethod
    def scan_for_sql_injection(cls, content: str, file_path: str) -> List[SecurityIssue]:
        """Scan content for SQL injection vulnerabilities."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in cls.SQL_INJECTION_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    issue = SecurityIssue(
                        id=f"SQL_INJECTION_{line_num}_{match.start()}",
                        severity=Severity.CRITICAL,
                        category=SecurityCategory.SQL_INJECTION,
                        file_path=file_path,
                        line_number=line_num,
                        description="Potential SQL injection vulnerability detected",
                        rule_id="SQL_INJECTION",
                        confidence=0.7,
                        remediation_suggestions=[
                            "Use parameterized queries or prepared statements",
                            "Validate and sanitize all user inputs",
                            "Use an ORM with built-in SQL injection protection"
                        ],
                        created_at=datetime.utcnow()
                    )
                    issues.append(issue)
        
        return issues
    
    @classmethod
    def scan_for_xss(cls, content: str, file_path: str) -> List[SecurityIssue]:
        """Scan content for XSS vulnerabilities."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in cls.XSS_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    issue = SecurityIssue(
                        id=f"XSS_{line_num}_{match.start()}",
                        severity=Severity.HIGH,
                        category=SecurityCategory.XSS,
                        file_path=file_path,
                        line_number=line_num,
                        description="Potential XSS vulnerability detected",
                        rule_id="XSS",
                        confidence=0.6,
                        remediation_suggestions=[
                            "Sanitize and encode all user inputs before output",
                            "Use Content Security Policy (CSP) headers",
                            "Avoid dynamic code execution with user input"
                        ],
                        created_at=datetime.utcnow()
                    )
                    issues.append(issue)
        
        return issues


class ConfigurationValidator:
    """Validates system configuration and settings."""
    
    @classmethod
    def validate_file_path(cls, path: str, must_exist: bool = True) -> Tuple[bool, Optional[str]]:
        """Validate a file path."""
        if not path or not path.strip():
            return False, "Path cannot be empty"
        
        try:
            path_obj = Path(path)
            
            if must_exist and not path_obj.exists():
                return False, f"Path does not exist: {path}"
            
            if must_exist and not path_obj.is_file():
                return False, f"Path is not a file: {path}"
            
            # Check for path traversal attempts
            if '..' in path or path.startswith('/'):
                return False, "Path contains potentially dangerous characters"
            
            return True, None
            
        except Exception as e:
            return False, f"Invalid path: {e}"
    
    @classmethod
    def validate_url(cls, url: str, require_https: bool = True) -> Tuple[bool, Optional[str]]:
        """Validate a URL."""
        if not url or not url.strip():
            return False, "URL cannot be empty"
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, "URL must include scheme (http/https)"
            
            if require_https and parsed.scheme != 'https':
                return False, "URL must use HTTPS for security"
            
            if not parsed.netloc:
                return False, "URL must include hostname"
            
            # Check for localhost/private IPs in production URLs
            if parsed.hostname:
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private and require_https:
                        return False, "Private IP addresses not allowed in production URLs"
                except ValueError:
                    pass  # Not an IP address, which is fine
            
            return True, None
            
        except Exception as e:
            return False, f"Invalid URL: {e}"
    
    @classmethod
    def validate_port(cls, port: int) -> Tuple[bool, Optional[str]]:
        """Validate a network port number."""
        if not isinstance(port, int):
            return False, "Port must be an integer"
        
        if not (1 <= port <= 65535):
            return False, "Port must be between 1 and 65535"
        
        # Warn about well-known ports
        if port < 1024:
            return True, f"Warning: Port {port} is a well-known port, ensure proper permissions"
        
        return True, None
    
    @classmethod
    def validate_timeout(cls, timeout: int, min_timeout: int = 1) -> Tuple[bool, Optional[str]]:
        """Validate a timeout value."""
        if not isinstance(timeout, int):
            return False, "Timeout must be an integer"
        
        if timeout < min_timeout:
            return False, f"Timeout must be at least {min_timeout} seconds"
        
        if timeout > 3600:  # 1 hour
            return True, f"Warning: Timeout of {timeout} seconds is very long"
        
        return True, None
    
    @classmethod
    def validate_severity_threshold(cls, threshold: Union[str, Severity]) -> Tuple[bool, Optional[str]]:
        """Validate a severity threshold."""
        if isinstance(threshold, str):
            try:
                threshold = Severity(threshold.lower())
            except ValueError:
                valid_values = [s.value for s in Severity]
                return False, f"Invalid severity. Must be one of: {valid_values}"
        
        if not isinstance(threshold, Severity):
            return False, "Severity must be a Severity enum value"
        
        return True, None
    
    @classmethod
    def validate_file_patterns(cls, patterns: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate file pattern list."""
        if not patterns:
            return False, "File patterns cannot be empty"
        
        for pattern in patterns:
            if not pattern or not pattern.strip():
                return False, "File pattern cannot be empty"
            
            # Basic validation for glob patterns
            if not re.match(r'^[\w\*\.\-/]+$', pattern):
                return False, f"Invalid file pattern: {pattern}"
        
        return True, None


class InputSanitizer:
    """Sanitizes user inputs to prevent security issues."""
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize a filename to prevent path traversal and other issues."""
        if not filename:
            return ""
        
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        sanitized = re.sub(r'\.\.+', '.', sanitized)
        sanitized = sanitized.strip('. ')
        
        # Limit length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        
        return sanitized
    
    @classmethod
    def sanitize_log_message(cls, message: str) -> str:
        """Sanitize log messages to prevent log injection."""
        if not message:
            return ""
        
        # Remove control characters and newlines
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', message)
        
        # Limit length
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000] + "..."
        
        return sanitized.strip()
    
    @classmethod
    def sanitize_user_input(cls, user_input: str, max_length: int = 1000) -> str:
        """General purpose user input sanitization."""
        if not user_input:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>&"\'`]', '', user_input)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()