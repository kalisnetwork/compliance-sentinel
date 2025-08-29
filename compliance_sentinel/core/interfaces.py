"""
Core interfaces and abstract base classes for the Compliance Sentinel system.

This module defines the contracts that all major components must implement,
ensuring consistency and enabling dependency injection throughout the system.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class Severity(Enum):
    """Security issue severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(Enum):
    """Categories of security issues."""
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_CRYPTO = "insecure_crypto"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    INJECTION = "injection"
    CODE_QUALITY = "code_quality"
    DEPENDENCY = "dependency"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    CRYPTOGRAPHY = "cryptography"
    PATH_TRAVERSAL = "path_traversal"
    CODE_INJECTION = "code_injection"
    DESERIALIZATION = "deserialization"
    CONFIGURATION = "configuration"


# Alias for backward compatibility
SecurityCategory = Category


class PolicyCategory(Enum):
    """Categories of security policies."""
    API_SECURITY = "api_security"
    CREDENTIAL_MANAGEMENT = "credential_management"
    DEPENDENCY_VALIDATION = "dependency_validation"
    CODE_PATTERNS = "code_patterns"


@dataclass
class SecurityIssue:
    """Represents a security issue found during analysis."""
    id: str
    rule_id: str
    severity: Severity
    category: Category
    description: str
    file_path: str
    line_number: int
    confidence: float
    remediation_suggestions: List[str] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.remediation_suggestions is None:
            self.remediation_suggestions = []
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class PolicyRule:
    """Represents a security policy rule."""
    id: str
    name: str
    description: str
    category: PolicyCategory
    severity: Severity
    pattern: str
    remediation_template: str
    applicable_file_types: List[str]


@dataclass
class VulnerabilityReport:
    """Represents a vulnerability found in dependencies."""
    cve_id: str
    package_name: str
    affected_versions: List[str]
    severity_score: float
    description: str
    remediation_available: bool
    upgrade_path: Optional[str]


@dataclass
class AnalysisResult:
    """Complete analysis result for a file or codebase."""
    file_path: str
    timestamp: datetime
    issues: List[SecurityIssue]
    vulnerabilities: List[VulnerabilityReport]
    compliance_status: str
    analysis_duration: float
    recommendations: List[str]


class SecurityAnalyzer(ABC):
    """Abstract base class for security analysis tools."""
    
    @abstractmethod
    def analyze_file(self, file_path: str) -> List[SecurityIssue]:
        """Analyze a single file for security issues."""
        pass
    
    @abstractmethod
    def get_supported_file_types(self) -> List[str]:
        """Return list of supported file extensions."""
        pass
    
    @abstractmethod
    def configure_rules(self, rules: List[str]) -> None:
        """Configure custom analysis rules."""
        pass


class PolicyManager(ABC):
    """Abstract base class for policy management."""
    
    @abstractmethod
    def load_policies(self) -> Dict[str, PolicyRule]:
        """Load all security policies from configuration."""
        pass
    
    @abstractmethod
    def validate_policy(self, policy: PolicyRule) -> bool:
        """Validate a policy rule for correctness."""
        pass
    
    @abstractmethod
    def get_applicable_rules(self, file_type: str, context: str) -> List[PolicyRule]:
        """Get rules applicable to a specific file type and context."""
        pass


class VulnerabilityScanner(ABC):
    """Abstract base class for vulnerability scanning."""
    
    @abstractmethod
    def scan_dependencies(self, requirements_file: str) -> List[VulnerabilityReport]:
        """Scan dependencies for known vulnerabilities."""
        pass
    
    @abstractmethod
    def check_package_vulnerability(self, package: str, version: str) -> Optional[VulnerabilityReport]:
        """Check a specific package version for vulnerabilities."""
        pass


class FeedbackEngine(ABC):
    """Abstract base class for generating user feedback."""
    
    @abstractmethod
    def generate_report(self, analysis_result: AnalysisResult) -> str:
        """Generate a human-readable analysis report."""
        pass
    
    @abstractmethod
    def format_ide_feedback(self, issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Format feedback for IDE integration."""
        pass
    
    @abstractmethod
    def prioritize_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Prioritize issues by severity and impact."""
        pass


class CacheManager(ABC):
    """Abstract base class for caching functionality."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached data by key."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Store data in cache with optional TTL."""
        pass
    
    @abstractmethod
    def invalidate(self, pattern: str) -> None:
        """Invalidate cached data matching pattern."""
        pass


class ErrorHandler(ABC):
    """Abstract base class for error handling."""
    
    @abstractmethod
    def handle_analysis_error(self, error: Exception, context: str) -> None:
        """Handle errors during analysis."""
        pass
    
    @abstractmethod
    def handle_external_service_error(self, service: str, error: Exception) -> None:
        """Handle errors from external services."""
        pass
    
    @abstractmethod
    def should_retry(self, error: Exception) -> bool:
        """Determine if an operation should be retried."""
        pass