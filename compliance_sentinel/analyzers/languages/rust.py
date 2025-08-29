"""Rust security analyzer."""

import re
from typing import List
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class RustAnalyzer(LanguageAnalyzer):
    """Security analyzer for Rust files."""
    
    def __init__(self):
        """Initialize Rust analyzer."""
        super().__init__(ProgrammingLanguage.RUST)
        
        # Rust-specific security patterns
        self.rust_patterns = {
            'unsafe_block': r'unsafe\s*{',
            'raw_pointer': r'\*(?:const|mut)\s+\w+',
            'transmute_usage': r'std::mem::transmute\s*\(',
            'panic_usage': r'panic!\s*\(',
            'unwrap_usage': r'\.unwrap\s*\(\s*\)',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Rust file for security issues."""
        issues = []
        
        # Check for Rust-specific vulnerabilities
        issues.extend(self._check_rust_vulnerabilities(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'Unsafe code blocks',
            'Raw pointer usage',
            'Unsafe transmute operations',
            'Panic usage in production code',
            'Unwrap usage without error handling',
            'Hardcoded secrets'
        ]
    
    def _check_rust_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for Rust-specific security vulnerabilities."""
        issues = []
        
        for vuln_type, pattern in self.rust_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"rust_{vuln_type}_{line_num}"
                severity = self._get_rust_vulnerability_severity(vuln_type)
                
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=self._get_rust_vulnerability_category(vuln_type),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Rust security issue ({vuln_type}): {match[:50]}...",
                    rule_id=f"rust_{vuln_type}",
                    confidence=0.8,
                    remediation_suggestions=self._get_rust_remediation(vuln_type)
                ))
        
        return issues
    
    def _get_rust_vulnerability_severity(self, vuln_type: str) -> Severity:
        """Get severity for Rust vulnerability type."""
        severity_map = {
            'unsafe_block': Severity.MEDIUM,
            'raw_pointer': Severity.MEDIUM,
            'transmute_usage': Severity.HIGH,
            'panic_usage': Severity.LOW,
            'unwrap_usage': Severity.LOW,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)
    
    def _get_rust_vulnerability_category(self, vuln_type: str) -> SecurityCategory:
        """Get category for Rust vulnerability type."""
        category_map = {
            'unsafe_block': SecurityCategory.INPUT_VALIDATION,
            'raw_pointer': SecurityCategory.INPUT_VALIDATION,
            'transmute_usage': SecurityCategory.INPUT_VALIDATION,
            'panic_usage': SecurityCategory.INPUT_VALIDATION,
            'unwrap_usage': SecurityCategory.INPUT_VALIDATION,
        }
        return category_map.get(vuln_type, SecurityCategory.INPUT_VALIDATION)
    
    def _get_rust_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation suggestions for Rust vulnerabilities."""
        remediation_map = {
            'unsafe_block': [
                "Minimize unsafe code usage",
                "Document safety invariants",
                "Use safe alternatives when possible"
            ],
            'raw_pointer': [
                "Use references instead of raw pointers",
                "Validate pointer safety",
                "Consider using smart pointers"
            ],
            'transmute_usage': [
                "Avoid transmute when possible",
                "Use safe type conversions",
                "Validate memory layout assumptions"
            ],
            'panic_usage': [
                "Use Result<T, E> for error handling",
                "Handle errors gracefully",
                "Avoid panics in library code"
            ],
            'unwrap_usage': [
                "Use expect() with descriptive messages",
                "Handle Option/Result properly",
                "Use pattern matching or if-let"
            ]
        }
        return remediation_map.get(vuln_type, ["Review and secure this pattern"])