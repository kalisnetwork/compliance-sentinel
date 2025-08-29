"""C# security analyzer."""

import re
from typing import List
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class CSharpAnalyzer(LanguageAnalyzer):
    """Security analyzer for C# files."""
    
    def __init__(self):
        """Initialize C# analyzer."""
        super().__init__(ProgrammingLanguage.CSHARP)
        
        # C#-specific security patterns
        self.csharp_patterns = {
            'unsafe_deserialization': r'BinaryFormatter\s*\(\s*\)\.Deserialize\s*\(',
            'sql_injection': r'SqlCommand\s*\([^)]*\+[^)]*\)',
            'xaml_injection': r'XamlReader\.Load\s*\([^)]*\)',
            'wcf_security': r'BasicHttpBinding\s*\(\s*\)',
            'unsafe_code': r'unsafe\s*{',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze C# file for security issues."""
        issues = []
        
        # Check for C#-specific vulnerabilities
        issues.extend(self._check_csharp_vulnerabilities(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'Unsafe deserialization (BinaryFormatter)',
            'SQL injection via SqlCommand',
            'XAML injection vulnerabilities',
            'WCF security misconfigurations',
            'Unsafe code blocks',
            'Hardcoded secrets'
        ]
    
    def _check_csharp_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for C#-specific security vulnerabilities."""
        issues = []
        
        for vuln_type, pattern in self.csharp_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"csharp_{vuln_type}_{line_num}"
                severity = self._get_csharp_vulnerability_severity(vuln_type)
                
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=self._get_csharp_vulnerability_category(vuln_type),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"C# security issue ({vuln_type}): {match[:50]}...",
                    rule_id=f"csharp_{vuln_type}",
                    confidence=0.8,
                    remediation_suggestions=self._get_csharp_remediation(vuln_type)
                ))
        
        return issues
    
    def _get_csharp_vulnerability_severity(self, vuln_type: str) -> Severity:
        """Get severity for C# vulnerability type."""
        severity_map = {
            'unsafe_deserialization': Severity.HIGH,
            'sql_injection': Severity.HIGH,
            'xaml_injection': Severity.HIGH,
            'wcf_security': Severity.MEDIUM,
            'unsafe_code': Severity.MEDIUM,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)
    
    def _get_csharp_vulnerability_category(self, vuln_type: str) -> SecurityCategory:
        """Get category for C# vulnerability type."""
        category_map = {
            'unsafe_deserialization': SecurityCategory.INPUT_VALIDATION,
            'sql_injection': SecurityCategory.SQL_INJECTION,
            'xaml_injection': SecurityCategory.INPUT_VALIDATION,
            'wcf_security': SecurityCategory.AUTHENTICATION,
            'unsafe_code': SecurityCategory.INPUT_VALIDATION,
        }
        return category_map.get(vuln_type, SecurityCategory.INPUT_VALIDATION)
    
    def _get_csharp_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation suggestions for C# vulnerabilities."""
        remediation_map = {
            'unsafe_deserialization': [
                "Use safe serialization methods like JSON.NET",
                "Validate deserialized objects",
                "Avoid BinaryFormatter for untrusted data"
            ],
            'sql_injection': [
                "Use parameterized queries with SqlParameter",
                "Use Entity Framework with LINQ",
                "Validate and sanitize input"
            ],
            'xaml_injection': [
                "Validate XAML input before loading",
                "Use safe XAML loading methods",
                "Sanitize user-provided XAML"
            ],
            'wcf_security': [
                "Use secure WCF bindings",
                "Enable message security",
                "Configure proper authentication"
            ],
            'unsafe_code': [
                "Review unsafe code blocks carefully",
                "Use safe alternatives when possible",
                "Validate pointer operations"
            ]
        }
        return remediation_map.get(vuln_type, ["Review and secure this pattern"])