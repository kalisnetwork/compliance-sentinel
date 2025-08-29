"""Java security analyzer."""

import re
from typing import List
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class JavaAnalyzer(LanguageAnalyzer):
    """Security analyzer for Java files."""
    
    def __init__(self):
        """Initialize Java analyzer."""
        super().__init__(ProgrammingLanguage.JAVA)
        
        # Java-specific security patterns
        self.java_patterns = {
            'deserialization': r'ObjectInputStream\s*\([^)]*\)\.readObject\s*\(\)',
            'xxe_vulnerability': r'DocumentBuilderFactory\.newInstance\s*\(\)',
            'sql_injection': r'Statement\s*\.\s*execute\w*\s*\([^)]*\+[^)]*\)',
            'reflection_usage': r'Class\.forName\s*\([^)]*\)',
            'jndi_injection': r'InitialContext\s*\(\s*\)\.lookup\s*\([^)]*\)',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Java file for security issues."""
        issues = []
        
        # Check for Java-specific vulnerabilities
        issues.extend(self._check_java_vulnerabilities(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'Deserialization vulnerabilities',
            'XXE (XML External Entity) attacks',
            'SQL injection via Statement',
            'Unsafe reflection usage',
            'JNDI injection vulnerabilities',
            'Hardcoded secrets'
        ]
    
    def _check_java_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for Java-specific security vulnerabilities."""
        issues = []
        
        for vuln_type, pattern in self.java_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"java_{vuln_type}_{line_num}"
                severity = self._get_java_vulnerability_severity(vuln_type)
                
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=self._get_java_vulnerability_category(vuln_type),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Java security issue ({vuln_type}): {match[:50]}...",
                    rule_id=f"java_{vuln_type}",
                    confidence=0.8,
                    remediation_suggestions=self._get_java_remediation(vuln_type)
                ))
        
        return issues
    
    def _get_java_vulnerability_severity(self, vuln_type: str) -> Severity:
        """Get severity for Java vulnerability type."""
        severity_map = {
            'deserialization': Severity.HIGH,
            'xxe_vulnerability': Severity.HIGH,
            'sql_injection': Severity.HIGH,
            'reflection_usage': Severity.MEDIUM,
            'jndi_injection': Severity.HIGH,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)
    
    def _get_java_vulnerability_category(self, vuln_type: str) -> SecurityCategory:
        """Get category for Java vulnerability type."""
        category_map = {
            'deserialization': SecurityCategory.INPUT_VALIDATION,
            'xxe_vulnerability': SecurityCategory.INPUT_VALIDATION,
            'sql_injection': SecurityCategory.SQL_INJECTION,
            'reflection_usage': SecurityCategory.INPUT_VALIDATION,
            'jndi_injection': SecurityCategory.INPUT_VALIDATION,
        }
        return category_map.get(vuln_type, SecurityCategory.INPUT_VALIDATION)
    
    def _get_java_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation suggestions for Java vulnerabilities."""
        remediation_map = {
            'deserialization': [
                "Avoid deserializing untrusted data",
                "Use safe serialization libraries",
                "Implement custom readObject() with validation"
            ],
            'xxe_vulnerability': [
                "Disable external entity processing",
                "Use secure XML parser configuration",
                "Validate XML input"
            ],
            'sql_injection': [
                "Use PreparedStatement with parameterized queries",
                "Validate and sanitize input",
                "Use ORM frameworks safely"
            ],
            'reflection_usage': [
                "Validate class names before reflection",
                "Use whitelist of allowed classes",
                "Avoid dynamic class loading with user input"
            ],
            'jndi_injection': [
                "Validate JNDI lookup names",
                "Use whitelist of allowed JNDI names",
                "Avoid user-controlled JNDI lookups"
            ]
        }
        return remediation_map.get(vuln_type, ["Review and secure this pattern"])