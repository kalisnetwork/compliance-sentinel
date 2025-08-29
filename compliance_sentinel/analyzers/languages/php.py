"""PHP security analyzer."""

import re
from typing import List
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class PHPAnalyzer(LanguageAnalyzer):
    """Security analyzer for PHP files."""
    
    def __init__(self):
        """Initialize PHP analyzer."""
        super().__init__(ProgrammingLanguage.PHP)
        
        # PHP-specific security patterns
        self.php_patterns = {
            'file_inclusion': r'(?:include|require)(?:_once)?\s*\(\s*\$[^)]*\)',
            'sql_injection': r'mysql_query\s*\([^)]*\$[^)]*\)',
            'xss_vulnerability': r'echo\s+\$[^;]*;',
            'code_injection': r'eval\s*\(\s*\$[^)]*\)',
            'session_fixation': r'session_id\s*\(\s*\$[^)]*\)',
            'weak_crypto': r'md5\s*\(\s*\$[^)]*\)',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze PHP file for security issues."""
        issues = []
        
        # Check for PHP-specific vulnerabilities
        issues.extend(self._check_php_vulnerabilities(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'File inclusion vulnerabilities (LFI/RFI)',
            'SQL injection via mysql_query',
            'XSS vulnerabilities via echo',
            'Code injection via eval',
            'Session fixation vulnerabilities',
            'Weak cryptographic functions',
            'Hardcoded secrets'
        ]
    
    def _check_php_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for PHP-specific security vulnerabilities."""
        issues = []
        
        for vuln_type, pattern in self.php_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"php_{vuln_type}_{line_num}"
                severity = self._get_php_vulnerability_severity(vuln_type)
                
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=self._get_php_vulnerability_category(vuln_type),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"PHP security issue ({vuln_type}): {match[:50]}...",
                    rule_id=f"php_{vuln_type}",
                    confidence=0.8,
                    remediation_suggestions=self._get_php_remediation(vuln_type)
                ))
        
        return issues
    
    def _get_php_vulnerability_severity(self, vuln_type: str) -> Severity:
        """Get severity for PHP vulnerability type."""
        severity_map = {
            'file_inclusion': Severity.HIGH,
            'sql_injection': Severity.HIGH,
            'xss_vulnerability': Severity.HIGH,
            'code_injection': Severity.HIGH,
            'session_fixation': Severity.MEDIUM,
            'weak_crypto': Severity.MEDIUM,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)
    
    def _get_php_vulnerability_category(self, vuln_type: str) -> SecurityCategory:
        """Get category for PHP vulnerability type."""
        category_map = {
            'file_inclusion': SecurityCategory.INPUT_VALIDATION,
            'sql_injection': SecurityCategory.SQL_INJECTION,
            'xss_vulnerability': SecurityCategory.XSS,
            'code_injection': SecurityCategory.INPUT_VALIDATION,
            'session_fixation': SecurityCategory.AUTHENTICATION,
            'weak_crypto': SecurityCategory.INSECURE_CRYPTO,
        }
        return category_map.get(vuln_type, SecurityCategory.INPUT_VALIDATION)
    
    def _get_php_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation suggestions for PHP vulnerabilities."""
        remediation_map = {
            'file_inclusion': [
                "Validate file paths against whitelist",
                "Use absolute paths for includes",
                "Avoid user input in file inclusion"
            ],
            'sql_injection': [
                "Use prepared statements with PDO",
                "Validate and sanitize input",
                "Use mysqli with prepared statements"
            ],
            'xss_vulnerability': [
                "Use htmlspecialchars() for output encoding",
                "Validate and sanitize input",
                "Use templating engines with auto-escaping"
            ],
            'code_injection': [
                "Avoid eval() with user input",
                "Use safe alternatives for dynamic code",
                "Validate input thoroughly"
            ],
            'session_fixation': [
                "Regenerate session ID after login",
                "Use session_regenerate_id()",
                "Validate session tokens"
            ],
            'weak_crypto': [
                "Use password_hash() for passwords",
                "Use stronger hash functions like SHA-256",
                "Avoid MD5 for security purposes"
            ]
        }
        return remediation_map.get(vuln_type, ["Review and secure this pattern"])