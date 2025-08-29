"""Go security analyzer."""

import re
from typing import List
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class GoAnalyzer(LanguageAnalyzer):
    """Security analyzer for Go files."""
    
    def __init__(self):
        """Initialize Go analyzer."""
        super().__init__(ProgrammingLanguage.GO)
        
        # Go-specific security patterns
        self.go_patterns = {
            'race_condition': r'go\s+func\s*\([^)]*\)\s*{[^}]*\w+\s*=\s*[^}]*}',
            'unsafe_pointer': r'unsafe\.Pointer\s*\(',
            'goroutine_leak': r'go\s+func\s*\([^)]*\)\s*{[^}]*for\s*{[^}]*}[^}]*}',
            'sql_injection': r'db\.Query\s*\([^)]*\+[^)]*\)',
            'command_injection': r'exec\.Command\s*\([^,]*,\s*[^)]*\+[^)]*\)',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Go file for security issues."""
        issues = []
        
        # Check for Go-specific vulnerabilities
        issues.extend(self._check_go_vulnerabilities(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'Race condition vulnerabilities',
            'Unsafe pointer operations',
            'Goroutine leak detection',
            'SQL injection via db.Query',
            'Command injection via exec.Command',
            'Hardcoded secrets'
        ]
    
    def _check_go_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for Go-specific security vulnerabilities."""
        issues = []
        
        for vuln_type, pattern in self.go_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"go_{vuln_type}_{line_num}"
                severity = self._get_go_vulnerability_severity(vuln_type)
                
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=self._get_go_vulnerability_category(vuln_type),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Go security issue ({vuln_type}): {match[:50]}...",
                    rule_id=f"go_{vuln_type}",
                    confidence=0.7,
                    remediation_suggestions=self._get_go_remediation(vuln_type)
                ))
        
        return issues
    
    def _get_go_vulnerability_severity(self, vuln_type: str) -> Severity:
        """Get severity for Go vulnerability type."""
        severity_map = {
            'race_condition': Severity.HIGH,
            'unsafe_pointer': Severity.MEDIUM,
            'goroutine_leak': Severity.MEDIUM,
            'sql_injection': Severity.HIGH,
            'command_injection': Severity.HIGH,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)
    
    def _get_go_vulnerability_category(self, vuln_type: str) -> SecurityCategory:
        """Get category for Go vulnerability type."""
        category_map = {
            'race_condition': SecurityCategory.INPUT_VALIDATION,
            'unsafe_pointer': SecurityCategory.INPUT_VALIDATION,
            'goroutine_leak': SecurityCategory.INPUT_VALIDATION,
            'sql_injection': SecurityCategory.SQL_INJECTION,
            'command_injection': SecurityCategory.INPUT_VALIDATION,
        }
        return category_map.get(vuln_type, SecurityCategory.INPUT_VALIDATION)
    
    def _get_go_remediation(self, vuln_type: str) -> List[str]:
        """Get remediation suggestions for Go vulnerabilities."""
        remediation_map = {
            'race_condition': [
                "Use sync.Mutex or sync.RWMutex for synchronization",
                "Use channels for goroutine communication",
                "Avoid shared mutable state"
            ],
            'unsafe_pointer': [
                "Avoid unsafe.Pointer when possible",
                "Use safe type conversions",
                "Validate pointer operations carefully"
            ],
            'goroutine_leak': [
                "Use context for goroutine cancellation",
                "Implement proper goroutine cleanup",
                "Use sync.WaitGroup for coordination"
            ],
            'sql_injection': [
                "Use prepared statements with placeholders",
                "Validate and sanitize input",
                "Use ORM libraries safely"
            ],
            'command_injection': [
                "Validate command arguments",
                "Use exec.CommandContext with validation",
                "Avoid user input in command construction"
            ]
        }
        return remediation_map.get(vuln_type, ["Review and secure this pattern"])