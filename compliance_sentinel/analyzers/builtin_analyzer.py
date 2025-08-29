"""Built-in security analyzer that doesn't require external tools."""

import re
import ast
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory

logger = logging.getLogger(__name__)


@dataclass
class SecurityPattern:
    """Represents a security pattern to detect."""
    id: str
    name: str
    pattern: str
    severity: Severity
    category: SecurityCategory
    description: str
    remediation: str


class BuiltinSecurityAnalyzer:
    """Built-in security analyzer with common patterns."""
    
    def __init__(self):
        """Initialize with built-in security patterns."""
        self.patterns = self._load_builtin_patterns()
        logger.info(f"Built-in analyzer initialized with {len(self.patterns)} patterns")
    
    def _load_builtin_patterns(self) -> List[SecurityPattern]:
        """Load built-in security patterns."""
        return [
            SecurityPattern(
                id="hardcoded_password",
                name="Hardcoded Password",
                pattern=r'(?i)(password|pwd|pass)\s*=\s*["\'][^"\']{3,}["\']',
                severity=Severity.HIGH,
                category=SecurityCategory.AUTHENTICATION,
                description="Hardcoded password detected",
                remediation="Use environment variables or secure configuration"
            ),
            SecurityPattern(
                id="sql_injection",
                name="SQL Injection Risk",
                pattern=r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\%s|f".*{.*}.*".*\s*(SELECT|INSERT|UPDATE|DELETE)',
                severity=Severity.HIGH,
                category=SecurityCategory.INJECTION,
                description="Potential SQL injection vulnerability",
                remediation="Use parameterized queries or ORM"
            ),
            SecurityPattern(
                id="command_injection",
                name="Command Injection Risk",
                pattern=r'subprocess\.(run|call|Popen).*shell\s*=\s*True',
                severity=Severity.HIGH,
                category=SecurityCategory.INJECTION,
                description="Command injection risk with shell=True",
                remediation="Avoid shell=True or sanitize input"
            ),
            SecurityPattern(
                id="weak_crypto_md5",
                name="Weak Cryptography - MD5",
                pattern=r'hashlib\.md5\(',
                severity=Severity.MEDIUM,
                category=SecurityCategory.CRYPTOGRAPHY,
                description="MD5 is cryptographically weak",
                remediation="Use SHA-256 or stronger hash functions"
            ),
            SecurityPattern(
                id="weak_crypto_sha1",
                name="Weak Cryptography - SHA1",
                pattern=r'hashlib\.sha1\(',
                severity=Severity.MEDIUM,
                category=SecurityCategory.CRYPTOGRAPHY,
                description="SHA1 is cryptographically weak",
                remediation="Use SHA-256 or stronger hash functions"
            ),
            SecurityPattern(
                id="path_traversal",
                name="Path Traversal Risk",
                pattern=r'open\s*\(\s*["\']?[^"\']*\+.*["\']?\s*,',
                severity=Severity.MEDIUM,
                category=SecurityCategory.PATH_TRAVERSAL,
                description="Potential path traversal vulnerability",
                remediation="Validate and sanitize file paths"
            ),
            SecurityPattern(
                id="debug_mode",
                name="Debug Mode Enabled",
                pattern=r'(?i)debug\s*=\s*True',
                severity=Severity.LOW,
                category=SecurityCategory.CONFIGURATION,
                description="Debug mode should not be enabled in production",
                remediation="Set debug=False in production"
            ),
            SecurityPattern(
                id="eval_usage",
                name="Dangerous eval() Usage",
                pattern=r'\beval\s*\(',
                severity=Severity.CRITICAL,
                category=SecurityCategory.CODE_INJECTION,
                description="Use of eval() can lead to code injection",
                remediation="Avoid eval() or use ast.literal_eval() for safe evaluation"
            ),
            SecurityPattern(
                id="exec_usage",
                name="Dangerous exec() Usage",
                pattern=r'\bexec\s*\(',
                severity=Severity.CRITICAL,
                category=SecurityCategory.CODE_INJECTION,
                description="Use of exec() can lead to code injection",
                remediation="Avoid exec() or carefully validate input"
            ),
            SecurityPattern(
                id="pickle_usage",
                name="Unsafe Pickle Usage",
                pattern=r'pickle\.loads?\(',
                severity=Severity.HIGH,
                category=SecurityCategory.DESERIALIZATION,
                description="Pickle can execute arbitrary code during deserialization",
                remediation="Use JSON or other safe serialization formats"
            )
        ]
    
    async def analyze_file(self, file_path: str) -> List[SecurityIssue]:
        """Analyze a single file for security issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            issues = []
            lines = content.split('\n')
            
            for pattern in self.patterns:
                pattern_issues = self._find_pattern_matches(
                    pattern, content, lines, file_path
                )
                issues.extend(pattern_issues)
            
            logger.debug(f"Found {len(issues)} issues in {file_path}")
            return issues
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return []
    
    def _find_pattern_matches(
        self, 
        pattern: SecurityPattern, 
        content: str, 
        lines: List[str], 
        file_path: str
    ) -> List[SecurityIssue]:
        """Find matches for a specific pattern."""
        issues = []
        
        try:
            regex = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
            
            for line_num, line in enumerate(lines, 1):
                matches = regex.finditer(line)
                
                for match in matches:
                    issue = SecurityIssue(
                        id=f"{pattern.id}_{file_path}_{line_num}_{match.start()}",
                        severity=pattern.severity,
                        category=pattern.category,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"{pattern.name}: {pattern.description}",
                        rule_id=pattern.id,
                        confidence=0.8,  # Medium confidence
                        remediation_suggestions=[pattern.remediation],
                        created_at=datetime.utcnow()
                    )
                    issues.append(issue)
        
        except re.error as e:
            logger.error(f"Invalid regex pattern {pattern.id}: {e}")
        
        return issues
    
    def _get_cwe_for_category(self, category: SecurityCategory) -> Optional[str]:
        """Get CWE ID for security category."""
        cwe_mapping = {
            SecurityCategory.INJECTION: "CWE-89",
            SecurityCategory.AUTHENTICATION: "CWE-798",
            SecurityCategory.CRYPTOGRAPHY: "CWE-327",
            SecurityCategory.PATH_TRAVERSAL: "CWE-22",
            SecurityCategory.CODE_INJECTION: "CWE-94",
            SecurityCategory.DESERIALIZATION: "CWE-502",
            SecurityCategory.CONFIGURATION: "CWE-16"
        }
        return cwe_mapping.get(category)
    
    async def analyze_files(self, file_paths: List[str]) -> List[SecurityIssue]:
        """Analyze multiple files."""
        all_issues = []
        
        for file_path in file_paths:
            if self._should_analyze_file(file_path):
                issues = await self.analyze_file(file_path)
                all_issues.extend(issues)
        
        return all_issues
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Check if file should be analyzed."""
        path = Path(file_path)
        
        # Only analyze certain file types
        supported_extensions = {'.py', '.js', '.ts', '.java', '.go', '.php', '.rb'}
        
        return path.suffix.lower() in supported_extensions
    
    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get information about this analyzer."""
        return {
            "name": "Built-in Security Analyzer",
            "version": "1.0.0",
            "patterns_count": len(self.patterns),
            "supported_languages": ["Python", "JavaScript", "TypeScript", "Java", "Go", "PHP", "Ruby"],
            "categories": list(set(p.category.value for p in self.patterns))
        }