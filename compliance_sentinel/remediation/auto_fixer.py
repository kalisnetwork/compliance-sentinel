"""Pattern-based automatic fix generation for common vulnerabilities."""

import re
import ast
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity
from compliance_sentinel.analyzers.languages.base import LanguageDetector, ProgrammingLanguage


logger = logging.getLogger(__name__)


class FixStatus(Enum):
    """Status of automatic fix application."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    REQUIRES_MANUAL = "requires_manual"


@dataclass
class FixResult:
    """Result of applying an automatic fix."""
    status: FixStatus
    original_code: str
    fixed_code: str
    changes_made: List[str]
    confidence: float
    warnings: List[str]
    manual_steps: List[str]
    applied_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'status': self.status.value,
            'original_code': self.original_code,
            'fixed_code': self.fixed_code,
            'changes_made': self.changes_made,
            'confidence': self.confidence,
            'warnings': self.warnings,
            'manual_steps': self.manual_steps,
            'applied_at': self.applied_at.isoformat()
        }


@dataclass
class FixPattern:
    """Pattern for automatic vulnerability fixes."""
    vulnerability_type: str
    language: ProgrammingLanguage
    pattern: str
    replacement: str
    confidence: float
    description: str
    conditions: List[str] = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []


class AutoFixer:
    """Automatic vulnerability fix generator using pattern matching."""
    
    def __init__(self):
        """Initialize auto-fixer with predefined patterns."""
        self.logger = logging.getLogger(f"{__name__}.auto_fixer")
        self.fix_patterns: Dict[str, List[FixPattern]] = {}
        self._initialize_fix_patterns()
    
    def _initialize_fix_patterns(self) -> None:
        """Initialize predefined fix patterns for common vulnerabilities."""
        
        # Hardcoded secrets fixes
        self._add_hardcoded_secrets_patterns()
        
        # SQL injection fixes
        self._add_sql_injection_patterns()
        
        # XSS prevention fixes
        self._add_xss_prevention_patterns()
        
        # Insecure crypto fixes
        self._add_crypto_fixes()
        
        # Input validation fixes
        self._add_input_validation_patterns()
        
        self.logger.info(f"Initialized {sum(len(patterns) for patterns in self.fix_patterns.values())} fix patterns")
    
    def _add_hardcoded_secrets_patterns(self) -> None:
        """Add patterns for fixing hardcoded secrets."""
        patterns = [
            # Python hardcoded passwords
            FixPattern(
                vulnerability_type="hardcoded_secrets",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'password\s*=\s*["\']([^"\']+)["\']',
                replacement=r'password = os.getenv("PASSWORD", "")',
                confidence=0.9,
                description="Replace hardcoded password with environment variable",
                conditions=["import os"]
            ),
            
            # Python API keys
            FixPattern(
                vulnerability_type="hardcoded_secrets",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'api_key\s*=\s*["\']([^"\']+)["\']',
                replacement=r'api_key = os.getenv("API_KEY", "")',
                confidence=0.9,
                description="Replace hardcoded API key with environment variable",
                conditions=["import os"]
            ),
            
            # JavaScript hardcoded secrets
            FixPattern(
                vulnerability_type="hardcoded_secrets",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'const\s+(\w*[Pp]assword\w*)\s*=\s*["\']([^"\']+)["\']',
                replacement=r'const \1 = process.env.PASSWORD || ""',
                confidence=0.8,
                description="Replace hardcoded password with environment variable"
            ),
            
            # Java hardcoded secrets
            FixPattern(
                vulnerability_type="hardcoded_secrets",
                language=ProgrammingLanguage.JAVA,
                pattern=r'String\s+(\w*[Pp]assword\w*)\s*=\s*"([^"]+)"',
                replacement=r'String \1 = System.getenv("PASSWORD")',
                confidence=0.8,
                description="Replace hardcoded password with environment variable"
            )
        ]
        
        self.fix_patterns["hardcoded_secrets"] = patterns
    
    def _add_sql_injection_patterns(self) -> None:
        """Add patterns for fixing SQL injection vulnerabilities."""
        patterns = [
            # Python string concatenation
            FixPattern(
                vulnerability_type="sql_injection",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'cursor\.execute\s*\(\s*["\']([^"\']*)\s*\+\s*([^"\']+)\s*\+\s*["\']([^"\']*)["\']',
                replacement=r'cursor.execute("\1%s\3", (\2,))',
                confidence=0.8,
                description="Replace string concatenation with parameterized query"
            ),
            
            # Python f-string injection
            FixPattern(
                vulnerability_type="sql_injection",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'cursor\.execute\s*\(\s*f["\']([^"\']*\{[^}]+\}[^"\']*)["\']',
                replacement=r'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                confidence=0.7,
                description="Replace f-string with parameterized query",
                conditions=["manual_parameter_mapping_required"]
            ),
            
            # JavaScript template literals
            FixPattern(
                vulnerability_type="sql_injection",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'query\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`',
                replacement=r'query("SELECT * FROM users WHERE id = ?", [userId])',
                confidence=0.7,
                description="Replace template literal with parameterized query"
            ),
            
            # Java string concatenation
            FixPattern(
                vulnerability_type="sql_injection",
                language=ProgrammingLanguage.JAVA,
                pattern=r'executeQuery\s*\(\s*"([^"]*"\s*\+\s*[^"]+\s*\+\s*"[^"]*)"',
                replacement=r'prepareStatement("SELECT * FROM users WHERE id = ?").setString(1, userId).executeQuery()',
                confidence=0.8,
                description="Replace string concatenation with PreparedStatement"
            )
        ]
        
        self.fix_patterns["sql_injection"] = patterns
    
    def _add_xss_prevention_patterns(self) -> None:
        """Add patterns for XSS prevention."""
        patterns = [
            # JavaScript innerHTML
            FixPattern(
                vulnerability_type="xss",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'(\w+)\.innerHTML\s*=\s*([^;]+)',
                replacement=r'\1.textContent = \2',
                confidence=0.8,
                description="Replace innerHTML with textContent to prevent XSS"
            ),
            
            # JavaScript document.write
            FixPattern(
                vulnerability_type="xss",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'document\.write\s*\(\s*([^)]+)\s*\)',
                replacement=r'// Use DOM manipulation instead: element.textContent = \1',
                confidence=0.9,
                description="Replace document.write with safe DOM manipulation"
            ),
            
            # Python Flask without escaping
            FixPattern(
                vulnerability_type="xss",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'return\s+["\']([^"\']*)\s*\+\s*([^"\']+)\s*\+\s*["\']([^"\']*)["\']',
                replacement=r'return "\1" + escape(\2) + "\3"',
                confidence=0.7,
                description="Add HTML escaping to prevent XSS",
                conditions=["from markupsafe import escape"]
            )
        ]
        
        self.fix_patterns["xss"] = patterns
    
    def _add_crypto_fixes(self) -> None:
        """Add patterns for fixing cryptographic issues."""
        patterns = [
            # Python weak hashing
            FixPattern(
                vulnerability_type="weak_crypto",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'hashlib\.md5\s*\(',
                replacement=r'hashlib.sha256(',
                confidence=0.9,
                description="Replace MD5 with SHA-256"
            ),
            
            FixPattern(
                vulnerability_type="weak_crypto",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'hashlib\.sha1\s*\(',
                replacement=r'hashlib.sha256(',
                confidence=0.9,
                description="Replace SHA-1 with SHA-256"
            ),
            
            # JavaScript weak random
            FixPattern(
                vulnerability_type="weak_crypto",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'Math\.random\s*\(\s*\)',
                replacement=r'crypto.getRandomValues(new Uint32Array(1))[0]',
                confidence=0.8,
                description="Replace Math.random with cryptographically secure random",
                conditions=["const crypto = require('crypto')"]
            ),
            
            # Java weak cipher
            FixPattern(
                vulnerability_type="weak_crypto",
                language=ProgrammingLanguage.JAVA,
                pattern=r'Cipher\.getInstance\s*\(\s*"DES"',
                replacement=r'Cipher.getInstance("AES/GCM/NoPadding"',
                confidence=0.9,
                description="Replace DES with AES-GCM"
            )
        ]
        
        self.fix_patterns["weak_crypto"] = patterns
    
    def _add_input_validation_patterns(self) -> None:
        """Add patterns for input validation fixes."""
        patterns = [
            # Python missing input validation
            FixPattern(
                vulnerability_type="input_validation",
                language=ProgrammingLanguage.PYTHON,
                pattern=r'def\s+(\w+)\s*\([^)]*(\w+)[^)]*\):\s*\n\s*([^#\n]*(?:int|float|eval)\s*\(\s*\2\s*\))',
                replacement=r'def \1(\2):\n    if not isinstance(\2, (int, float)) or \2 < 0:\n        raise ValueError("Invalid input")\n    \3',
                confidence=0.6,
                description="Add input validation for numeric conversions"
            ),
            
            # JavaScript missing validation
            FixPattern(
                vulnerability_type="input_validation",
                language=ProgrammingLanguage.JAVASCRIPT,
                pattern=r'parseInt\s*\(\s*([^)]+)\s*\)',
                replacement=r'(function(val) { const num = parseInt(val); if (isNaN(num)) throw new Error("Invalid number"); return num; })(\1)',
                confidence=0.7,
                description="Add validation to parseInt calls"
            )
        ]
        
        self.fix_patterns["input_validation"] = patterns
    
    def apply_fix(self, issue: SecurityIssue, code: str) -> FixResult:
        """Apply automatic fix for a security issue."""
        try:
            # Detect language
            language = LanguageDetector.detect_language(issue.file_path, code)
            
            # Get applicable patterns
            patterns = self._get_applicable_patterns(issue, language)
            
            if not patterns:
                return FixResult(
                    status=FixStatus.NOT_APPLICABLE,
                    original_code=code,
                    fixed_code=code,
                    changes_made=[],
                    confidence=0.0,
                    warnings=["No applicable fix patterns found"],
                    manual_steps=self._get_manual_remediation_steps(issue),
                    applied_at=datetime.now()
                )
            
            # Apply the best matching pattern
            best_pattern = max(patterns, key=lambda p: p.confidence)
            return self._apply_pattern(code, best_pattern, issue)
        
        except Exception as e:
            self.logger.error(f"Fix application failed: {e}")
            return FixResult(
                status=FixStatus.FAILED,
                original_code=code,
                fixed_code=code,
                changes_made=[],
                confidence=0.0,
                warnings=[f"Fix application failed: {str(e)}"],
                manual_steps=self._get_manual_remediation_steps(issue),
                applied_at=datetime.now()
            )
    
    def _get_applicable_patterns(self, issue: SecurityIssue, language: ProgrammingLanguage) -> List[FixPattern]:
        """Get fix patterns applicable to the security issue."""
        applicable_patterns = []
        
        # Map security categories to vulnerability types
        category_mapping = {
            SecurityCategory.HARDCODED_SECRETS: "hardcoded_secrets",
            SecurityCategory.INJECTION: "sql_injection",
            SecurityCategory.XSS: "xss",
            SecurityCategory.INSECURE_CRYPTO: "weak_crypto",
            SecurityCategory.INPUT_VALIDATION: "input_validation"
        }
        
        vulnerability_type = category_mapping.get(issue.category)
        if vulnerability_type and vulnerability_type in self.fix_patterns:
            for pattern in self.fix_patterns[vulnerability_type]:
                if pattern.language == language:
                    applicable_patterns.append(pattern)
        
        return applicable_patterns
    
    def _apply_pattern(self, code: str, pattern: FixPattern, issue: SecurityIssue) -> FixResult:
        """Apply a specific fix pattern to code."""
        changes_made = []
        warnings = []
        manual_steps = []
        
        # Apply regex replacement
        original_code = code
        fixed_code = code
        
        try:
            # Find matches
            matches = list(re.finditer(pattern.pattern, code, re.MULTILINE | re.DOTALL))
            
            if not matches:
                return FixResult(
                    status=FixStatus.NOT_APPLICABLE,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    changes_made=[],
                    confidence=0.0,
                    warnings=["Pattern did not match code"],
                    manual_steps=self._get_manual_remediation_steps(issue),
                    applied_at=datetime.now()
                )
            
            # Apply replacements (in reverse order to maintain positions)
            for match in reversed(matches):
                start, end = match.span()
                replacement = re.sub(pattern.pattern, pattern.replacement, match.group(0))
                fixed_code = fixed_code[:start] + replacement + fixed_code[end:]
                changes_made.append(f"Line {self._get_line_number(original_code, start)}: {pattern.description}")
            
            # Check for required conditions
            for condition in pattern.conditions:
                if condition.startswith("import ") or condition.startswith("from "):
                    if condition not in fixed_code:
                        # Add import at the top
                        fixed_code = condition + "\\n" + fixed_code
                        changes_made.append(f"Added import: {condition}")
                elif condition == "manual_parameter_mapping_required":
                    manual_steps.append("Review and adjust parameter mapping for prepared statement")
                    warnings.append("Manual parameter mapping may be required")
            
            # Determine status
            status = FixStatus.SUCCESS
            if manual_steps or warnings:
                status = FixStatus.PARTIAL
            
            return FixResult(
                status=status,
                original_code=original_code,
                fixed_code=fixed_code,
                changes_made=changes_made,
                confidence=pattern.confidence,
                warnings=warnings,
                manual_steps=manual_steps,
                applied_at=datetime.now()
            )
        
        except Exception as e:
            return FixResult(
                status=FixStatus.FAILED,
                original_code=original_code,
                fixed_code=original_code,
                changes_made=[],
                confidence=0.0,
                warnings=[f"Pattern application failed: {str(e)}"],
                manual_steps=self._get_manual_remediation_steps(issue),
                applied_at=datetime.now()
            )
    
    def _get_line_number(self, code: str, position: int) -> int:
        """Get line number for a character position in code."""
        return code[:position].count('\\n') + 1
    
    def _get_manual_remediation_steps(self, issue: SecurityIssue) -> List[str]:
        """Get manual remediation steps for issues that can't be auto-fixed."""
        manual_steps = {
            SecurityCategory.HARDCODED_SECRETS: [
                "Move secrets to environment variables or secure vault",
                "Update deployment configuration to inject secrets",
                "Review and rotate any exposed credentials"
            ],
            SecurityCategory.INJECTION: [
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Review all user input handling code"
            ],
            SecurityCategory.XSS: [
                "Implement proper output encoding/escaping",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs"
            ],
            SecurityCategory.INSECURE_CRYPTO: [
                "Use strong, modern cryptographic algorithms",
                "Implement proper key management",
                "Review cryptographic implementation with security expert"
            ],
            SecurityCategory.INPUT_VALIDATION: [
                "Implement comprehensive input validation",
                "Use allowlist validation where possible",
                "Add proper error handling for invalid inputs"
            ]
        }
        
        return manual_steps.get(issue.category, issue.remediation_suggestions or [
            "Review security issue and implement appropriate fix",
            "Consult security documentation for best practices"
        ])
    
    def get_fix_preview(self, issue: SecurityIssue, code: str) -> Dict[str, Any]:
        """Get a preview of what fixes would be applied without actually applying them."""
        language = LanguageDetector.detect_language(issue.file_path, code)
        patterns = self._get_applicable_patterns(issue, language)
        
        if not patterns:
            return {
                "applicable": False,
                "patterns": [],
                "confidence": 0.0,
                "description": "No applicable fix patterns found"
            }
        
        best_pattern = max(patterns, key=lambda p: p.confidence)
        matches = list(re.finditer(best_pattern.pattern, code, re.MULTILINE | re.DOTALL))
        
        return {
            "applicable": len(matches) > 0,
            "patterns": [
                {
                    "description": p.description,
                    "confidence": p.confidence,
                    "language": p.language.value
                }
                for p in patterns
            ],
            "best_match": {
                "description": best_pattern.description,
                "confidence": best_pattern.confidence,
                "matches": len(matches)
            } if matches else None,
            "confidence": best_pattern.confidence if matches else 0.0,
            "description": best_pattern.description if matches else "Pattern does not match code"
        }
    
    def add_custom_pattern(self, pattern: FixPattern) -> None:
        """Add a custom fix pattern."""
        if pattern.vulnerability_type not in self.fix_patterns:
            self.fix_patterns[pattern.vulnerability_type] = []
        
        self.fix_patterns[pattern.vulnerability_type].append(pattern)
        self.logger.info(f"Added custom fix pattern for {pattern.vulnerability_type}")
    
    def get_supported_vulnerabilities(self) -> List[str]:
        """Get list of vulnerability types that can be auto-fixed."""
        return list(self.fix_patterns.keys())
    
    def get_fix_statistics(self) -> Dict[str, Any]:
        """Get statistics about available fix patterns."""
        stats = {}
        total_patterns = 0
        
        for vuln_type, patterns in self.fix_patterns.items():
            language_counts = {}
            for pattern in patterns:
                lang = pattern.language.value
                language_counts[lang] = language_counts.get(lang, 0) + 1
                total_patterns += 1
            
            stats[vuln_type] = {
                "total_patterns": len(patterns),
                "languages": language_counts,
                "avg_confidence": sum(p.confidence for p in patterns) / len(patterns)
            }
        
        return {
            "total_patterns": total_patterns,
            "vulnerability_types": len(self.fix_patterns),
            "by_type": stats
        }


# Global auto-fixer instance
_global_auto_fixer: Optional[AutoFixer] = None


def get_auto_fixer() -> AutoFixer:
    """Get global auto-fixer instance."""
    global _global_auto_fixer
    if _global_auto_fixer is None:
        _global_auto_fixer = AutoFixer()
    return _global_auto_fixer


def reset_auto_fixer() -> None:
    """Reset global auto-fixer (for testing)."""
    global _global_auto_fixer
    _global_auto_fixer = None