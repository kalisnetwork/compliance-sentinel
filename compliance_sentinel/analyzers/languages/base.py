"""Base classes for multi-language security analyzers."""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
from enum import Enum
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity
from compliance_sentinel.core.interfaces import AnalysisResult


logger = logging.getLogger(__name__)


class ProgrammingLanguage(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    CPP = "cpp"
    C = "c"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    RUBY = "ruby"
    SCALA = "scala"
    UNKNOWN = "unknown"


class LanguageDetector:
    """Detects programming language from file content and extension."""
    
    # File extension mappings
    EXTENSION_MAP = {
        '.py': ProgrammingLanguage.PYTHON,
        '.js': ProgrammingLanguage.JAVASCRIPT,
        '.jsx': ProgrammingLanguage.JAVASCRIPT,
        '.ts': ProgrammingLanguage.TYPESCRIPT,
        '.tsx': ProgrammingLanguage.TYPESCRIPT,
        '.java': ProgrammingLanguage.JAVA,
        '.cs': ProgrammingLanguage.CSHARP,
        '.go': ProgrammingLanguage.GO,
        '.rs': ProgrammingLanguage.RUST,
        '.php': ProgrammingLanguage.PHP,
        '.cpp': ProgrammingLanguage.CPP,
        '.cc': ProgrammingLanguage.CPP,
        '.cxx': ProgrammingLanguage.CPP,
        '.c': ProgrammingLanguage.C,
        '.h': ProgrammingLanguage.C,
        '.kt': ProgrammingLanguage.KOTLIN,
        '.swift': ProgrammingLanguage.SWIFT,
        '.rb': ProgrammingLanguage.RUBY,
        '.scala': ProgrammingLanguage.SCALA,
    }
    
    # Content-based detection patterns
    CONTENT_PATTERNS = {
        ProgrammingLanguage.PYTHON: [
            r'^\s*import\s+\w+',
            r'^\s*from\s+\w+\s+import',
            r'^\s*def\s+\w+\s*\(',
            r'^\s*class\s+\w+\s*\(',
        ],
        ProgrammingLanguage.JAVASCRIPT: [
            r'^\s*const\s+\w+\s*=',
            r'^\s*let\s+\w+\s*=',
            r'^\s*var\s+\w+\s*=',
            r'^\s*function\s+\w+\s*\(',
            r'require\s*\(',
            r'module\.exports',
        ],
        ProgrammingLanguage.TYPESCRIPT: [
            r'^\s*interface\s+\w+',
            r'^\s*type\s+\w+\s*=',
            r':\s*\w+\s*=',
            r'<\w+>',
        ],
        ProgrammingLanguage.JAVA: [
            r'^\s*package\s+[\w\.]+;',
            r'^\s*import\s+[\w\.]+;',
            r'^\s*public\s+class\s+\w+',
            r'^\s*private\s+\w+\s+\w+',
            r'System\.out\.println',
        ],
        ProgrammingLanguage.CSHARP: [
            r'^\s*using\s+[\w\.]+;',
            r'^\s*namespace\s+[\w\.]+',
            r'^\s*public\s+class\s+\w+',
            r'Console\.WriteLine',
        ],
        ProgrammingLanguage.GO: [
            r'^\s*package\s+\w+',
            r'^\s*import\s+\(',
            r'^\s*func\s+\w+\s*\(',
            r'fmt\.Print',
        ],
        ProgrammingLanguage.RUST: [
            r'^\s*use\s+\w+',
            r'^\s*fn\s+\w+\s*\(',
            r'^\s*struct\s+\w+',
            r'println!',
        ],
        ProgrammingLanguage.PHP: [
            r'^\s*<\?php',
            r'^\s*namespace\s+[\w\\]+;',
            r'^\s*use\s+[\w\\]+;',
            r'\$\w+\s*=',
        ],
    }
    
    @classmethod
    def detect_language(cls, file_path: str, content: Optional[str] = None) -> ProgrammingLanguage:
        """
        Detect programming language from file path and content.
        
        Args:
            file_path: Path to the file
            content: Optional file content for content-based detection
            
        Returns:
            Detected programming language
        """
        # First try extension-based detection
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension in cls.EXTENSION_MAP:
            detected_lang = cls.EXTENSION_MAP[extension]
            
            # For ambiguous extensions, use content-based detection
            if content and extension in ['.h']:  # Could be C or C++
                return cls._detect_from_content(content, [ProgrammingLanguage.C, ProgrammingLanguage.CPP])
            
            return detected_lang
        
        # Fall back to content-based detection
        if content:
            return cls._detect_from_content(content)
        
        return ProgrammingLanguage.UNKNOWN
    
    @classmethod
    def _detect_from_content(cls, content: str, candidates: Optional[List[ProgrammingLanguage]] = None) -> ProgrammingLanguage:
        """Detect language from content patterns."""
        if candidates is None:
            candidates = list(cls.CONTENT_PATTERNS.keys())
        
        scores = {}
        lines = content.split('\n')[:50]  # Check first 50 lines
        
        for language in candidates:
            if language not in cls.CONTENT_PATTERNS:
                continue
                
            score = 0
            patterns = cls.CONTENT_PATTERNS[language]
            
            for line in lines:
                for pattern in patterns:
                    if re.search(pattern, line, re.MULTILINE):
                        score += 1
            
            scores[language] = score
        
        if scores:
            return max(scores, key=scores.get)
        
        return ProgrammingLanguage.UNKNOWN
    
    @classmethod
    def get_supported_extensions(cls) -> Set[str]:
        """Get all supported file extensions."""
        return set(cls.EXTENSION_MAP.keys())
    
    @classmethod
    def is_supported_language(cls, language: ProgrammingLanguage) -> bool:
        """Check if a language is supported for analysis."""
        return language in cls.CONTENT_PATTERNS


class LanguageAnalyzer(ABC):
    """Base class for language-specific security analyzers."""
    
    def __init__(self, language: ProgrammingLanguage):
        """Initialize language analyzer."""
        self.language = language
        self.logger = logging.getLogger(f"{__name__}.{language.value}")
        
    @abstractmethod
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """
        Analyze a file for security issues.
        
        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze
            
        Returns:
            List of security issues found
        """
        pass
    
    @abstractmethod
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        pass
    
    def can_analyze_file(self, file_path: str) -> bool:
        """Check if this analyzer can analyze the given file."""
        detected_lang = LanguageDetector.detect_language(file_path)
        return detected_lang == self.language
    
    def _create_security_issue(
        self,
        issue_id: str,
        severity: Severity,
        category: SecurityCategory,
        file_path: str,
        line_number: int,
        description: str,
        rule_id: str,
        confidence: float = 0.8,
        remediation_suggestions: Optional[List[str]] = None
    ) -> SecurityIssue:
        """Helper method to create security issues."""
        from datetime import datetime
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=category,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=rule_id,
            confidence=confidence,
            remediation_suggestions=remediation_suggestions or [],
            created_at=datetime.now()
        )
    
    def _find_pattern_matches(
        self,
        content: str,
        pattern: str,
        flags: int = re.MULTILINE | re.IGNORECASE
    ) -> List[Tuple[int, str]]:
        """
        Find pattern matches in content and return line numbers.
        
        Args:
            content: Content to search
            pattern: Regex pattern to match
            flags: Regex flags
            
        Returns:
            List of (line_number, matched_text) tuples
        """
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            match = re.search(pattern, line, flags)
            if match:
                matches.append((line_num, match.group(0)))
        
        return matches
    
    def _extract_string_literals(self, content: str) -> List[Tuple[int, str]]:
        """Extract string literals from code content."""
        # Basic string literal extraction (can be overridden by language-specific analyzers)
        patterns = [
            r'"([^"\\]|\\.)*"',  # Double-quoted strings
            r"'([^'\\]|\\.)*'",  # Single-quoted strings
        ]
        
        matches = []
        for pattern in patterns:
            matches.extend(self._find_pattern_matches(content, pattern))
        
        return matches
    
    def _check_hardcoded_secrets(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Generic hardcoded secrets detection."""
        issues = []
        
        # Common secret patterns
        secret_patterns = {
            'password': r'(password|pwd|pass)\s*[=:]\s*["\']([^"\']{3,})["\']',
            'api_key': r'(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']',
            'secret_key': r'(secret[_-]?key|secretkey)\s*[=:]\s*["\']([^"\']{10,})["\']',
            'token': r'(token|auth[_-]?token)\s*[=:]\s*["\']([^"\']{10,})["\']',
            'private_key': r'(private[_-]?key|privatekey)\s*[=:]\s*["\']([^"\']{20,})["\']',
        }
        
        for secret_type, pattern in secret_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"{self.language.value}_hardcoded_{secret_type}_{line_num}"
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=Severity.HIGH,
                    category=SecurityCategory.HARDCODED_SECRETS,
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Hardcoded {secret_type.replace('_', ' ')} detected: {match[:50]}...",
                    rule_id=f"hardcoded_{secret_type}",
                    confidence=0.9,
                    remediation_suggestions=[
                        f"Move {secret_type.replace('_', ' ')} to environment variables",
                        "Use a secure configuration management system",
                        "Consider using a secrets management service"
                    ]
                ))
        
        return issues


class LanguageAnalyzerRegistry:
    """Registry for managing language-specific analyzers."""
    
    def __init__(self):
        """Initialize analyzer registry."""
        self._analyzers: Dict[ProgrammingLanguage, LanguageAnalyzer] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_analyzer(self, analyzer: LanguageAnalyzer) -> None:
        """Register a language analyzer."""
        self._analyzers[analyzer.language] = analyzer
        self.logger.info(f"Registered analyzer for {analyzer.language.value}")
    
    def get_analyzer(self, language: ProgrammingLanguage) -> Optional[LanguageAnalyzer]:
        """Get analyzer for a specific language."""
        return self._analyzers.get(language)
    
    def get_analyzer_for_file(self, file_path: str, content: Optional[str] = None) -> Optional[LanguageAnalyzer]:
        """Get appropriate analyzer for a file."""
        language = LanguageDetector.detect_language(file_path, content)
        return self.get_analyzer(language)
    
    def get_supported_languages(self) -> List[ProgrammingLanguage]:
        """Get list of supported languages."""
        return list(self._analyzers.keys())
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze a file using the appropriate language analyzer."""
        analyzer = self.get_analyzer_for_file(file_path, content)
        if analyzer:
            return analyzer.analyze_file(file_path, content)
        
        self.logger.warning(f"No analyzer found for file: {file_path}")
        return []


# Global registry instance
_global_registry: Optional[LanguageAnalyzerRegistry] = None


def get_language_analyzer_registry() -> LanguageAnalyzerRegistry:
    """Get global language analyzer registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = LanguageAnalyzerRegistry()
    return _global_registry


def reset_language_analyzer_registry() -> None:
    """Reset global registry (for testing)."""
    global _global_registry
    _global_registry = None