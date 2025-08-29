"""Code anonymization system for ML training data protection."""

import re
import ast
import hashlib
import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import random
import string

from compliance_sentinel.core.interfaces import SecurityIssue


logger = logging.getLogger(__name__)


class AnonymizationLevel(Enum):
    """Levels of code anonymization."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    COMPLETE = "complete"


class AnonymizationType(Enum):
    """Types of anonymization to apply."""
    IDENTIFIERS = "identifiers"
    COMMENTS = "comments"
    STRINGS = "strings"
    LITERALS = "literals"
    STRUCTURE = "structure"


@dataclass
class AnonymizationConfig:
    """Configuration for code anonymization."""
    
    # Anonymization settings
    level: AnonymizationLevel = AnonymizationLevel.STANDARD
    types: Set[AnonymizationType] = field(default_factory=lambda: {
        AnonymizationType.IDENTIFIERS,
        AnonymizationType.COMMENTS,
        AnonymizationType.STRINGS
    })
    
    # Preservation settings
    preserve_keywords: bool = True
    preserve_builtin_functions: bool = True
    preserve_common_patterns: bool = True
    preserve_structure: bool = True
    
    # Anonymization parameters
    use_deterministic_mapping: bool = True
    seed: Optional[int] = None
    
    # Output settings
    generate_mapping: bool = True
    include_metadata: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'level': self.level.value,
            'types': [t.value for t in self.types],
            'preserve_keywords': self.preserve_keywords,
            'preserve_builtin_functions': self.preserve_builtin_functions,
            'preserve_common_patterns': self.preserve_common_patterns,
            'preserve_structure': self.preserve_structure,
            'use_deterministic_mapping': self.use_deterministic_mapping,
            'seed': self.seed,
            'generate_mapping': self.generate_mapping,
            'include_metadata': self.include_metadata
        }


@dataclass
class AnonymizationResult:
    """Result of code anonymization."""
    
    original_code: str
    anonymized_code: str
    
    # Mapping information
    identifier_mapping: Dict[str, str] = field(default_factory=dict)
    string_mapping: Dict[str, str] = field(default_factory=dict)
    comment_mapping: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    anonymization_level: AnonymizationLevel = AnonymizationLevel.STANDARD
    anonymization_types: Set[AnonymizationType] = field(default_factory=set)
    anonymized_at: datetime = field(default_factory=datetime.now)
    
    # Statistics
    identifiers_anonymized: int = 0
    strings_anonymized: int = 0
    comments_anonymized: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'anonymized_code': self.anonymized_code,
            'anonymization_level': self.anonymization_level.value,
            'anonymization_types': [t.value for t in self.anonymization_types],
            'anonymized_at': self.anonymized_at.isoformat(),
            'identifiers_anonymized': self.identifiers_anonymized,
            'strings_anonymized': self.strings_anonymized,
            'comments_anonymized': self.comments_anonymized,
            'has_mapping': bool(self.identifier_mapping or self.string_mapping or self.comment_mapping)
        }


class IdentifierAnonymizer:
    """Anonymizes code identifiers while preserving functionality."""
    
    def __init__(self, config: AnonymizationConfig):
        """Initialize identifier anonymizer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Mapping storage
        self.identifier_mapping = {}
        self.reverse_mapping = {}
        
        # Preserved identifiers
        self.preserved_keywords = self._load_preserved_keywords()
        self.preserved_builtins = self._load_preserved_builtins()
        
        # Random generator
        if config.seed is not None:
            random.seed(config.seed)
    
    def _load_preserved_keywords(self) -> Set[str]:
        """Load language keywords to preserve."""
        # Python keywords
        python_keywords = {
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
            'elif', 'else', 'except', 'exec', 'finally', 'for', 'from', 'global',
            'if', 'import', 'in', 'is', 'lambda', 'not', 'or', 'pass', 'print',
            'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None'
        }
        
        # JavaScript keywords
        js_keywords = {
            'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while',
            'do', 'break', 'continue', 'switch', 'case', 'default', 'try', 'catch',
            'finally', 'throw', 'new', 'this', 'typeof', 'instanceof', 'in', 'of',
            'true', 'false', 'null', 'undefined'
        }
        
        # Java keywords
        java_keywords = {
            'public', 'private', 'protected', 'static', 'final', 'abstract', 'class',
            'interface', 'extends', 'implements', 'import', 'package', 'void', 'int',
            'String', 'boolean', 'if', 'else', 'for', 'while', 'do', 'switch', 'case',
            'default', 'break', 'continue', 'return', 'try', 'catch', 'finally', 'throw'
        }
        
        return python_keywords | js_keywords | java_keywords
    
    def _load_preserved_builtins(self) -> Set[str]:
        """Load built-in functions to preserve."""
        return {
            # Python builtins
            'len', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'range',
            'enumerate', 'zip', 'map', 'filter', 'sorted', 'reversed', 'sum', 'min', 'max',
            'print', 'input', 'open', 'type', 'isinstance', 'hasattr', 'getattr', 'setattr',
            
            # JavaScript builtins
            'console', 'document', 'window', 'Array', 'Object', 'String', 'Number',
            'Boolean', 'Date', 'Math', 'JSON', 'parseInt', 'parseFloat', 'isNaN',
            'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
            
            # Java builtins
            'System', 'String', 'Integer', 'Double', 'Boolean', 'ArrayList', 'HashMap',
            'Scanner', 'Math', 'Collections'
        }
    
    def anonymize_identifiers(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Anonymize identifiers in code."""
        
        # Pattern to match identifiers
        identifier_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        
        def replace_identifier(match):
            identifier = match.group(0)
            
            # Skip preserved identifiers
            if self.config.preserve_keywords and identifier in self.preserved_keywords:
                return identifier
            
            if self.config.preserve_builtin_functions and identifier in self.preserved_builtins:
                return identifier
            
            # Get or create anonymized version
            if identifier not in self.identifier_mapping:
                anonymized = self._generate_anonymized_identifier(identifier)
                self.identifier_mapping[identifier] = anonymized
                self.reverse_mapping[anonymized] = identifier
            
            return self.identifier_mapping[identifier]
        
        anonymized_code = re.sub(identifier_pattern, replace_identifier, code)
        return anonymized_code, self.identifier_mapping.copy()
    
    def _generate_anonymized_identifier(self, original: str) -> str:
        """Generate anonymized identifier."""
        
        if self.config.use_deterministic_mapping:
            # Use hash-based deterministic mapping
            hash_obj = hashlib.md5(original.encode())
            hash_hex = hash_obj.hexdigest()[:8]
            return f"id_{hash_hex}"
        else:
            # Use random mapping
            length = min(len(original), 8)
            chars = string.ascii_lowercase + string.digits
            return 'id_' + ''.join(random.choices(chars, k=length))


class CommentAnonymizer:
    """Anonymizes comments while preserving code structure."""
    
    def __init__(self, config: AnonymizationConfig):
        """Initialize comment anonymizer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.comment_mapping = {}
    
    def anonymize_comments(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Anonymize comments in code."""
        
        # Patterns for different comment styles
        patterns = [
            (r'//.*$', 'single_line'),  # Single-line comments (// style)
            (r'#.*$', 'hash_comment'),  # Hash comments (Python style)
            (r'/\*.*?\*/', 'multi_line'),  # Multi-line comments (/* */ style)
            (r'""".*?"""', 'docstring'),  # Python docstrings
            (r"'''.*?'''", 'docstring'),  # Python docstrings (single quotes)
        ]
        
        anonymized_code = code
        
        for pattern, comment_type in patterns:
            def replace_comment(match):
                comment = match.group(0)
                
                if comment not in self.comment_mapping:
                    anonymized = self._generate_anonymized_comment(comment, comment_type)
                    self.comment_mapping[comment] = anonymized
                
                return self.comment_mapping[comment]
            
            anonymized_code = re.sub(pattern, replace_comment, anonymized_code, flags=re.MULTILINE | re.DOTALL)
        
        return anonymized_code, self.comment_mapping.copy()
    
    def _generate_anonymized_comment(self, original: str, comment_type: str) -> str:
        """Generate anonymized comment."""
        
        if self.config.level == AnonymizationLevel.MINIMAL:
            # Just remove sensitive information
            return self._sanitize_comment(original)
        
        elif self.config.level == AnonymizationLevel.STANDARD:
            # Replace with generic comment
            if comment_type == 'single_line':
                return '// [comment removed]'
            elif comment_type == 'hash_comment':
                return '# [comment removed]'
            elif comment_type == 'multi_line':
                return '/* [comment removed] */'
            elif comment_type == 'docstring':
                return '"""[docstring removed]"""'
        
        elif self.config.level in [AnonymizationLevel.AGGRESSIVE, AnonymizationLevel.COMPLETE]:
            # Remove comments entirely
            return ''
        
        return original
    
    def _sanitize_comment(self, comment: str) -> str:
        """Sanitize comment by removing sensitive information."""
        
        # Patterns for sensitive information
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[email]'),  # Email
            (r'\b\d{3}-\d{2}-\d{4}\b', '[ssn]'),  # SSN
            (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[card]'),  # Credit card
            (r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b', '[phone]'),  # Phone
            (r'(?i)(password|secret|key|token)[\s]*[:=][\s]*[^\s]+', r'\1: [redacted]'),  # Secrets
        ]
        
        sanitized = comment
        for pattern, replacement in sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized)
        
        return sanitized


class StringAnonymizer:
    """Anonymizes string literals while preserving code functionality."""
    
    def __init__(self, config: AnonymizationConfig):
        """Initialize string anonymizer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.string_mapping = {}
        
        # Patterns to preserve
        self.preserve_patterns = {
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # Simple identifiers
            r'^\w+$',  # Single words
            r'^[0-9]+$',  # Numbers
            r'^[0-9]+\.[0-9]+$',  # Decimals
            r'^https?://.*',  # URLs (structure preserved)
            r'^/.*',  # File paths (structure preserved)
        }
    
    def anonymize_strings(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Anonymize string literals in code."""
        
        # Patterns for different string styles
        string_patterns = [
            r'"([^"\\]|\\.)*"',  # Double-quoted strings
            r"'([^'\\]|\\.)*'",  # Single-quoted strings
            r'`([^`\\]|\\.)*`',  # Template literals (JavaScript)
        ]
        
        anonymized_code = code
        
        for pattern in string_patterns:
            def replace_string(match):
                string_literal = match.group(0)
                
                # Extract content without quotes
                quote_char = string_literal[0]
                content = string_literal[1:-1]
                
                # Check if should be preserved
                if self._should_preserve_string(content):
                    return string_literal
                
                if string_literal not in self.string_mapping:
                    anonymized_content = self._generate_anonymized_string(content)
                    self.string_mapping[string_literal] = f"{quote_char}{anonymized_content}{quote_char}"
                
                return self.string_mapping[string_literal]
            
            anonymized_code = re.sub(pattern, replace_string, anonymized_code)
        
        return anonymized_code, self.string_mapping.copy()
    
    def _should_preserve_string(self, content: str) -> bool:
        """Check if string should be preserved."""
        
        if not self.config.preserve_common_patterns:
            return False
        
        # Check against preserve patterns
        for pattern in self.preserve_patterns:
            if re.match(pattern, content):
                return True
        
        # Preserve very short strings
        if len(content) <= 2:
            return True
        
        # Preserve strings that look like configuration keys
        if content.isupper() and '_' in content:
            return True
        
        return False
    
    def _generate_anonymized_string(self, original: str) -> str:
        """Generate anonymized string."""
        
        if self.config.level == AnonymizationLevel.MINIMAL:
            # Just mask sensitive parts
            return self._mask_sensitive_content(original)
        
        elif self.config.level == AnonymizationLevel.STANDARD:
            # Replace with generic placeholder
            if len(original) <= 10:
                return '[string]'
            else:
                return '[long_string]'
        
        elif self.config.level == AnonymizationLevel.AGGRESSIVE:
            # Replace with random string of similar length
            length = min(len(original), 20)
            chars = string.ascii_lowercase + string.digits
            return ''.join(random.choices(chars, k=length))
        
        elif self.config.level == AnonymizationLevel.COMPLETE:
            # Replace with hash
            hash_obj = hashlib.md5(original.encode())
            return hash_obj.hexdigest()[:16]
        
        return original
    
    def _mask_sensitive_content(self, content: str) -> str:
        """Mask sensitive content in string."""
        
        # Patterns for sensitive information
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[email]'),
            (r'\b\d{3}-\d{2}-\d{4}\b', '[ssn]'),
            (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', '[card]'),
            (r'(?i)(password|secret|key|token)', '[credential]'),
        ]
        
        masked = content
        for pattern, replacement in sensitive_patterns:
            masked = re.sub(pattern, replacement, masked)
        
        return masked


class CodeAnonymizer:
    """Main code anonymization system."""
    
    def __init__(self, config: Optional[AnonymizationConfig] = None):
        """Initialize code anonymizer."""
        self.config = config or AnonymizationConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize component anonymizers
        self.identifier_anonymizer = IdentifierAnonymizer(self.config)
        self.comment_anonymizer = CommentAnonymizer(self.config)
        self.string_anonymizer = StringAnonymizer(self.config)
    
    def anonymize_code(self, code: str, language: Optional[str] = None) -> AnonymizationResult:
        """Anonymize code according to configuration."""
        
        result = AnonymizationResult(
            original_code=code,
            anonymized_code=code,
            anonymization_level=self.config.level,
            anonymization_types=self.config.types.copy()
        )
        
        try:
            # Apply anonymization based on configuration
            current_code = code
            
            # Anonymize identifiers
            if AnonymizationType.IDENTIFIERS in self.config.types:
                current_code, identifier_mapping = self.identifier_anonymizer.anonymize_identifiers(current_code)
                result.identifier_mapping = identifier_mapping
                result.identifiers_anonymized = len(identifier_mapping)
            
            # Anonymize comments
            if AnonymizationType.COMMENTS in self.config.types:
                current_code, comment_mapping = self.comment_anonymizer.anonymize_comments(current_code)
                result.comment_mapping = comment_mapping
                result.comments_anonymized = len(comment_mapping)
            
            # Anonymize strings
            if AnonymizationType.STRINGS in self.config.types:
                current_code, string_mapping = self.string_anonymizer.anonymize_strings(current_code)
                result.string_mapping = string_mapping
                result.strings_anonymized = len(string_mapping)
            
            # Apply structural anonymization if requested
            if AnonymizationType.STRUCTURE in self.config.types:
                current_code = self._anonymize_structure(current_code, language)
            
            result.anonymized_code = current_code
            
        except Exception as e:
            self.logger.error(f"Error during code anonymization: {e}")
            # Return original code if anonymization fails
            result.anonymized_code = code
        
        return result
    
    def _anonymize_structure(self, code: str, language: Optional[str]) -> str:
        """Anonymize code structure while preserving functionality."""
        
        # This is a simplified structural anonymization
        # In practice, this would use AST manipulation
        
        if self.config.level == AnonymizationLevel.COMPLETE:
            # Normalize whitespace and formatting
            lines = code.split('\n')
            normalized_lines = []
            
            for line in lines:
                # Remove extra whitespace but preserve indentation
                stripped = line.rstrip()
                if stripped:
                    # Normalize indentation to spaces
                    indent = len(line) - len(line.lstrip())
                    normalized_lines.append(' ' * indent + stripped.lstrip())
                else:
                    normalized_lines.append('')
            
            return '\n'.join(normalized_lines)
        
        return code
    
    def anonymize_batch(self, code_samples: List[str], language: Optional[str] = None) -> List[AnonymizationResult]:
        """Anonymize multiple code samples."""
        
        results = []
        
        for i, code in enumerate(code_samples):
            try:
                result = self.anonymize_code(code, language)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error anonymizing code sample {i}: {e}")
                # Create error result
                error_result = AnonymizationResult(
                    original_code=code,
                    anonymized_code=code,  # Return original on error
                    anonymization_level=self.config.level,
                    anonymization_types=self.config.types.copy()
                )
                results.append(error_result)
        
        return results
    
    def create_training_dataset(self, 
                              code_samples: List[str],
                              labels: Optional[List[Any]] = None,
                              language: Optional[str] = None) -> Dict[str, Any]:
        """Create anonymized training dataset for ML."""
        
        anonymized_results = self.anonymize_batch(code_samples, language)
        
        dataset = {
            'anonymized_samples': [result.anonymized_code for result in anonymized_results],
            'original_count': len(code_samples),
            'anonymized_count': len(anonymized_results),
            'anonymization_config': self.config.to_dict(),
            'created_at': datetime.now().isoformat(),
            'language': language
        }
        
        if labels is not None:
            dataset['labels'] = labels
        
        if self.config.include_metadata:
            dataset['anonymization_results'] = [result.to_dict() for result in anonymized_results]
        
        return dataset
    
    def get_anonymization_statistics(self, results: List[AnonymizationResult]) -> Dict[str, Any]:
        """Get statistics about anonymization results."""
        
        if not results:
            return {}
        
        total_identifiers = sum(r.identifiers_anonymized for r in results)
        total_strings = sum(r.strings_anonymized for r in results)
        total_comments = sum(r.comments_anonymized for r in results)
        
        return {
            'total_samples': len(results),
            'total_identifiers_anonymized': total_identifiers,
            'total_strings_anonymized': total_strings,
            'total_comments_anonymized': total_comments,
            'avg_identifiers_per_sample': total_identifiers / len(results),
            'avg_strings_per_sample': total_strings / len(results),
            'avg_comments_per_sample': total_comments / len(results),
            'anonymization_level': results[0].anonymization_level.value if results else None,
            'anonymization_types': [t.value for t in results[0].anonymization_types] if results else []
        }


# Utility functions

def create_ml_training_config() -> AnonymizationConfig:
    """Create configuration optimized for ML training data."""
    
    return AnonymizationConfig(
        level=AnonymizationLevel.STANDARD,
        types={
            AnonymizationType.IDENTIFIERS,
            AnonymizationType.COMMENTS,
            AnonymizationType.STRINGS
        },
        preserve_keywords=True,
        preserve_builtin_functions=True,
        preserve_common_patterns=True,
        preserve_structure=True,
        use_deterministic_mapping=True,
        generate_mapping=False,  # Don't store mappings for ML training
        include_metadata=False
    )


def create_privacy_compliant_config() -> AnonymizationConfig:
    """Create configuration for privacy-compliant anonymization."""
    
    return AnonymizationConfig(
        level=AnonymizationLevel.AGGRESSIVE,
        types={
            AnonymizationType.IDENTIFIERS,
            AnonymizationType.COMMENTS,
            AnonymizationType.STRINGS,
            AnonymizationType.LITERALS
        },
        preserve_keywords=True,
        preserve_builtin_functions=True,
        preserve_common_patterns=False,
        preserve_structure=True,
        use_deterministic_mapping=False,
        generate_mapping=True,
        include_metadata=True
    )


def anonymize_for_sharing(code: str, language: Optional[str] = None) -> str:
    """Quick function to anonymize code for sharing."""
    
    config = create_privacy_compliant_config()
    anonymizer = CodeAnonymizer(config)
    result = anonymizer.anonymize_code(code, language)
    
    return result.anonymized_code