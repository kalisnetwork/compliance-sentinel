"""Machine learning threat detection engine for advanced security analysis."""

import re
import ast
import hashlib
import numpy as np
from typing import List, Dict, Optional, Tuple, Set, Any, Union
from pathlib import Path
import logging
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import json

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity
from compliance_sentinel.analyzers.languages.base import LanguageDetector, ProgrammingLanguage


logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of ML-detected threats."""
    ANOMALOUS_CODE_PATTERN = "anomalous_code_pattern"
    POTENTIAL_BACKDOOR = "potential_backdoor"
    SUSPICIOUS_OBFUSCATION = "suspicious_obfuscation"
    UNUSUAL_NETWORK_ACTIVITY = "unusual_network_activity"
    SUSPICIOUS_FILE_OPERATIONS = "suspicious_file_operations"
    POTENTIAL_DATA_EXFILTRATION = "potential_data_exfiltration"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    INSIDER_THREAT_INDICATOR = "insider_threat_indicator"


@dataclass
class CodeFeatures:
    """Features extracted from code for ML analysis."""
    # Structural features
    complexity_score: float = 0.0
    nesting_depth: int = 0
    function_count: int = 0
    class_count: int = 0
    
    # String and comment features
    string_entropy: float = 0.0
    comment_ratio: float = 0.0
    suspicious_strings: List[str] = field(default_factory=list)
    
    # Pattern features
    import_patterns: List[str] = field(default_factory=list)
    function_patterns: List[str] = field(default_factory=list)
    variable_patterns: List[str] = field(default_factory=list)
    
    # Security-relevant features
    crypto_usage: bool = False
    network_usage: bool = False
    file_operations: bool = False
    system_calls: bool = False
    
    # Behavioral features
    code_similarity_score: float = 0.0
    unusual_patterns: List[str] = field(default_factory=list)


@dataclass
class AnomalyReport:
    """Report of detected anomalies."""
    anomaly_id: str
    anomaly_type: ThreatType
    confidence_score: float
    file_path: str
    line_number: int
    code_snippet: str
    features: CodeFeatures
    risk_assessment: str
    similar_patterns: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)


class CodeFeatureExtractor:
    """Extracts features from code for ML analysis."""
    
    def __init__(self):
        """Initialize feature extractor."""
        self.logger = logging.getLogger(f"{__name__}.feature_extractor")
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'obfuscation': [
                r'eval\s*\(\s*["\'][^"\']*["\']\.replace',
                r'exec\s*\(\s*["\'][^"\']*["\']\.decode',
                r'[a-zA-Z0-9+/]{50,}',  # Base64-like strings
                r'\\x[0-9a-fA-F]{2}',   # Hex encoding
            ],
            'network': [
                r'socket\s*\(',
                r'urllib\s*\.',
                r'requests\s*\.',
                r'http\s*\.',
                r'connect\s*\(',
            ],
            'file_ops': [
                r'open\s*\(',
                r'file\s*\(',
                r'read\s*\(',
                r'write\s*\(',
                r'delete\s*\(',
            ],
            'system': [
                r'os\s*\.',
                r'subprocess\s*\.',
                r'system\s*\(',
                r'exec\s*\(',
                r'shell\s*=\s*True',
            ]
        }
    
    def extract_features(self, code: str, language: ProgrammingLanguage) -> CodeFeatures:
        """Extract comprehensive features from code."""
        features = CodeFeatures()
        
        # Basic structural features
        features.complexity_score = self._calculate_complexity(code)
        features.nesting_depth = self._calculate_nesting_depth(code)
        features.function_count = self._count_functions(code, language)
        features.class_count = self._count_classes(code, language)
        
        # String and comment analysis
        features.string_entropy = self._calculate_string_entropy(code)
        features.comment_ratio = self._calculate_comment_ratio(code, language)
        features.suspicious_strings = self._find_suspicious_strings(code)
        
        # Pattern analysis
        features.import_patterns = self._extract_import_patterns(code, language)
        features.function_patterns = self._extract_function_patterns(code, language)
        features.variable_patterns = self._extract_variable_patterns(code, language)
        
        # Security-relevant features
        features.crypto_usage = self._detect_crypto_usage(code)
        features.network_usage = self._detect_network_usage(code)
        features.file_operations = self._detect_file_operations(code)
        features.system_calls = self._detect_system_calls(code)
        
        # Behavioral features
        features.unusual_patterns = self._detect_unusual_patterns(code)
        
        return features    
  
  def _calculate_complexity(self, code: str) -> float:
        """Calculate cyclomatic complexity score."""
        complexity = 1  # Base complexity
        
        # Count decision points
        decision_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'case', 'switch']
        
        for keyword in decision_keywords:
            pattern = rf'\b{keyword}\b'
            complexity += len(re.findall(pattern, code, re.IGNORECASE))
        
        # Normalize by lines of code
        lines = len([line for line in code.split('\n') if line.strip()])
        return complexity / max(lines, 1)
    
    def _calculate_nesting_depth(self, code: str) -> int:
        """Calculate maximum nesting depth."""
        max_depth = 0
        current_depth = 0
        
        for char in code:
            if char in '{([':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in '})]':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _count_functions(self, code: str, language: ProgrammingLanguage) -> int:
        """Count function definitions."""
        patterns = {
            ProgrammingLanguage.PYTHON: r'def\s+\w+\s*\(',
            ProgrammingLanguage.JAVASCRIPT: r'function\s+\w+\s*\(',
            ProgrammingLanguage.JAVA: r'(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\(',
            ProgrammingLanguage.CSHARP: r'(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\(',
        }
        
        pattern = patterns.get(language, r'(def|function)\s+\w+\s*\(')
        return len(re.findall(pattern, code, re.IGNORECASE))
    
    def _count_classes(self, code: str, language: ProgrammingLanguage) -> int:
        """Count class definitions."""
        patterns = {
            ProgrammingLanguage.PYTHON: r'class\s+\w+',
            ProgrammingLanguage.JAVASCRIPT: r'class\s+\w+',
            ProgrammingLanguage.JAVA: r'(public|private)?\s*class\s+\w+',
            ProgrammingLanguage.CSHARP: r'(public|private|internal)?\s*class\s+\w+',
        }
        
        pattern = patterns.get(language, r'class\s+\w+')
        return len(re.findall(pattern, code, re.IGNORECASE))
    
    def _calculate_string_entropy(self, code: str) -> float:
        """Calculate entropy of string literals."""
        strings = re.findall(r'["\']([^"\']+)["\']', code)
        
        if not strings:
            return 0.0
        
        # Calculate average entropy of all strings
        total_entropy = 0.0
        for string in strings:
            if len(string) > 5:  # Only analyze longer strings
                entropy = self._shannon_entropy(string)
                total_entropy += entropy
        
        return total_entropy / len(strings) if strings else 0.0
    
    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_comment_ratio(self, code: str, language: ProgrammingLanguage) -> float:
        """Calculate ratio of comments to code."""
        comment_patterns = {
            ProgrammingLanguage.PYTHON: [r'#.*$'],
            ProgrammingLanguage.JAVASCRIPT: [r'//.*$', r'/\*.*?\*/'],
            ProgrammingLanguage.JAVA: [r'//.*$', r'/\*.*?\*/'],
            ProgrammingLanguage.CSHARP: [r'//.*$', r'/\*.*?\*/'],
        }
        
        patterns = comment_patterns.get(language, [r'#.*$', r'//.*$'])
        
        comment_chars = 0
        for pattern in patterns:
            matches = re.findall(pattern, code, re.MULTILINE | re.DOTALL)
            comment_chars += sum(len(match) for match in matches)
        
        total_chars = len(code)
        return comment_chars / max(total_chars, 1)
    
    def _find_suspicious_strings(self, code: str) -> List[str]:
        """Find potentially suspicious string literals."""
        suspicious = []
        strings = re.findall(r'["\']([^"\']+)["\']', code)
        
        for string in strings:
            # Check for high entropy (potential obfuscation)
            if len(string) > 20 and self._shannon_entropy(string) > 4.5:
                suspicious.append(f"High entropy string: {string[:30]}...")
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'password', 'secret', 'key', 'token', 'backdoor',
                'exploit', 'payload', 'shell', 'reverse', 'bind'
            ]
            
            string_lower = string.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    suspicious.append(f"Suspicious keyword '{keyword}' in string")
        
        return suspicious
    
    def _extract_import_patterns(self, code: str, language: ProgrammingLanguage) -> List[str]:
        """Extract import/include patterns."""
        patterns = {
            ProgrammingLanguage.PYTHON: r'(?:import|from)\s+([a-zA-Z0-9_.]+)',
            ProgrammingLanguage.JAVASCRIPT: r'(?:import|require)\s*\(?["\']([^"\']+)["\']',
            ProgrammingLanguage.JAVA: r'import\s+([a-zA-Z0-9_.]+)',
        }
        
        pattern = patterns.get(language, r'(?:import|include|require)\s+([a-zA-Z0-9_.]+)')
        return re.findall(pattern, code, re.IGNORECASE)
    
    def _extract_function_patterns(self, code: str, language: ProgrammingLanguage) -> List[str]:
        """Extract function call patterns."""
        # Look for function calls
        function_calls = re.findall(r'(\w+)\s*\(', code)
        
        # Filter out common/safe functions and focus on potentially dangerous ones
        dangerous_functions = [
            'eval', 'exec', 'system', 'shell_exec', 'popen', 'subprocess',
            'socket', 'connect', 'bind', 'listen', 'accept',
            'open', 'file', 'read', 'write', 'delete', 'unlink'
        ]
        
        return [func for func in function_calls if func.lower() in dangerous_functions]
    
    def _extract_variable_patterns(self, code: str, language: ProgrammingLanguage) -> List[str]:
        """Extract suspicious variable naming patterns."""
        # Find variable assignments
        var_patterns = {
            ProgrammingLanguage.PYTHON: r'(\w+)\s*=',
            ProgrammingLanguage.JAVASCRIPT: r'(?:var|let|const)\s+(\w+)',
            ProgrammingLanguage.JAVA: r'\w+\s+(\w+)\s*=',
        }
        
        pattern = var_patterns.get(language, r'(\w+)\s*=')
        variables = re.findall(pattern, code)
        
        # Look for suspicious variable names
        suspicious_vars = []
        suspicious_patterns = [
            r'^[a-f0-9]{8,}$',  # Hex-like names
            r'^[A-Z0-9_]{10,}$',  # All caps long names
            r'^(payload|exploit|backdoor|shell|reverse)',  # Suspicious keywords
        ]
        
        for var in variables:
            for sus_pattern in suspicious_patterns:
                if re.match(sus_pattern, var, re.IGNORECASE):
                    suspicious_vars.append(var)
        
        return suspicious_vars
    
    def _detect_crypto_usage(self, code: str) -> bool:
        """Detect cryptographic operations."""
        crypto_patterns = [
            r'crypto', r'hash', r'encrypt', r'decrypt', r'cipher',
            r'aes', r'rsa', r'sha', r'md5', r'ssl', r'tls'
        ]
        
        code_lower = code.lower()
        return any(pattern in code_lower for pattern in crypto_patterns)
    
    def _detect_network_usage(self, code: str) -> bool:
        """Detect network operations."""
        for pattern in self.suspicious_patterns['network']:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False
    
    def _detect_file_operations(self, code: str) -> bool:
        """Detect file operations."""
        for pattern in self.suspicious_patterns['file_ops']:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False
    
    def _detect_system_calls(self, code: str) -> bool:
        """Detect system calls."""
        for pattern in self.suspicious_patterns['system']:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False
    
    def _detect_unusual_patterns(self, code: str) -> List[str]:
        """Detect unusual code patterns."""
        unusual = []
        
        # Check for obfuscation patterns
        for pattern in self.suspicious_patterns['obfuscation']:
            if re.search(pattern, code, re.IGNORECASE):
                unusual.append(f"Obfuscation pattern detected: {pattern}")
        
        # Check for unusual string operations
        if re.search(r'\.decode\s*\(\s*["\']base64["\']', code, re.IGNORECASE):
            unusual.append("Base64 decoding detected")
        
        if re.search(r'\.replace\s*\([^)]*\)\s*\.replace', code):
            unusual.append("Multiple string replacements (potential deobfuscation)")
        
        return unusual


class AnomalyDetector:
    """ML-based anomaly detection for code patterns."""
    
    def __init__(self):
        """Initialize anomaly detector."""
        self.logger = logging.getLogger(f"{__name__}.anomaly_detector")
        self.feature_extractor = CodeFeatureExtractor()
        
        # Baseline patterns (in production, these would be learned from training data)
        self.baseline_patterns = self._initialize_baseline_patterns()
    
    def _initialize_baseline_patterns(self) -> Dict[str, Any]:
        """Initialize baseline patterns for anomaly detection."""
        return {
            'normal_complexity_range': (0.1, 2.0),
            'normal_nesting_depth': 10,
            'normal_string_entropy': 4.0,
            'normal_comment_ratio': (0.05, 0.3),
            'suspicious_function_threshold': 3,
            'high_entropy_threshold': 4.5,
        }
    
    def detect_anomalies(self, file_path: str, code: str, language: ProgrammingLanguage) -> List[AnomalyReport]:
        """Detect anomalies in code using ML techniques."""
        anomalies = []
        
        # Extract features
        features = self.feature_extractor.extract_features(code, language)
        
        # Detect various types of anomalies
        anomalies.extend(self._detect_complexity_anomalies(file_path, code, features))
        anomalies.extend(self._detect_obfuscation_anomalies(file_path, code, features))
        anomalies.extend(self._detect_behavioral_anomalies(file_path, code, features))
        anomalies.extend(self._detect_backdoor_patterns(file_path, code, features))
        
        return anomalies
    
    def _detect_complexity_anomalies(self, file_path: str, code: str, features: CodeFeatures) -> List[AnomalyReport]:
        """Detect complexity-based anomalies."""
        anomalies = []
        
        normal_range = self.baseline_patterns['normal_complexity_range']
        
        if features.complexity_score > normal_range[1] * 2:
            anomalies.append(AnomalyReport(
                anomaly_id=f"complexity_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.ANOMALOUS_CODE_PATTERN,
                confidence_score=min(0.9, features.complexity_score / normal_range[1]),
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment="High complexity code may indicate obfuscation or malicious intent",
                recommended_actions=[
                    "Review code for unnecessary complexity",
                    "Check for obfuscation techniques",
                    "Verify code functionality matches expectations"
                ]
            ))
        
        if features.nesting_depth > self.baseline_patterns['normal_nesting_depth']:
            anomalies.append(AnomalyReport(
                anomaly_id=f"nesting_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.ANOMALOUS_CODE_PATTERN,
                confidence_score=0.7,
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment="Excessive nesting depth may indicate complex attack logic",
                recommended_actions=[
                    "Refactor deeply nested code",
                    "Review for hidden functionality",
                    "Consider code maintainability"
                ]
            ))
        
        return anomalies
    
    def _detect_obfuscation_anomalies(self, file_path: str, code: str, features: CodeFeatures) -> List[AnomalyReport]:
        """Detect code obfuscation anomalies."""
        anomalies = []
        
        # High string entropy indicates potential obfuscation
        if features.string_entropy > self.baseline_patterns['high_entropy_threshold']:
            anomalies.append(AnomalyReport(
                anomaly_id=f"obfuscation_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.SUSPICIOUS_OBFUSCATION,
                confidence_score=min(0.95, features.string_entropy / 6.0),
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment="High entropy strings suggest code obfuscation or encoded payloads",
                recommended_actions=[
                    "Analyze string content for malicious payloads",
                    "Check for base64 or hex encoding",
                    "Verify legitimate use of high-entropy data"
                ]
            ))
        
        # Unusual patterns indicate obfuscation
        if features.unusual_patterns:
            anomalies.append(AnomalyReport(
                anomaly_id=f"patterns_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.SUSPICIOUS_OBFUSCATION,
                confidence_score=0.8,
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment=f"Unusual patterns detected: {', '.join(features.unusual_patterns[:3])}",
                recommended_actions=[
                    "Investigate unusual code patterns",
                    "Check for deobfuscation techniques",
                    "Verify code legitimacy"
                ]
            ))
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, file_path: str, code: str, features: CodeFeatures) -> List[AnomalyReport]:
        """Detect behavioral anomalies."""
        anomalies = []
        
        # Suspicious combination of capabilities
        capabilities = [
            features.network_usage,
            features.file_operations,
            features.system_calls,
            features.crypto_usage
        ]
        
        capability_count = sum(capabilities)
        
        if capability_count >= 3:
            anomalies.append(AnomalyReport(
                anomaly_id=f"behavior_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.BEHAVIORAL_ANOMALY,
                confidence_score=0.7 + (capability_count - 3) * 0.1,
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment="Code combines multiple high-risk capabilities (network, file, system, crypto)",
                recommended_actions=[
                    "Review necessity of combined capabilities",
                    "Implement principle of least privilege",
                    "Add security controls and monitoring"
                ]
            ))
        
        # Suspicious function usage
        if len(features.function_patterns) > self.baseline_patterns['suspicious_function_threshold']:
            anomalies.append(AnomalyReport(
                anomaly_id=f"functions_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.BEHAVIORAL_ANOMALY,
                confidence_score=0.8,
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment=f"Multiple suspicious functions: {', '.join(features.function_patterns)}",
                recommended_actions=[
                    "Review usage of dangerous functions",
                    "Implement input validation",
                    "Add security logging"
                ]
            ))
        
        return anomalies
    
    def _detect_backdoor_patterns(self, file_path: str, code: str, features: CodeFeatures) -> List[AnomalyReport]:
        """Detect potential backdoor patterns."""
        anomalies = []
        
        # Look for backdoor indicators
        backdoor_patterns = [
            r'backdoor',
            r'reverse\s*shell',
            r'bind\s*shell',
            r'netcat',
            r'nc\s+-',
            r'/bin/sh',
            r'cmd\.exe',
        ]
        
        code_lower = code.lower()
        detected_patterns = []
        
        for pattern in backdoor_patterns:
            if re.search(pattern, code_lower):
                detected_patterns.append(pattern)
        
        if detected_patterns:
            anomalies.append(AnomalyReport(
                anomaly_id=f"backdoor_{hash(file_path) % 10000}",
                anomaly_type=ThreatType.POTENTIAL_BACKDOOR,
                confidence_score=0.9,
                file_path=file_path,
                line_number=1,
                code_snippet=code[:200] + "..." if len(code) > 200 else code,
                features=features,
                risk_assessment=f"Potential backdoor patterns: {', '.join(detected_patterns)}",
                recommended_actions=[
                    "Immediately investigate potential backdoor",
                    "Isolate affected systems",
                    "Conduct security incident response",
                    "Review code commit history"
                ]
            ))
        
        return anomalies


class MLThreatDetectionEngine:
    """Main ML threat detection engine."""
    
    def __init__(self):
        """Initialize ML threat detection engine."""
        self.anomaly_detector = AnomalyDetector()
        self.logger = logging.getLogger(__name__)
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze file using ML threat detection."""
        issues = []
        
        # Detect programming language
        language = LanguageDetector.detect_language(file_path, content)
        
        # Skip analysis for unknown languages
        if language == ProgrammingLanguage.UNKNOWN:
            return issues
        
        try:
            # Detect anomalies
            anomalies = self.anomaly_detector.detect_anomalies(file_path, content, language)
            
            # Convert anomalies to security issues
            for anomaly in anomalies:
                issues.append(self._convert_anomaly_to_issue(anomaly))
        
        except Exception as e:
            self.logger.error(f"ML analysis failed for {file_path}: {e}")
        
        return issues
    
    def _convert_anomaly_to_issue(self, anomaly: AnomalyReport) -> SecurityIssue:
        """Convert anomaly report to security issue."""
        # Map threat types to security categories
        category_map = {
            ThreatType.ANOMALOUS_CODE_PATTERN: SecurityCategory.INPUT_VALIDATION,
            ThreatType.POTENTIAL_BACKDOOR: SecurityCategory.AUTHENTICATION,
            ThreatType.SUSPICIOUS_OBFUSCATION: SecurityCategory.INPUT_VALIDATION,
            ThreatType.BEHAVIORAL_ANOMALY: SecurityCategory.INPUT_VALIDATION,
        }
        
        # Map confidence to severity
        if anomaly.confidence_score >= 0.9:
            severity = Severity.HIGH
        elif anomaly.confidence_score >= 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return SecurityIssue(
            id=anomaly.anomaly_id,
            severity=severity,
            category=category_map.get(anomaly.anomaly_type, SecurityCategory.INPUT_VALIDATION),
            file_path=anomaly.file_path,
            line_number=anomaly.line_number,
            description=f"ML Threat Detection: {anomaly.risk_assessment}",
            rule_id=f"ml_{anomaly.anomaly_type.value}",
            confidence=anomaly.confidence_score,
            remediation_suggestions=anomaly.recommended_actions,
            created_at=datetime.now()
        )
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of ML detection patterns."""
        return [
            'Anomalous code complexity patterns',
            'Suspicious code obfuscation',
            'Potential backdoor indicators',
            'Behavioral anomalies',
            'High-entropy string analysis',
            'Unusual function usage patterns',
            'Suspicious variable naming',
            'Combined high-risk capabilities'
        ]


# Global ML engine instance
_global_ml_engine: Optional[MLThreatDetectionEngine] = None


def get_ml_threat_engine() -> MLThreatDetectionEngine:
    """Get global ML threat detection engine."""
    global _global_ml_engine
    if _global_ml_engine is None:
        _global_ml_engine = MLThreatDetectionEngine()
    return _global_ml_engine


def reset_ml_threat_engine() -> None:
    """Reset global ML engine (for testing)."""
    global _global_ml_engine
    _global_ml_engine = None