"""Advanced cryptographic security analyzer."""

import re
import hashlib
import base64
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
import logging
from enum import Enum

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity
from compliance_sentinel.analyzers.languages.base import LanguageDetector, ProgrammingLanguage


logger = logging.getLogger(__name__)


class CryptoVulnerabilityType(Enum):
    """Types of cryptographic vulnerabilities."""
    WEAK_ALGORITHM = "weak_algorithm"
    WEAK_KEY_GENERATION = "weak_key_generation"
    IMPROPER_IV_USAGE = "improper_iv_usage"
    PADDING_ORACLE = "padding_oracle"
    CERTIFICATE_VALIDATION_BYPASS = "certificate_validation_bypass"
    TIMING_ATTACK = "timing_attack"
    WEAK_RANDOM = "weak_random"
    HARDCODED_CRYPTO_MATERIAL = "hardcoded_crypto_material"
    INSECURE_HASH = "insecure_hash"
    WEAK_CIPHER_SUITE = "weak_cipher_suite"


class EntropyAnalyzer:
    """Analyzes entropy of cryptographic material."""
    
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        # Count frequency of each character
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                import math
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def is_low_entropy(data: str, threshold: float = 3.0) -> bool:
        """Check if data has low entropy (potentially weak key/password)."""
        entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        return entropy < threshold
    
    @staticmethod
    def analyze_key_strength(key_data: str) -> Dict[str, any]:
        """Analyze cryptographic key strength."""
        analysis = {
            'length': len(key_data),
            'entropy': EntropyAnalyzer.calculate_shannon_entropy(key_data),
            'has_patterns': EntropyAnalyzer._has_patterns(key_data),
            'character_diversity': EntropyAnalyzer._character_diversity(key_data),
            'strength': 'unknown'
        }
        
        # Determine strength based on multiple factors
        if analysis['length'] < 16:
            analysis['strength'] = 'weak'
        elif analysis['entropy'] < 3.0 or analysis['has_patterns']:
            analysis['strength'] = 'weak'
        elif analysis['length'] >= 32 and analysis['entropy'] >= 4.0:
            analysis['strength'] = 'strong'
        else:
            analysis['strength'] = 'medium'
        
        return analysis
    
    @staticmethod
    def _has_patterns(data: str) -> bool:
        """Check for common patterns that reduce entropy."""
        patterns = [
            r'(.)\1{3,}',  # Repeated characters
            r'(..)\1{2,}',  # Repeated pairs
            r'123|abc|qwe|asd',  # Sequential patterns
            r'password|secret|key',  # Common words
        ]
        
        data_lower = data.lower()
        return any(re.search(pattern, data_lower) for pattern in patterns)
    
    @staticmethod
    def _character_diversity(data: str) -> float:
        """Calculate character diversity (0-1)."""
        if not data:
            return 0.0
        
        unique_chars = len(set(data))
        return unique_chars / len(data)


class AdvancedCryptoAnalyzer:
    """Advanced cryptographic security analyzer."""
    
    def __init__(self):
        """Initialize crypto analyzer."""
        self.entropy_analyzer = EntropyAnalyzer()
        self.logger = logging.getLogger(__name__)
        
        # Weak cryptographic algorithms
        self.weak_algorithms = {
            'hash': ['md5', 'sha1', 'md4', 'md2'],
            'cipher': ['des', 'rc4', 'rc2', '3des'],
            'signature': ['md5withrsa', 'sha1withrsa'],
        }
        
        # Language-specific crypto patterns
        self.crypto_patterns = self._initialize_crypto_patterns()
        
        # Certificate validation bypass patterns
        self.cert_bypass_patterns = self._initialize_cert_bypass_patterns()
        
        # Timing attack patterns
        self.timing_attack_patterns = self._initialize_timing_attack_patterns()
    
    def _initialize_crypto_patterns(self) -> Dict[ProgrammingLanguage, Dict[str, str]]:
        """Initialize language-specific cryptographic patterns."""
        return {
            ProgrammingLanguage.PYTHON: {
                'weak_hash': r'hashlib\.(md5|sha1|md4)\s*\(',
                'weak_cipher': r'(DES|RC4|RC2)\.new\s*\(',
                'hardcoded_key': r'(key|secret|password)\s*=\s*[b]?["\'][a-zA-Z0-9+/=]{16,}["\']',
                'weak_random': r'random\.(randint|choice|random)\s*\(',
                'insecure_ssl': r'ssl\.create_default_context\s*\([^)]*check_hostname\s*=\s*False',
            },
            ProgrammingLanguage.JAVA: {
                'weak_hash': r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|MD4)["\']',
                'weak_cipher': r'Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|RC2)',
                'hardcoded_key': r'(key|secret|password)\s*=\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                'weak_random': r'new\s+Random\s*\(\s*\)',
                'insecure_ssl': r'setHostnameVerifier\s*\(\s*new\s+HostnameVerifier',
            },
            ProgrammingLanguage.JAVASCRIPT: {
                'weak_hash': r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1|md4)["\']',
                'weak_cipher': r'crypto\.createCipher\s*\(\s*["\'](?:des|rc4|rc2)',
                'hardcoded_key': r'(key|secret|password)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                'weak_random': r'Math\.random\s*\(\s*\)',
                'insecure_ssl': r'rejectUnauthorized\s*:\s*false',
            },
            ProgrammingLanguage.CSHARP: {
                'weak_hash': r'(?:MD5|SHA1)\.Create\s*\(\s*\)',
                'weak_cipher': r'new\s+(?:DESCryptoServiceProvider|RC2CryptoServiceProvider)',
                'hardcoded_key': r'(key|secret|password)\s*=\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
                'weak_random': r'new\s+Random\s*\(\s*\)',
                'insecure_ssl': r'ServerCertificateValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true',
            },
            ProgrammingLanguage.GO: {
                'weak_hash': r'(?:md5|sha1)\.(?:New|Sum)\s*\(',
                'weak_cipher': r'(?:des|rc4)\.New\w*\s*\(',
                'hardcoded_key': r'(key|secret|password)\s*:?=\s*["`\'][a-zA-Z0-9+/=]{16,}["`\']',
                'weak_random': r'rand\.(?:Int|Float|Intn)\s*\(',
                'insecure_ssl': r'InsecureSkipVerify\s*:\s*true',
            },
        }
    
    def _initialize_cert_bypass_patterns(self) -> Dict[ProgrammingLanguage, List[str]]:
        """Initialize certificate validation bypass patterns."""
        return {
            ProgrammingLanguage.PYTHON: [
                r'ssl\.create_default_context\s*\([^)]*check_hostname\s*=\s*False',
                r'ssl\._create_unverified_context\s*\(',
                r'verify\s*=\s*False',
            ],
            ProgrammingLanguage.JAVA: [
                r'setHostnameVerifier\s*\([^)]*\)',
                r'TrustManager\[\]\s*{\s*new\s+X509TrustManager',
                r'checkServerTrusted\s*\([^)]*\)\s*{\s*}',
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'rejectUnauthorized\s*:\s*false',
                r'process\.env\[?["\']NODE_TLS_REJECT_UNAUTHORIZED["\']?\]?\s*=\s*["\']0["\']',
                r'agent\s*:\s*new\s+https\.Agent\s*\(\s*{\s*rejectUnauthorized\s*:\s*false',
            ],
            ProgrammingLanguage.CSHARP: [
                r'ServerCertificateValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true',
                r'ServicePointManager\.ServerCertificateValidationCallback\s*=',
                r'RemoteCertificateValidationCallback\s*\([^)]*\)\s*{\s*return\s+true',
            ],
        }
    
    def _initialize_timing_attack_patterns(self) -> Dict[ProgrammingLanguage, List[str]]:
        """Initialize timing attack vulnerability patterns."""
        return {
            ProgrammingLanguage.PYTHON: [
                r'==\s*["\'][^"\']*["\']',  # String comparison
                r'password\s*==\s*input',
                r'token\s*==\s*provided',
            ],
            ProgrammingLanguage.JAVA: [
                r'\.equals\s*\(\s*[^)]*password',
                r'String\.equals\s*\(',
                r'password\.equals\s*\(',
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'password\s*===?\s*input',
                r'token\s*===?\s*provided',
                r'secret\s*===?\s*user',
            ],
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze file for cryptographic security issues."""
        issues = []
        
        # Detect programming language
        language = LanguageDetector.detect_language(file_path, content)
        
        # Perform various crypto analyses
        issues.extend(self._check_weak_algorithms(file_path, content, language))
        issues.extend(self._check_key_generation(file_path, content, language))
        issues.extend(self._check_iv_usage(file_path, content, language))
        issues.extend(self._check_certificate_validation(file_path, content, language))
        issues.extend(self._check_timing_attacks(file_path, content, language))
        issues.extend(self._check_hardcoded_crypto_material(file_path, content))
        issues.extend(self._check_random_number_generation(file_path, content, language))
        
        return issues
    
    def _check_weak_algorithms(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for usage of weak cryptographic algorithms."""
        issues = []
        
        if language not in self.crypto_patterns:
            return issues
        
        patterns = self.crypto_patterns[language]
        
        # Check for weak hash algorithms
        if 'weak_hash' in patterns:
            matches = self._find_pattern_matches(content, patterns['weak_hash'])
            for line_num, match in matches:
                issues.append(self._create_crypto_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=CryptoVulnerabilityType.WEAK_ALGORITHM,
                    description=f"Weak hash algorithm detected: {match}",
                    match=match,
                    severity=Severity.MEDIUM,
                    remediation=[
                        "Use SHA-256, SHA-384, or SHA-512 instead",
                        "Avoid MD5 and SHA-1 for security purposes",
                        "Consider using bcrypt or scrypt for password hashing"
                    ]
                ))
        
        # Check for weak cipher algorithms
        if 'weak_cipher' in patterns:
            matches = self._find_pattern_matches(content, patterns['weak_cipher'])
            for line_num, match in matches:
                issues.append(self._create_crypto_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=CryptoVulnerabilityType.WEAK_ALGORITHM,
                    description=f"Weak cipher algorithm detected: {match}",
                    match=match,
                    severity=Severity.HIGH,
                    remediation=[
                        "Use AES-256 or ChaCha20 for symmetric encryption",
                        "Avoid DES, 3DES, and RC4",
                        "Use authenticated encryption modes like GCM"
                    ]
                ))
        
        return issues
    
    def _check_key_generation(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for weak key generation patterns."""
        issues = []
        
        # Look for hardcoded keys
        if language in self.crypto_patterns and 'hardcoded_key' in self.crypto_patterns[language]:
            pattern = self.crypto_patterns[language]['hardcoded_key']
            matches = self._find_pattern_matches(content, pattern)
            
            for line_num, match in matches:
                # Extract the key value for entropy analysis
                key_match = re.search(r'["\']([a-zA-Z0-9+/=]{16,})["\']', match)
                if key_match:
                    key_value = key_match.group(1)
                    key_analysis = self.entropy_analyzer.analyze_key_strength(key_value)
                    
                    severity = Severity.HIGH if key_analysis['strength'] == 'weak' else Severity.MEDIUM
                    
                    issues.append(self._create_crypto_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CryptoVulnerabilityType.HARDCODED_CRYPTO_MATERIAL,
                        description=f"Hardcoded cryptographic key detected (strength: {key_analysis['strength']})",
                        match=match,
                        severity=severity,
                        remediation=[
                            "Move cryptographic keys to environment variables",
                            "Use a key management service (KMS)",
                            "Generate keys dynamically with proper entropy",
                            f"Key entropy: {key_analysis['entropy']:.2f} (should be > 4.0)"
                        ]
                    ))
        
        return issues
    
    def _check_iv_usage(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for improper IV (Initialization Vector) usage."""
        issues = []
        
        # Language-specific IV patterns
        iv_patterns = {
            ProgrammingLanguage.PYTHON: [
                r'iv\s*=\s*[b]?["\'][^"\']{1,15}["\']',  # Short IV
                r'iv\s*=\s*[b]?["\']0+["\']',  # Zero IV
                r'iv\s*=\s*b?["\'](.)\1+["\']',  # Repeated patterns
            ],
            ProgrammingLanguage.JAVA: [
                r'IvParameterSpec\s*\(\s*["\'][^"\']{1,15}["\']',
                r'IvParameterSpec\s*\(\s*new\s+byte\[\d+\]',  # Zero-initialized array
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'iv\s*:\s*["\'][^"\']{1,15}["\']',
                r'iv\s*:\s*Buffer\.alloc\s*\(\d+\)',  # Zero buffer
            ],
        }
        
        if language in iv_patterns:
            for pattern in iv_patterns[language]:
                matches = self._find_pattern_matches(content, pattern)
                for line_num, match in matches:
                    issues.append(self._create_crypto_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CryptoVulnerabilityType.IMPROPER_IV_USAGE,
                        description=f"Improper IV usage detected: {match}",
                        match=match,
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Use cryptographically secure random IVs",
                            "Ensure IV is unique for each encryption operation",
                            "IV should be at least 16 bytes for AES",
                            "Never reuse IVs with the same key"
                        ]
                    ))
        
        return issues
    
    def _check_certificate_validation(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for certificate validation bypasses."""
        issues = []
        
        if language in self.cert_bypass_patterns:
            for pattern in self.cert_bypass_patterns[language]:
                matches = self._find_pattern_matches(content, pattern)
                for line_num, match in matches:
                    issues.append(self._create_crypto_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CryptoVulnerabilityType.CERTIFICATE_VALIDATION_BYPASS,
                        description=f"Certificate validation bypass detected: {match}",
                        match=match,
                        severity=Severity.HIGH,
                        remediation=[
                            "Enable proper certificate validation",
                            "Verify hostname matches certificate",
                            "Check certificate chain and expiration",
                            "Use certificate pinning for additional security"
                        ]
                    ))
        
        return issues
    
    def _check_timing_attacks(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for timing attack vulnerabilities."""
        issues = []
        
        if language in self.timing_attack_patterns:
            for pattern in self.timing_attack_patterns[language]:
                matches = self._find_pattern_matches(content, pattern)
                for line_num, match in matches:
                    # Check if this looks like a security-sensitive comparison
                    if self._is_security_sensitive_comparison(match):
                        issues.append(self._create_crypto_issue(
                            file_path=file_path,
                            line_number=line_num,
                            vuln_type=CryptoVulnerabilityType.TIMING_ATTACK,
                            description=f"Potential timing attack vulnerability: {match}",
                            match=match,
                            severity=Severity.MEDIUM,
                            remediation=[
                                "Use constant-time comparison functions",
                                "Implement HMAC-based authentication",
                                "Use secure comparison libraries",
                                "Avoid early returns in security checks"
                            ]
                        ))
        
        return issues
    
    def _check_hardcoded_crypto_material(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for hardcoded cryptographic material."""
        issues = []
        
        # Look for base64-encoded data that might be keys/certificates
        base64_pattern = r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'
        matches = self._find_pattern_matches(content, base64_pattern)
        
        for line_num, match in matches:
            # Extract the base64 data
            b64_match = re.search(base64_pattern, match)
            if b64_match:
                b64_data = b64_match.group(1)
                
                # Check if it looks like cryptographic material
                if self._looks_like_crypto_material(b64_data):
                    issues.append(self._create_crypto_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CryptoVulnerabilityType.HARDCODED_CRYPTO_MATERIAL,
                        description=f"Potential hardcoded cryptographic material: {b64_data[:20]}...",
                        match=match,
                        severity=Severity.HIGH,
                        remediation=[
                            "Move cryptographic material to secure storage",
                            "Use environment variables or key management services",
                            "Never commit keys or certificates to version control",
                            "Rotate compromised keys immediately"
                        ]
                    ))
        
        return issues
    
    def _check_random_number_generation(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for weak random number generation."""
        issues = []
        
        if language in self.crypto_patterns and 'weak_random' in self.crypto_patterns[language]:
            pattern = self.crypto_patterns[language]['weak_random']
            matches = self._find_pattern_matches(content, pattern)
            
            for line_num, match in matches:
                # Check if this is used in a security context
                if self._is_security_context(content, line_num):
                    issues.append(self._create_crypto_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CryptoVulnerabilityType.WEAK_RANDOM,
                        description=f"Weak random number generation in security context: {match}",
                        match=match,
                        severity=Severity.MEDIUM,
                        remediation=self._get_secure_random_remediation(language)
                    ))
        
        return issues
    
    def _create_crypto_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: CryptoVulnerabilityType,
        description: str,
        match: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a cryptographic security issue."""
        from datetime import datetime
        
        issue_id = f"crypto_{vuln_type.value}_{line_number}_{hash(match) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.INSECURE_CRYPTO,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"crypto_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )
    
    def _find_pattern_matches(self, content: str, pattern: str) -> List[Tuple[int, str]]:
        """Find pattern matches and return line numbers."""
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                matches.append((line_num, match.group(0)))
        
        return matches
    
    def _is_security_sensitive_comparison(self, match: str) -> bool:
        """Check if a comparison involves security-sensitive data."""
        sensitive_keywords = [
            'password', 'token', 'secret', 'key', 'auth', 'credential',
            'session', 'cookie', 'jwt', 'oauth', 'api_key'
        ]
        
        match_lower = match.lower()
        return any(keyword in match_lower for keyword in sensitive_keywords)
    
    def _looks_like_crypto_material(self, b64_data: str) -> bool:
        """Check if base64 data looks like cryptographic material."""
        # Check length (keys are typically 128+ bits = 16+ bytes = 24+ base64 chars)
        if len(b64_data) < 24:
            return False
        
        # Check entropy
        entropy = self.entropy_analyzer.calculate_shannon_entropy(b64_data)
        if entropy < 3.5:  # Low entropy suggests not random data
            return False
        
        # Check for common key/cert patterns
        try:
            decoded = base64.b64decode(b64_data)
            # Look for ASN.1 DER patterns (certificates/keys often start with 0x30)
            if decoded and decoded[0] == 0x30:
                return True
        except:
            pass
        
        # High entropy + reasonable length suggests crypto material
        return entropy > 4.0 and len(b64_data) >= 40
    
    def _is_security_context(self, content: str, line_number: int) -> bool:
        """Check if line is in a security-related context."""
        lines = content.split('\n')
        
        # Check surrounding lines for security keywords
        start = max(0, line_number - 3)
        end = min(len(lines), line_number + 3)
        
        context_lines = ' '.join(lines[start:end]).lower()
        
        security_keywords = [
            'password', 'token', 'secret', 'key', 'auth', 'login',
            'session', 'crypto', 'encrypt', 'decrypt', 'hash', 'sign'
        ]
        
        return any(keyword in context_lines for keyword in security_keywords)
    
    def _get_secure_random_remediation(self, language: ProgrammingLanguage) -> List[str]:
        """Get language-specific secure random remediation."""
        remediation_map = {
            ProgrammingLanguage.PYTHON: [
                "Use secrets.randbelow() or secrets.token_bytes()",
                "Use os.urandom() for cryptographic randomness",
                "Avoid random module for security purposes"
            ],
            ProgrammingLanguage.JAVA: [
                "Use SecureRandom instead of Random",
                "Initialize SecureRandom properly",
                "Use SecureRandom.getInstanceStrong() for high security"
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                "Use crypto.getRandomValues() for secure randomness",
                "Avoid Math.random() for security purposes",
                "Use Node.js crypto.randomBytes() in server environments"
            ],
            ProgrammingLanguage.CSHARP: [
                "Use RNGCryptoServiceProvider or RandomNumberGenerator",
                "Avoid Random class for security purposes",
                "Use cryptographically secure random generators"
            ],
        }
        
        return remediation_map.get(language, [
            "Use cryptographically secure random number generator",
            "Avoid predictable random sources for security"
        ])


# Global analyzer instance
_global_crypto_analyzer: Optional[AdvancedCryptoAnalyzer] = None


def get_crypto_analyzer() -> AdvancedCryptoAnalyzer:
    """Get global crypto analyzer instance."""
    global _global_crypto_analyzer
    if _global_crypto_analyzer is None:
        _global_crypto_analyzer = AdvancedCryptoAnalyzer()
    return _global_crypto_analyzer


def reset_crypto_analyzer() -> None:
    """Reset global crypto analyzer (for testing)."""
    global _global_crypto_analyzer
    _global_crypto_analyzer = None