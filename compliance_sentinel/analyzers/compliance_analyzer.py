"""Compliance framework analyzer for SOC 2, PCI DSS, HIPAA, GDPR, and ISO 27001."""

import re
from typing import List, Optional
from enum import Enum
from datetime import datetime
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Category, Severity


logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    SOC2_TYPE_II = "soc2_type_ii"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"


class ComplianceAnalyzer:
    """Main compliance analyzer that coordinates all framework analyzers."""
    
    def __init__(self):
        """Initialize compliance analyzer."""
        self.logger = logging.getLogger(__name__)
    
    def analyze_file(self, file_path: str, content: str, frameworks: List[ComplianceFramework]) -> List[SecurityIssue]:
        """Analyze file for compliance violations across specified frameworks."""
        issues = []
        
        try:
            # Detect language
            language = LanguageDetector.detect_language(file_path, content)
            
            # Run analysis for each requested framework
            for framework in frameworks:
                if framework == ComplianceFramework.SOC2_TYPE_II:
                    issues.extend(self._analyze_soc2(file_path, content, language))
                elif framework == ComplianceFramework.PCI_DSS:
                    issues.extend(self._analyze_pci_dss(file_path, content, language))
                elif framework == ComplianceFramework.HIPAA:
                    issues.extend(self._analyze_hipaa(file_path, content, language))
        
        except Exception as e:
            self.logger.error(f"Compliance analysis failed for {file_path}: {e}")
        
        return issues
    
    def _analyze_soc2(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze for SOC 2 Type II compliance."""
        issues = []
        
        # Check for missing authentication on endpoints
        endpoint_patterns = {
            ProgrammingLanguage.PYTHON: r'@app\.route\s*\([^)]*\)',
            ProgrammingLanguage.JAVASCRIPT: r'app\.(get|post|put|delete)\s*\([^)]*\)',
            ProgrammingLanguage.JAVA: r'@(Get|Post|Put|Delete|Request)Mapping'
        }
        
        auth_patterns = {
            ProgrammingLanguage.PYTHON: [r'@login_required', r'@auth\.login_required'],
            ProgrammingLanguage.JAVASCRIPT: [r'authenticate\s*\(', r'requireAuth\s*\('],
            ProgrammingLanguage.JAVA: [r'@PreAuthorize', r'@Secured']
        }
        
        if language in endpoint_patterns:
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                if re.search(endpoint_patterns[language], line, re.IGNORECASE):
                    # Check for authentication in surrounding lines
                    auth_found = False
                    check_range = range(max(0, line_num - 5), min(len(lines), line_num + 5))
                    
                    for check_line_num in check_range:
                        check_line = lines[check_line_num]
                        for auth_pattern in auth_patterns.get(language, []):
                            if re.search(auth_pattern, check_line, re.IGNORECASE):
                                auth_found = True
                                break
                        if auth_found:
                            break
                    
                    if not auth_found and not self._is_public_endpoint(line):
                        issues.append(SecurityIssue(
                            id=f"soc2_cc6_1_{line_num}",
                            rule_id="soc2_cc6_1_access_control",
                            severity=Severity.HIGH,
                            category=Category.AUTHENTICATION,
                            description=f"[SOC2] API endpoint without authentication controls: {line.strip()}",
                            file_path=file_path,
                            line_number=line_num,
                            confidence=0.9
                        ))
        
        # Check for unencrypted sensitive data
        sensitive_patterns = [
            r'password\s*[=:]\s*["\'][^"\']+["\']',
            r'api_key\s*[=:]\s*["\'][^"\']+["\']',
            r'secret\s*[=:]\s*["\'][^"\']+["\']'
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in sensitive_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        id=f"soc2_cc6_7_{line_num}",
                        rule_id="soc2_cc6_7_data_encryption",
                        severity=Severity.HIGH,
                        category=Category.HARDCODED_SECRETS,
                        description=f"[SOC2] Sensitive data without encryption: {line.strip()}",
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.9
                    ))
        
        return issues
    
    def _analyze_pci_dss(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze for PCI DSS compliance."""
        issues = []
        
        # Check for cardholder data patterns
        card_patterns = [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',          # MasterCard
            r'\b3[47][0-9]{13}\b',           # American Express
            r'card_number\s*[=:]\s*["\'][^"\']+["\']',
            r'credit_card\s*[=:]\s*["\'][^"\']+["\']'
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in card_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        id=f"pci_req3_4_{line_num}",
                        rule_id="pci_req3_4_cardholder_protection",
                        severity=Severity.CRITICAL,
                        category=Category.HARDCODED_SECRETS,
                        description=f"[PCI DSS] Unencrypted cardholder data detected: {line.strip()}",
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.95
                    ))
        
        # Check for unencrypted transmission
        transmission_patterns = [
            r'http://',
            r'requests\.get\s*\(\s*["\']http://',
            r'requests\.post\s*\(\s*["\']http://'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in transmission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        id=f"pci_req4_1_{line_num}",
                        rule_id="pci_req4_1_secure_transmission",
                        severity=Severity.HIGH,
                        category=Category.INSECURE_CRYPTO,
                        description=f"[PCI DSS] Unencrypted data transmission: {line.strip()}",
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.8
                    ))
        
        return issues
    
    def _analyze_hipaa(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze for HIPAA compliance."""
        issues = []
        
        # Check for PHI patterns
        phi_patterns = [
            r'ssn\s*[=:]\s*["\'][^"\']+["\']',
            r'social_security\s*[=:]\s*["\'][^"\']+["\']',
            r'medical_record\s*[=:]\s*["\'][^"\']+["\']',
            r'patient_id\s*[=:]\s*["\'][^"\']+["\']',
            r'diagnosis\s*[=:]\s*["\'][^"\']+["\']'
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in phi_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        id=f"hipaa_164_312_a_1_{line_num}",
                        rule_id="hipaa_164_312_a_1_access_control",
                        severity=Severity.CRITICAL,
                        category=Category.HARDCODED_SECRETS,
                        description=f"[HIPAA] Unprotected PHI detected: {line.strip()}",
                        file_path=file_path,
                        line_number=line_num,
                        confidence=0.9
                    ))
        
        # Check for unencrypted PHI transmission
        transmission_patterns = [
            r'http://',
            r'send_email\s*\(',
            r'requests\.post\s*\(\s*["\']http://'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in transmission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if this might involve PHI
                    phi_keywords = ['patient', 'medical', 'health', 'phi', 'diagnosis']
                    if any(keyword in line.lower() for keyword in phi_keywords):
                        issues.append(SecurityIssue(
                            id=f"hipaa_164_312_e_1_{line_num}",
                            rule_id="hipaa_164_312_e_1_transmission_security",
                            severity=Severity.HIGH,
                            category=Category.INSECURE_CRYPTO,
                            description=f"[HIPAA] Unencrypted PHI transmission: {line.strip()}",
                            file_path=file_path,
                            line_number=line_num,
                            confidence=0.8
                        ))
        
        return issues
    
    def _detect_language(self, file_path: str, content: str) -> ProgrammingLanguage:
        """Detect programming language from file path and content."""
        file_path_lower = file_path.lower()
        
        if file_path_lower.endswith(('.py', '.pyw')):
            return ProgrammingLanguage.PYTHON
        elif file_path_lower.endswith(('.js', '.jsx', '.ts', '.tsx')):
            return ProgrammingLanguage.JAVASCRIPT
        elif file_path_lower.endswith(('.java', '.class')):
            return ProgrammingLanguage.JAVA
        elif file_path_lower.endswith(('.cs', '.csx')):
            return ProgrammingLanguage.CSHARP
        elif file_path_lower.endswith('.go'):
            return ProgrammingLanguage.GO
        elif file_path_lower.endswith(('.rs', '.rlib')):
            return ProgrammingLanguage.RUST
        elif file_path_lower.endswith(('.php', '.phtml', '.php3', '.php4', '.php5')):
            return ProgrammingLanguage.PHP
        else:
            return ProgrammingLanguage.UNKNOWN
    
    def _is_public_endpoint(self, line: str) -> bool:
        """Check if endpoint is intentionally public."""
        public_indicators = ['health', 'status', 'ping', 'version', 'public', 'static']
        return any(indicator in line.lower() for indicator in public_indicators)


# Global analyzer instance
_global_compliance_analyzer: Optional[ComplianceAnalyzer] = None


def get_compliance_analyzer() -> ComplianceAnalyzer:
    """Get global compliance analyzer instance."""
    global _global_compliance_analyzer
    if _global_compliance_analyzer is None:
        _global_compliance_analyzer = ComplianceAnalyzer()
    return _global_compliance_analyzer


def reset_compliance_analyzer() -> None:
    """Reset global compliance analyzer (for testing)."""
    global _global_compliance_analyzer
    _global_compliance_analyzer = None