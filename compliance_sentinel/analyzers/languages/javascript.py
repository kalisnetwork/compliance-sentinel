"""JavaScript and TypeScript security analyzer."""

import re
import json
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
import logging

from .base import LanguageAnalyzer, ProgrammingLanguage
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class JavaScriptAnalyzer(LanguageAnalyzer):
    """Security analyzer for JavaScript and TypeScript files."""
    
    def __init__(self):
        """Initialize JavaScript analyzer."""
        super().__init__(ProgrammingLanguage.JAVASCRIPT)
        
        # XSS vulnerability patterns
        self.xss_patterns = {
            'innerHTML': r'\.innerHTML\s*=\s*[^;]+',
            'outerHTML': r'\.outerHTML\s*=\s*[^;]+',
            'document_write': r'document\.write\s*\([^)]*\)',
            'eval_like': r'(eval|setTimeout|setInterval)\s*\(\s*[^)]*\+[^)]*\)',
            'jquery_html': r'\$\([^)]*\)\.html\s*\([^)]*\+[^)]*\)',
        }
        
        # Prototype pollution patterns
        self.prototype_pollution_patterns = {
            'object_assign': r'Object\.assign\s*\([^,]+,\s*[^)]*\)',
            'bracket_notation': r'\w+\[[^]]*\]\s*=',
            'constructor_prototype': r'\.constructor\.prototype\.',
            'proto_access': r'\.__proto__\.',
        }
        
        # Insecure patterns
        self.insecure_patterns = {
            'eval_usage': r'\beval\s*\(',
            'function_constructor': r'new\s+Function\s*\(',
            'settimeout_string': r'setTimeout\s*\(\s*["\'][^"\']*["\']',
            'setinterval_string': r'setInterval\s*\(\s*["\'][^"\']*["\']',
            'document_domain': r'document\.domain\s*=',
            'postmessage_wildcard': r'postMessage\s*\([^,]*,\s*["\']?\*["\']?\)',
        }
        
        # Crypto and security patterns
        self.crypto_patterns = {
            'weak_random': r'Math\.random\s*\(\)',
            'insecure_hash': r'(md5|sha1)\s*\(',
            'hardcoded_crypto_key': r'(key|secret|password)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze JavaScript/TypeScript file for security issues."""
        issues = []
        
        # Check for XSS vulnerabilities
        issues.extend(self._check_xss_vulnerabilities(file_path, content))
        
        # Check for prototype pollution
        issues.extend(self._check_prototype_pollution(file_path, content))
        
        # Check for insecure patterns
        issues.extend(self._check_insecure_patterns(file_path, content))
        
        # Check for crypto issues
        issues.extend(self._check_crypto_issues(file_path, content))
        
        # Check for hardcoded secrets (from base class)
        issues.extend(self._check_hardcoded_secrets(file_path, content))
        
        # Check for npm vulnerabilities if package.json
        if file_path.endswith('package.json'):
            issues.extend(self._check_npm_vulnerabilities(file_path, content))
        
        # Check for async/await security issues
        issues.extend(self._check_async_security_issues(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        return [
            'XSS vulnerabilities',
            'Prototype pollution',
            'Code injection (eval, Function constructor)',
            'Insecure random number generation',
            'Weak cryptographic functions',
            'Hardcoded secrets',
            'NPM package vulnerabilities',
            'Async/await security issues',
            'DOM manipulation flaws',
            'PostMessage security issues'
        ]
    
    def _check_xss_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for XSS vulnerabilities."""
        issues = []
        
        for xss_type, pattern in self.xss_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                # Check if the assignment involves user input or variables
                if self._involves_user_input(match):
                    issue_id = f"js_xss_{xss_type}_{line_num}"
                    issues.append(self._create_security_issue(
                        issue_id=issue_id,
                        severity=Severity.HIGH,
                        category=SecurityCategory.XSS,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"Potential XSS vulnerability via {xss_type}: {match[:50]}...",
                        rule_id=f"js_xss_{xss_type}",
                        confidence=0.8,
                        remediation_suggestions=[
                            "Use textContent instead of innerHTML for text content",
                            "Sanitize user input before inserting into DOM",
                            "Use a trusted HTML sanitization library",
                            "Implement Content Security Policy (CSP)"
                        ]
                    ))
        
        return issues
    
    def _check_prototype_pollution(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for prototype pollution vulnerabilities."""
        issues = []
        
        for pollution_type, pattern in self.prototype_pollution_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                # Check for dangerous property assignments
                if self._is_dangerous_property_assignment(match):
                    issue_id = f"js_prototype_pollution_{pollution_type}_{line_num}"
                    issues.append(self._create_security_issue(
                        issue_id=issue_id,
                        severity=Severity.MEDIUM,
                        category=SecurityCategory.INPUT_VALIDATION,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"Potential prototype pollution via {pollution_type}: {match[:50]}...",
                        rule_id=f"js_prototype_pollution_{pollution_type}",
                        confidence=0.7,
                        remediation_suggestions=[
                            "Validate property names before assignment",
                            "Use Object.create(null) for objects without prototype",
                            "Implement property name whitelist",
                            "Use Map instead of plain objects for dynamic properties"
                        ]
                    ))
        
        return issues
    
    def _check_insecure_patterns(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for insecure coding patterns."""
        issues = []
        
        for pattern_type, pattern in self.insecure_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                severity = Severity.HIGH if pattern_type in ['eval_usage', 'function_constructor'] else Severity.MEDIUM
                
                issue_id = f"js_insecure_{pattern_type}_{line_num}"
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=severity,
                    category=SecurityCategory.INPUT_VALIDATION,
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Insecure pattern detected ({pattern_type}): {match[:50]}...",
                    rule_id=f"js_insecure_{pattern_type}",
                    confidence=0.9,
                    remediation_suggestions=self._get_insecure_pattern_remediation(pattern_type)
                ))
        
        return issues
    
    def _check_crypto_issues(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for cryptographic security issues."""
        issues = []
        
        for crypto_type, pattern in self.crypto_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"js_crypto_{crypto_type}_{line_num}"
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=Severity.MEDIUM,
                    category=SecurityCategory.INSECURE_CRYPTO,
                    file_path=file_path,
                    line_number=line_num,
                    description=f"Cryptographic issue ({crypto_type}): {match[:50]}...",
                    rule_id=f"js_crypto_{crypto_type}",
                    confidence=0.8,
                    remediation_suggestions=self._get_crypto_remediation(crypto_type)
                ))
        
        return issues
    
    def _check_npm_vulnerabilities(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for npm package vulnerabilities."""
        issues = []
        
        try:
            package_data = json.loads(content)
            dependencies = {}
            dependencies.update(package_data.get('dependencies', {}))
            dependencies.update(package_data.get('devDependencies', {}))
            
            # Check for known vulnerable packages (simplified example)
            vulnerable_packages = {
                'lodash': ['4.17.20', 'Prototype pollution vulnerability'],
                'moment': ['2.29.1', 'ReDoS vulnerability'],
                'handlebars': ['4.7.6', 'Prototype pollution vulnerability'],
                'yargs-parser': ['18.1.3', 'Prototype pollution vulnerability'],
            }
            
            for package_name, version in dependencies.items():
                if package_name in vulnerable_packages:
                    min_version, vuln_desc = vulnerable_packages[package_name]
                    issue_id = f"js_npm_vuln_{package_name}"
                    issues.append(self._create_security_issue(
                        issue_id=issue_id,
                        severity=Severity.MEDIUM,
                        category=SecurityCategory.DEPENDENCY_VULNERABILITY,
                        file_path=file_path,
                        line_number=1,
                        description=f"Potentially vulnerable npm package: {package_name}@{version} - {vuln_desc}",
                        rule_id=f"js_npm_vulnerable_package",
                        confidence=0.6,
                        remediation_suggestions=[
                            f"Update {package_name} to version {min_version} or later",
                            "Run 'npm audit' to check for vulnerabilities",
                            "Consider using 'npm audit fix' to automatically fix issues",
                            "Review package dependencies regularly"
                        ]
                    ))
        
        except json.JSONDecodeError:
            # Invalid JSON in package.json
            issues.append(self._create_security_issue(
                issue_id="js_invalid_package_json",
                severity=Severity.LOW,
                category=SecurityCategory.INPUT_VALIDATION,
                file_path=file_path,
                line_number=1,
                description="Invalid JSON in package.json file",
                rule_id="js_invalid_package_json",
                confidence=1.0,
                remediation_suggestions=["Fix JSON syntax errors in package.json"]
            ))
        
        return issues
    
    def _check_async_security_issues(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for async/await security issues."""
        issues = []
        
        # Check for unhandled promise rejections
        async_patterns = {
            'unhandled_promise': r'(?:await\s+)?[^.]+\.[^(]+\([^)]*\)(?!\s*\.catch)',
            'promise_without_catch': r'new\s+Promise\s*\([^)]*\)(?!\s*\.catch)',
            'async_without_try': r'async\s+function[^{]*{[^}]*await[^}]*}(?![^}]*catch)',
        }
        
        for pattern_type, pattern in async_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                if self._is_likely_unhandled_async(match):
                    issue_id = f"js_async_{pattern_type}_{line_num}"
                    issues.append(self._create_security_issue(
                        issue_id=issue_id,
                        severity=Severity.LOW,
                        category=SecurityCategory.INPUT_VALIDATION,
                        file_path=file_path,
                        line_number=line_num,
                        description=f"Potential unhandled async operation: {match[:50]}...",
                        rule_id=f"js_async_{pattern_type}",
                        confidence=0.5,
                        remediation_suggestions=[
                            "Add proper error handling with try/catch or .catch()",
                            "Handle promise rejections appropriately",
                            "Consider using async/await with try/catch blocks"
                        ]
                    ))
        
        return issues
    
    def _involves_user_input(self, code_snippet: str) -> bool:
        """Check if code snippet involves user input."""
        user_input_indicators = [
            'req.', 'request.', 'params.', 'query.', 'body.',
            'location.', 'window.', 'document.',
            'innerHTML', 'value', 'getAttribute',
            'prompt(', 'confirm(', 'alert('
        ]
        
        return any(indicator in code_snippet for indicator in user_input_indicators)
    
    def _is_dangerous_property_assignment(self, code_snippet: str) -> bool:
        """Check if property assignment could be dangerous."""
        dangerous_properties = [
            'constructor', 'prototype', '__proto__',
            'toString', 'valueOf', 'hasOwnProperty'
        ]
        
        return any(prop in code_snippet for prop in dangerous_properties)
    
    def _is_likely_unhandled_async(self, code_snippet: str) -> bool:
        """Check if async operation is likely unhandled."""
        # Simple heuristic - look for common async operations without error handling
        async_indicators = ['fetch(', 'axios.', 'request(', 'http.']
        error_handling = ['.catch', 'try', 'catch']
        
        has_async = any(indicator in code_snippet for indicator in async_indicators)
        has_error_handling = any(handler in code_snippet for handler in error_handling)
        
        return has_async and not has_error_handling
    
    def _get_insecure_pattern_remediation(self, pattern_type: str) -> List[str]:
        """Get remediation suggestions for insecure patterns."""
        remediation_map = {
            'eval_usage': [
                "Avoid using eval() - use JSON.parse() for JSON data",
                "Use Function constructor alternatives",
                "Validate and sanitize input before processing"
            ],
            'function_constructor': [
                "Avoid Function constructor with dynamic code",
                "Use predefined functions or safe alternatives",
                "Validate input thoroughly"
            ],
            'settimeout_string': [
                "Use function references instead of string code",
                "Pass functions directly to setTimeout",
                "Avoid dynamic code execution"
            ],
            'document_domain': [
                "Avoid setting document.domain",
                "Use postMessage for cross-origin communication",
                "Implement proper CORS headers"
            ],
            'postmessage_wildcard': [
                "Specify target origin instead of '*'",
                "Validate message origin and content",
                "Use specific origin URLs"
            ]
        }
        
        return remediation_map.get(pattern_type, ["Review and secure this pattern"])
    
    def _get_crypto_remediation(self, crypto_type: str) -> List[str]:
        """Get remediation suggestions for crypto issues."""
        remediation_map = {
            'weak_random': [
                "Use crypto.getRandomValues() for cryptographic randomness",
                "Use a cryptographically secure random number generator",
                "Avoid Math.random() for security-sensitive operations"
            ],
            'insecure_hash': [
                "Use SHA-256 or stronger hash functions",
                "Avoid MD5 and SHA-1 for security purposes",
                "Use bcrypt or scrypt for password hashing"
            ],
            'hardcoded_crypto_key': [
                "Move cryptographic keys to environment variables",
                "Use a key management service",
                "Generate keys dynamically when possible"
            ]
        }
        
        return remediation_map.get(crypto_type, ["Review cryptographic implementation"])


class TypeScriptAnalyzer(JavaScriptAnalyzer):
    """Security analyzer for TypeScript files (extends JavaScript analyzer)."""
    
    def __init__(self):
        """Initialize TypeScript analyzer."""
        super().__init__()
        self.language = ProgrammingLanguage.TYPESCRIPT
        
        # TypeScript-specific patterns
        self.ts_patterns = {
            'any_type_usage': r':\s*any\b',
            'type_assertion_unsafe': r'as\s+any\b',
            'non_null_assertion': r'!\s*\.',
            'unsafe_cast': r'<[^>]+>\s*\w+',
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze TypeScript file for security issues."""
        # Get JavaScript issues first
        issues = super().analyze_file(file_path, content)
        
        # Add TypeScript-specific issues
        issues.extend(self._check_typescript_specific_issues(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of security patterns this analyzer supports."""
        patterns = super().get_supported_patterns()
        patterns.extend([
            'Unsafe type assertions',
            'Any type usage',
            'Non-null assertion operator misuse',
            'Unsafe type casting'
        ])
        return patterns
    
    def _check_typescript_specific_issues(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for TypeScript-specific security issues."""
        issues = []
        
        for ts_type, pattern in self.ts_patterns.items():
            matches = self._find_pattern_matches(content, pattern)
            for line_num, match in matches:
                issue_id = f"ts_{ts_type}_{line_num}"
                issues.append(self._create_security_issue(
                    issue_id=issue_id,
                    severity=Severity.LOW,
                    category=SecurityCategory.INPUT_VALIDATION,
                    file_path=file_path,
                    line_number=line_num,
                    description=f"TypeScript type safety issue ({ts_type}): {match[:50]}...",
                    rule_id=f"ts_{ts_type}",
                    confidence=0.6,
                    remediation_suggestions=self._get_typescript_remediation(ts_type)
                ))
        
        return issues
    
    def _get_typescript_remediation(self, ts_type: str) -> List[str]:
        """Get remediation suggestions for TypeScript issues."""
        remediation_map = {
            'any_type_usage': [
                "Use specific types instead of 'any'",
                "Define proper interfaces or types",
                "Enable strict type checking"
            ],
            'type_assertion_unsafe': [
                "Avoid 'as any' type assertions",
                "Use type guards for safe type checking",
                "Define proper types instead of assertions"
            ],
            'non_null_assertion': [
                "Use optional chaining (?.) instead of non-null assertion",
                "Add proper null checks",
                "Ensure variable is definitely not null"
            ],
            'unsafe_cast': [
                "Use type guards for safe type checking",
                "Validate data before casting",
                "Use proper type definitions"
            ]
        }
        
        return remediation_map.get(ts_type, ["Review TypeScript type usage"])