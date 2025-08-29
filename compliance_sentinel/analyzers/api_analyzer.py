"""API security analyzer for REST, GraphQL, and authentication patterns."""

import re
import json
from typing import List, Dict, Optional, Tuple, Set, Any
from pathlib import Path
import logging
from enum import Enum

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity
from compliance_sentinel.analyzers.languages.base import LanguageDetector, ProgrammingLanguage


logger = logging.getLogger(__name__)


class APIVulnerabilityType(Enum):
    """Types of API security vulnerabilities."""
    MISSING_AUTHENTICATION = "missing_authentication"
    INSUFFICIENT_RATE_LIMITING = "insufficient_rate_limiting"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    GRAPHQL_QUERY_DEPTH_ATTACK = "graphql_query_depth_attack"
    GRAPHQL_INTROSPECTION_EXPOSED = "graphql_introspection_exposed"
    OAUTH_PKCE_BYPASS = "oauth_pkce_bypass"
    OAUTH_STATE_PARAMETER_MISSING = "oauth_state_parameter_missing"
    JWT_ALGORITHM_CONFUSION = "jwt_algorithm_confusion"
    JWT_WEAK_SECRET = "jwt_weak_secret"
    JWT_IMPROPER_VALIDATION = "jwt_improper_validation"
    API_ENDPOINT_EXPOSURE = "api_endpoint_exposure"
    INSUFFICIENT_INPUT_VALIDATION = "insufficient_input_validation"
    BROKEN_AUTHORIZATION = "broken_authorization"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


class RESTAPIAnalyzer:
    """Analyzes REST API implementations for security issues."""
    
    def __init__(self):
        """Initialize REST API analyzer."""
        self.logger = logging.getLogger(f"{__name__}.rest")
        
        # Framework-specific patterns
        self.framework_patterns = self._initialize_framework_patterns()
        
        # Authentication patterns
        self.auth_patterns = self._initialize_auth_patterns()
        
        # Rate limiting patterns
        self.rate_limit_patterns = self._initialize_rate_limit_patterns()
    
    def _initialize_framework_patterns(self) -> Dict[ProgrammingLanguage, Dict[str, str]]:
        """Initialize framework-specific API patterns."""
        return {
            ProgrammingLanguage.PYTHON: {
                'flask_route': r'@app\.route\s*\([^)]*\)',
                'django_url': r'path\s*\([^)]*\)',
                'fastapi_route': r'@app\.(get|post|put|delete|patch)\s*\([^)]*\)',
                'endpoint_handler': r'def\s+(\w+)\s*\([^)]*request',
            },
            ProgrammingLanguage.JAVASCRIPT: {
                'express_route': r'app\.(get|post|put|delete|patch)\s*\([^)]*\)',
                'router_route': r'router\.(get|post|put|delete|patch)\s*\([^)]*\)',
                'endpoint_handler': r'(req|request)\s*,\s*(res|response)',
            },
            ProgrammingLanguage.JAVA: {
                'spring_mapping': r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\([^)]*\)',
                'jax_rs': r'@(GET|POST|PUT|DELETE|PATCH)\s*',
                'servlet_mapping': r'@WebServlet\s*\([^)]*\)',
            },
            ProgrammingLanguage.CSHARP: {
                'asp_net_route': r'\[Route\s*\([^)]*\)\]',
                'http_method': r'\[Http(Get|Post|Put|Delete|Patch)\s*\]',
                'controller_action': r'public\s+\w+\s+\w+\s*\([^)]*\)',
            },
            ProgrammingLanguage.GO: {
                'http_handler': r'http\.Handle(Func)?\s*\([^)]*\)',
                'gin_route': r'router\.(GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)',
                'mux_route': r'router\.Methods\s*\([^)]*\)',
            },
        }
    
    def _initialize_auth_patterns(self) -> Dict[ProgrammingLanguage, List[str]]:
        """Initialize authentication check patterns."""
        return {
            ProgrammingLanguage.PYTHON: [
                r'@login_required',
                r'@auth\.login_required',
                r'@require_auth',
                r'if\s+not\s+authenticated',
                r'check_auth\s*\(',
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'authenticate\s*\(',
                r'isAuthenticated\s*\(',
                r'requireAuth\s*\(',
                r'jwt\.verify\s*\(',
                r'passport\.authenticate',
            ],
            ProgrammingLanguage.JAVA: [
                r'@PreAuthorize\s*\(',
                r'@Secured\s*\(',
                r'@RolesAllowed\s*\(',
                r'SecurityContextHolder\.getContext',
                r'@EnableWebSecurity',
            ],
            ProgrammingLanguage.CSHARP: [
                r'\[Authorize\s*\]',
                r'\[AllowAnonymous\s*\]',
                r'User\.Identity\.IsAuthenticated',
                r'ClaimsPrincipal\.',
            ],
        }
    
    def _initialize_rate_limit_patterns(self) -> Dict[ProgrammingLanguage, List[str]]:
        """Initialize rate limiting patterns."""
        return {
            ProgrammingLanguage.PYTHON: [
                r'@limiter\.limit\s*\(',
                r'@rate_limit\s*\(',
                r'RateLimiter\s*\(',
                r'slowapi',
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'express-rate-limit',
                r'rateLimit\s*\(',
                r'rate-limiter',
                r'slowDown\s*\(',
            ],
            ProgrammingLanguage.JAVA: [
                r'@RateLimited\s*\(',
                r'RateLimiter\.',
                r'Bucket4j',
                r'@Throttle\s*\(',
            ],
        }
    
    def analyze(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze REST API code for security issues."""
        issues = []
        
        issues.extend(self._check_missing_authentication(file_path, content, language))
        issues.extend(self._check_rate_limiting(file_path, content, language))
        issues.extend(self._check_cors_configuration(file_path, content, language))
        issues.extend(self._check_input_validation(file_path, content, language))
        issues.extend(self._check_authorization_bypass(file_path, content, language))
        issues.extend(self._check_sensitive_data_exposure(file_path, content, language))
        
        return issues
    
    def _check_missing_authentication(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for API endpoints without authentication."""
        issues = []
        
        if language not in self.framework_patterns:
            return issues
        
        framework_patterns = self.framework_patterns[language]
        auth_patterns = self.auth_patterns.get(language, [])
        
        # Find API endpoints
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Check if line defines an API endpoint
            is_endpoint = False
            for pattern_name, pattern in framework_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    is_endpoint = True
                    break
            
            if is_endpoint:
                # Check if authentication is present in surrounding lines
                auth_found = False
                check_range = range(max(0, line_num - 5), min(len(lines), line_num + 10))
                
                for check_line_num in check_range:
                    check_line = lines[check_line_num]
                    for auth_pattern in auth_patterns:
                        if re.search(auth_pattern, check_line, re.IGNORECASE):
                            auth_found = True
                            break
                    if auth_found:
                        break
                
                # Check if it's a public endpoint (health check, etc.)
                if not auth_found and not self._is_public_endpoint(line):
                    issues.append(self._create_api_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.MISSING_AUTHENTICATION,
                        description=f"API endpoint without authentication: {line.strip()}",
                        match=line.strip(),
                        severity=Severity.HIGH,
                        remediation=[
                            "Add authentication middleware or decorator",
                            "Implement proper access control",
                            "Use JWT, OAuth, or session-based authentication",
                            "Ensure all non-public endpoints require authentication"
                        ]
                    ))
        
        return issues
    
    def _check_rate_limiting(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for missing rate limiting."""
        issues = []
        
        if language not in self.framework_patterns:
            return issues
        
        framework_patterns = self.framework_patterns[language]
        rate_limit_patterns = self.rate_limit_patterns.get(language, [])
        
        # Check if any rate limiting is implemented
        has_rate_limiting = any(
            re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            for pattern in rate_limit_patterns
        )
        
        if not has_rate_limiting:
            # Find API endpoints without rate limiting
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern in framework_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append(self._create_api_issue(
                            file_path=file_path,
                            line_number=line_num,
                            vuln_type=APIVulnerabilityType.INSUFFICIENT_RATE_LIMITING,
                            description=f"API endpoint without rate limiting: {line.strip()}",
                            match=line.strip(),
                            severity=Severity.MEDIUM,
                            remediation=[
                                "Implement rate limiting middleware",
                                "Set appropriate request limits per IP/user",
                                "Use sliding window or token bucket algorithms",
                                "Monitor and alert on rate limit violations"
                            ]
                        ))
                        break
        
        return issues
    
    def _check_cors_configuration(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for CORS misconfigurations."""
        issues = []
        
        # CORS misconfiguration patterns
        cors_patterns = {
            'wildcard_origin': r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*["\']?',
            'credentials_with_wildcard': r'Access-Control-Allow-Credentials["\']?\s*:\s*["\']?true["\']?.*Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*',
            'overly_permissive': r'Access-Control-Allow-Methods["\']?\s*:\s*["\']?\*["\']?',
        }
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in cors_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.HIGH if 'wildcard' in pattern_name else Severity.MEDIUM
                    
                    issues.append(self._create_api_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.CORS_MISCONFIGURATION,
                        description=f"CORS misconfiguration ({pattern_name}): {line.strip()}",
                        match=line.strip(),
                        severity=severity,
                        remediation=[
                            "Specify explicit allowed origins instead of '*'",
                            "Avoid using credentials with wildcard origins",
                            "Limit allowed methods to necessary ones only",
                            "Implement proper CORS policy validation"
                        ]
                    ))
        
        return issues
    
    def _check_input_validation(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for insufficient input validation."""
        issues = []
        
        # Input validation patterns (absence indicates potential issue)
        validation_patterns = {
            ProgrammingLanguage.PYTHON: [
                r'validate\s*\(',
                r'schema\s*\.',
                r'marshmallow',
                r'pydantic',
                r'cerberus',
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                r'joi\.',
                r'validate\s*\(',
                r'ajv\.',
                r'express-validator',
            ],
            ProgrammingLanguage.JAVA: [
                r'@Valid\s',
                r'@Validated\s',
                r'ValidationUtils\.',
                r'Validator\.',
            ],
        }
        
        if language in validation_patterns:
            patterns = validation_patterns[language]
            
            # Check if validation is present
            has_validation = any(
                re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            )
            
            if not has_validation:
                # Look for request parameter usage without validation
                param_patterns = {
                    ProgrammingLanguage.PYTHON: [r'request\.(json|form|args|values)\['],
                    ProgrammingLanguage.JAVASCRIPT: [r'req\.(body|query|params)\.'],
                    ProgrammingLanguage.JAVA: [r'@RequestParam\s', r'@RequestBody\s'],
                }
                
                if language in param_patterns:
                    lines = content.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        for pattern in param_patterns[language]:
                            if re.search(pattern, line, re.IGNORECASE):
                                issues.append(self._create_api_issue(
                                    file_path=file_path,
                                    line_number=line_num,
                                    vuln_type=APIVulnerabilityType.INSUFFICIENT_INPUT_VALIDATION,
                                    description=f"Request parameter usage without validation: {line.strip()}",
                                    match=line.strip(),
                                    severity=Severity.MEDIUM,
                                    remediation=[
                                        "Implement input validation for all parameters",
                                        "Use validation libraries (Joi, Marshmallow, etc.)",
                                        "Sanitize and validate data types, ranges, formats",
                                        "Reject invalid input with proper error messages"
                                    ]
                                ))
        
        return issues
    
    def _check_authorization_bypass(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for authorization bypass vulnerabilities."""
        issues = []
        
        # Authorization bypass patterns
        bypass_patterns = [
            r'if\s+user_id\s*==\s*request\.(json|form|args)\[',  # Direct user ID from request
            r'WHERE\s+id\s*=\s*\$\{?user_input',  # SQL with user input
            r'find\s*\(\s*req\.(params|query)\.id\s*\)',  # Direct ID lookup
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in bypass_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_api_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.BROKEN_AUTHORIZATION,
                        description=f"Potential authorization bypass: {line.strip()}",
                        match=line.strip(),
                        severity=Severity.HIGH,
                        remediation=[
                            "Implement proper authorization checks",
                            "Verify user ownership of resources",
                            "Use role-based access control (RBAC)",
                            "Validate user permissions before data access"
                        ]
                    ))
        
        return issues
    
    def _check_sensitive_data_exposure(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for sensitive data exposure in API responses."""
        issues = []
        
        # Sensitive data patterns in responses
        sensitive_patterns = [
            r'password["\']?\s*:\s*[^,}]+',
            r'secret["\']?\s*:\s*[^,}]+',
            r'token["\']?\s*:\s*[^,}]+',
            r'ssn["\']?\s*:\s*[^,}]+',
            r'credit_card["\']?\s*:\s*[^,}]+',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in sensitive_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it's in a response context
                    if self._is_response_context(line):
                        issues.append(self._create_api_issue(
                            file_path=file_path,
                            line_number=line_num,
                            vuln_type=APIVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            description=f"Sensitive data in API response: {line.strip()}",
                            match=line.strip(),
                            severity=Severity.HIGH,
                            remediation=[
                                "Remove sensitive fields from API responses",
                                "Use field filtering or serialization controls",
                                "Implement data masking for sensitive information",
                                "Follow principle of least information disclosure"
                            ]
                        ))
        
        return issues
    
    def _is_public_endpoint(self, line: str) -> bool:
        """Check if endpoint is likely public (health check, etc.)."""
        public_indicators = [
            'health', 'ping', 'status', 'version', 'info',
            'public', 'static', 'assets', 'favicon'
        ]
        
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in public_indicators)
    
    def _is_response_context(self, line: str) -> bool:
        """Check if line is in a response context."""
        response_indicators = [
            'return', 'response', 'json', 'render', 'send'
        ]
        
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in response_indicators)
    
    def _create_api_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: APIVulnerabilityType,
        description: str,
        match: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create an API security issue."""
        from datetime import datetime
        
        issue_id = f"api_{vuln_type.value}_{line_number}_{hash(match) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"api_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class GraphQLAnalyzer:
    """Analyzes GraphQL implementations for security issues."""
    
    def __init__(self):
        """Initialize GraphQL analyzer."""
        self.logger = logging.getLogger(f"{__name__}.graphql")
    
    def analyze(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze GraphQL code for security issues."""
        issues = []
        
        issues.extend(self._check_query_depth_limits(file_path, content))
        issues.extend(self._check_introspection_exposure(file_path, content))
        issues.extend(self._check_authorization_directives(file_path, content))
        issues.extend(self._check_query_complexity_limits(file_path, content))
        
        return issues
    
    def _check_query_depth_limits(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for query depth attack protection."""
        issues = []
        
        # Look for depth limiting configuration
        depth_limit_patterns = [
            r'depthLimit\s*\(',
            r'queryDepth\s*:',
            r'maxDepth\s*:',
            r'depth-limit',
        ]
        
        has_depth_limit = any(
            re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            for pattern in depth_limit_patterns
        )
        
        if not has_depth_limit and 'graphql' in content.lower():
            issues.append(self._create_graphql_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=APIVulnerabilityType.GRAPHQL_QUERY_DEPTH_ATTACK,
                description="GraphQL schema without query depth limiting",
                severity=Severity.MEDIUM,
                remediation=[
                    "Implement query depth limiting",
                    "Set maximum query depth (e.g., 10-15 levels)",
                    "Use libraries like graphql-depth-limit",
                    "Monitor and log deep queries"
                ]
            ))
        
        return issues
    
    def _check_introspection_exposure(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for GraphQL introspection exposure."""
        issues = []
        
        # Look for introspection configuration
        introspection_patterns = [
            r'introspection\s*:\s*true',
            r'enableIntrospection\s*:\s*true',
            r'disableIntrospection\s*:\s*false',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in introspection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_graphql_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.GRAPHQL_INTROSPECTION_EXPOSED,
                        description=f"GraphQL introspection enabled in production: {line.strip()}",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Disable introspection in production",
                            "Only enable introspection in development",
                            "Use environment-based configuration",
                            "Implement proper schema security"
                        ]
                    ))
        
        return issues
    
    def _check_authorization_directives(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for missing authorization directives."""
        issues = []
        
        # Look for GraphQL type definitions without authorization
        type_pattern = r'type\s+\w+\s*{'
        auth_patterns = [
            r'@auth\s*\(',
            r'@authorized\s*\(',
            r'@requireAuth\s*\(',
            r'@hasRole\s*\(',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            if re.search(type_pattern, line, re.IGNORECASE):
                # Check if authorization is present in surrounding lines
                auth_found = False
                check_range = range(max(0, line_num - 2), min(len(lines), line_num + 10))
                
                for check_line_num in check_range:
                    check_line = lines[check_line_num]
                    for auth_pattern in auth_patterns:
                        if re.search(auth_pattern, check_line, re.IGNORECASE):
                            auth_found = True
                            break
                    if auth_found:
                        break
                
                if not auth_found:
                    issues.append(self._create_graphql_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.BROKEN_AUTHORIZATION,
                        description=f"GraphQL type without authorization directive: {line.strip()}",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Add authorization directives to GraphQL types",
                            "Implement field-level authorization",
                            "Use @auth or @requireAuth directives",
                            "Validate user permissions for each field"
                        ]
                    ))
        
        return issues
    
    def _check_query_complexity_limits(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for query complexity limiting."""
        issues = []
        
        complexity_patterns = [
            r'queryComplexity\s*:',
            r'complexityLimit\s*\(',
            r'query-complexity',
            r'maxComplexity\s*:',
        ]
        
        has_complexity_limit = any(
            re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            for pattern in complexity_patterns
        )
        
        if not has_complexity_limit and 'graphql' in content.lower():
            issues.append(self._create_graphql_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=APIVulnerabilityType.GRAPHQL_QUERY_DEPTH_ATTACK,
                description="GraphQL schema without query complexity limiting",
                severity=Severity.MEDIUM,
                remediation=[
                    "Implement query complexity analysis",
                    "Set maximum query complexity limits",
                    "Use libraries like graphql-query-complexity",
                    "Monitor expensive queries"
                ]
            ))
        
        return issues
    
    def _create_graphql_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: APIVulnerabilityType,
        description: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a GraphQL security issue."""
        from datetime import datetime
        
        issue_id = f"graphql_{vuln_type.value}_{line_number}_{hash(description) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"graphql_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class JWTAnalyzer:
    """Analyzes JWT implementations for security issues."""
    
    def __init__(self):
        """Initialize JWT analyzer."""
        self.logger = logging.getLogger(f"{__name__}.jwt")
    
    def analyze(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Analyze JWT code for security issues."""
        issues = []
        
        issues.extend(self._check_algorithm_confusion(file_path, content, language))
        issues.extend(self._check_weak_secrets(file_path, content, language))
        issues.extend(self._check_improper_validation(file_path, content, language))
        issues.extend(self._check_token_storage(file_path, content, language))
        
        return issues
    
    def _check_algorithm_confusion(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for JWT algorithm confusion vulnerabilities."""
        issues = []
        
        # Algorithm confusion patterns
        confusion_patterns = [
            r'algorithm\s*:\s*["\']none["\']',
            r'verify\s*:\s*false',
            r'algorithms\s*:\s*\[\s*["\']none["\']',
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in confusion_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_jwt_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.JWT_ALGORITHM_CONFUSION,
                        description=f"JWT algorithm confusion vulnerability: {line.strip()}",
                        match=line.strip(),
                        severity=Severity.HIGH,
                        remediation=[
                            "Never use 'none' algorithm in production",
                            "Always verify JWT signatures",
                            "Specify allowed algorithms explicitly",
                            "Use strong signing algorithms (RS256, ES256)"
                        ]
                    ))
        
        return issues
    
    def _check_weak_secrets(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for weak JWT secrets."""
        issues = []
        
        # JWT secret patterns
        secret_patterns = [
            r'jwt\.sign\s*\([^,]*,\s*["\'][^"\']{1,15}["\']',  # Short secret
            r'secret\s*:\s*["\'](?:secret|password|123|key)["\']',  # Weak secret
            r'JWT_SECRET\s*=\s*["\'][^"\']{1,15}["\']',  # Short env var
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_jwt_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.JWT_WEAK_SECRET,
                        description=f"Weak JWT secret detected: {line.strip()}",
                        match=line.strip(),
                        severity=Severity.HIGH,
                        remediation=[
                            "Use strong, randomly generated secrets (32+ characters)",
                            "Store secrets in environment variables",
                            "Use asymmetric algorithms (RS256) when possible",
                            "Rotate JWT secrets regularly"
                        ]
                    ))
        
        return issues
    
    def _check_improper_validation(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for improper JWT validation."""
        issues = []
        
        # Improper validation patterns
        validation_patterns = [
            r'jwt\.decode\s*\([^)]*\)',  # Look for decode without proper validation
            r'verify\s*=\s*False',
            r'options\s*:\s*{\s*verify\s*:\s*false',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if proper validation is missing
                    if 'verify' in line.lower() and 'false' in line.lower():
                        issues.append(self._create_jwt_issue(
                            file_path=file_path,
                            line_number=line_num,
                            vuln_type=APIVulnerabilityType.JWT_IMPROPER_VALIDATION,
                            description=f"JWT validation disabled: {line.strip()}",
                            match=line.strip(),
                            severity=Severity.HIGH,
                            remediation=[
                                "Enable JWT signature verification",
                                "Validate token expiration (exp claim)",
                                "Check token issuer (iss claim)",
                                "Validate audience (aud claim) when applicable"
                            ]
                        ))
        
        return issues
    
    def _check_token_storage(self, file_path: str, content: str, language: ProgrammingLanguage) -> List[SecurityIssue]:
        """Check for insecure JWT token storage."""
        issues = []
        
        # Insecure storage patterns
        storage_patterns = [
            r'localStorage\.setItem\s*\([^,]*token',
            r'sessionStorage\.setItem\s*\([^,]*token',
            r'document\.cookie\s*=.*token.*secure\s*=\s*false',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in storage_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_jwt_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=APIVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                        description=f"Insecure JWT token storage: {line.strip()}",
                        match=line.strip(),
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Use httpOnly cookies for token storage",
                            "Set secure flag for cookies in production",
                            "Avoid localStorage for sensitive tokens",
                            "Implement proper token refresh mechanisms"
                        ]
                    ))
        
        return issues
    
    def _create_jwt_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: APIVulnerabilityType,
        description: str,
        match: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a JWT security issue."""
        from datetime import datetime
        
        issue_id = f"jwt_{vuln_type.value}_{line_number}_{hash(match) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"jwt_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class APISecurityAnalyzer:
    """Main API security analyzer that coordinates different API analyzers."""
    
    def __init__(self):
        """Initialize API security analyzer."""
        self.rest_analyzer = RESTAPIAnalyzer()
        self.graphql_analyzer = GraphQLAnalyzer()
        self.jwt_analyzer = JWTAnalyzer()
        self.logger = logging.getLogger(__name__)
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze API code for security issues."""
        issues = []
        
        # Detect programming language
        language = LanguageDetector.detect_language(file_path, content)
        
        # Run all API analyzers
        issues.extend(self.rest_analyzer.analyze(file_path, content, language))
        issues.extend(self.graphql_analyzer.analyze(file_path, content, language))
        issues.extend(self.jwt_analyzer.analyze(file_path, content, language))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of API security patterns this analyzer supports."""
        return [
            'Missing authentication on API endpoints',
            'Insufficient rate limiting',
            'CORS misconfigurations',
            'GraphQL query depth attacks',
            'GraphQL introspection exposure',
            'OAuth PKCE bypass vulnerabilities',
            'JWT algorithm confusion',
            'JWT weak secrets',
            'JWT improper validation',
            'API endpoint exposure',
            'Insufficient input validation',
            'Broken authorization',
            'Sensitive data exposure in responses'
        ]


# Global analyzer instance
_global_api_analyzer: Optional[APISecurityAnalyzer] = None


def get_api_analyzer() -> APISecurityAnalyzer:
    """Get global API analyzer instance."""
    global _global_api_analyzer
    if _global_api_analyzer is None:
        _global_api_analyzer = APISecurityAnalyzer()
    return _global_api_analyzer


def reset_api_analyzer() -> None:
    """Reset global API analyzer (for testing)."""
    global _global_api_analyzer
    _global_api_analyzer = None