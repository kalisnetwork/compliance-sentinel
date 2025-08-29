"""Policy management and enforcement engine for the Compliance Sentinel system."""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging

from compliance_sentinel.core.interfaces import (
    PolicyManager as IPolicyManager,
    PolicyRule,
    PolicyCategory,
    Severity,
    SecurityIssue,
    SecurityCategory
)
from compliance_sentinel.core.validation import SecurityValidator, ValidationError
from compliance_sentinel.utils.error_handler import get_global_error_handler, safe_execute
from compliance_sentinel.utils.cache import get_global_cache


logger = logging.getLogger(__name__)


@dataclass
class PolicyMetadata:
    """Metadata for policy rules."""
    created_at: datetime
    updated_at: datetime
    version: str
    author: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)


@dataclass
class PolicyRuleExtended(PolicyRule):
    """Extended policy rule with additional metadata and validation."""
    metadata: PolicyMetadata = field(default_factory=lambda: PolicyMetadata(
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        version="1.0"
    ))
    enabled: bool = True
    test_cases: List[Dict[str, Any]] = field(default_factory=list)
    false_positive_patterns: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate extended policy rule."""
        # Validate base PolicyRule
        errors = SecurityValidator.validate_policy_rule(self)
        if errors:
            raise ValidationError(f"Policy rule validation failed: {'; '.join(errors)}")
        
        # Additional validation for extended fields
        if self.metadata.version and not re.match(r'^\d+\.\d+(\.\d+)?$', self.metadata.version):
            raise ValidationError("Policy version must follow semantic versioning (x.y or x.y.z)")


class PolicyParser:
    """Parses security policies from markdown and YAML formats."""
    
    # Regex patterns for parsing markdown policy documents
    RULE_HEADER_PATTERN = r'^### Rule (\d+):\s*(.+)$'
    POLICY_SECTION_PATTERN = r'^\*\*Policy\*\*:\s*(.+)$'
    REQUIREMENTS_SECTION_PATTERN = r'^\*\*Requirements\*\*:$'
    CODE_PATTERNS_SECTION_PATTERN = r'^\*\*Code Patterns to Detect\*\*:$'
    
    @classmethod
    def parse_markdown_policy(cls, content: str, file_path: str) -> List[PolicyRuleExtended]:
        """Parse policy rules from markdown content."""
        rules = []
        lines = content.split('\n')
        current_rule = None
        current_section = None
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('<!--'):
                continue
            
            # Check for rule header
            rule_match = re.match(cls.RULE_HEADER_PATTERN, line)
            if rule_match:
                # Save previous rule if exists
                if current_rule:
                    rules.append(current_rule)
                
                # Start new rule
                rule_number = rule_match.group(1)
                rule_name = rule_match.group(2)
                
                current_rule = {
                    'id': f"POLICY_RULE_{rule_number}",
                    'name': rule_name,
                    'description': '',
                    'category': PolicyCategory.CODE_PATTERNS,
                    'severity': Severity.MEDIUM,
                    'pattern': '',
                    'remediation_template': '',
                    'applicable_file_types': ['.py', '.js', '.ts'],
                    'requirements': [],
                    'code_patterns': []
                }
                current_section = 'header'
                continue
            
            if not current_rule:
                continue
            
            # Check for section headers
            if re.match(cls.POLICY_SECTION_PATTERN, line):
                policy_match = re.match(cls.POLICY_SECTION_PATTERN, line)
                current_rule['description'] = policy_match.group(1)
                current_section = 'policy'
                continue
            
            if re.match(cls.REQUIREMENTS_SECTION_PATTERN, line):
                current_section = 'requirements'
                continue
            
            if re.match(cls.CODE_PATTERNS_SECTION_PATTERN, line):
                current_section = 'code_patterns'
                continue
            
            # Parse content based on current section
            if current_section == 'requirements' and line.startswith('-'):
                requirement = line[1:].strip()
                current_rule['requirements'].append(requirement)
            
            elif current_section == 'code_patterns' and line.startswith('-'):
                pattern = line[1:].strip()
                current_rule['code_patterns'].append(pattern)
        
        # Add the last rule
        if current_rule:
            rules.append(current_rule)
        
        # Convert to PolicyRuleExtended objects
        policy_rules = []
        for rule_data in rules:
            try:
                # Determine category based on rule name
                category = cls._determine_category(rule_data['name'])
                
                # Determine severity based on keywords
                severity = cls._determine_severity(rule_data['name'], rule_data['description'])
                
                # Create regex pattern from code patterns
                pattern = cls._create_regex_pattern(rule_data['code_patterns'])
                
                # Create remediation template
                remediation = cls._create_remediation_template(rule_data['requirements'])
                
                policy_rule = PolicyRuleExtended(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    description=rule_data['description'],
                    category=category,
                    severity=severity,
                    pattern=pattern,
                    remediation_template=remediation,
                    applicable_file_types=rule_data['applicable_file_types'],
                    metadata=PolicyMetadata(
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow(),
                        version="1.0",
                        tags=cls._extract_tags(rule_data['name'])
                    )
                )
                
                policy_rules.append(policy_rule)
                
            except Exception as e:
                logger.error(f"Error parsing policy rule in {file_path}: {e}")
                get_global_error_handler().handle_analysis_error(e, f"policy_parsing:{file_path}")
        
        return policy_rules
    
    @classmethod
    def _determine_category(cls, rule_name: str) -> PolicyCategory:
        """Determine policy category from rule name."""
        name_lower = rule_name.lower()
        
        if any(keyword in name_lower for keyword in ['api', 'endpoint', 'authentication', 'authorization']):
            return PolicyCategory.API_SECURITY
        elif any(keyword in name_lower for keyword in ['credential', 'secret', 'password', 'key']):
            return PolicyCategory.CREDENTIAL_MANAGEMENT
        elif any(keyword in name_lower for keyword in ['dependency', 'package', 'library', 'vulnerability']):
            return PolicyCategory.DEPENDENCY_VALIDATION
        else:
            return PolicyCategory.CODE_PATTERNS
    
    @classmethod
    def _determine_severity(cls, rule_name: str, description: str) -> Severity:
        """Determine severity from rule name and description."""
        text = f"{rule_name} {description}".lower()
        
        if any(keyword in text for keyword in ['critical', 'severe', 'high risk', 'security breach']):
            return Severity.CRITICAL
        elif any(keyword in text for keyword in ['high', 'important', 'significant']):
            return Severity.HIGH
        elif any(keyword in text for keyword in ['medium', 'moderate', 'warning']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    @classmethod
    def _create_regex_pattern(cls, code_patterns: List[str]) -> str:
        """Create a combined regex pattern from code patterns."""
        if not code_patterns:
            return r'(?i)security_violation'  # Default pattern
        
        # Convert natural language patterns to regex
        regex_patterns = []
        for pattern in code_patterns:
            pattern_lower = pattern.lower()
            
            if 'hardcoded' in pattern_lower and ('password' in pattern_lower or 'key' in pattern_lower):
                regex_patterns.append(r'(?i)(password|passwd|pwd|key|secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']')
            elif 'sql injection' in pattern_lower:
                regex_patterns.append(r'(?i)execute\s*\(\s*["\'][^"\']*%[sd][^"\']*["\']')
            elif 'xss' in pattern_lower or 'cross-site scripting' in pattern_lower:
                regex_patterns.append(r'(?i)innerHTML\s*[=:]\s*[^;]*\+')
            elif 'weak' in pattern_lower and 'crypto' in pattern_lower:
                regex_patterns.append(r'(?i)\b(md5|sha1|des|rc4)\b')
            elif 'ssl' in pattern_lower and 'verify' in pattern_lower:
                regex_patterns.append(r'(?i)ssl[_-]?verify\s*[=:]\s*(false|0|none)')
            else:
                # Generic pattern for other cases
                keywords = re.findall(r'\b\w+\b', pattern_lower)
                if keywords:
                    regex_patterns.append(f"(?i){'|'.join(re.escape(kw) for kw in keywords[:3])}")
        
        return '|'.join(regex_patterns) if regex_patterns else r'(?i)security_violation'
    
    @classmethod
    def _create_remediation_template(cls, requirements: List[str]) -> str:
        """Create remediation template from requirements."""
        if not requirements:
            return "Review and fix the security issue according to best practices."
        
        # Convert requirements to actionable remediation steps
        remediation_steps = []
        for req in requirements[:3]:  # Limit to top 3 requirements
            if req.strip():
                # Clean up the requirement text
                clean_req = re.sub(r'^[-*•]\s*', '', req.strip())
                if not clean_req.endswith('.'):
                    clean_req += '.'
                remediation_steps.append(clean_req)
        
        return ' '.join(remediation_steps)
    
    @classmethod
    def _extract_tags(cls, rule_name: str) -> List[str]:
        """Extract tags from rule name."""
        tags = []
        name_lower = rule_name.lower()
        
        tag_keywords = {
            'security': ['security', 'secure'],
            'authentication': ['auth', 'login', 'credential'],
            'encryption': ['crypto', 'encrypt', 'hash'],
            'injection': ['injection', 'sql', 'xss'],
            'api': ['api', 'endpoint', 'rest'],
            'dependency': ['dependency', 'package', 'library']
        }
        
        for tag, keywords in tag_keywords.items():
            if any(keyword in name_lower for keyword in keywords):
                tags.append(tag)
        
        return tags


class PolicyEngine(IPolicyManager):
    """Main policy management engine."""
    
    def __init__(self, policy_file_path: Optional[str] = None):
        """Initialize policy engine.
        
        Args:
            policy_file_path: Path to the security policy file (defaults to .kiro/steering/security.md)
        """
        self.policy_file_path = policy_file_path or Path.cwd() / ".kiro" / "steering" / "security_simple.md"
        self.policies: Dict[str, PolicyRuleExtended] = {}
        self.policy_cache_key = "policy_rules_cache"
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        
        # Load policies on initialization
        self.load_policies()
    
    async def initialize(self) -> None:
        """Initialize the policy engine asynchronously."""
        # Reload policies to ensure they're current
        self.load_policies()
        logger.info("Policy engine initialized")
    
    def load_policies(self) -> Dict[str, PolicyRule]:
        """Load all security policies from configuration."""
        try:
            # Check cache first
            cached_policies = self.cache.get(self.policy_cache_key)
            if cached_policies and self._is_cache_valid():
                self.policies = cached_policies
                logger.info(f"Loaded {len(self.policies)} policies from cache")
                return {k: v for k, v in self.policies.items()}
            
            # Load from file
            if not Path(self.policy_file_path).exists():
                logger.warning(f"Policy file not found: {self.policy_file_path}")
                self._create_default_policies()
                return {k: v for k, v in self.policies.items()}
            
            with open(self.policy_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse policies
            parsed_policies = PolicyParser.parse_markdown_policy(content, str(self.policy_file_path))
            
            # Convert to dictionary
            self.policies = {policy.id: policy for policy in parsed_policies}
            
            # Cache the policies
            self.cache.set(self.policy_cache_key, self.policies, ttl=3600)  # Cache for 1 hour
            
            logger.info(f"Loaded {len(self.policies)} policies from {self.policy_file_path}")
            return {k: v for k, v in self.policies.items()}
            
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
            self.error_handler.handle_analysis_error(e, "policy_loading")
            self._create_default_policies()
            return {k: v for k, v in self.policies.items()}
    
    def validate_policy(self, policy: PolicyRule) -> bool:
        """Validate a policy rule for correctness."""
        try:
            errors = SecurityValidator.validate_policy_rule(policy)
            if errors:
                logger.warning(f"Policy validation errors for {policy.id}: {'; '.join(errors)}")
                return False
            
            # Test the regex pattern
            try:
                re.compile(policy.pattern)
            except re.error as e:
                logger.error(f"Invalid regex pattern in policy {policy.id}: {e}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating policy {policy.id}: {e}")
            return False
    
    def get_applicable_rules(self, file_type: str, context: str = "") -> List[PolicyRule]:
        """Get rules applicable to a specific file type and context."""
        applicable_rules = []
        
        for policy in self.policies.values():
            if not policy.enabled:
                continue
            
            # Check file type compatibility
            if file_type and policy.applicable_file_types:
                if not any(file_type.endswith(ext) for ext in policy.applicable_file_types):
                    continue
            
            # Check context relevance (optional filtering)
            if context:
                context_lower = context.lower()
                policy_text = f"{policy.name} {policy.description}".lower()
                
                # Simple relevance scoring
                relevance_keywords = context_lower.split()
                matches = sum(1 for keyword in relevance_keywords if keyword in policy_text)
                
                # Only include if somewhat relevant
                if matches == 0 and len(relevance_keywords) > 2:
                    continue
            
            applicable_rules.append(policy)
        
        # Sort by severity (critical first) and then by name
        applicable_rules.sort(key=lambda p: (p.severity.value, p.name))
        
        return applicable_rules
    
    def apply_policies_to_content(self, content: str, file_path: str, file_type: str) -> List[SecurityIssue]:
        """Apply all applicable policies to content and return security issues."""
        issues = []
        applicable_rules = self.get_applicable_rules(file_type)
        
        for policy in applicable_rules:
            try:
                policy_issues = self._apply_single_policy(policy, content, file_path)
                issues.extend(policy_issues)
            except Exception as e:
                logger.error(f"Error applying policy {policy.id} to {file_path}: {e}")
                self.error_handler.handle_analysis_error(e, f"policy_application:{policy.id}")
        
        return issues
    
    async def apply_policies_to_file(self, file_path: str, existing_issues: List[SecurityIssue] = None) -> List[SecurityIssue]:
        """Apply policies to a specific file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Determine file type from extension
            file_ext = Path(file_path).suffix
            policy_issues = self.apply_policies_to_content(content, file_path, file_ext)
            
            # Combine with existing issues if provided
            if existing_issues:
                all_issues = existing_issues + policy_issues
            else:
                all_issues = policy_issues
            
            return all_issues
            
        except Exception as e:
            logger.error(f"Error applying policies to file {file_path}: {e}")
            self.error_handler.handle_analysis_error(e, f"policy_file_application:{file_path}")
            return existing_issues or []
    
    async def apply_global_policies(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Apply global policies that work across all issues."""
        try:
            # For now, just return the issues as-is
            # In the future, this could apply cross-file policies, 
            # severity adjustments, or global filtering rules
            return issues
            
        except Exception as e:
            logger.error(f"Error applying global policies: {e}")
            self.error_handler.handle_analysis_error(e, "global_policy_application")
            return issues
    
    def _apply_single_policy(self, policy: PolicyRuleExtended, content: str, file_path: str) -> List[SecurityIssue]:
        """Apply a single policy to content."""
        issues = []
        lines = content.split('\n')
        
        try:
            pattern = re.compile(policy.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.error(f"Invalid regex in policy {policy.id}: {e}")
            return issues
        
        for line_num, line in enumerate(lines, 1):
            matches = pattern.finditer(line)
            
            for match in matches:
                # Check for false positives
                if self._is_false_positive(line, policy.false_positive_patterns):
                    continue
                
                # Create security issue
                issue = SecurityIssue(
                    id=f"{policy.id}_{line_num}_{match.start()}",
                    severity=policy.severity,
                    category=self._map_policy_category_to_security_category(policy.category),
                    file_path=file_path,
                    line_number=line_num,
                    description=f"{policy.name}: {policy.description}",
                    rule_id=policy.id,
                    confidence=self._calculate_confidence(match, line, policy),
                    remediation_suggestions=self._generate_remediation_suggestions(policy),
                    created_at=datetime.utcnow()
                )
                
                issues.append(issue)
        
        return issues
    
    def _is_false_positive(self, line: str, false_positive_patterns: List[str]) -> bool:
        """Check if a match is a false positive."""
        for fp_pattern in false_positive_patterns:
            try:
                if re.search(fp_pattern, line, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False
    
    def _calculate_confidence(self, match: re.Match, line: str, policy: PolicyRuleExtended) -> float:
        """Calculate confidence score for a policy match."""
        base_confidence = 0.7
        
        # Increase confidence for exact keyword matches
        if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
            base_confidence += 0.2
        
        # Decrease confidence for comments
        if line.strip().startswith('#') or line.strip().startswith('//'):
            base_confidence -= 0.3
        
        # Adjust based on match length
        match_length = len(match.group())
        if match_length > 20:
            base_confidence += 0.1
        elif match_length < 5:
            base_confidence -= 0.1
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation_suggestions(self, policy: PolicyRuleExtended) -> List[str]:
        """Generate remediation suggestions for a policy violation."""
        suggestions = []
        
        # Use policy's remediation template
        if policy.remediation_template:
            suggestions.append(policy.remediation_template)
        
        # Add category-specific suggestions
        category_suggestions = {
            PolicyCategory.CREDENTIAL_MANAGEMENT: [
                "Use environment variables for sensitive data",
                "Implement secure secret management system",
                "Never commit secrets to version control"
            ],
            PolicyCategory.API_SECURITY: [
                "Implement proper authentication mechanisms",
                "Add rate limiting to prevent abuse",
                "Validate all input parameters"
            ],
            PolicyCategory.DEPENDENCY_VALIDATION: [
                "Update to latest secure version",
                "Review dependency security advisories",
                "Consider alternative packages if needed"
            ]
        }
        
        if policy.category in category_suggestions:
            suggestions.extend(category_suggestions[policy.category][:2])  # Add top 2
        
        return suggestions[:3]  # Limit to 3 suggestions
    
    def _map_policy_category_to_security_category(self, policy_category: PolicyCategory) -> SecurityCategory:
        """Map policy category to security category."""
        mapping = {
            PolicyCategory.CREDENTIAL_MANAGEMENT: SecurityCategory.HARDCODED_SECRETS,
            PolicyCategory.API_SECURITY: SecurityCategory.AUTHENTICATION,
            PolicyCategory.DEPENDENCY_VALIDATION: SecurityCategory.DEPENDENCY_VULNERABILITY,
            PolicyCategory.CODE_PATTERNS: SecurityCategory.INPUT_VALIDATION
        }
        return mapping.get(policy_category, SecurityCategory.INPUT_VALIDATION)
    
    def _is_cache_valid(self) -> bool:
        """Check if the policy cache is still valid."""
        try:
            if not Path(self.policy_file_path).exists():
                return False
            
            file_mtime = Path(self.policy_file_path).stat().st_mtime
            cache_time = getattr(self, '_last_cache_time', 0)
            
            return file_mtime <= cache_time
        except Exception:
            return False
    
    def _create_default_policies(self) -> None:
        """Create default policies if no policy file exists."""
        default_policies = [
            PolicyRuleExtended(
                id="DEFAULT_HARDCODED_SECRETS",
                name="Hardcoded Secrets Detection",
                description="Detect hardcoded passwords, API keys, and other secrets",
                category=PolicyCategory.CREDENTIAL_MANAGEMENT,
                severity=Severity.HIGH,
                pattern=r'(?i)(password|passwd|pwd|api[_-]?key|secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
                remediation_template="Move secrets to environment variables or secure secret management system",
                applicable_file_types=['.py', '.js', '.ts', '.java', '.go'],
                metadata=PolicyMetadata(
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    version="1.0",
                    tags=["security", "credentials"]
                )
            ),
            PolicyRuleExtended(
                id="DEFAULT_WEAK_CRYPTO",
                name="Weak Cryptographic Practices",
                description="Detect use of weak cryptographic algorithms",
                category=PolicyCategory.CODE_PATTERNS,
                severity=Severity.HIGH,
                pattern=r'(?i)\b(md5|sha1|des|rc4)\b|ssl[_-]?verify\s*[=:]\s*(false|0)',
                remediation_template="Use strong encryption algorithms (AES-256, SHA-256+) and enable SSL verification",
                applicable_file_types=['.py', '.js', '.ts', '.java', '.go'],
                metadata=PolicyMetadata(
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    version="1.0",
                    tags=["security", "encryption"]
                )
            )
        ]
        
        self.policies = {policy.id: policy for policy in default_policies}
        logger.info(f"Created {len(default_policies)} default policies")
    
    def get_policy_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded policies."""
        if not self.policies:
            return {"total_policies": 0}
        
        stats = {
            "total_policies": len(self.policies),
            "enabled_policies": sum(1 for p in self.policies.values() if p.enabled),
            "by_category": {},
            "by_severity": {},
            "file_types_covered": set(),
            "last_updated": max(p.metadata.updated_at for p in self.policies.values()).isoformat()
        }
        
        for policy in self.policies.values():
            # Count by category
            category = policy.category.value
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # Count by severity
            severity = policy.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Collect file types
            stats["file_types_covered"].update(policy.applicable_file_types)
        
        stats["file_types_covered"] = list(stats["file_types_covered"])
        
        return stats
    
    def reload_policies(self) -> bool:
        """Reload policies from file and clear cache."""
        try:
            # Clear cache
            self.cache.invalidate(self.policy_cache_key)
            
            # Reload policies
            self.load_policies()
            
            logger.info("Policies reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error reloading policies: {e}")
            self.error_handler.handle_analysis_error(e, "policy_reload")
            return False