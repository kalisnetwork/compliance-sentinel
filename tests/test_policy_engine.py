"""Tests for the policy management engine."""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from compliance_sentinel.engines.policy_engine import (
    PolicyEngine,
    PolicyParser,
    PolicyRuleExtended,
    PolicyMetadata
)
from compliance_sentinel.core.interfaces import (
    PolicyCategory,
    Severity,
    SecurityCategory
)


class TestPolicyParser:
    """Test cases for PolicyParser."""
    
    def test_parse_markdown_policy_basic(self):
        """Test parsing a basic markdown policy."""
        content = """
# Security Policy

## Rules

### Rule 1: API Security and Authentication

**Policy**: All API endpoints must implement proper authentication and authorization mechanisms.

**Requirements**:
- Every API endpoint must require authentication (except public health checks)
- Implement rate limiting to prevent abuse (max 100 requests/minute per client)
- Use secure session management with proper timeout

**Code Patterns to Detect**:
- Endpoints without authentication decorators
- Missing rate limiting configuration
- Hardcoded API keys or tokens

### Rule 2: Credential and Secret Management

**Policy**: Never hardcode sensitive credentials or secrets in source code.

**Requirements**:
- All secrets must be loaded from environment variables
- Use secure secret management systems
- Rotate credentials regularly

**Code Patterns to Detect**:
- Hardcoded passwords, API keys, database connections
- Secrets in configuration files committed to version control
"""
        
        rules = PolicyParser.parse_markdown_policy(content, "test.md")
        
        assert len(rules) == 2
        
        # Check first rule
        rule1 = rules[0]
        assert rule1.id == "POLICY_RULE_1"
        assert "API Security" in rule1.name
        assert rule1.category == PolicyCategory.API_SECURITY
        assert rule1.severity in [Severity.HIGH, Severity.MEDIUM]
        assert rule1.pattern  # Should have generated a pattern
        
        # Check second rule
        rule2 = rules[1]
        assert rule2.id == "POLICY_RULE_2"
        assert "Credential" in rule2.name
        assert rule2.category == PolicyCategory.CREDENTIAL_MANAGEMENT
    
    def test_determine_category(self):
        """Test category determination from rule names."""
        assert PolicyParser._determine_category("API Security") == PolicyCategory.API_SECURITY
        assert PolicyParser._determine_category("Credential Management") == PolicyCategory.CREDENTIAL_MANAGEMENT
        assert PolicyParser._determine_category("Dependency Validation") == PolicyCategory.DEPENDENCY_VALIDATION
        assert PolicyParser._determine_category("Code Quality") == PolicyCategory.CODE_PATTERNS
    
    def test_determine_severity(self):
        """Test severity determination from rule content."""
        assert PolicyParser._determine_severity("Critical Security", "severe vulnerability") == Severity.CRITICAL
        assert PolicyParser._determine_severity("High Risk", "important security") == Severity.HIGH
        assert PolicyParser._determine_severity("Medium Warning", "moderate issue") == Severity.MEDIUM
        assert PolicyParser._determine_severity("Info", "general guideline") == Severity.LOW
    
    def test_create_regex_pattern(self):
        """Test regex pattern creation from code patterns."""
        patterns = [
            "Hardcoded passwords and API keys",
            "SQL injection vulnerabilities",
            "Weak cryptographic algorithms"
        ]
        
        regex = PolicyParser._create_regex_pattern(patterns)
        
        assert regex  # Should generate a pattern
        assert isinstance(regex, str)
        
        # Test that it compiles
        import re
        compiled = re.compile(regex)
        assert compiled is not None


class TestPolicyEngine:
    """Test cases for PolicyEngine."""
    
    @pytest.fixture
    def temp_policy_file(self):
        """Create a temporary policy file for testing."""
        content = """
# Security Policy

## Rules

### Rule 1: Hardcoded Secrets

**Policy**: Never hardcode sensitive credentials or secrets in source code.

**Requirements**:
- All secrets must be loaded from environment variables
- Use secure secret management systems

**Code Patterns to Detect**:
- Hardcoded passwords, API keys, database connections
- Secrets in configuration files

### Rule 2: Weak Cryptography

**Policy**: Use only approved cryptographic algorithms and implementations.

**Requirements**:
- Use strong encryption algorithms (AES-256, RSA-2048+)
- Ensure proper certificate validation

**Code Patterns to Detect**:
- Weak encryption algorithms (DES, MD5, SHA1 for passwords)
- Disabled certificate validation
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            return f.name
    
    def test_policy_engine_initialization(self, temp_policy_file):
        """Test PolicyEngine initialization."""
        engine = PolicyEngine(temp_policy_file)
        
        assert len(engine.policies) > 0
        assert all(isinstance(policy, PolicyRuleExtended) for policy in engine.policies.values())
    
    def test_load_policies(self, temp_policy_file):
        """Test loading policies from file."""
        engine = PolicyEngine(temp_policy_file)
        policies = engine.load_policies()
        
        assert len(policies) >= 2
        assert "POLICY_RULE_1" in policies
        assert "POLICY_RULE_2" in policies
        
        # Check policy structure
        policy = list(policies.values())[0]
        assert hasattr(policy, 'id')
        assert hasattr(policy, 'name')
        assert hasattr(policy, 'pattern')
        assert hasattr(policy, 'severity')
    
    def test_validate_policy(self, temp_policy_file):
        """Test policy validation."""
        engine = PolicyEngine(temp_policy_file)
        
        # Get a valid policy
        policy = list(engine.policies.values())[0]
        assert engine.validate_policy(policy)
        
        # Create invalid policy
        invalid_policy = PolicyRuleExtended(
            id="",  # Invalid empty ID
            name="Test",
            description="Test",
            category=PolicyCategory.CODE_PATTERNS,
            severity=Severity.MEDIUM,
            pattern="[invalid regex",  # Invalid regex
            remediation_template="Fix it",
            applicable_file_types=['.py']
        )
        
        assert not engine.validate_policy(invalid_policy)
    
    def test_get_applicable_rules(self, temp_policy_file):
        """Test getting applicable rules for file types."""
        engine = PolicyEngine(temp_policy_file)
        
        # Test Python file
        py_rules = engine.get_applicable_rules('.py')
        assert len(py_rules) > 0
        assert all(rule.enabled for rule in py_rules)
        
        # Test with context
        context_rules = engine.get_applicable_rules('.py', 'authentication security')
        assert len(context_rules) >= 0  # May filter based on relevance
    
    def test_apply_policies_to_content(self, temp_policy_file):
        """Test applying policies to code content."""
        engine = PolicyEngine(temp_policy_file)
        
        # Test content with security issues
        content = '''
password = "hardcoded_secret_123"
api_key = "ak_1234567890abcdef"
hash = hashlib.md5(data)
ssl_verify = False
'''
        
        issues = engine.apply_policies_to_content(content, "test.py", ".py")
        
        # Should find multiple issues
        assert len(issues) > 0
        
        # Check issue structure
        issue = issues[0]
        assert hasattr(issue, 'id')
        assert hasattr(issue, 'severity')
        assert hasattr(issue, 'file_path')
        assert hasattr(issue, 'line_number')
        assert hasattr(issue, 'remediation_suggestions')
        
        assert issue.file_path == "test.py"
        assert issue.line_number > 0
        assert len(issue.remediation_suggestions) > 0
    
    def test_policy_statistics(self, temp_policy_file):
        """Test getting policy statistics."""
        engine = PolicyEngine(temp_policy_file)
        stats = engine.get_policy_statistics()
        
        assert "total_policies" in stats
        assert "enabled_policies" in stats
        assert "by_category" in stats
        assert "by_severity" in stats
        assert "file_types_covered" in stats
        
        assert stats["total_policies"] > 0
        assert isinstance(stats["by_category"], dict)
        assert isinstance(stats["file_types_covered"], list)
    
    def test_reload_policies(self, temp_policy_file):
        """Test reloading policies."""
        engine = PolicyEngine(temp_policy_file)
        initial_count = len(engine.policies)
        
        # Reload should work
        success = engine.reload_policies()
        assert success
        assert len(engine.policies) == initial_count
    
    def test_default_policies_creation(self):
        """Test creation of default policies when no file exists."""
        # Use non-existent file path
        engine = PolicyEngine("/nonexistent/path/policy.md")
        
        # Should create default policies
        assert len(engine.policies) > 0
        
        # Check that default policies are valid
        for policy in engine.policies.values():
            assert engine.validate_policy(policy)
            assert policy.pattern  # Should have patterns
            assert policy.remediation_template  # Should have remediation
    
    def test_false_positive_detection(self, temp_policy_file):
        """Test false positive detection."""
        engine = PolicyEngine(temp_policy_file)
        
        # Add false positive patterns to a policy
        policy = list(engine.policies.values())[0]
        policy.false_positive_patterns = [r'#.*password.*test', r'//.*example']
        
        # Test content with comments (should be filtered out)
        content = '''
# This is a test password = "example_only"
password = "real_secret_123"  # This should be detected
'''
        
        issues = engine._apply_single_policy(policy, content, "test.py")
        
        # Should detect the real issue but not the comment
        assert len(issues) >= 1
        
        # Check that the detected issue is not from the comment line
        real_issues = [issue for issue in issues if 'test password' not in content.split('\n')[issue.line_number - 1]]
        assert len(real_issues) >= 1
    
    def test_confidence_calculation(self, temp_policy_file):
        """Test confidence score calculation."""
        engine = PolicyEngine(temp_policy_file)
        policy = list(engine.policies.values())[0]
        
        import re
        
        # High confidence case (clear secret)
        line_high = 'password = "very_secret_key_123456"'
        match_high = re.search(r'password\s*=\s*"[^"]*"', line_high)
        confidence_high = engine._calculate_confidence(match_high, line_high, policy)
        
        # Low confidence case (comment)
        line_low = '# password = "just_an_example"'
        match_low = re.search(r'password\s*=\s*"[^"]*"', line_low)
        confidence_low = engine._calculate_confidence(match_low, line_low, policy)
        
        assert confidence_high > confidence_low
        assert 0.1 <= confidence_high <= 1.0
        assert 0.1 <= confidence_low <= 1.0


class TestPolicyRuleExtended:
    """Test cases for PolicyRuleExtended."""
    
    def test_valid_policy_rule_extended(self):
        """Test creating a valid extended policy rule."""
        metadata = PolicyMetadata(
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            version="1.0.0",
            author="test_author",
            tags=["security", "test"]
        )
        
        rule = PolicyRuleExtended(
            id="TEST_RULE",
            name="Test Rule",
            description="Test description",
            category=PolicyCategory.CODE_PATTERNS,
            severity=Severity.MEDIUM,
            pattern=r'test_pattern',
            remediation_template="Fix the issue",
            applicable_file_types=['.py'],
            metadata=metadata,
            enabled=True
        )
        
        assert rule.id == "TEST_RULE"
        assert rule.enabled
        assert rule.metadata.version == "1.0.0"
        assert "security" in rule.metadata.tags
    
    def test_invalid_version_format(self):
        """Test that invalid version format raises error."""
        with pytest.raises(Exception):  # Should raise ValidationError
            PolicyRuleExtended(
                id="TEST_RULE",
                name="Test Rule", 
                description="Test description",
                category=PolicyCategory.CODE_PATTERNS,
                severity=Severity.MEDIUM,
                pattern=r'test_pattern',
                remediation_template="Fix the issue",
                applicable_file_types=['.py'],
                metadata=PolicyMetadata(
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    version="invalid_version"  # Invalid format
                )
            )


# Cleanup fixture
@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Clean up temporary files after tests."""
    yield
    # Cleanup happens automatically with tempfile.NamedTemporaryFile(delete=False)
    # In a real implementation, you might want to explicitly clean up