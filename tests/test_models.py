"""Tests for data models and validation."""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import os

from compliance_sentinel.models.analysis import (
    AnalysisRequest,
    AnalysisResponse, 
    BatchAnalysisResult,
    PolicyViolation,
    AnalysisType,
    AnalysisStatus
)
from compliance_sentinel.core.interfaces import (
    SecurityIssue,
    VulnerabilityReport,
    Severity,
    SecurityCategory
)
from compliance_sentinel.core.validation import (
    SecurityValidator,
    ConfigurationValidator,
    InputSanitizer,
    ValidationError
)


class TestAnalysisRequest:
    """Test cases for AnalysisRequest model."""
    
    def test_valid_analysis_request(self, tmp_path):
        """Test creating a valid analysis request."""
        # Create temporary test file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello world')")
        
        request = AnalysisRequest(
            file_paths=[str(test_file)],
            analysis_type=AnalysisType.SECURITY_SCAN,
            priority=5,
            timeout_seconds=300
        )
        
        assert request.file_paths == [str(test_file)]
        assert request.analysis_type == AnalysisType.SECURITY_SCAN
        assert request.priority == 5
        assert request.timeout_seconds == 300
        assert request.request_id is not None
        assert isinstance(request.created_at, datetime)
    
    def test_empty_file_paths_raises_error(self):
        """Test that empty file paths raises ValueError."""
        with pytest.raises(ValueError, match="file_paths cannot be empty"):
            AnalysisRequest(
                file_paths=[],
                analysis_type=AnalysisType.SECURITY_SCAN
            )
    
    def test_invalid_priority_raises_error(self, tmp_path):
        """Test that invalid priority raises ValueError."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        
        with pytest.raises(ValueError, match="priority must be between 1 and 10"):
            AnalysisRequest(
                file_paths=[str(test_file)],
                analysis_type=AnalysisType.SECURITY_SCAN,
                priority=15
            )
    
    def test_nonexistent_file_raises_error(self):
        """Test that nonexistent file raises ValueError."""
        with pytest.raises(ValueError, match="File does not exist"):
            AnalysisRequest(
                file_paths=["/nonexistent/file.py"],
                analysis_type=AnalysisType.SECURITY_SCAN
            )
    
    def test_get_file_extensions(self, tmp_path):
        """Test getting file extensions from request."""
        py_file = tmp_path / "test.py"
        js_file = tmp_path / "test.js"
        py_file.write_text("print('hello')")
        js_file.write_text("console.log('hello')")
        
        request = AnalysisRequest(
            file_paths=[str(py_file), str(js_file)],
            analysis_type=AnalysisType.SECURITY_SCAN
        )
        
        extensions = request.get_file_extensions()
        assert set(extensions) == {'.py', '.js'}
    
    def test_is_high_priority(self, tmp_path):
        """Test high priority detection."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        
        high_priority_request = AnalysisRequest(
            file_paths=[str(test_file)],
            analysis_type=AnalysisType.SECURITY_SCAN,
            priority=8
        )
        
        low_priority_request = AnalysisRequest(
            file_paths=[str(test_file)],
            analysis_type=AnalysisType.SECURITY_SCAN,
            priority=3
        )
        
        assert high_priority_request.is_high_priority()
        assert not low_priority_request.is_high_priority()


class TestAnalysisResponse:
    """Test cases for AnalysisResponse model."""
    
    def test_valid_analysis_response(self):
        """Test creating a valid analysis response."""
        started_at = datetime.utcnow()
        completed_at = started_at + timedelta(seconds=30)
        
        response = AnalysisResponse(
            request_id="test-123",
            status=AnalysisStatus.COMPLETED,
            started_at=started_at,
            completed_at=completed_at,
            total_files_analyzed=5,
            total_lines_analyzed=1000
        )
        
        assert response.request_id == "test-123"
        assert response.status == AnalysisStatus.COMPLETED
        assert response.duration_seconds == 30.0
        assert response.total_files_analyzed == 5
    
    def test_severity_distribution_calculation(self):
        """Test automatic calculation of severity distribution."""
        issues = [
            SecurityIssue(
                id="1", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="test.py", line_number=1, description="Test", rule_id="TEST",
                confidence=0.8, remediation_suggestions=[], created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="2", severity=Severity.CRITICAL, category=SecurityCategory.SQL_INJECTION,
                file_path="test.py", line_number=2, description="Test", rule_id="TEST",
                confidence=0.9, remediation_suggestions=[], created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="3", severity=Severity.HIGH, category=SecurityCategory.XSS,
                file_path="test.py", line_number=3, description="Test", rule_id="TEST",
                confidence=0.7, remediation_suggestions=[], created_at=datetime.utcnow()
            )
        ]
        
        response = AnalysisResponse(
            request_id="test-123",
            status=AnalysisStatus.COMPLETED,
            started_at=datetime.utcnow(),
            issues=issues
        )
        
        assert response.issues_by_severity['high'] == 2
        assert response.issues_by_severity['critical'] == 1
        assert response.issues_by_severity['medium'] == 0
        assert response.issues_by_severity['low'] == 0
    
    def test_has_blocking_issues(self):
        """Test detection of blocking issues."""
        critical_issue = SecurityIssue(
            id="1", severity=Severity.CRITICAL, category=SecurityCategory.SQL_INJECTION,
            file_path="test.py", line_number=1, description="Test", rule_id="TEST",
            confidence=0.9, remediation_suggestions=[], created_at=datetime.utcnow()
        )
        
        low_issue = SecurityIssue(
            id="2", severity=Severity.LOW, category=SecurityCategory.HARDCODED_SECRETS,
            file_path="test.py", line_number=2, description="Test", rule_id="TEST",
            confidence=0.5, remediation_suggestions=[], created_at=datetime.utcnow()
        )
        
        blocking_response = AnalysisResponse(
            request_id="test-123",
            status=AnalysisStatus.COMPLETED,
            started_at=datetime.utcnow(),
            issues=[critical_issue]
        )
        
        non_blocking_response = AnalysisResponse(
            request_id="test-456",
            status=AnalysisStatus.COMPLETED,
            started_at=datetime.utcnow(),
            issues=[low_issue]
        )
        
        assert blocking_response.has_blocking_issues()
        assert not non_blocking_response.has_blocking_issues()


class TestSecurityValidator:
    """Test cases for SecurityValidator."""
    
    def test_scan_for_hardcoded_secrets(self):
        """Test scanning for hardcoded secrets."""
        content = '''
        password = "super_secret_password123"
        api_key = "ak_1234567890abcdef"
        normal_var = "not_a_secret"
        '''
        
        issues = SecurityValidator.scan_for_hardcoded_secrets(content, "test.py")
        
        assert len(issues) == 2
        assert all(issue.category == SecurityCategory.HARDCODED_SECRETS for issue in issues)
        assert all(issue.severity == Severity.HIGH for issue in issues)
    
    def test_scan_for_weak_crypto(self):
        """Test scanning for weak cryptographic practices."""
        content = '''
        import hashlib
        hash = hashlib.md5(data)
        ssl_verify = False
        random.random()
        '''
        
        issues = SecurityValidator.scan_for_weak_crypto(content, "test.py")
        
        assert len(issues) >= 2  # Should find md5 and ssl_verify=False
        assert all(issue.category == SecurityCategory.INSECURE_CRYPTO for issue in issues)
    
    def test_scan_for_sql_injection(self):
        """Test scanning for SQL injection vulnerabilities."""
        content = '''
        query = "SELECT * FROM users WHERE id = %s" % user_id
        cursor.execute("SELECT * FROM table WHERE name = %s" % name)
        safe_query = cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        '''
        
        issues = SecurityValidator.scan_for_sql_injection(content, "test.py")
        
        assert len(issues) >= 1  # Should find at least one SQL injection pattern
        assert all(issue.category == SecurityCategory.SQL_INJECTION for issue in issues)
        assert all(issue.severity == Severity.CRITICAL for issue in issues)
    
    def test_validate_security_issue(self):
        """Test validation of SecurityIssue objects."""
        valid_issue = SecurityIssue(
            id="TEST_001",
            severity=Severity.HIGH,
            category=SecurityCategory.HARDCODED_SECRETS,
            file_path="test.py",
            line_number=10,
            description="Test security issue",
            rule_id="HARDCODED_SECRETS",
            confidence=0.8,
            remediation_suggestions=["Fix this"],
            created_at=datetime.utcnow()
        )
        
        errors = SecurityValidator.validate_security_issue(valid_issue)
        assert len(errors) == 1  # File doesn't exist error
        
        # Test invalid issue
        invalid_issue = SecurityIssue(
            id="",  # Empty ID
            severity=Severity.HIGH,
            category=SecurityCategory.HARDCODED_SECRETS,
            file_path="",  # Empty path
            line_number=-1,  # Invalid line number
            description="",  # Empty description
            rule_id="invalid-rule-id!",  # Invalid format
            confidence=1.5,  # Invalid confidence
            remediation_suggestions=[],
            created_at=datetime.utcnow()
        )
        
        errors = SecurityValidator.validate_security_issue(invalid_issue)
        assert len(errors) > 3  # Multiple validation errors


class TestConfigurationValidator:
    """Test cases for ConfigurationValidator."""
    
    def test_validate_url(self):
        """Test URL validation."""
        # Valid HTTPS URL
        valid, error = ConfigurationValidator.validate_url("https://api.example.com/v1")
        assert valid
        assert error is None
        
        # Invalid HTTP URL (when HTTPS required)
        valid, error = ConfigurationValidator.validate_url("http://api.example.com/v1", require_https=True)
        assert not valid
        assert "HTTPS" in error
        
        # Invalid URL format
        valid, error = ConfigurationValidator.validate_url("not-a-url")
        assert not valid
        assert error is not None
    
    def test_validate_port(self):
        """Test port validation."""
        # Valid port
        valid, error = ConfigurationValidator.validate_port(8080)
        assert valid
        
        # Invalid port (too high)
        valid, error = ConfigurationValidator.validate_port(70000)
        assert not valid
        assert "between 1 and 65535" in error
        
        # Well-known port (warning)
        valid, error = ConfigurationValidator.validate_port(80)
        assert valid
        assert "well-known port" in error
    
    def test_validate_file_patterns(self):
        """Test file pattern validation."""
        # Valid patterns
        valid, error = ConfigurationValidator.validate_file_patterns(["*.py", "*.js", "src/**/*.ts"])
        assert valid
        assert error is None
        
        # Empty patterns
        valid, error = ConfigurationValidator.validate_file_patterns([])
        assert not valid
        assert "cannot be empty" in error


class TestInputSanitizer:
    """Test cases for InputSanitizer."""
    
    def test_sanitize_filename(self):
        """Test filename sanitization."""
        # Dangerous filename
        dangerous = "../../../etc/passwd"
        sanitized = InputSanitizer.sanitize_filename(dangerous)
        assert ".." not in sanitized
        assert "/" not in sanitized
        
        # Normal filename
        normal = "my_file.txt"
        sanitized = InputSanitizer.sanitize_filename(normal)
        assert sanitized == normal
    
    def test_sanitize_log_message(self):
        """Test log message sanitization."""
        # Message with control characters
        dangerous = "User input: \r\n\x00malicious\x1f"
        sanitized = InputSanitizer.sanitize_log_message(dangerous)
        assert "\r" not in sanitized
        assert "\n" not in sanitized
        assert "\x00" not in sanitized
    
    def test_sanitize_user_input(self):
        """Test general user input sanitization."""
        # Input with dangerous characters
        dangerous = "<script>alert('xss')</script>"
        sanitized = InputSanitizer.sanitize_user_input(dangerous)
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "script" in sanitized  # Content preserved, just tags removed


# Fixtures for testing
@pytest.fixture
def sample_security_issue():
    """Create a sample SecurityIssue for testing."""
    return SecurityIssue(
        id="TEST_001",
        severity=Severity.HIGH,
        category=SecurityCategory.HARDCODED_SECRETS,
        file_path="test.py",
        line_number=10,
        description="Hardcoded password detected",
        rule_id="HARDCODED_SECRETS",
        confidence=0.9,
        remediation_suggestions=["Use environment variables", "Use secret management"],
        created_at=datetime.utcnow()
    )


@pytest.fixture
def sample_vulnerability_report():
    """Create a sample VulnerabilityReport for testing."""
    return VulnerabilityReport(
        cve_id="CVE-2023-1234",
        package_name="vulnerable-package",
        affected_versions=["1.0.0", "1.1.0"],
        severity_score=7.5,
        description="Critical vulnerability in package",
        remediation_available=True,
        upgrade_path="2.0.0"
    )