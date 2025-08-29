"""Tests for production data validator."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch

from compliance_sentinel.testing.production_data_validator import (
    ProductionDataValidator, ValidationConfig, ValidationIssue, ValidationSeverity,
    validate_production_code, is_production_environment, validate_current_environment
)


class TestProductionDataValidator:
    """Test cases for ProductionDataValidator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = ProductionDataValidator()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, filename: str, content: str) -> str:
        """Create a test file with given content."""
        file_path = os.path.join(self.temp_dir, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        return file_path
    
    def test_detect_hardcoded_api_key(self):
        """Test detection of hardcoded API keys."""
        content = '''
API_KEY = "test-api-key-12345"
def get_data():
    return requests.get(url, headers={"Authorization": API_KEY})
'''
        file_path = self.create_test_file("test_api.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        api_key_issues = [issue for issue in issues if "api" in issue.description.lower()]
        assert len(api_key_issues) > 0
        assert api_key_issues[0].severity in [ValidationSeverity.HIGH, ValidationSeverity.MEDIUM]
    
    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords."""
        content = '''
DATABASE_PASSWORD = "test-password-123"
connection = connect_db(password=DATABASE_PASSWORD)
'''
        file_path = self.create_test_file("test_db.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        password_issues = [issue for issue in issues if "password" in issue.description.lower()]
        assert len(password_issues) > 0
    
    def test_detect_localhost_test_urls(self):
        """Test detection of localhost test URLs."""
        content = '''
TEST_URL = "http://localhost:8080/test"
def connect():
    return requests.get(TEST_URL)
'''
        file_path = self.create_test_file("test_url.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        url_issues = [issue for issue in issues if "localhost" in issue.description.lower()]
        assert len(url_issues) > 0
    
    def test_ignore_comments(self):
        """Test that comments are ignored."""
        content = '''
# This is a comment with test-api-key-12345
// Another comment with test-password-123
def normal_function():
    return "normal code"
'''
        file_path = self.create_test_file("test_comments.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        # Should not detect issues in comments
        assert len(issues) == 0
    
    def test_exclude_test_directories(self):
        """Test that test directories are excluded."""
        # Create file in test directory
        test_content = '''
API_KEY = "test-api-key-12345"
'''
        test_file = self.create_test_file("tests/test_module.py", test_content)
        
        issues = self.validator.validate_directory(self.temp_dir)
        
        # Should not find issues in test directory
        assert len(issues) == 0
    
    def test_validate_directory(self):
        """Test directory validation."""
        # Create multiple files with issues
        self.create_test_file("module1.py", 'API_KEY = "test-api-key-123"')
        self.create_test_file("module2.py", 'PASSWORD = "test-password-456"')
        self.create_test_file("subdir/module3.py", 'SECRET = "test-secret-789"')
        
        issues = self.validator.validate_directory(self.temp_dir)
        
        assert len(issues) >= 3
        
        # Check that issues are from different files
        file_paths = set(issue.file_path for issue in issues)
        assert len(file_paths) >= 3
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "production"})
    def test_production_environment_severity(self):
        """Test that production environment increases severity."""
        content = '''
API_KEY = "test-api-key-12345"
'''
        file_path = self.create_test_file("prod_test.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        # In production, severity should be higher
        critical_or_high = [issue for issue in issues 
                           if issue.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]]
        assert len(critical_or_high) > 0
    
    def test_ast_validation_python(self):
        """Test AST-based validation for Python files."""
        content = '''
import os

class Config:
    def __init__(self):
        self.api_key = "test-api-key-12345"
        self.database_url = "postgresql://user:test-password@localhost/db"
    
    def get_secret(self):
        return "hardcoded-secret-value"
'''
        file_path = self.create_test_file("config.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        # Should detect multiple test data patterns
        assert len(issues) >= 2
    
    def test_get_issues_by_severity(self):
        """Test grouping issues by severity."""
        content = '''
API_KEY = "test-api-key-123"
PASSWORD = "admin123"
SECRET = "test-secret-456"
'''
        file_path = self.create_test_file("severity_test.py", content)
        
        issues = self.validator.validate_file(file_path)
        issues_by_severity = self.validator.get_issues_by_severity()
        
        assert len(issues) > 0
        
        # Check that all severity levels are represented in the dict
        for severity in ValidationSeverity:
            assert severity in issues_by_severity
        
        # Total issues should match
        total_grouped = sum(len(issues_list) for issues_list in issues_by_severity.values())
        assert total_grouped == len(issues)
    
    def test_generate_report(self):
        """Test report generation."""
        content = '''
API_KEY = "test-api-key-123"
PASSWORD = "test-password-456"
'''
        file_path = self.create_test_file("report_test.py", content)
        
        issues = self.validator.validate_file(file_path)
        report = self.validator.generate_report()
        
        assert len(issues) > 0
        assert "Production Data Validation Report" in report
        assert "Summary" in report
        assert "Total Issues:" in report
        
        # Should contain issue details
        assert "test-api-key" in report or "API_KEY" in report
    
    def test_custom_validation_config(self):
        """Test validator with custom configuration."""
        custom_config = ValidationConfig(
            test_data_patterns=[r'custom[-_]test[-_]pattern'],
            excluded_directories={'custom_exclude'},
            included_file_patterns=['*.custom']
        )
        
        validator = ProductionDataValidator(custom_config)
        
        content = '''
VALUE = "custom-test-pattern-123"
'''
        file_path = self.create_test_file("test.custom", content)
        
        issues = validator.validate_file(file_path)
        
        assert len(issues) > 0
        assert "custom-test-pattern" in issues[0].description.lower()
    
    def test_recommendations(self):
        """Test that appropriate recommendations are provided."""
        content = '''
API_KEY = "test-api-key-123"
PASSWORD = "test-password-456"
SECRET_TOKEN = "test-secret-789"
LOCALHOST_URL = "http://localhost:8080/test"
'''
        file_path = self.create_test_file("recommendations_test.py", content)
        
        issues = self.validator.validate_file(file_path)
        
        assert len(issues) > 0
        
        # Check that recommendations are provided
        for issue in issues:
            assert issue.recommendation
            assert len(issue.recommendation) > 10  # Should be meaningful
            
            # Check specific recommendations
            if "api" in issue.description.lower():
                assert "environment variable" in issue.recommendation.lower()
            elif "password" in issue.description.lower():
                assert "secret management" in issue.recommendation.lower()


class TestProductionEnvironmentDetection:
    """Test production environment detection functions."""
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "production"})
    def test_is_production_environment_true(self):
        """Test production environment detection returns True."""
        assert is_production_environment() is True
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "development"})
    def test_is_production_environment_false(self):
        """Test non-production environment detection returns False."""
        assert is_production_environment() is False
    
    @patch.dict(os.environ, {}, clear=True)
    def test_is_production_environment_default(self):
        """Test default environment is not production."""
        assert is_production_environment() is False
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "prod"})
    def test_is_production_environment_prod_alias(self):
        """Test 'prod' is recognized as production."""
        assert is_production_environment() is True
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "live"})
    def test_is_production_environment_live_alias(self):
        """Test 'live' is recognized as production."""
        assert is_production_environment() is True


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, filename: str, content: str) -> str:
        """Create a test file with given content."""
        file_path = os.path.join(self.temp_dir, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        return file_path
    
    def test_validate_production_code(self):
        """Test validate_production_code convenience function."""
        self.create_test_file("module.py", 'API_KEY = "test-api-key-123"')
        
        issues = validate_production_code(self.temp_dir)
        
        assert len(issues) > 0
        assert isinstance(issues[0], ValidationIssue)
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "development"})
    def test_validate_current_environment_development(self):
        """Test validate_current_environment in development."""
        is_prod, issues = validate_current_environment()
        
        assert is_prod is False
        assert len(issues) == 0
    
    @patch.dict(os.environ, {"COMPLIANCE_SENTINEL_ENVIRONMENT": "production"})
    @patch('compliance_sentinel.testing.production_data_validator.validate_production_code')
    def test_validate_current_environment_production(self, mock_validate):
        """Test validate_current_environment in production."""
        mock_validate.return_value = [
            ValidationIssue(
                file_path="test.py",
                line_number=1,
                issue_type="test_data",
                severity=ValidationSeverity.HIGH,
                description="Test issue",
                code_snippet="test code",
                recommendation="Fix it"
            )
        ]
        
        is_prod, issues = validate_current_environment()
        
        assert is_prod is True
        assert len(issues) > 0
        mock_validate.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])