"""Pytest configuration and fixtures for Compliance Sentinel tests."""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_security_issues():
    """Provide sample security issues for testing."""
    return [
        SecurityIssue(
            id="test_001",
            severity=Severity.HIGH,
            category=SecurityCategory.HARDCODED_SECRETS,
            file_path="test.py",
            line_number=10,
            description="Hardcoded API key detected",
            rule_id="hardcoded_secrets",
            confidence=0.95,
            remediation_suggestions=["Use environment variables"],
            created_at=datetime.now()
        ),
        SecurityIssue(
            id="test_002",
            severity=Severity.CRITICAL,
            category=SecurityCategory.INJECTION,
            file_path="app.py",
            line_number=25,
            description="SQL injection vulnerability",
            rule_id="sql_injection",
            confidence=0.9,
            remediation_suggestions=["Use parameterized queries"],
            created_at=datetime.now()
        )
    ]


@pytest.fixture
def mock_analyzer():
    """Provide a mock analyzer for testing."""
    analyzer = Mock()
    analyzer.analyze_content.return_value = []
    analyzer.analyze_file.return_value = []
    return analyzer


@pytest.fixture
def test_code_samples():
    """Provide test code samples for different languages."""
    return {
        "python_with_secrets": '''
def login():
    api_key = "sk-1234567890abcdef"  # Hardcoded secret
    password = "admin123"  # Another secret
    return authenticate(api_key, password)
''',
        "javascript_with_xss": '''
function displayUser(name) {
    document.getElementById("user").innerHTML = name;  // XSS vulnerability
    return true;
}
''',
        "sql_injection_example": '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
    return execute_query(query)
''',
        "clean_code": '''
def calculate_total(items):
    """Calculate total price of items."""
    return sum(item.price for item in items)
'''
    }


# Test markers
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )


# Test collection customization
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Mark performance tests
        if "test_performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        
        # Mark integration tests
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        
        # Mark slow tests
        if any(keyword in item.name.lower() for keyword in ["stress", "large", "batch"]):
            item.add_marker(pytest.mark.slow)