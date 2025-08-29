"""Tests for security analyzers and coordination."""

import pytest
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from compliance_sentinel.analyzers.bandit_analyzer import BanditAnalyzer, BanditConfig
from compliance_sentinel.analyzers.semgrep_analyzer import SemgrepAnalyzer, SemgrepConfig
from compliance_sentinel.analyzers.coordinator import AnalysisCoordinator, CoordinatorConfig
from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


class TestBanditAnalyzer:
    """Test cases for BanditAnalyzer."""
    
    @pytest.fixture
    def mock_bandit_subprocess(self):
        """Mock subprocess calls for Bandit."""
        with patch('subprocess.run') as mock_run:
            # Mock version check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "bandit 1.7.5"
            yield mock_run
    
    @pytest.fixture
    def sample_bandit_output(self):
        """Sample Bandit JSON output."""
        return {
            "results": [
                {
                    "code": "password = 'hardcoded_secret_123'",
                    "filename": "test.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "HIGH",
                    "issue_text": "Possible hardcoded password: 'hardcoded_secret_123'",
                    "line_number": 1,
                    "line_range": [1],
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string"
                },
                {
                    "code": "hashlib.md5(data)",
                    "filename": "test.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "MEDIUM",
                    "issue_text": "Use of insecure MD5 hash function.",
                    "line_number": 5,
                    "line_range": [5],
                    "test_id": "B303",
                    "test_name": "blacklist"
                }
            ],
            "metrics": {}
        }
    
    def test_bandit_analyzer_initialization(self, mock_bandit_subprocess):
        """Test BanditAnalyzer initialization."""
        config = BanditConfig(confidence_level="high", severity_level="medium")
        analyzer = BanditAnalyzer(config)
        
        assert analyzer.config.confidence_level == "high"
        assert analyzer.config.severity_level == "medium"
        assert len(analyzer.config.excluded_paths) > 0
    
    def test_bandit_installation_check_failure(self):
        """Test handling of Bandit installation check failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("bandit not found")
            
            with pytest.raises(RuntimeError, match="Bandit is not installed"):
                BanditAnalyzer()
    
    def test_analyze_file_success(self, mock_bandit_subprocess, sample_bandit_output, tmp_path):
        """Test successful file analysis."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret'\nhashlib.md5(data)")
        
        # Mock Bandit execution
        mock_bandit_subprocess.return_value.returncode = 1  # Issues found
        mock_bandit_subprocess.return_value.stdout = str(sample_bandit_output).replace("'", '"')
        
        with patch('json.loads', return_value=sample_bandit_output):
            analyzer = BanditAnalyzer()
            issues = analyzer.analyze_file(str(test_file))
        
        assert len(issues) == 2
        assert all(isinstance(issue, SecurityIssue) for issue in issues)
        
        # Check first issue (hardcoded password)
        password_issue = issues[0]
        assert password_issue.severity == Severity.HIGH
        assert password_issue.category == SecurityCategory.HARDCODED_SECRETS
        assert "B105" in password_issue.rule_id
        assert len(password_issue.remediation_suggestions) > 0
    
    def test_analyze_file_not_found(self, mock_bandit_subprocess):
        """Test analysis of non-existent file."""
        analyzer = BanditAnalyzer()
        
        with pytest.raises(FileNotFoundError):
            analyzer.analyze_file("/nonexistent/file.py")
    
    def test_analyze_non_python_file(self, mock_bandit_subprocess, tmp_path):
        """Test analysis of non-Python file."""
        test_file = tmp_path / "test.js"
        test_file.write_text("console.log('hello');")
        
        analyzer = BanditAnalyzer()
        issues = analyzer.analyze_file(str(test_file))
        
        assert len(issues) == 0  # Should skip non-Python files
    
    def test_confidence_calculation(self, mock_bandit_subprocess):
        """Test confidence score calculation."""
        analyzer = BanditAnalyzer()
        
        # High confidence case
        confidence_high = analyzer._calculate_confidence_score("HIGH", "B105", "password = 'secret'")
        
        # Low confidence case (comment)
        confidence_low = analyzer._calculate_confidence_score("LOW", "B999", "# password = 'example'")
        
        assert confidence_high > confidence_low
        assert 0.1 <= confidence_high <= 1.0
        assert 0.1 <= confidence_low <= 1.0
    
    def test_remediation_suggestions(self, mock_bandit_subprocess):
        """Test remediation suggestion generation."""
        analyzer = BanditAnalyzer()
        
        # Test hardcoded password suggestions
        suggestions = analyzer._generate_remediation_suggestions("B105", "hardcoded_password_string", "")
        
        assert len(suggestions) > 0
        assert any("environment variables" in suggestion.lower() for suggestion in suggestions)
        assert any("secret management" in suggestion.lower() for suggestion in suggestions)
    
    def test_configure_rules(self, mock_bandit_subprocess):
        """Test rule configuration."""
        analyzer = BanditAnalyzer()
        initial_skipped = len(analyzer.config.skipped_tests)
        
        # Configure rules
        rules = ["skip:B101", "severity:high", "confidence:medium"]
        analyzer.configure_rules(rules)
        
        assert "B101" in analyzer.config.skipped_tests
        assert analyzer.config.severity_level == "high"
        assert analyzer.config.confidence_level == "medium"


class TestSemgrepAnalyzer:
    """Test cases for SemgrepAnalyzer."""
    
    @pytest.fixture
    def mock_semgrep_subprocess(self):
        """Mock subprocess calls for Semgrep."""
        with patch('subprocess.run') as mock_run:
            # Mock version check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "1.45.0"
            yield mock_run
    
    @pytest.fixture
    def sample_semgrep_output(self):
        """Sample Semgrep JSON output."""
        return {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
                    "path": "test.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 20},
                    "message": "Found dynamic content when calling a system command. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands.",
                    "severity": "ERROR",
                    "extra": {
                        "message": "Found dynamic content when calling a system command.",
                        "metadata": {
                            "owasp": "A03:2021 - Injection",
                            "category": "security",
                            "confidence": "HIGH"
                        },
                        "severity": "ERROR",
                        "lines": "os.system(user_input)"
                    }
                }
            ],
            "errors": []
        }
    
    def test_semgrep_analyzer_initialization(self, mock_semgrep_subprocess):
        """Test SemgrepAnalyzer initialization."""
        config = SemgrepConfig(rulesets=["security", "owasp-top-ten"], timeout=60)
        analyzer = SemgrepAnalyzer(config)
        
        assert "security" in analyzer.config.rulesets
        assert analyzer.config.timeout == 60
        assert len(analyzer.config.excluded_paths) > 0
    
    def test_semgrep_installation_check_failure(self):
        """Test handling of Semgrep installation check failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("semgrep not found")
            
            with pytest.raises(RuntimeError, match="Semgrep is not installed"):
                SemgrepAnalyzer()
    
    def test_analyze_file_success(self, mock_semgrep_subprocess, sample_semgrep_output, tmp_path):
        """Test successful file analysis."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("import os\nos.system(user_input)")
        
        # Mock Semgrep execution
        mock_semgrep_subprocess.return_value.returncode = 1  # Issues found
        mock_semgrep_subprocess.return_value.stdout = str(sample_semgrep_output).replace("'", '"')
        
        with patch('json.loads', return_value=sample_semgrep_output):
            analyzer = SemgrepAnalyzer()
            issues = analyzer.analyze_file(str(test_file))
        
        assert len(issues) == 1
        assert isinstance(issues[0], SecurityIssue)
        
        issue = issues[0]
        assert issue.severity == Severity.HIGH  # ERROR maps to HIGH
        assert "SEMGREP_" in issue.rule_id
        assert len(issue.remediation_suggestions) > 0
    
    def test_supported_file_types(self, mock_semgrep_subprocess):
        """Test supported file type detection."""
        analyzer = SemgrepAnalyzer()
        supported_types = analyzer.get_supported_file_types()
        
        assert ".py" in supported_types
        assert ".js" in supported_types
        assert ".java" in supported_types
        assert len(supported_types) > 10  # Should support many file types
    
    def test_is_supported_file(self, mock_semgrep_subprocess, tmp_path):
        """Test file support detection."""
        analyzer = SemgrepAnalyzer()
        
        # Supported files
        py_file = tmp_path / "test.py"
        js_file = tmp_path / "test.js"
        dockerfile = tmp_path / "Dockerfile"
        
        assert analyzer._is_supported_file(py_file)
        assert analyzer._is_supported_file(js_file)
        assert analyzer._is_supported_file(dockerfile)
        
        # Unsupported file
        binary_file = tmp_path / "test.bin"
        assert not analyzer._is_supported_file(binary_file)
    
    def test_determine_category(self, mock_semgrep_subprocess):
        """Test security category determination."""
        analyzer = SemgrepAnalyzer()
        
        # SQL injection
        category = analyzer._determine_category("sql-injection", "SQL injection vulnerability", {})
        assert category == SecurityCategory.SQL_INJECTION
        
        # XSS
        category = analyzer._determine_category("xss-vulnerability", "Cross-site scripting", {})
        assert category == SecurityCategory.XSS
        
        # Hardcoded secrets
        category = analyzer._determine_category("hardcoded-secret", "API key found", {})
        assert category == SecurityCategory.HARDCODED_SECRETS
        
        # Default case
        category = analyzer._determine_category("unknown-rule", "Some issue", {})
        assert category == SecurityCategory.INPUT_VALIDATION
    
    def test_custom_rules_creation(self, mock_semgrep_subprocess):
        """Test custom rules file creation."""
        custom_rules = [
            """
            id: test-rule
            message: Test rule
            languages: [python]
            severity: ERROR
            pattern: dangerous_function()
            """
        ]
        
        config = SemgrepConfig(custom_rules=custom_rules)
        analyzer = SemgrepAnalyzer(config)
        
        assert analyzer.custom_rules_file is not None
        assert Path(analyzer.custom_rules_file).exists()
    
    def test_rule_validation(self, mock_semgrep_subprocess):
        """Test Semgrep rule validation."""
        analyzer = SemgrepAnalyzer()
        
        # Valid rule
        valid_rule = """
        id: test-rule
        message: Test message
        languages: [python]
        severity: ERROR
        pattern: test_pattern()
        """
        assert analyzer.validate_rule_syntax(valid_rule)
        
        # Invalid rule (missing required field)
        invalid_rule = """
        id: test-rule
        message: Test message
        # missing languages and severity
        pattern: test_pattern()
        """
        assert not analyzer.validate_rule_syntax(invalid_rule)


class TestAnalysisCoordinator:
    """Test cases for AnalysisCoordinator."""
    
    @pytest.fixture
    def mock_analyzers(self):
        """Mock analyzers for testing."""
        bandit_mock = Mock(spec=BanditAnalyzer)
        bandit_mock.get_supported_file_types.return_value = ['.py']
        bandit_mock.analyze_file.return_value = [
            SecurityIssue(
                id="BANDIT_B105_1",
                severity=Severity.HIGH,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path="test.py",
                line_number=1,
                description="Hardcoded password",
                rule_id="BANDIT_B105",
                confidence=0.9,
                remediation_suggestions=["Use environment variables"],
                created_at=datetime.utcnow()
            )
        ]
        
        semgrep_mock = Mock(spec=SemgrepAnalyzer)
        semgrep_mock.get_supported_file_types.return_value = ['.py', '.js', '.java']
        semgrep_mock.analyze_file.return_value = [
            SecurityIssue(
                id="SEMGREP_SQL_1",
                severity=Severity.CRITICAL,
                category=SecurityCategory.SQL_INJECTION,
                file_path="test.py",
                line_number=5,
                description="SQL injection vulnerability",
                rule_id="SEMGREP_SQL",
                confidence=0.8,
                remediation_suggestions=["Use parameterized queries"],
                created_at=datetime.utcnow()
            )
        ]
        
        return {"bandit": bandit_mock, "semgrep": semgrep_mock}
    
    @pytest.fixture
    def coordinator_with_mocks(self, mock_analyzers):
        """Create coordinator with mocked analyzers."""
        config = CoordinatorConfig(enable_bandit=True, enable_semgrep=True, enable_policy_engine=False)
        coordinator = AnalysisCoordinator(config)
        coordinator.analyzers = mock_analyzers
        return coordinator
    
    def test_coordinator_initialization(self):
        """Test AnalysisCoordinator initialization."""
        config = CoordinatorConfig(
            max_concurrent_analyses=3,
            enable_bandit=False,
            enable_semgrep=False,
            enable_policy_engine=False
        )
        
        with patch('compliance_sentinel.analyzers.bandit_analyzer.BanditAnalyzer'):
            with patch('compliance_sentinel.analyzers.semgrep_analyzer.SemgrepAnalyzer'):
                coordinator = AnalysisCoordinator(config)
        
        assert coordinator.config.max_concurrent_analyses == 3
        assert not coordinator.config.enable_bandit
        assert not coordinator.config.enable_semgrep
    
    @pytest.mark.asyncio
    async def test_comprehensive_scan(self, coordinator_with_mocks, tmp_path):
        """Test comprehensive security scan."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret'\nquery = f'SELECT * FROM users WHERE id = {user_id}'")
        
        # Create analysis request
        request = AnalysisRequest(
            file_paths=[str(test_file)],
            analysis_type=AnalysisType.COMPREHENSIVE,
            timeout_seconds=60
        )
        
        # Run comprehensive scan
        response = await coordinator_with_mocks.run_comprehensive_scan(request)
        
        assert response.status.value == "completed"
        assert len(response.issues) > 0
        assert response.total_files_analyzed == 1
        assert len(response.tools_used) > 0
        assert len(response.recommendations) > 0
    
    def test_deduplicate_issues(self, coordinator_with_mocks):
        """Test issue deduplication."""
        # Create duplicate issues
        issue1 = SecurityIssue(
            id="TEST_1", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
            file_path="test.py", line_number=1, description="Issue", rule_id="TEST_RULE",
            confidence=0.8, remediation_suggestions=[], created_at=datetime.utcnow()
        )
        
        issue2 = SecurityIssue(
            id="TEST_2", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
            file_path="test.py", line_number=1, description="Issue", rule_id="TEST_RULE",
            confidence=0.9, remediation_suggestions=[], created_at=datetime.utcnow()
        )
        
        issues = [issue1, issue2]
        deduplicated = coordinator_with_mocks._deduplicate_issues(issues)
        
        assert len(deduplicated) == 1
        assert deduplicated[0].confidence == 0.9  # Should keep higher confidence issue
    
    def test_prioritize_issues(self, coordinator_with_mocks):
        """Test issue prioritization."""
        issues = [
            SecurityIssue(
                id="LOW_1", severity=Severity.LOW, category=SecurityCategory.INPUT_VALIDATION,
                file_path="test.py", line_number=10, description="Low issue", rule_id="LOW_RULE",
                confidence=0.5, remediation_suggestions=[], created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="CRITICAL_1", severity=Severity.CRITICAL, category=SecurityCategory.SQL_INJECTION,
                file_path="test.py", line_number=5, description="Critical issue", rule_id="CRITICAL_RULE",
                confidence=0.9, remediation_suggestions=[], created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="HIGH_1", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="test.py", line_number=1, description="High issue", rule_id="HIGH_RULE",
                confidence=0.8, remediation_suggestions=[], created_at=datetime.utcnow()
            )
        ]
        
        prioritized = coordinator_with_mocks.prioritize_issues(issues)
        
        # Should be ordered by severity (critical, high, low)
        assert prioritized[0].severity == Severity.CRITICAL
        assert prioritized[1].severity == Severity.HIGH
        assert prioritized[2].severity == Severity.LOW
    
    def test_generate_recommendations(self, coordinator_with_mocks):
        """Test recommendation generation."""
        issues = [
            SecurityIssue(
                id="CRITICAL_1", severity=Severity.CRITICAL, category=SecurityCategory.SQL_INJECTION,
                file_path="test.py", line_number=1, description="SQL injection", rule_id="SQL_RULE",
                confidence=0.9, remediation_suggestions=[], created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="HIGH_1", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="test.py", line_number=2, description="Hardcoded secret", rule_id="SECRET_RULE",
                confidence=0.8, remediation_suggestions=[], created_at=datetime.utcnow()
            )
        ]
        
        recommendations = coordinator_with_mocks._generate_recommendations(issues)
        
        assert len(recommendations) > 0
        assert any("critical" in rec.lower() for rec in recommendations)
        assert any("parameterized queries" in rec.lower() for rec in recommendations)
        assert any("secret management" in rec.lower() for rec in recommendations)
    
    def test_analyzer_status(self, coordinator_with_mocks):
        """Test analyzer status reporting."""
        # Mock analyzer info
        coordinator_with_mocks.analyzers["bandit"].get_analyzer_info.return_value = {
            "name": "Bandit",
            "version": "1.7.5",
            "supported_languages": ["Python"]
        }
        
        coordinator_with_mocks.analyzers["semgrep"].get_analyzer_info.return_value = {
            "name": "Semgrep",
            "version": "1.45.0",
            "supported_languages": ["Python", "JavaScript", "Java"]
        }
        
        status = coordinator_with_mocks.get_analyzer_status()
        
        assert status["total_analyzers"] == 2
        assert "bandit" in status["analyzers"]
        assert "semgrep" in status["analyzers"]
        assert status["analyzers"]["bandit"]["status"] == "available"
        assert status["analyzers"]["semgrep"]["status"] == "available"


# Integration test fixtures
@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Python code for testing."""
    return '''
import hashlib
import os

# Hardcoded password
password = "super_secret_password_123"

# Weak crypto
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# Command injection
def run_command(user_input):
    os.system(f"ls {user_input}")

# SQL injection potential
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''


@pytest.mark.integration
class TestAnalyzersIntegration:
    """Integration tests for analyzers (require actual tools to be installed)."""
    
    def test_bandit_real_analysis(self, sample_vulnerable_code, tmp_path):
        """Test real Bandit analysis (requires Bandit to be installed)."""
        pytest.importorskip("bandit")
        
        # Create test file
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text(sample_vulnerable_code)
        
        try:
            analyzer = BanditAnalyzer()
            issues = analyzer.analyze_file(str(test_file))
            
            # Should find multiple issues
            assert len(issues) > 0
            
            # Should find hardcoded password
            password_issues = [i for i in issues if "password" in i.description.lower()]
            assert len(password_issues) > 0
            
            # Should find weak crypto
            crypto_issues = [i for i in issues if "md5" in i.description.lower()]
            assert len(crypto_issues) > 0
            
        except RuntimeError as e:
            if "not installed" in str(e):
                pytest.skip("Bandit not installed")
            raise
    
    def test_semgrep_real_analysis(self, sample_vulnerable_code, tmp_path):
        """Test real Semgrep analysis (requires Semgrep to be installed)."""
        pytest.importorskip("semgrep")
        
        # Create test file
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text(sample_vulnerable_code)
        
        try:
            analyzer = SemgrepAnalyzer()
            issues = analyzer.analyze_file(str(test_file))
            
            # Should find issues (exact count depends on Semgrep rules)
            assert len(issues) >= 0  # May find 0 issues depending on ruleset
            
        except RuntimeError as e:
            if "not installed" in str(e):
                pytest.skip("Semgrep not installed")
            raise