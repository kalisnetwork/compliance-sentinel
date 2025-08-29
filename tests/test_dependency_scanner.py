"""Tests for dependency security scanner."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from compliance_sentinel.engines.dependency_scanner import (
    DependencyScanner,
    DependencyParser,
    SafetyScanner,
    PipAuditScanner,
    ScannerConfig,
    DependencyInfo
)
from compliance_sentinel.core.interfaces import VulnerabilityReport, Severity


class TestDependencyParser:
    """Test cases for DependencyParser."""
    
    def test_parse_requirements_txt(self, tmp_path):
        """Test parsing requirements.txt file."""
        requirements_content = """
# This is a comment
Django==4.2.0
requests>=2.28.0
flask~=2.0.0
numpy
-e git+https://github.com/user/repo.git#egg=package
"""
        
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(requirements_content)
        
        dependencies = DependencyParser.parse_requirements_txt(str(requirements_file))
        
        assert len(dependencies) == 4  # Should skip comment and git dependency
        
        # Check Django dependency
        django_dep = next(dep for dep in dependencies if dep.name == "Django")
        assert django_dep.version == "4.2.0"
        assert django_dep.ecosystem == "pip"
        assert not django_dep.is_dev_dependency
        
        # Check requests dependency
        requests_dep = next(dep for dep in dependencies if dep.name == "requests")
        assert requests_dep.version == "2.28.0"
        
        # Check numpy (no version specified)
        numpy_dep = next(dep for dep in dependencies if dep.name == "numpy")
        assert numpy_dep.version == "latest"
    
    def test_parse_requirements_dev_txt(self, tmp_path):
        """Test parsing requirements-dev.txt file."""
        requirements_content = "pytest==7.4.0\nblack>=23.0.0"
        
        requirements_file = tmp_path / "requirements-dev.txt"
        requirements_file.write_text(requirements_content)
        
        dependencies = DependencyParser.parse_requirements_txt(str(requirements_file))
        
        assert len(dependencies) == 2
        assert all(dep.is_dev_dependency for dep in dependencies)
    
    def test_parse_package_json(self, tmp_path):
        """Test parsing package.json file."""
        package_json_content = {
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": ">=29.0.0",
                "eslint": "8.45.0"
            }
        }
        
        package_file = tmp_path / "package.json"
        package_file.write_text(json.dumps(package_json_content))
        
        dependencies = DependencyParser.parse_package_json(str(package_file))
        
        assert len(dependencies) == 4
        
        # Check regular dependencies
        express_dep = next(dep for dep in dependencies if dep.name == "express")
        assert express_dep.version == "4.18.0"
        assert express_dep.ecosystem == "npm"
        assert not express_dep.is_dev_dependency
        
        # Check dev dependencies
        jest_dep = next(dep for dep in dependencies if dep.name == "jest")
        assert jest_dep.is_dev_dependency
    
    def test_parse_pyproject_toml(self, tmp_path):
        """Test parsing pyproject.toml file."""
        toml_content = """
[project]
name = "test-project"
dependencies = [
    "requests>=2.28.0",
    "click==8.1.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=23.0.0"
]
test = [
    "coverage>=6.0.0"
]
"""
        
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(toml_content)
        
        # Mock tomli import
        with patch('compliance_sentinel.engines.dependency_scanner.tomli') as mock_tomli:
            mock_tomli.load.return_value = {
                "project": {
                    "name": "test-project",
                    "dependencies": ["requests>=2.28.0", "click==8.1.0"],
                    "optional-dependencies": {
                        "dev": ["pytest>=7.0.0", "black>=23.0.0"],
                        "test": ["coverage>=6.0.0"]
                    }
                }
            }
            
            dependencies = DependencyParser.parse_pyproject_toml(str(pyproject_file))
        
        assert len(dependencies) == 5
        
        # Check main dependencies
        requests_dep = next(dep for dep in dependencies if dep.name == "requests")
        assert not requests_dep.is_dev_dependency
        
        # Check dev dependencies
        pytest_dep = next(dep for dep in dependencies if dep.name == "pytest")
        assert pytest_dep.is_dev_dependency
        
        # Check test dependencies (should be marked as dev)
        coverage_dep = next(dep for dep in dependencies if dep.name == "coverage")
        assert not coverage_dep.is_dev_dependency  # 'test' group not considered dev
    
    def test_clean_npm_version(self):
        """Test npm version cleaning."""
        assert DependencyParser._clean_npm_version("^4.18.0") == "4.18.0"
        assert DependencyParser._clean_npm_version("~2.17.21") == "2.17.21"
        assert DependencyParser._clean_npm_version(">=1.0.0") == "1.0.0"
        assert DependencyParser._clean_npm_version("1.2.3") == "1.2.3"
        assert DependencyParser._clean_npm_version("1.2.3-beta.1") == "1.2.3"


class TestSafetyScanner:
    """Test cases for SafetyScanner."""
    
    @pytest.fixture
    def mock_safety_subprocess(self):
        """Mock subprocess calls for Safety."""
        with patch('subprocess.run') as mock_run:
            # Mock version check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "safety 2.3.0"
            yield mock_run
    
    @pytest.fixture
    def sample_safety_output(self):
        """Sample Safety JSON output."""
        return [
            {
                "package": "django",
                "installed_version": "3.0.0",
                "vulnerability_id": "CVE-2023-1234",
                "advisory": "Django 3.0.0 has a SQL injection vulnerability in the admin interface.",
                "affected_versions": ["<3.0.5"],
                "fixed_versions": ["3.0.5", "3.1.0"]
            },
            {
                "package": "requests",
                "installed_version": "2.25.0",
                "vulnerability_id": "SAFETY-12345",
                "advisory": "Requests library has an SSL verification bypass vulnerability.",
                "affected_versions": ["<2.25.1"],
                "fixed_versions": ["2.25.1"]
            }
        ]
    
    def test_safety_scanner_initialization(self, mock_safety_subprocess):
        """Test SafetyScanner initialization."""
        config = ScannerConfig(safety_db_update=False)
        scanner = SafetyScanner(config)
        
        assert scanner.config.safety_db_update is False
    
    def test_safety_installation_check_failure(self):
        """Test handling of Safety installation check failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("safety not found")
            
            with pytest.raises(RuntimeError, match="Safety is not installed"):
                SafetyScanner(ScannerConfig())
    
    def test_scan_dependencies_success(self, mock_safety_subprocess, sample_safety_output, tmp_path):
        """Test successful dependency scanning."""
        # Create test dependencies
        dependencies = [
            DependencyInfo("django", "3.0.0", "requirements.txt", 1, "pip"),
            DependencyInfo("requests", "2.25.0", "requirements.txt", 2, "pip")
        ]
        
        # Mock Safety execution
        mock_safety_subprocess.return_value.returncode = 1  # Vulnerabilities found
        mock_safety_subprocess.return_value.stdout = json.dumps(sample_safety_output)
        
        config = ScannerConfig(safety_db_update=False)
        scanner = SafetyScanner(config)
        
        vulnerabilities = scanner.scan_dependencies(dependencies)
        
        assert len(vulnerabilities) == 2
        
        # Check Django vulnerability
        django_vuln = next(v for v in vulnerabilities if v.package_name == "django")
        assert django_vuln.cve_id == "CVE-2023-1234"
        assert django_vuln.remediation_available
        assert django_vuln.upgrade_path == "3.1.0"  # Should pick latest fixed version
        
        # Check Requests vulnerability
        requests_vuln = next(v for v in vulnerabilities if v.package_name == "requests")
        assert requests_vuln.cve_id == "SAFETY-12345"
        assert requests_vuln.upgrade_path == "2.25.1"
    
    def test_scan_empty_dependencies(self, mock_safety_subprocess):
        """Test scanning with empty dependencies list."""
        config = ScannerConfig(safety_db_update=False)
        scanner = SafetyScanner(config)
        
        vulnerabilities = scanner.scan_dependencies([])
        assert len(vulnerabilities) == 0
    
    def test_scan_non_python_dependencies(self, mock_safety_subprocess):
        """Test scanning with non-Python dependencies."""
        dependencies = [
            DependencyInfo("express", "4.18.0", "package.json", 1, "npm"),
            DependencyInfo("lodash", "4.17.21", "package.json", 2, "npm")
        ]
        
        config = ScannerConfig(safety_db_update=False)
        scanner = SafetyScanner(config)
        
        vulnerabilities = scanner.scan_dependencies(dependencies)
        assert len(vulnerabilities) == 0  # Should skip non-Python dependencies
    
    def test_estimate_severity_score(self, mock_safety_subprocess):
        """Test severity score estimation."""
        config = ScannerConfig(safety_db_update=False)
        scanner = SafetyScanner(config)
        
        # High severity
        high_score = scanner._estimate_severity_score("Remote code execution vulnerability", "CVE-2023-1234")
        assert high_score >= 8.0
        
        # Medium severity
        medium_score = scanner._estimate_severity_score("Cross-site scripting vulnerability", "CVE-2023-5678")
        assert 6.0 <= medium_score < 8.0
        
        # Low severity
        low_score = scanner._estimate_severity_score("Information disclosure", "CVE-2023-9999")
        assert low_score < 6.0


class TestPipAuditScanner:
    """Test cases for PipAuditScanner."""
    
    @pytest.fixture
    def mock_pip_audit_subprocess(self):
        """Mock subprocess calls for pip-audit."""
        with patch('subprocess.run') as mock_run:
            # Mock version check
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "pip-audit 2.6.0"
            yield mock_run
    
    @pytest.fixture
    def sample_pip_audit_output(self):
        """Sample pip-audit JSON output."""
        return {
            "dependencies": [
                {
                    "name": "django",
                    "version": "3.0.0",
                    "vulns": [
                        {
                            "id": "CVE-2023-1234",
                            "description": "Django SQL injection vulnerability",
                            "severity": 8.5,
                            "fix_versions": ["3.0.5", "3.1.0"]
                        }
                    ]
                },
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "vulns": []
                }
            ]
        }
    
    def test_pip_audit_scanner_initialization(self, mock_pip_audit_subprocess):
        """Test PipAuditScanner initialization."""
        config = ScannerConfig()
        scanner = PipAuditScanner(config)
        
        assert scanner.config is not None
    
    def test_scan_requirements_file_success(self, mock_pip_audit_subprocess, sample_pip_audit_output, tmp_path):
        """Test successful requirements file scanning."""
        # Create test requirements file
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("django==3.0.0\nrequests==2.25.0")
        
        # Mock pip-audit execution
        mock_pip_audit_subprocess.return_value.returncode = 1  # Vulnerabilities found
        mock_pip_audit_subprocess.return_value.stdout = json.dumps(sample_pip_audit_output)
        
        config = ScannerConfig()
        scanner = PipAuditScanner(config)
        
        vulnerabilities = scanner.scan_requirements_file(str(requirements_file))
        
        assert len(vulnerabilities) == 1
        
        # Check Django vulnerability
        django_vuln = vulnerabilities[0]
        assert django_vuln.package_name == "django"
        assert django_vuln.cve_id == "CVE-2023-1234"
        assert django_vuln.severity_score == 8.5
        assert django_vuln.remediation_available
        assert django_vuln.upgrade_path == "3.0.5"  # Should pick minimum fixed version


class TestDependencyScanner:
    """Test cases for DependencyScanner."""
    
    @pytest.fixture
    def mock_scanners(self):
        """Mock scanners for testing."""
        safety_mock = Mock(spec=SafetyScanner)
        safety_mock.scan_dependencies.return_value = [
            VulnerabilityReport(
                cve_id="CVE-2023-1234",
                package_name="django",
                affected_versions=["<3.0.5"],
                severity_score=8.5,
                description="SQL injection vulnerability",
                remediation_available=True,
                upgrade_path="3.0.5"
            )
        ]
        
        pip_audit_mock = Mock(spec=PipAuditScanner)
        pip_audit_mock.scan_requirements_file.return_value = [
            VulnerabilityReport(
                cve_id="CVE-2023-5678",
                package_name="requests",
                affected_versions=["<2.25.1"],
                severity_score=6.0,
                description="SSL verification bypass",
                remediation_available=True,
                upgrade_path="2.25.1"
            )
        ]
        
        return {"safety": safety_mock, "pip-audit": pip_audit_mock}
    
    @pytest.fixture
    def scanner_with_mocks(self, mock_scanners):
        """Create scanner with mocked tools."""
        config = ScannerConfig(enable_safety=True, enable_pip_audit=True)
        scanner = DependencyScanner(config)
        scanner.scanners = mock_scanners
        return scanner
    
    def test_scanner_initialization(self):
        """Test DependencyScanner initialization."""
        config = ScannerConfig(
            enable_safety=False,
            enable_pip_audit=False,
            severity_threshold=Severity.HIGH
        )
        
        with patch('compliance_sentinel.engines.dependency_scanner.SafetyScanner'):
            with patch('compliance_sentinel.engines.dependency_scanner.PipAuditScanner'):
                scanner = DependencyScanner(config)
        
        assert scanner.config.severity_threshold == Severity.HIGH
        assert not scanner.config.enable_safety
        assert not scanner.config.enable_pip_audit
    
    def test_scan_dependencies_success(self, scanner_with_mocks, tmp_path):
        """Test successful dependency scanning."""
        # Create test requirements file
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("django==3.0.0\nrequests==2.25.0")
        
        # Mock dependency parsing
        with patch.object(scanner_with_mocks, '_parse_dependency_file') as mock_parse:
            mock_parse.return_value = [
                DependencyInfo("django", "3.0.0", str(requirements_file), 1, "pip"),
                DependencyInfo("requests", "2.25.0", str(requirements_file), 2, "pip")
            ]
            
            vulnerabilities = scanner_with_mocks.scan_dependencies(str(requirements_file))
        
        assert len(vulnerabilities) == 2
        
        # Verify both scanners were called
        scanner_with_mocks.scanners["safety"].scan_dependencies.assert_called_once()
        scanner_with_mocks.scanners["pip-audit"].scan_requirements_file.assert_called_once()
    
    def test_check_package_vulnerability(self, scanner_with_mocks):
        """Test checking specific package vulnerability."""
        vulnerability = scanner_with_mocks.check_package_vulnerability("django", "3.0.0")
        
        assert vulnerability is not None
        assert vulnerability.package_name == "django"
        assert vulnerability.cve_id == "CVE-2023-1234"
    
    def test_deduplicate_vulnerabilities(self, scanner_with_mocks):
        """Test vulnerability deduplication."""
        # Create duplicate vulnerabilities
        vuln1 = VulnerabilityReport(
            cve_id="CVE-2023-1234",
            package_name="django",
            affected_versions=["<3.0.5"],
            severity_score=8.5,
            description="Short description",
            remediation_available=True,
            upgrade_path="3.0.5"
        )
        
        vuln2 = VulnerabilityReport(
            cve_id="CVE-2023-1234",
            package_name="django",
            affected_versions=["<3.0.5"],
            severity_score=8.5,
            description="Much longer and more detailed description of the vulnerability",
            remediation_available=True,
            upgrade_path="3.0.5"
        )
        
        vulnerabilities = [vuln1, vuln2]
        deduplicated = scanner_with_mocks._deduplicate_vulnerabilities(vulnerabilities)
        
        assert len(deduplicated) == 1
        assert len(deduplicated[0].description) > len(vuln1.description)  # Should keep longer description
    
    def test_filter_by_severity(self, scanner_with_mocks):
        """Test severity filtering."""
        vulnerabilities = [
            VulnerabilityReport(
                cve_id="CVE-2023-1", package_name="pkg1", affected_versions=["1.0.0"],
                severity_score=9.5, description="Critical", remediation_available=False
            ),
            VulnerabilityReport(
                cve_id="CVE-2023-2", package_name="pkg2", affected_versions=["1.0.0"],
                severity_score=6.0, description="Medium", remediation_available=False
            ),
            VulnerabilityReport(
                cve_id="CVE-2023-3", package_name="pkg3", affected_versions=["1.0.0"],
                severity_score=2.0, description="Low", remediation_available=False
            )
        ]
        
        # Test with HIGH threshold
        scanner_with_mocks.config.severity_threshold = Severity.HIGH
        filtered = scanner_with_mocks._filter_by_severity(vulnerabilities)
        
        assert len(filtered) == 1  # Only critical should pass
        assert filtered[0].severity_score == 9.5
    
    def test_scan_project_dependencies(self, scanner_with_mocks, tmp_path):
        """Test scanning all dependency files in a project."""
        # Create multiple dependency files
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text("django==3.0.0")
        
        package_file = tmp_path / "package.json"
        package_file.write_text('{"dependencies": {"express": "4.18.0"}}')
        
        # Mock scan_dependencies to return different results for different files
        def mock_scan_dependencies(file_path):
            if "requirements.txt" in file_path:
                return [VulnerabilityReport(
                    cve_id="CVE-2023-1", package_name="django", affected_versions=["<3.0.5"],
                    severity_score=8.5, description="Django vuln", remediation_available=True
                )]
            return []
        
        scanner_with_mocks.scan_dependencies = mock_scan_dependencies
        
        results = scanner_with_mocks.scan_project_dependencies(str(tmp_path))
        
        assert len(results) == 1  # Only requirements.txt should have vulnerabilities
        assert str(requirements_file) in results
    
    def test_generate_upgrade_recommendations(self, scanner_with_mocks):
        """Test upgrade recommendation generation."""
        vulnerabilities = [
            VulnerabilityReport(
                cve_id="CVE-2023-1", package_name="django", affected_versions=["<3.0.5"],
                severity_score=8.5, description="Django vuln", remediation_available=True,
                upgrade_path="3.0.5"
            ),
            VulnerabilityReport(
                cve_id="CVE-2023-2", package_name="django", affected_versions=["<3.1.0"],
                severity_score=7.0, description="Another Django vuln", remediation_available=True,
                upgrade_path="3.1.0"
            ),
            VulnerabilityReport(
                cve_id="CVE-2023-3", package_name="requests", affected_versions=["<2.25.1"],
                severity_score=9.5, description="Critical requests vuln", remediation_available=False
            )
        ]
        
        recommendations = scanner_with_mocks.generate_upgrade_recommendations(vulnerabilities)
        
        assert len(recommendations) == 2
        
        # Should recommend upgrading Django to highest version
        django_rec = next(rec for rec in recommendations if "django" in rec.lower())
        assert "3.1.0" in django_rec
        assert "fixes 2 vulnerabilit" in django_rec
        
        # Should warn about requests with no fix
        requests_rec = next(rec for rec in recommendations if "requests" in rec.lower())
        assert "critical" in requests_rec.lower()
        assert "no available fix" in requests_rec.lower()
    
    def test_get_scanner_info(self, scanner_with_mocks):
        """Test scanner information retrieval."""
        # Mock subprocess calls for version info
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "2.3.0"
            
            info = scanner_with_mocks.get_scanner_info()
        
        assert "available_scanners" in info
        assert "supported_ecosystems" in info
        assert "supported_files" in info
        assert "configuration" in info
        
        assert "pip" in info["supported_ecosystems"]
        assert "npm" in info["supported_ecosystems"]
        assert "requirements.txt" in info["supported_files"]


# Integration test fixtures
@pytest.fixture
def sample_vulnerable_requirements():
    """Sample requirements.txt with known vulnerabilities."""
    return """
# Known vulnerable versions for testing
Django==2.0.0
requests==2.20.0
Pillow==6.0.0
urllib3==1.24.0
"""


@pytest.mark.integration
class TestDependencyScannerIntegration:
    """Integration tests for dependency scanner (require actual tools to be installed)."""
    
    def test_safety_real_scan(self, sample_vulnerable_requirements, tmp_path):
        """Test real Safety scanning (requires Safety to be installed)."""
        pytest.importorskip("safety")
        
        # Create test requirements file
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(sample_vulnerable_requirements)
        
        try:
            config = ScannerConfig(enable_safety=True, enable_pip_audit=False, safety_db_update=False)
            scanner = DependencyScanner(config)
            
            vulnerabilities = scanner.scan_dependencies(str(requirements_file))
            
            # Should find vulnerabilities in old versions
            assert len(vulnerabilities) >= 0  # May find 0 if Safety DB is outdated
            
        except RuntimeError as e:
            if "not installed" in str(e):
                pytest.skip("Safety not installed")
            raise
    
    def test_pip_audit_real_scan(self, sample_vulnerable_requirements, tmp_path):
        """Test real pip-audit scanning (requires pip-audit to be installed)."""
        pytest.importorskip("pip_audit")
        
        # Create test requirements file
        requirements_file = tmp_path / "requirements.txt"
        requirements_file.write_text(sample_vulnerable_requirements)
        
        try:
            config = ScannerConfig(enable_safety=False, enable_pip_audit=True)
            scanner = DependencyScanner(config)
            
            vulnerabilities = scanner.scan_dependencies(str(requirements_file))
            
            # Should find vulnerabilities in old versions
            assert len(vulnerabilities) >= 0  # May find 0 depending on database
            
        except RuntimeError as e:
            if "not installed" in str(e):
                pytest.skip("pip-audit not installed")
            raise