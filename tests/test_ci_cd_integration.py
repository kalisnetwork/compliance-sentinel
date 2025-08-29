"""Tests for CI/CD pipeline integration."""

import pytest
import tempfile
import os
import json
import yaml
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.ci_cd.security_gate import SecurityGateConfig, SecurityGateEvaluator, SecurityGateResult
from compliance_sentinel.ci_cd.jenkins_plugin import JenkinsSecurityGate
from compliance_sentinel.ci_cd.github_actions import GitHubActionsWorkflow
from compliance_sentinel.ci_cd.gitlab_ci import GitLabCIIntegration
from compliance_sentinel.ci_cd.azure_devops import AzureDevOpsExtension
from compliance_sentinel.ci_cd.deployment_validator import DeploymentSecurityValidator


class TestSecurityGateConfig:
    """Test security gate configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SecurityGateConfig()
        
        assert config.enabled is True
        assert config.fail_on_error is True
        assert config.block_on_critical is True
        assert config.block_on_high is True
        assert config.block_on_medium is False
        assert config.max_critical_issues == 0
        assert config.max_high_issues == 5
        assert config.generate_report is True
    
    def test_config_from_dict(self):
        """Test configuration creation from dictionary."""
        config_dict = {
            'enabled': True,
            'fail_on_error': False,
            'max_critical_issues': 2,
            'max_high_issues': 10,
            'excluded_files': ['*.test.js', 'test_*.py'],
            'rules': [
                {
                    'name': 'Test Rule',
                    'severity_threshold': 'HIGH',
                    'max_issues': 0,
                    'categories': ['HARDCODED_SECRETS'],
                    'action': 'block',
                    'enabled': True
                }
            ]
        }
        
        config = SecurityGateConfig.from_dict(config_dict)
        
        assert config.enabled is True
        assert config.fail_on_error is False
        assert config.max_critical_issues == 2
        assert config.max_high_issues == 10
        assert len(config.excluded_files) == 2
        assert len(config.rules) == 1
        assert config.rules[0].name == 'Test Rule'
        assert config.rules[0].severity_threshold == Severity.HIGH
    
    def test_config_to_dict(self):
        """Test configuration serialization to dictionary."""
        config = SecurityGateConfig(
            enabled=True,
            max_critical_issues=1,
            excluded_files=['*.test.js']
        )
        
        config_dict = config.to_dict()
        
        assert config_dict['enabled'] is True
        assert config_dict['max_critical_issues'] == 1
        assert config_dict['excluded_files'] == ['*.test.js']


class TestSecurityGateEvaluator:
    """Test security gate evaluation logic."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig(
            max_critical_issues=0,
            max_high_issues=2,
            max_medium_issues=5
        )
        self.evaluator = SecurityGateEvaluator(self.config)
        
        self.sample_issues = [
            SecurityIssue(
                id="critical_001", severity=Severity.CRITICAL, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="app.py", line_number=10, description="Critical issue", rule_id="rule1",
                confidence=0.9, remediation_suggestions=[], created_at=datetime.now()
            ),
            SecurityIssue(
                id="high_001", severity=Severity.HIGH, category=SecurityCategory.INJECTION,
                file_path="app.py", line_number=20, description="High issue 1", rule_id="rule2",
                confidence=0.8, remediation_suggestions=[], created_at=datetime.now()
            ),
            SecurityIssue(
                id="high_002", severity=Severity.HIGH, category=SecurityCategory.XSS,
                file_path="app.py", line_number=30, description="High issue 2", rule_id="rule3",
                confidence=0.85, remediation_suggestions=[], created_at=datetime.now()
            ),
            SecurityIssue(
                id="medium_001", severity=Severity.MEDIUM, category=SecurityCategory.INPUT_VALIDATION,
                file_path="utils.py", line_number=15, description="Medium issue", rule_id="rule4",
                confidence=0.7, remediation_suggestions=[], created_at=datetime.now()
            )
        ]
    
    def test_evaluation_with_blocking_issues(self):
        """Test evaluation when issues exceed thresholds."""
        result = self.evaluator.evaluate(self.sample_issues, 2.5, 10)
        
        assert result.status.value == 'failed'
        assert result.total_issues == 4
        assert len(result.blocked_issues) > 0
        assert result.issues_by_severity[Severity.CRITICAL] == 1
        assert result.issues_by_severity[Severity.HIGH] == 2
        assert result.issues_by_severity[Severity.MEDIUM] == 1
        assert len(result.failed_rules) > 0
    
    def test_evaluation_with_passing_issues(self):
        """Test evaluation when issues are within thresholds."""
        # Remove critical issue and one high issue
        passing_issues = self.sample_issues[1:3]  # 2 high issues, within limit
        
        result = self.evaluator.evaluate(passing_issues, 1.5, 8)
        
        assert result.status.value == 'passed'
        assert result.total_issues == 2
        assert len(result.blocked_issues) == 0
        assert result.issues_by_severity[Severity.HIGH] == 2
    
    def test_evaluation_with_excluded_files(self):
        """Test evaluation with file exclusions."""
        config = SecurityGateConfig(
            max_critical_issues=0,
            excluded_files=['app.py']
        )
        evaluator = SecurityGateEvaluator(config)
        
        result = evaluator.evaluate(self.sample_issues, 2.0, 10)
        
        # Only utils.py issue should remain
        assert result.total_issues == 1
        assert result.all_issues[0].file_path == "utils.py"
    
    def test_custom_rules_evaluation(self):
        """Test evaluation with custom rules."""
        from compliance_sentinel.ci_cd.security_gate import SecurityGateRule, SecurityGateAction
        
        custom_rule = SecurityGateRule(
            name="No Hardcoded Secrets",
            severity_threshold=Severity.HIGH,
            max_issues=0,
            categories=[SecurityCategory.HARDCODED_SECRETS],
            action=SecurityGateAction.BLOCK
        )
        
        config = SecurityGateConfig(rules=[custom_rule])
        evaluator = SecurityGateEvaluator(config)
        
        result = evaluator.evaluate(self.sample_issues, 2.0, 10)
        
        # Should fail due to critical hardcoded secret
        assert result.status.value == 'failed'
        assert any("No Hardcoded Secrets" in rule for rule in result.failed_rules)


class TestJenkinsIntegration:
    """Test Jenkins plugin integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig(max_critical_issues=0, max_high_issues=1)
        self.jenkins_gate = JenkinsSecurityGate(self.config)
    
    @patch('compliance_sentinel.ci_cd.jenkins_plugin.ProjectAnalyzer')
    def test_jenkins_security_scan(self, mock_analyzer):
        """Test Jenkins security scan execution."""
        # Mock analyzer results
        mock_scan_result = {
            'issues': [
                SecurityIssue(
                    id="jenkins_001", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
                    file_path="src/main.py", line_number=10, description="Jenkins test issue",
                    rule_id="test_rule", confidence=0.9, remediation_suggestions=[], created_at=datetime.now()
                )
            ],
            'summary': {
                'scan_duration': 3.2,
                'files_scanned': 15
            }
        }
        
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.jenkins_gate.execute_security_scan(temp_dir)
            
            assert isinstance(result, SecurityGateResult)
            assert result.total_issues == 1
            assert result.scan_duration == 3.2
            assert result.files_scanned == 15
            
            # Check that reports were generated
            reports_dir = Path(temp_dir) / "security-reports"
            assert reports_dir.exists()
    
    def test_jenkins_junit_xml_generation(self):
        """Test JUnit XML report generation."""
        sample_result = SecurityGateResult(
            status='failed',
            total_issues=1,
            issues_by_severity={Severity.HIGH: 1},
            issues_by_category={SecurityCategory.HARDCODED_SECRETS: 1},
            blocked_issues=[
                SecurityIssue(
                    id="junit_001", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
                    file_path="test.py", line_number=5, description="JUnit test issue",
                    rule_id="junit_rule", confidence=0.8, remediation_suggestions=[], created_at=datetime.now()
                )
            ],
            warning_issues=[],
            all_issues=[],
            scan_duration=1.5,
            files_scanned=5,
            timestamp=datetime.now(),
            failed_rules=['Test rule failed'],
            passed_rules=['Other rule passed'],
            summary_message="Test failed",
            detailed_messages=["Detail 1", "Detail 2"]
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            junit_path = Path(temp_dir) / "junit-report.xml"
            self.jenkins_gate._generate_junit_xml(sample_result, junit_path)
            
            assert junit_path.exists()
            
            # Verify XML content
            xml_content = junit_path.read_text()
            assert 'testsuite' in xml_content
            assert 'testcase' in xml_content
            assert 'failure' in xml_content


class TestGitHubActionsIntegration:
    """Test GitHub Actions integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig()
        self.github_workflow = GitHubActionsWorkflow(self.config)
    
    @patch.dict(os.environ, {
        'GITHUB_WORKSPACE': '/tmp/test',
        'GITHUB_EVENT_NAME': 'pull_request',
        'GITHUB_REPOSITORY': 'test/repo',
        'GITHUB_SHA': 'abc123'
    })
    @patch('compliance_sentinel.ci_cd.github_actions.ProjectAnalyzer')
    def test_github_actions_execution(self, mock_analyzer):
        """Test GitHub Actions workflow execution."""
        mock_scan_result = {
            'issues': [],
            'summary': {'scan_duration': 2.1, 'files_scanned': 8}
        }
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.github_workflow.execute_action(temp_dir)
            
            assert isinstance(result, SecurityGateResult)
            assert result.status.value == 'passed'
            assert result.total_issues == 0
    
    def test_sarif_report_generation(self):
        """Test SARIF report generation for GitHub Security tab."""
        sample_issues = [
            SecurityIssue(
                id="sarif_001", severity=Severity.HIGH, category=SecurityCategory.INJECTION,
                file_path="app.py", line_number=15, description="SARIF test issue",
                rule_id="sarif_rule", confidence=0.9, remediation_suggestions=["Fix it"], created_at=datetime.now()
            )
        ]
        
        sample_result = SecurityGateResult(
            status='failed', total_issues=1, issues_by_severity={Severity.HIGH: 1},
            issues_by_category={SecurityCategory.INJECTION: 1}, blocked_issues=sample_issues,
            warning_issues=[], all_issues=sample_issues, scan_duration=1.0, files_scanned=3,
            timestamp=datetime.now(), failed_rules=[], passed_rules=[], summary_message="Test",
            detailed_messages=[]
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            sarif_path = Path(temp_dir) / "test.sarif"
            self.github_workflow._generate_sarif_report(sample_result, sarif_path)
            
            assert sarif_path.exists()
            
            # Verify SARIF content
            with open(sarif_path, 'r') as f:
                sarif_data = json.load(f)
            
            assert sarif_data['version'] == '2.1.0'
            assert len(sarif_data['runs']) == 1
            assert len(sarif_data['runs'][0]['results']) == 1
            assert sarif_data['runs'][0]['results'][0]['ruleId'] == 'sarif_rule'


class TestGitLabCIIntegration:
    """Test GitLab CI integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig()
        self.gitlab_ci = GitLabCIIntegration(self.config)
    
    @patch.dict(os.environ, {
        'CI_PROJECT_DIR': '/tmp/test',
        'CI_PROJECT_ID': '123',
        'CI_PIPELINE_ID': '456',
        'CI_MERGE_REQUEST_IID': '789'
    })
    @patch('compliance_sentinel.ci_cd.gitlab_ci.ProjectAnalyzer')
    def test_gitlab_ci_execution(self, mock_analyzer):
        """Test GitLab CI job execution."""
        mock_scan_result = {
            'issues': [],
            'summary': {'scan_duration': 1.8, 'files_scanned': 12}
        }
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.gitlab_ci.execute_security_job(temp_dir)
            
            assert isinstance(result, SecurityGateResult)
            assert result.status.value == 'passed'
    
    def test_gitlab_security_report_format(self):
        """Test GitLab Security Report format generation."""
        sample_issues = [
            SecurityIssue(
                id="gitlab_001", severity=Severity.CRITICAL, category=SecurityCategory.HARDCODED_SECRETS,
                file_path="config.py", line_number=8, description="GitLab test issue",
                rule_id="gitlab_rule", confidence=0.95, remediation_suggestions=[], created_at=datetime.now()
            )
        ]
        
        sample_result = SecurityGateResult(
            status='failed', total_issues=1, issues_by_severity={Severity.CRITICAL: 1},
            issues_by_category={SecurityCategory.HARDCODED_SECRETS: 1}, blocked_issues=sample_issues,
            warning_issues=[], all_issues=sample_issues, scan_duration=2.0, files_scanned=6,
            timestamp=datetime.now(), failed_rules=[], passed_rules=[], summary_message="Test",
            detailed_messages=[]
        )
        
        gitlab_report = self.gitlab_ci._generate_gitlab_security_report(sample_result)
        
        assert gitlab_report['version'] == '14.0.0'
        assert len(gitlab_report['vulnerabilities']) == 1
        
        vuln = gitlab_report['vulnerabilities'][0]
        assert vuln['id'] == 'gitlab_001'
        assert vuln['severity'] == 'Critical'
        assert vuln['location']['file'] == 'config.py'
        assert vuln['location']['start_line'] == 8


class TestAzureDevOpsIntegration:
    """Test Azure DevOps integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig()
        self.azure_devops = AzureDevOpsExtension(self.config)
    
    @patch.dict(os.environ, {
        'BUILD_SOURCESDIRECTORY': '/tmp/test',
        'BUILD_BUILDID': '123',
        'SYSTEM_TEAMPROJECT': 'TestProject'
    })
    @patch('compliance_sentinel.ci_cd.azure_devops.ProjectAnalyzer')
    def test_azure_devops_execution(self, mock_analyzer):
        """Test Azure DevOps pipeline task execution."""
        mock_scan_result = {
            'issues': [],
            'summary': {'scan_duration': 2.3, 'files_scanned': 20}
        }
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.azure_devops.execute_pipeline_task(temp_dir)
            
            assert isinstance(result, SecurityGateResult)
            assert result.status.value == 'passed'
    
    def test_vstest_report_generation(self):
        """Test VSTest (TRX) report generation."""
        sample_result = SecurityGateResult(
            status='passed', total_issues=0, issues_by_severity={}, issues_by_category={},
            blocked_issues=[], warning_issues=[], all_issues=[], scan_duration=1.2,
            files_scanned=10, timestamp=datetime.now(), failed_rules=[], passed_rules=[],
            summary_message="All tests passed", detailed_messages=[]
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            trx_path = Path(temp_dir) / "test-results.trx"
            self.azure_devops._generate_vstest_report(sample_result, trx_path)
            
            assert trx_path.exists()
            
            # Verify TRX content
            trx_content = trx_path.read_text()
            assert 'TestRun' in trx_content
            assert 'UnitTestResult' in trx_content


class TestDeploymentValidator:
    """Test deployment security validator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = SecurityGateConfig(
            max_critical_issues=0,
            max_high_issues=0  # Strict for production
        )
        self.validator = DeploymentSecurityValidator(self.config)
    
    @patch('compliance_sentinel.ci_cd.deployment_validator.ProjectAnalyzer')
    def test_production_deployment_validation(self, mock_analyzer):
        """Test production deployment validation."""
        # Mock scan with no issues (should pass)
        mock_scan_result = {
            'issues': [],
            'summary': {'scan_duration': 1.5, 'files_scanned': 25}
        }
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            is_approved, result = self.validator.validate_deployment(
                temp_dir, 
                environment="production"
            )
            
            assert is_approved is True
            assert result.status.value == 'passed'
    
    @patch('compliance_sentinel.ci_cd.deployment_validator.ProjectAnalyzer')
    def test_deployment_with_security_issues(self, mock_analyzer):
        """Test deployment validation with security issues."""
        # Mock scan with critical issue (should fail)
        critical_issue = SecurityIssue(
            id="deploy_001", severity=Severity.CRITICAL, category=SecurityCategory.HARDCODED_SECRETS,
            file_path="prod.py", line_number=5, description="Critical deployment issue",
            rule_id="deploy_rule", confidence=0.9, remediation_suggestions=[], created_at=datetime.now()
        )
        
        mock_scan_result = {
            'issues': [critical_issue],
            'summary': {'scan_duration': 2.0, 'files_scanned': 30}
        }
        mock_analyzer.return_value.scan_project.return_value = mock_scan_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            is_approved, result = self.validator.validate_deployment(
                temp_dir,
                environment="production"
            )
            
            assert is_approved is False
            assert result.status.value == 'failed'
            assert len(result.blocked_issues) > 0
    
    def test_deployment_artifacts_validation(self):
        """Test deployment artifacts validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create sensitive files that shouldn't be deployed
            sensitive_file = Path(temp_dir) / ".env"
            sensitive_file.write_text("SECRET_KEY=abc123")
            
            debug_file = Path(temp_dir) / "debug.py"
            debug_file.write_text("print('debug mode')")
            
            artifacts_check = self.validator._validate_deployment_artifacts(temp_dir)
            
            assert artifacts_check['passed'] is False
            assert len(artifacts_check['issues']) > 0
            assert any('.env' in issue for issue in artifacts_check['issues'])
    
    def test_environment_requirements_validation(self):
        """Test environment-specific requirements validation."""
        # Test with hardcoded secrets in production (should fail)
        secret_issue = SecurityIssue(
            id="env_001", severity=Severity.HIGH, category=SecurityCategory.HARDCODED_SECRETS,
            file_path="app.py", line_number=10, description="Hardcoded secret",
            rule_id="secret_rule", confidence=0.9, remediation_suggestions=[], created_at=datetime.now()
        )
        
        env_check = self.validator._validate_environment_requirements([secret_issue], "production")
        
        assert env_check['passed'] is False
        assert 'hardcoded secrets not allowed' in env_check['message'].lower()
        
        # Test same issue in development (should pass)
        env_check_dev = self.validator._validate_environment_requirements([secret_issue], "development")
        
        assert env_check_dev['passed'] is True


class TestCICDTemplates:
    """Test CI/CD template generation."""
    
    def test_jenkins_pipeline_template(self):
        """Test Jenkins pipeline script generation."""
        from compliance_sentinel.ci_cd.jenkins_plugin import create_jenkins_pipeline_script
        
        pipeline_script = create_jenkins_pipeline_script()
        
        assert 'pipeline {' in pipeline_script
        assert 'Security Scan' in pipeline_script
        assert 'compliance_sentinel' in pipeline_script
        assert 'publishHTML' in pipeline_script
    
    def test_github_workflow_template(self):
        """Test GitHub Actions workflow generation."""
        from compliance_sentinel.ci_cd.github_actions import create_github_workflow
        
        workflow_yaml = create_github_workflow()
        
        assert 'name: Security Scan' in workflow_yaml
        assert 'uses: actions/checkout@v3' in workflow_yaml
        assert 'upload-sarif@v2' in workflow_yaml
        assert 'compliance-sentinel' in workflow_yaml
    
    def test_gitlab_ci_template(self):
        """Test GitLab CI template generation."""
        from compliance_sentinel.ci_cd.gitlab_ci import create_gitlab_ci_template
        
        gitlab_yaml = create_gitlab_ci_template()
        
        assert 'security_scan:' in gitlab_yaml
        assert 'sast:' in gitlab_yaml
        assert 'codequality:' in gitlab_yaml
        assert 'compliance-sentinel' in gitlab_yaml
    
    def test_azure_pipeline_template(self):
        """Test Azure DevOps pipeline template generation."""
        from compliance_sentinel.ci_cd.azure_devops import create_azure_pipeline_template
        
        pipeline_yaml = create_azure_pipeline_template()
        
        assert 'SecurityScan' in pipeline_yaml
        assert 'PublishTestResults@2' in pipeline_yaml
        assert 'PublishSecurityAnalysisLogs@3' in pipeline_yaml
        assert 'compliance-sentinel' in pipeline_yaml


if __name__ == "__main__":
    pytest.main([__file__])