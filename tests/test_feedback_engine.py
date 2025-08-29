"""Tests for feedback and remediation engine."""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from compliance_sentinel.engines.feedback_engine import (
    FeedbackEngine,
    RemediationDatabase,
    RemediationAction,
    RemediationPriority,
    FeedbackReport
)
from compliance_sentinel.core.interfaces import (
    SecurityIssue,
    SecurityCategory,
    Severity
)
from compliance_sentinel.models.analysis import AnalysisResponse
from compliance_sentinel.models.config import FeedbackConfig


class TestRemediationAction:
    """Test cases for RemediationAction."""
    
    def test_remediation_action_creation(self):
        """Test creating a remediation action."""
        action = RemediationAction(
            action_id="test_action_1",
            title="Fix SQL Injection",
            description="Implement parameterized queries",
            priority=RemediationPriority.IMMEDIATE,
            effort_level="medium",
            impact_level="high",
            estimated_time_minutes=45
        )
        
        assert action.action_id == "test_action_1"
        assert action.title == "Fix SQL Injection"
        assert action.priority == RemediationPriority.IMMEDIATE
        assert action.estimated_time_minutes == 45
    
    def test_priority_score_calculation(self):
        """Test priority score calculation."""
        high_priority_action = RemediationAction(
            action_id="high",
            title="Critical Fix",
            description="Fix critical issue",
            priority=RemediationPriority.IMMEDIATE,
            effort_level="low",
            impact_level="high"
        )
        
        low_priority_action = RemediationAction(
            action_id="low",
            title="Minor Fix",
            description="Fix minor issue",
            priority=RemediationPriority.LOW,
            effort_level="high",
            impact_level="low"
        )
        
        high_score = high_priority_action.get_priority_score()
        low_score = low_priority_action.get_priority_score()
        
        assert high_score > low_score
        assert high_score > 100  # Should be high priority
        assert low_score < 50   # Should be low priority


class TestRemediationDatabase:
    """Test cases for RemediationDatabase."""
    
    def test_remediation_database_initialization(self):
        """Test remediation database initialization."""
        db = RemediationDatabase()
        
        assert len(db.remediation_templates) > 0
        assert len(db.code_examples) > 0
        assert len(db.documentation_links) > 0
    
    def test_get_remediation_actions(self):
        """Test getting remediation actions for a category."""
        db = RemediationDatabase()
        
        actions = db.get_remediation_actions(SecurityCategory.HARDCODED_SECRETS, Severity.HIGH)
        
        assert len(actions) > 0
        assert all(isinstance(action, dict) for action in actions)
        assert all("title" in action for action in actions)
        assert all("description" in action for action in actions)
    
    def test_get_code_example(self):
        """Test getting code examples."""
        db = RemediationDatabase()
        
        # Test existing code example
        example = db.get_code_example("environment_variables", "python")
        assert example is not None
        assert "os.getenv" in example
        
        # Test non-existent example
        example = db.get_code_example("nonexistent", "python")
        assert example is None
    
    def test_get_documentation_links(self):
        """Test getting documentation links."""
        db = RemediationDatabase()
        
        links = db.get_documentation_links(SecurityCategory.SQL_INJECTION)
        
        assert len(links) > 0
        assert all(link.startswith("http") for link in links)
        assert any("owasp.org" in link for link in links)


class TestFeedbackEngine:
    """Test cases for FeedbackEngine."""
    
    @pytest.fixture
    def sample_security_issues(self):
        """Create sample security issues for testing."""
        return [
            SecurityIssue(
                id="issue_1",
                severity=Severity.CRITICAL,
                category=SecurityCategory.SQL_INJECTION,
                file_path="app.py",
                line_number=25,
                description="SQL injection vulnerability detected",
                rule_id="SQL_INJECTION_001",
                confidence=0.9,
                remediation_suggestions=["Use parameterized queries"],
                created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="issue_2",
                severity=Severity.HIGH,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path="config.py",
                line_number=10,
                description="Hardcoded API key detected",
                rule_id="HARDCODED_SECRET_001",
                confidence=0.8,
                remediation_suggestions=["Use environment variables"],
                created_at=datetime.utcnow()
            ),
            SecurityIssue(
                id="issue_3",
                severity=Severity.MEDIUM,
                category=SecurityCategory.XSS,
                file_path="templates.py",
                line_number=15,
                description="Potential XSS vulnerability",
                rule_id="XSS_001",
                confidence=0.7,
                remediation_suggestions=["Sanitize user input"],
                created_at=datetime.utcnow()
            )
        ]
    
    @pytest.fixture
    def sample_analysis_result(self, sample_security_issues):
        """Create sample analysis result."""
        return AnalysisResult(
            file_path="test_project",
            timestamp=datetime.utcnow(),
            issues=sample_security_issues,
            vulnerabilities=[],
            compliance_status="NON_COMPLIANT",
            analysis_duration=2.5,
            recommendations=["Fix critical issues first"]
        )
    
    def test_feedback_engine_initialization(self):
        """Test feedback engine initialization."""
        config = FeedbackConfig(
            include_code_examples=True,
            max_suggestions_per_issue=3
        )
        
        engine = FeedbackEngine(config)
        
        assert engine.config.include_code_examples
        assert engine.config.max_suggestions_per_issue == 3
        assert engine.remediation_db is not None
    
    def test_generate_report(self, sample_analysis_result):
        """Test generating a feedback report."""
        engine = FeedbackEngine()
        
        report = engine.generate_report(sample_analysis_result)
        
        assert isinstance(report, str)
        assert "SECURITY ANALYSIS REPORT" in report
        assert "CRITICAL" in report  # Should mention critical issues
        assert "SQL injection" in report.lower()
        assert "REMEDIATION ACTIONS" in report
    
    def test_format_ide_feedback(self, sample_security_issues):
        """Test formatting feedback for IDE integration."""
        engine = FeedbackEngine()
        
        ide_feedback = engine.format_ide_feedback(sample_security_issues)
        
        assert "version" in ide_feedback
        assert "timestamp" in ide_feedback
        assert "total_issues" in ide_feedback
        assert "files" in ide_feedback
        
        assert ide_feedback["total_issues"] == 3
        
        # Check file grouping
        files = ide_feedback["files"]
        assert "app.py" in files
        assert "config.py" in files
        assert "templates.py" in files
        
        # Check issue format
        app_issues = files["app.py"]["issues"]
        assert len(app_issues) == 1
        
        issue = app_issues[0]
        assert "id" in issue
        assert "severity" in issue
        assert "line" in issue
        assert "message" in issue
        assert "remediation" in issue
    
    def test_prioritize_issues(self, sample_security_issues):
        """Test issue prioritization."""
        engine = FeedbackEngine()
        
        prioritized = engine.prioritize_issues(sample_security_issues)
        
        assert len(prioritized) == 3
        
        # Critical issue should be first
        assert prioritized[0].severity == Severity.CRITICAL
        assert prioritized[0].category == SecurityCategory.SQL_INJECTION
        
        # High severity should be second
        assert prioritized[1].severity == Severity.HIGH
        
        # Medium severity should be last
        assert prioritized[2].severity == Severity.MEDIUM
    
    def test_security_score_calculation(self):
        """Test security score calculation."""
        engine = FeedbackEngine()
        
        # Test with no issues (perfect score)
        score = engine._calculate_security_score([])
        assert score == 100.0
        
        # Test with critical issue (should significantly reduce score)
        critical_issue = SecurityIssue(
            id="critical",
            severity=Severity.CRITICAL,
            category=SecurityCategory.SQL_INJECTION,
            file_path="test.py",
            line_number=1,
            description="Critical issue",
            rule_id="TEST",
            confidence=1.0,
            remediation_suggestions=[],
            created_at=datetime.utcnow()
        )
        
        score = engine._calculate_security_score([critical_issue])
        assert score < 80.0  # Should be significantly reduced
        
        # Test with low severity issue (minor reduction)
        low_issue = SecurityIssue(
            id="low",
            severity=Severity.LOW,
            category=SecurityCategory.INPUT_VALIDATION,
            file_path="test.py",
            line_number=1,
            description="Low issue",
            rule_id="TEST",
            confidence=0.5,
            remediation_suggestions=[],
            created_at=datetime.utcnow()
        )
        
        score = engine._calculate_security_score([low_issue])
        assert score > 95.0  # Should be only slightly reduced
    
    def test_executive_summary_generation(self, sample_analysis_result):
        """Test executive summary generation."""
        engine = FeedbackEngine()
        
        summary = engine._generate_executive_summary(sample_analysis_result, 75.0)
        
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "CRITICAL" in summary  # Should mention critical issues
        assert "75" in summary  # Should include security score
    
    def test_remediation_actions_generation(self, sample_security_issues):
        """Test remediation actions generation."""
        engine = FeedbackEngine()
        
        actions = engine._generate_remediation_actions(sample_security_issues)
        
        assert len(actions) > 0
        assert all(isinstance(action, RemediationAction) for action in actions)
        
        # Should have actions for different categories
        action_categories = set()
        for action in actions:
            if "SQL" in action.title or "parameterized" in action.title.lower():
                action_categories.add("sql")
            elif "secret" in action.title.lower() or "environment" in action.title.lower():
                action_categories.add("secrets")
        
        assert len(action_categories) > 1  # Should cover multiple categories
    
    def test_compliance_status_assessment(self, sample_security_issues):
        """Test compliance status assessment."""
        engine = FeedbackEngine()
        
        compliance_status = engine._assess_compliance_status(sample_security_issues)
        
        assert "owasp_top_10" in compliance_status
        assert "overall_compliance" in compliance_status
        
        # Should be non-compliant due to critical issues
        assert compliance_status["overall_compliance"] in ["NON_COMPLIANT", "CRITICAL_NON_COMPLIANT"]
        
        # Should have OWASP violations
        owasp_status = compliance_status["owasp_top_10"]
        assert not owasp_status["compliant"]
        assert len(owasp_status["violations"]) > 0
    
    def test_detailed_findings_creation(self, sample_security_issues):
        """Test detailed findings creation."""
        engine = FeedbackEngine()
        
        findings = engine._create_detailed_findings(sample_security_issues)
        
        assert len(findings) == 3
        
        for finding in findings:
            assert "issue_id" in finding
            assert "severity" in finding
            assert "category" in finding
            assert "title" in finding
            assert "file_path" in finding
            assert "line_number" in finding
            assert "confidence" in finding
            assert "severity_color" in finding
            assert "category_icon" in finding
    
    def test_next_steps_generation(self):
        """Test next steps generation."""
        engine = FeedbackEngine()
        
        # Create sample remediation actions
        actions = [
            RemediationAction(
                action_id="1",
                title="Fix Critical Issue",
                description="Fix critical security issue",
                priority=RemediationPriority.IMMEDIATE,
                effort_level="medium",
                impact_level="high"
            ),
            RemediationAction(
                action_id="2",
                title="Fix High Priority Issue",
                description="Fix high priority issue",
                priority=RemediationPriority.HIGH,
                effort_level="low",
                impact_level="medium"
            )
        ]
        
        next_steps = engine._generate_next_steps(actions)
        
        assert len(next_steps) > 0
        assert any("IMMEDIATE" in step for step in next_steps)
        assert any("HIGH PRIORITY" in step for step in next_steps)
    
    def test_fix_time_estimation(self):
        """Test fix time estimation."""
        engine = FeedbackEngine()
        
        actions = [
            RemediationAction(
                action_id="1",
                title="Quick Fix",
                description="Quick fix",
                priority=RemediationPriority.HIGH,
                effort_level="low",
                impact_level="high",
                estimated_time_minutes=30
            ),
            RemediationAction(
                action_id="2",
                title="Complex Fix",
                description="Complex fix",
                priority=RemediationPriority.MEDIUM,
                effort_level="high",
                impact_level="medium",
                estimated_time_minutes=120
            )
        ]
        
        total_time = engine._estimate_fix_time(actions)
        
        assert total_time == 2.5  # 150 minutes = 2.5 hours
    
    def test_error_handling(self):
        """Test error handling in feedback generation."""
        engine = FeedbackEngine()
        
        # Test with invalid analysis result
        with patch.object(engine, '_create_feedback_report', side_effect=Exception("Test error")):
            report = engine.generate_report(Mock())
            
            assert "ERROR: Feedback Generation Failed" in report
            assert "Test error" in report
    
    def test_category_icon_mapping(self):
        """Test security category icon mapping."""
        engine = FeedbackEngine()
        
        # Test known categories
        assert engine._get_category_icon(SecurityCategory.SQL_INJECTION) == "💉"
        assert engine._get_category_icon(SecurityCategory.HARDCODED_SECRETS) == "🔑"
        assert engine._get_category_icon(SecurityCategory.XSS) == "🕸️"
        
        # Test fallback for unknown category
        # This would require creating a new category or mocking
        # For now, just verify the method doesn't crash
        icon = engine._get_category_icon(SecurityCategory.INPUT_VALIDATION)
        assert isinstance(icon, str)
        assert len(icon) > 0


class TestFeedbackReport:
    """Test cases for FeedbackReport."""
    
    def test_feedback_report_creation(self):
        """Test creating a feedback report."""
        report = FeedbackReport(
            report_id="test_report_123",
            generated_at=datetime.utcnow(),
            total_issues=5,
            critical_issues=1,
            high_issues=2,
            medium_issues=1,
            low_issues=1,
            overall_security_score=75.5,
            remediation_actions=[],
            executive_summary="Test summary",
            detailed_findings=[],
            compliance_status={},
            next_steps=[],
            estimated_fix_time_hours=2.5
        )
        
        assert report.report_id == "test_report_123"
        assert report.total_issues == 5
        assert report.overall_security_score == 75.5
    
    def test_severity_distribution(self):
        """Test severity distribution calculation."""
        report = FeedbackReport(
            report_id="test",
            generated_at=datetime.utcnow(),
            total_issues=4,
            critical_issues=1,
            high_issues=2,
            medium_issues=1,
            low_issues=0,
            overall_security_score=70.0,
            remediation_actions=[],
            executive_summary="",
            detailed_findings=[],
            compliance_status={},
            next_steps=[],
            estimated_fix_time_hours=1.0
        )
        
        distribution = report.get_severity_distribution()
        
        assert distribution["critical"] == 1
        assert distribution["high"] == 2
        assert distribution["medium"] == 1
        assert distribution["low"] == 0
    
    def test_risk_level_determination(self):
        """Test risk level determination."""
        # Critical risk
        critical_report = FeedbackReport(
            report_id="test", generated_at=datetime.utcnow(), total_issues=1,
            critical_issues=1, high_issues=0, medium_issues=0, low_issues=0,
            overall_security_score=50.0, remediation_actions=[], executive_summary="",
            detailed_findings=[], compliance_status={}, next_steps=[], estimated_fix_time_hours=1.0
        )
        assert critical_report.get_risk_level() == "CRITICAL"
        
        # High risk (many high severity issues)
        high_report = FeedbackReport(
            report_id="test", generated_at=datetime.utcnow(), total_issues=6,
            critical_issues=0, high_issues=6, medium_issues=0, low_issues=0,
            overall_security_score=60.0, remediation_actions=[], executive_summary="",
            detailed_findings=[], compliance_status={}, next_steps=[], estimated_fix_time_hours=2.0
        )
        assert high_report.get_risk_level() == "HIGH"
        
        # Medium risk
        medium_report = FeedbackReport(
            report_id="test", generated_at=datetime.utcnow(), total_issues=2,
            critical_issues=0, high_issues=1, medium_issues=1, low_issues=0,
            overall_security_score=80.0, remediation_actions=[], executive_summary="",
            detailed_findings=[], compliance_status={}, next_steps=[], estimated_fix_time_hours=0.5
        )
        assert medium_report.get_risk_level() == "MEDIUM"
        
        # Low risk
        low_report = FeedbackReport(
            report_id="test", generated_at=datetime.utcnow(), total_issues=1,
            critical_issues=0, high_issues=0, medium_issues=0, low_issues=1,
            overall_security_score=95.0, remediation_actions=[], executive_summary="",
            detailed_findings=[], compliance_status={}, next_steps=[], estimated_fix_time_hours=0.2
        )
        assert low_report.get_risk_level() == "LOW"