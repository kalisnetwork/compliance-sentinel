"""Tests for IDE integration and user experience components."""

import pytest
import time
from unittest.mock import Mock, patch

from compliance_sentinel.ide.feedback_formatter import (
    IDEFeedbackFormatter, IDEType, IDEDiagnostic, IDEQuickFix, IDECodeAction
)
from compliance_sentinel.ide.code_highlighter import (
    CodeHighlighter, HighlightType, CodeRange, CodeHighlight
)
from compliance_sentinel.ide.contextual_help import (
    ContextualHelpProvider, HelpContent
)
from compliance_sentinel.ide.progress_indicators import (
    ProgressTracker, ProgressManager, ProgressType, ProgressState, ProgressStep
)
from compliance_sentinel.models.analysis import SecurityIssue, Severity


@pytest.fixture
def sample_security_issue():
    """Create sample security issue for testing."""
    return SecurityIssue(
        rule_id="B101",
        title="Hardcoded password",
        description="Password is hardcoded in source code",
        severity=Severity.HIGH,
        file_path="/path/to/file.py",
        line_number=10,
        column_number=5,
        code_snippet='password = "admin123"',
        remediation="Use environment variables for passwords",
        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"],
        cwe_id="798",
        confidence="high"
    )


class TestIDEFeedbackFormatter:
    """Test cases for IDE feedback formatting."""
    
    def test_formatter_initialization(self):
        """Test formatter initialization with different IDE types."""
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        assert formatter.ide_type == IDEType.VSCODE
        
        formatter = IDEFeedbackFormatter(IDEType.KIRO)
        assert formatter.ide_type == IDEType.KIRO
    
    def test_format_single_issue(self, sample_security_issue):
        """Test formatting single security issue."""
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        feedback = formatter.format_issues([sample_security_issue])
        
        assert len(feedback.diagnostics) == 1
        diagnostic = feedback.diagnostics[0]
        
        assert diagnostic.file_path == sample_security_issue.file_path
        assert diagnostic.line == sample_security_issue.line_number
        assert diagnostic.column == sample_security_issue.column_number
        assert diagnostic.severity == "error"  # HIGH maps to error
        assert diagnostic.code == sample_security_issue.rule_id
        assert "security" in diagnostic.tags
    
    def test_format_multiple_issues(self, sample_security_issue):
        """Test formatting multiple security issues."""
        issue2 = SecurityIssue(
            rule_id="B102",
            title="SQL injection",
            description="Possible SQL injection",
            severity=Severity.CRITICAL,
            file_path="/path/to/other.py",
            line_number=20,
            column_number=10,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            remediation="Use parameterized queries",
            references=[],
            confidence="high"
        )
        
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        feedback = formatter.format_issues([sample_security_issue, issue2])
        
        assert len(feedback.diagnostics) == 2
        assert feedback.metadata["total_issues"] == 2
        assert feedback.metadata["severity_counts"]["high"] == 1
        assert feedback.metadata["severity_counts"]["critical"] == 1
    
    def test_quick_fix_generation(self, sample_security_issue):
        """Test quick fix generation for security issues."""
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        feedback = formatter.format_issues([sample_security_issue])
        
        assert len(feedback.quick_fixes) > 0
        quick_fix = feedback.quick_fixes[0]
        
        assert quick_fix.title == "Replace with environment variable"
        assert quick_fix.edit_type == "replace"
        assert quick_fix.file_path == sample_security_issue.file_path
        assert "os.environ.get" in quick_fix.new_text
    
    def test_code_actions_generation(self, sample_security_issue):
        """Test code actions generation."""
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        feedback = formatter.format_issues([sample_security_issue])
        
        assert len(feedback.code_actions) > 0
        
        # Check for ignore action
        ignore_action = next((a for a in feedback.code_actions if "Ignore" in a.title), None)
        assert ignore_action is not None
        assert ignore_action.kind == "source"
        
        # Check for documentation action
        doc_action = next((a for a in feedback.code_actions if "documentation" in a.title), None)
        assert doc_action is not None
    
    def test_hover_info_generation(self, sample_security_issue):
        """Test hover information generation."""
        formatter = IDEFeedbackFormatter(IDEType.KIRO)  # Kiro supports hover
        feedback = formatter.format_issues([sample_security_issue])
        
        assert len(feedback.hover_info) > 0
        hover = feedback.hover_info[0]
        
        assert hover.file_path == sample_security_issue.file_path
        assert hover.line == sample_security_issue.line_number
        assert len(hover.contents) > 0
        assert sample_security_issue.title in hover.contents[0]
    
    def test_vscode_export_format(self, sample_security_issue):
        """Test VS Code export format."""
        formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        feedback = formatter.format_issues([sample_security_issue])
        vscode_format = formatter.export_vscode_format(feedback)
        
        assert "diagnostics" in vscode_format
        assert "quickFixes" in vscode_format
        assert "codeActions" in vscode_format
        assert "metadata" in vscode_format
        
        # Check diagnostic format
        file_diagnostics = vscode_format["diagnostics"][sample_security_issue.file_path]
        assert len(file_diagnostics) == 1
        
        diagnostic = file_diagnostics[0]
        assert "range" in diagnostic
        assert "severity" in diagnostic
        assert "message" in diagnostic
    
    def test_kiro_export_format(self, sample_security_issue):
        """Test Kiro export format."""
        formatter = IDEFeedbackFormatter(IDEType.KIRO)
        feedback = formatter.format_issues([sample_security_issue])
        kiro_format = formatter.export_kiro_format(feedback)
        
        assert kiro_format["version"] == "1.0"
        assert kiro_format["source"] == "compliance-sentinel"
        assert "diagnostics" in kiro_format
        assert "quickFixes" in kiro_format
        assert "hoverInfo" in kiro_format
        
        # Check diagnostic format
        diagnostic = kiro_format["diagnostics"][0]
        assert diagnostic["file"] == sample_security_issue.file_path
        assert diagnostic["ruleId"] == sample_security_issue.rule_id
    
    def test_ide_feature_support(self):
        """Test IDE feature support detection."""
        vscode_formatter = IDEFeedbackFormatter(IDEType.VSCODE)
        assert vscode_formatter._supports_feature("supports_quick_fixes")
        assert vscode_formatter._supports_feature("supports_hover")
        
        generic_formatter = IDEFeedbackFormatter(IDEType.GENERIC)
        assert not generic_formatter._supports_feature("supports_quick_fixes")
        assert not generic_formatter._supports_feature("supports_hover")


class TestCodeHighlighter:
    """Test cases for code highlighting."""
    
    def test_highlighter_initialization(self):
        """Test code highlighter initialization."""
        highlighter = CodeHighlighter()
        assert highlighter.severity_to_highlight[Severity.CRITICAL] == HighlightType.ERROR
        assert highlighter.severity_to_highlight[Severity.LOW] == HighlightType.INFO
    
    def test_create_highlights_from_issues(self, sample_security_issue):
        """Test creating highlights from security issues."""
        highlighter = CodeHighlighter()
        highlights_by_file = highlighter.create_highlights([sample_security_issue])
        
        assert sample_security_issue.file_path in highlights_by_file
        file_highlights = highlights_by_file[sample_security_issue.file_path]
        
        assert len(file_highlights.highlights) > 0
        highlight = file_highlights.highlights[0]
        
        assert highlight.range.start_line == sample_security_issue.line_number
        assert highlight.range.start_column == sample_security_issue.column_number
        assert highlight.highlight_type == HighlightType.ERROR  # HIGH severity
        assert highlight.rule_id == sample_security_issue.rule_id
    
    def test_highlight_range_calculation(self, sample_security_issue):
        """Test highlight range calculation."""
        highlighter = CodeHighlighter()
        range_info = highlighter._calculate_highlight_range(sample_security_issue)
        
        assert range_info.start_line == sample_security_issue.line_number
        assert range_info.start_column == sample_security_issue.column_number
        assert range_info.end_line >= range_info.start_line
        assert range_info.end_column > range_info.start_column
    
    def test_tooltip_creation(self, sample_security_issue):
        """Test tooltip content creation."""
        highlighter = CodeHighlighter()
        tooltip = highlighter._create_tooltip(sample_security_issue)
        
        assert sample_security_issue.title in tooltip
        assert sample_security_issue.description in tooltip
        assert sample_security_issue.severity.value.upper() in tooltip
        assert sample_security_issue.remediation in tooltip
    
    def test_pattern_highlights(self):
        """Test pattern-based highlighting."""
        highlighter = CodeHighlighter()
        file_content = '''
password = "admin123"
api_key = "sk-1234567890"
eval(user_input)
subprocess.call(cmd, shell=True)
'''
        
        highlights = highlighter.create_pattern_highlights("/test/file.py", file_content)
        assert len(highlights) > 0
        
        # Should find password pattern
        password_highlight = next((h for h in highlights if "password" in h.message.lower()), None)
        assert password_highlight is not None
        assert password_highlight.highlight_type == HighlightType.SECURITY
    
    def test_highlight_optimization(self):
        """Test highlight optimization (merging overlapping highlights)."""
        highlighter = CodeHighlighter()
        
        # Create overlapping highlights
        highlight1 = CodeHighlight(
            range=CodeRange(10, 5, 10, 15),
            highlight_type=HighlightType.ERROR,
            style=highlighter.severity_to_style[Severity.HIGH],
            message="Issue 1",
            severity="high",
            rule_id="B101"
        )
        
        highlight2 = CodeHighlight(
            range=CodeRange(10, 10, 10, 20),
            highlight_type=HighlightType.ERROR,
            style=highlighter.severity_to_style[Severity.HIGH],
            message="Issue 2",
            severity="high",
            rule_id="B102"
        )
        
        optimized = highlighter._optimize_highlights([highlight1, highlight2])
        assert len(optimized) == 1  # Should be merged
        
        merged = optimized[0]
        assert merged.range.start_column == 5
        assert merged.range.end_column == 20
        assert "Issue 1" in merged.message and "Issue 2" in merged.message
    
    def test_vscode_decorations_export(self, sample_security_issue):
        """Test VS Code decorations export."""
        highlighter = CodeHighlighter()
        highlights_by_file = highlighter.create_highlights([sample_security_issue])
        file_highlights = highlights_by_file[sample_security_issue.file_path]
        
        decorations = highlighter.export_vscode_decorations(file_highlights)
        
        assert "error" in decorations
        assert len(decorations["error"]) > 0
        
        decoration = decorations["error"][0]
        assert "range" in decoration
        assert "hoverMessage" in decoration
        assert "renderOptions" in decoration
    
    def test_kiro_annotations_export(self, sample_security_issue):
        """Test Kiro annotations export."""
        highlighter = CodeHighlighter()
        highlights_by_file = highlighter.create_highlights([sample_security_issue])
        file_highlights = highlights_by_file[sample_security_issue.file_path]
        
        annotations = highlighter.export_kiro_annotations(file_highlights)
        
        assert annotations["file"] == sample_security_issue.file_path
        assert "highlights" in annotations
        assert "lineAnnotations" in annotations
        
        highlight_annotation = annotations["highlights"][0]
        assert highlight_annotation["type"] == "highlight"
        assert "range" in highlight_annotation
        assert "style" in highlight_annotation


class TestContextualHelpProvider:
    """Test cases for contextual help provider."""
    
    def test_help_provider_initialization(self):
        """Test help provider initialization."""
        provider = ContextualHelpProvider()
        assert len(provider.help_database) > 0
        assert len(provider.cwe_database) > 0
        assert len(provider.examples_database) > 0
    
    def test_get_help_for_issue(self, sample_security_issue):
        """Test getting help for specific issue."""
        provider = ContextualHelpProvider()
        help_content = provider.get_help_for_issue(sample_security_issue)
        
        assert isinstance(help_content, HelpContent)
        assert help_content.title
        assert help_content.description
        assert help_content.severity_info is not None
        assert help_content.severity_info["level"] == "High"
    
    def test_get_interactive_example(self):
        """Test getting interactive examples."""
        provider = ContextualHelpProvider()
        example = provider.get_interactive_example("B101", "python")
        
        assert example is not None
        assert example.vulnerable_code
        assert example.secure_code
        assert example.explanation
        assert len(example.key_changes) > 0
    
    def test_search_help(self):
        """Test help content search."""
        provider = ContextualHelpProvider()
        results = provider.search_help("password")
        
        assert len(results) > 0
        assert any("password" in result.title.lower() for result in results)
    
    def test_get_related_help(self, sample_security_issue):
        """Test getting related help content."""
        provider = ContextualHelpProvider()
        related_help = provider.get_related_help(sample_security_issue)
        
        # Should return some related help items
        assert isinstance(related_help, list)
    
    def test_format_help_markdown(self, sample_security_issue):
        """Test formatting help as Markdown."""
        provider = ContextualHelpProvider()
        help_content = provider.get_help_for_issue(sample_security_issue)
        markdown = provider.format_help_for_ide(help_content, "markdown")
        
        assert markdown.startswith("#")  # Should have header
        assert help_content.title in markdown
        assert help_content.description in markdown
    
    def test_format_help_plain_text(self, sample_security_issue):
        """Test formatting help as plain text."""
        provider = ContextualHelpProvider()
        help_content = provider.get_help_for_issue(sample_security_issue)
        plain_text = provider.format_help_for_ide(help_content, "plain")
        
        assert help_content.title in plain_text
        assert help_content.description in plain_text
        assert "=" in plain_text  # Should have text formatting


class TestProgressIndicators:
    """Test cases for progress indicators."""
    
    def test_progress_tracker_initialization(self):
        """Test progress tracker initialization."""
        tracker = ProgressTracker("test-1", "Test Progress", "Testing progress tracking")
        
        assert tracker.progress_info.id == "test-1"
        assert tracker.progress_info.title == "Test Progress"
        assert tracker.progress_info.state == ProgressState.NOT_STARTED
        assert tracker.progress_info.percentage == 0.0
    
    def test_add_steps(self):
        """Test adding steps to progress tracker."""
        tracker = ProgressTracker("test-2", "Test Progress")
        
        steps = [
            ProgressStep("step1", "Step 1", "First step"),
            ProgressStep("step2", "Step 2", "Second step")
        ]
        tracker.add_steps(steps)
        
        assert tracker.progress_info.total_steps == 2
        assert len(tracker.progress_info.steps) == 2
    
    def test_progress_tracking(self):
        """Test progress tracking through steps."""
        tracker = ProgressTracker("test-3", "Test Progress")
        tracker.add_step("step1", "Step 1", weight=1.0)
        tracker.add_step("step2", "Step 2", weight=1.0)
        
        tracker.start()
        assert tracker.progress_info.state == ProgressState.RUNNING
        
        tracker.start_step("step1")
        assert tracker.progress_info.current_step == 1
        assert tracker.progress_info.current_step_name == "Step 1"
        
        tracker.complete_step("step1")
        info = tracker.get_progress_info()
        assert info.percentage == 50.0  # 1 of 2 steps completed
        
        tracker.complete_step("step2")
        tracker.complete()
        assert tracker.progress_info.state == ProgressState.COMPLETED
        assert tracker.progress_info.percentage == 100.0
    
    def test_progress_callbacks(self):
        """Test progress update callbacks."""
        tracker = ProgressTracker("test-4", "Test Progress")
        callback_called = False
        callback_info = None
        
        def test_callback(info):
            nonlocal callback_called, callback_info
            callback_called = True
            callback_info = info
        
        tracker.add_callback(test_callback)
        tracker.start()
        
        # Give callback time to be called
        time.sleep(0.01)
        
        assert callback_called
        assert callback_info is not None
        assert callback_info.state == ProgressState.RUNNING
    
    def test_progress_manager(self):
        """Test progress manager functionality."""
        manager = ProgressManager()
        
        tracker1 = manager.create_tracker("analysis-1", "Analysis 1")
        tracker2 = manager.create_tracker("analysis-2", "Analysis 2")
        
        assert len(manager.trackers) == 2
        assert manager.get_tracker("analysis-1") == tracker1
        
        # Test getting all progress
        all_progress = manager.get_all_progress()
        assert len(all_progress) == 2
        assert "analysis-1" in all_progress
        assert "analysis-2" in all_progress
        
        # Test active progress
        tracker1.start()
        active_progress = manager.get_active_progress()
        assert len(active_progress) == 1
        assert "analysis-1" in active_progress
    
    def test_progress_error_handling(self):
        """Test progress error handling."""
        tracker = ProgressTracker("test-5", "Test Progress")
        tracker.add_step("step1", "Step 1")
        
        tracker.start()
        tracker.start_step("step1")
        tracker.complete_step("step1", error="Something went wrong")
        
        assert tracker.progress_info.state == ProgressState.ERROR
        step = tracker._find_step("step1")
        assert step.error == "Something went wrong"
    
    def test_progress_cancellation(self):
        """Test progress cancellation."""
        tracker = ProgressTracker("test-6", "Test Progress")
        tracker.start()
        tracker.cancel()
        
        assert tracker.progress_info.state == ProgressState.CANCELLED
    
    def test_ide_progress_formatting(self):
        """Test IDE-specific progress formatting."""
        from compliance_sentinel.ide.progress_indicators import IDEProgressFormatter
        
        tracker = ProgressTracker("test-7", "Test Progress", "Testing formatting")
        tracker.add_step("step1", "Step 1", "First step")
        tracker.start()
        tracker.start_step("step1")
        
        info = tracker.get_progress_info()
        
        # Test VS Code format
        vscode_format = IDEProgressFormatter.format_vscode_progress(info)
        assert "title" in vscode_format
        assert "message" in vscode_format
        assert vscode_format["title"] == "Test Progress"
        
        # Test Kiro format
        kiro_format = IDEProgressFormatter.format_kiro_progress(info)
        assert "id" in kiro_format
        assert "title" in kiro_format
        assert "progress" in kiro_format
        assert "steps" in kiro_format
        
        # Test generic format
        generic_format = IDEProgressFormatter.format_generic_progress(info)
        assert "title" in generic_format
        assert "state" in generic_format


if __name__ == "__main__":
    pytest.main([__file__])