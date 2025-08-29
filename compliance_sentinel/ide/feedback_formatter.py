"""IDE feedback formatting for various violation types and editors."""

import json
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import logging

from compliance_sentinel.models.analysis import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class IDEType(Enum):
    """Supported IDE types."""
    VSCODE = "vscode"
    KIRO = "kiro"
    INTELLIJ = "intellij"
    SUBLIME = "sublime"
    VIM = "vim"
    EMACS = "emacs"
    GENERIC = "generic"


class FeedbackType(Enum):
    """Types of IDE feedback."""
    DIAGNOSTIC = "diagnostic"
    QUICK_FIX = "quick_fix"
    CODE_ACTION = "code_action"
    HOVER = "hover"
    INLINE_ANNOTATION = "inline_annotation"
    PROBLEM_MARKER = "problem_marker"


@dataclass
class IDEDiagnostic:
    """IDE diagnostic message."""
    file_path: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    severity: str = "error"
    message: str = ""
    code: Optional[str] = None
    source: str = "compliance-sentinel"
    tags: List[str] = field(default_factory=list)
    related_information: List[Dict[str, Any]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IDEQuickFix:
    """IDE quick fix suggestion."""
    title: str
    description: str
    edit_type: str  # "replace", "insert", "delete"
    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    new_text: str = ""
    command: Optional[str] = None
    arguments: List[Any] = field(default_factory=list)


@dataclass
class IDECodeAction:
    """IDE code action."""
    title: str
    kind: str  # "quickfix", "refactor", "source"
    description: str
    is_preferred: bool = False
    disabled_reason: Optional[str] = None
    edit: Optional[Dict[str, Any]] = None
    command: Optional[Dict[str, Any]] = None


@dataclass
class IDEHoverInfo:
    """IDE hover information."""
    file_path: str
    line: int
    column: int
    contents: List[str]
    range: Optional[Dict[str, int]] = None


@dataclass
class IDEFeedback:
    """Complete IDE feedback package."""
    diagnostics: List[IDEDiagnostic] = field(default_factory=list)
    quick_fixes: List[IDEQuickFix] = field(default_factory=list)
    code_actions: List[IDECodeAction] = field(default_factory=list)
    hover_info: List[IDEHoverInfo] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class IDEFeedbackFormatter:
    """Formats security issues for IDE integration."""
    
    def __init__(self, ide_type: IDEType = IDEType.GENERIC):
        """Initialize formatter for specific IDE type."""
        self.ide_type = ide_type
        self.severity_mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error", 
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
            Severity.INFO: "hint"
        }
        
        # IDE-specific configurations
        self.ide_configs = {
            IDEType.VSCODE: {
                "supports_quick_fixes": True,
                "supports_code_actions": True,
                "supports_hover": True,
                "max_message_length": 500,
                "supports_markdown": True
            },
            IDEType.KIRO: {
                "supports_quick_fixes": True,
                "supports_code_actions": True,
                "supports_hover": True,
                "max_message_length": 1000,
                "supports_markdown": True,
                "supports_inline_annotations": True
            },
            IDEType.INTELLIJ: {
                "supports_quick_fixes": True,
                "supports_code_actions": True,
                "supports_hover": True,
                "max_message_length": 300,
                "supports_markdown": False
            },
            IDEType.GENERIC: {
                "supports_quick_fixes": False,
                "supports_code_actions": False,
                "supports_hover": False,
                "max_message_length": 200,
                "supports_markdown": False
            }
        }
    
    def format_issues(self, issues: List[SecurityIssue]) -> IDEFeedback:
        """Format security issues for IDE display."""
        feedback = IDEFeedback()
        
        for issue in issues:
            # Create diagnostic
            diagnostic = self._create_diagnostic(issue)
            feedback.diagnostics.append(diagnostic)
            
            # Create quick fixes if supported
            if self._supports_feature("supports_quick_fixes"):
                quick_fixes = self._create_quick_fixes(issue)
                feedback.quick_fixes.extend(quick_fixes)
            
            # Create code actions if supported
            if self._supports_feature("supports_code_actions"):
                code_actions = self._create_code_actions(issue)
                feedback.code_actions.extend(code_actions)
            
            # Create hover info if supported
            if self._supports_feature("supports_hover"):
                hover_info = self._create_hover_info(issue)
                if hover_info:
                    feedback.hover_info.append(hover_info)
        
        # Add metadata
        feedback.metadata = {
            "ide_type": self.ide_type.value,
            "total_issues": len(issues),
            "severity_counts": self._count_severities(issues),
            "generated_at": "2025-01-13T00:00:00Z"
        }
        
        return feedback
    
    def _create_diagnostic(self, issue: SecurityIssue) -> IDEDiagnostic:
        """Create IDE diagnostic from security issue."""
        # Map severity
        ide_severity = self.severity_mapping.get(issue.severity, "info")
        
        # Format message
        message = self._format_message(issue)
        
        # Create tags
        tags = ["security", "compliance-sentinel"]
        if issue.cwe_id:
            tags.append(f"cwe-{issue.cwe_id}")
        
        # Calculate end position
        end_line = issue.line_number
        end_column = issue.column_number + len(issue.code_snippet.split('\n')[0]) if issue.code_snippet else issue.column_number + 10
        
        return IDEDiagnostic(
            file_path=issue.file_path,
            line=issue.line_number,
            column=issue.column_number,
            end_line=end_line,
            end_column=end_column,
            severity=ide_severity,
            message=message,
            code=issue.rule_id,
            source="compliance-sentinel",
            tags=tags,
            data={
                "issue_id": issue.rule_id,
                "confidence": issue.confidence,
                "cwe_id": issue.cwe_id,
                "references": issue.references
            }
        )
    
    def _create_quick_fixes(self, issue: SecurityIssue) -> List[IDEQuickFix]:
        """Create quick fixes for security issue."""
        quick_fixes = []
        
        # Generate quick fixes based on issue type
        if "hardcoded" in issue.title.lower() and "secret" in issue.title.lower():
            quick_fixes.append(self._create_secret_quick_fix(issue))
        elif "sql injection" in issue.title.lower():
            quick_fixes.append(self._create_sql_injection_quick_fix(issue))
        elif "xss" in issue.title.lower() or "cross-site scripting" in issue.title.lower():
            quick_fixes.append(self._create_xss_quick_fix(issue))
        elif "command injection" in issue.title.lower():
            quick_fixes.append(self._create_command_injection_quick_fix(issue))
        
        # Generic remediation quick fix
        if issue.remediation and not quick_fixes:
            quick_fixes.append(self._create_generic_quick_fix(issue))
        
        return quick_fixes
    
    def _create_secret_quick_fix(self, issue: SecurityIssue) -> IDEQuickFix:
        """Create quick fix for hardcoded secrets."""
        return IDEQuickFix(
            title="Replace with environment variable",
            description="Replace hardcoded secret with environment variable",
            edit_type="replace",
            file_path=issue.file_path,
            start_line=issue.line_number,
            start_column=issue.column_number,
            end_line=issue.line_number,
            end_column=issue.column_number + len(issue.code_snippet) if issue.code_snippet else issue.column_number + 20,
            new_text="os.environ.get('SECRET_KEY')",
            command="compliance-sentinel.explain-env-vars"
        )
    
    def _create_sql_injection_quick_fix(self, issue: SecurityIssue) -> IDEQuickFix:
        """Create quick fix for SQL injection."""
        return IDEQuickFix(
            title="Use parameterized query",
            description="Replace string formatting with parameterized query",
            edit_type="replace",
            file_path=issue.file_path,
            start_line=issue.line_number,
            start_column=issue.column_number,
            end_line=issue.line_number,
            end_column=issue.column_number + len(issue.code_snippet) if issue.code_snippet else issue.column_number + 50,
            new_text="cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))",
            command="compliance-sentinel.explain-parameterized-queries"
        )
    
    def _create_xss_quick_fix(self, issue: SecurityIssue) -> IDEQuickFix:
        """Create quick fix for XSS vulnerability."""
        return IDEQuickFix(
            title="Escape user input",
            description="Escape user input to prevent XSS",
            edit_type="replace",
            file_path=issue.file_path,
            start_line=issue.line_number,
            start_column=issue.column_number,
            end_line=issue.line_number,
            end_column=issue.column_number + len(issue.code_snippet) if issue.code_snippet else issue.column_number + 30,
            new_text="html.escape(user_input)",
            command="compliance-sentinel.explain-xss-prevention"
        )
    
    def _create_command_injection_quick_fix(self, issue: SecurityIssue) -> IDEQuickFix:
        """Create quick fix for command injection."""
        return IDEQuickFix(
            title="Use subprocess with list",
            description="Use subprocess with argument list instead of shell=True",
            edit_type="replace",
            file_path=issue.file_path,
            start_line=issue.line_number,
            start_column=issue.column_number,
            end_line=issue.line_number,
            end_column=issue.column_number + len(issue.code_snippet) if issue.code_snippet else issue.column_number + 40,
            new_text="subprocess.run(['ls', '-la', filename], check=True)",
            command="compliance-sentinel.explain-subprocess-safety"
        )
    
    def _create_generic_quick_fix(self, issue: SecurityIssue) -> IDEQuickFix:
        """Create generic quick fix based on remediation."""
        return IDEQuickFix(
            title="Apply suggested fix",
            description=issue.remediation[:100] + "..." if len(issue.remediation) > 100 else issue.remediation,
            edit_type="replace",
            file_path=issue.file_path,
            start_line=issue.line_number,
            start_column=issue.column_number,
            end_line=issue.line_number,
            end_column=issue.column_number + 10,
            new_text="# TODO: " + issue.remediation,
            command="compliance-sentinel.show-remediation",
            arguments=[issue.rule_id]
        )
    
    def _create_code_actions(self, issue: SecurityIssue) -> List[IDECodeAction]:
        """Create code actions for security issue."""
        actions = []
        
        # Ignore/suppress action
        actions.append(IDECodeAction(
            title=f"Ignore {issue.rule_id}",
            kind="source",
            description=f"Add ignore comment for {issue.rule_id}",
            edit={
                "changes": {
                    issue.file_path: [{
                        "range": {
                            "start": {"line": issue.line_number - 1, "character": 0},
                            "end": {"line": issue.line_number - 1, "character": 0}
                        },
                        "newText": f"# compliance-sentinel: ignore {issue.rule_id}\n"
                    }]
                }
            }
        ))
        
        # Show documentation action
        actions.append(IDECodeAction(
            title="Show security documentation",
            kind="source",
            description=f"Show documentation for {issue.rule_id}",
            command={
                "title": "Show Documentation",
                "command": "compliance-sentinel.show-docs",
                "arguments": [issue.rule_id, issue.cwe_id]
            }
        ))
        
        # Show similar issues action
        actions.append(IDECodeAction(
            title="Show similar issues",
            kind="source",
            description="Show other instances of this issue type",
            command={
                "title": "Show Similar Issues",
                "command": "compliance-sentinel.show-similar",
                "arguments": [issue.rule_id]
            }
        ))
        
        return actions
    
    def _create_hover_info(self, issue: SecurityIssue) -> Optional[IDEHoverInfo]:
        """Create hover information for security issue."""
        if not self._supports_feature("supports_hover"):
            return None
        
        contents = []
        
        # Main description
        if self._supports_feature("supports_markdown"):
            contents.append(f"**{issue.title}**\n\n{issue.description}")
        else:
            contents.append(f"{issue.title}\n\n{issue.description}")
        
        # Severity and confidence
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠", 
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "ℹ️"
        }
        
        emoji = severity_emoji.get(issue.severity, "")
        contents.append(f"{emoji} Severity: {issue.severity.value.upper()}")
        contents.append(f"Confidence: {issue.confidence}")
        
        # CWE information
        if issue.cwe_id:
            contents.append(f"CWE-{issue.cwe_id}")
        
        # Remediation
        if issue.remediation:
            if self._supports_feature("supports_markdown"):
                contents.append(f"**Remediation:**\n{issue.remediation}")
            else:
                contents.append(f"Remediation: {issue.remediation}")
        
        # References
        if issue.references:
            if self._supports_feature("supports_markdown"):
                ref_links = "\n".join([f"- [{ref}]({ref})" for ref in issue.references])
                contents.append(f"**References:**\n{ref_links}")
            else:
                contents.append(f"References: {', '.join(issue.references)}")
        
        return IDEHoverInfo(
            file_path=issue.file_path,
            line=issue.line_number,
            column=issue.column_number,
            contents=contents,
            range={
                "start_line": issue.line_number,
                "start_column": issue.column_number,
                "end_line": issue.line_number,
                "end_column": issue.column_number + len(issue.code_snippet.split('\n')[0]) if issue.code_snippet else issue.column_number + 10
            }
        )
    
    def _format_message(self, issue: SecurityIssue) -> str:
        """Format issue message for IDE display."""
        max_length = self.ide_configs[self.ide_type]["max_message_length"]
        
        # Start with title and description
        message = f"{issue.title}: {issue.description}"
        
        # Add remediation if space allows
        if issue.remediation and len(message) + len(issue.remediation) + 20 < max_length:
            message += f" | Fix: {issue.remediation}"
        
        # Truncate if too long
        if len(message) > max_length:
            message = message[:max_length - 3] + "..."
        
        return message
    
    def _supports_feature(self, feature: str) -> bool:
        """Check if IDE supports a specific feature."""
        return self.ide_configs[self.ide_type].get(feature, False)
    
    def _count_severities(self, issues: List[SecurityIssue]) -> Dict[str, int]:
        """Count issues by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in issues:
            counts[issue.severity.value] += 1
        return counts
    
    def export_vscode_format(self, feedback: IDEFeedback) -> Dict[str, Any]:
        """Export feedback in VS Code diagnostic format."""
        diagnostics_by_file = {}
        
        for diagnostic in feedback.diagnostics:
            if diagnostic.file_path not in diagnostics_by_file:
                diagnostics_by_file[diagnostic.file_path] = []
            
            vscode_diagnostic = {
                "range": {
                    "start": {
                        "line": diagnostic.line - 1,  # VS Code uses 0-based indexing
                        "character": diagnostic.column - 1
                    },
                    "end": {
                        "line": (diagnostic.end_line or diagnostic.line) - 1,
                        "character": (diagnostic.end_column or diagnostic.column + 10) - 1
                    }
                },
                "severity": self._vscode_severity_mapping(diagnostic.severity),
                "message": diagnostic.message,
                "code": diagnostic.code,
                "source": diagnostic.source,
                "tags": diagnostic.tags,
                "relatedInformation": diagnostic.related_information
            }
            
            diagnostics_by_file[diagnostic.file_path].append(vscode_diagnostic)
        
        return {
            "diagnostics": diagnostics_by_file,
            "quickFixes": [self._export_vscode_quick_fix(qf) for qf in feedback.quick_fixes],
            "codeActions": [self._export_vscode_code_action(ca) for ca in feedback.code_actions],
            "metadata": feedback.metadata
        }
    
    def export_kiro_format(self, feedback: IDEFeedback) -> Dict[str, Any]:
        """Export feedback in Kiro-specific format."""
        return {
            "version": "1.0",
            "source": "compliance-sentinel",
            "diagnostics": [
                {
                    "file": d.file_path,
                    "line": d.line,
                    "column": d.column,
                    "endLine": d.end_line,
                    "endColumn": d.end_column,
                    "severity": d.severity,
                    "message": d.message,
                    "ruleId": d.code,
                    "tags": d.tags,
                    "data": d.data
                }
                for d in feedback.diagnostics
            ],
            "quickFixes": [
                {
                    "title": qf.title,
                    "description": qf.description,
                    "file": qf.file_path,
                    "range": {
                        "start": {"line": qf.start_line, "column": qf.start_column},
                        "end": {"line": qf.end_line, "column": qf.end_column}
                    },
                    "newText": qf.new_text,
                    "command": qf.command
                }
                for qf in feedback.quick_fixes
            ],
            "hoverInfo": [
                {
                    "file": hi.file_path,
                    "line": hi.line,
                    "column": hi.column,
                    "contents": hi.contents,
                    "range": hi.range
                }
                for hi in feedback.hover_info
            ],
            "metadata": feedback.metadata
        }
    
    def export_generic_format(self, feedback: IDEFeedback) -> Dict[str, Any]:
        """Export feedback in generic format."""
        return {
            "issues": [
                {
                    "file": d.file_path,
                    "line": d.line,
                    "column": d.column,
                    "severity": d.severity,
                    "message": d.message,
                    "rule": d.code,
                    "tags": d.tags
                }
                for d in feedback.diagnostics
            ],
            "summary": feedback.metadata
        }
    
    def _vscode_severity_mapping(self, severity: str) -> int:
        """Map severity to VS Code severity numbers."""
        mapping = {
            "error": 1,
            "warning": 2,
            "info": 3,
            "hint": 4
        }
        return mapping.get(severity, 3)
    
    def _export_vscode_quick_fix(self, quick_fix: IDEQuickFix) -> Dict[str, Any]:
        """Export quick fix in VS Code format."""
        return {
            "title": quick_fix.title,
            "kind": "quickfix",
            "edit": {
                "changes": {
                    quick_fix.file_path: [{
                        "range": {
                            "start": {
                                "line": quick_fix.start_line - 1,
                                "character": quick_fix.start_column - 1
                            },
                            "end": {
                                "line": quick_fix.end_line - 1,
                                "character": quick_fix.end_column - 1
                            }
                        },
                        "newText": quick_fix.new_text
                    }]
                }
            },
            "command": {
                "title": quick_fix.title,
                "command": quick_fix.command,
                "arguments": quick_fix.arguments
            } if quick_fix.command else None
        }
    
    def _export_vscode_code_action(self, code_action: IDECodeAction) -> Dict[str, Any]:
        """Export code action in VS Code format."""
        return {
            "title": code_action.title,
            "kind": code_action.kind,
            "isPreferred": code_action.is_preferred,
            "disabled": {"reason": code_action.disabled_reason} if code_action.disabled_reason else None,
            "edit": code_action.edit,
            "command": code_action.command
        }