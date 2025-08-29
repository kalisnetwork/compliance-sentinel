"""Inline code highlighting system for security issues."""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

from compliance_sentinel.models.analysis import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class HighlightType(Enum):
    """Types of code highlighting."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUGGESTION = "suggestion"
    DEPRECATED = "deprecated"
    SECURITY = "security"


class HighlightStyle(Enum):
    """Highlighting styles."""
    UNDERLINE = "underline"
    BACKGROUND = "background"
    BORDER = "border"
    SQUIGGLY = "squiggly"
    DOTTED = "dotted"
    SOLID = "solid"


@dataclass
class CodeRange:
    """Represents a range of code to highlight."""
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    
    def contains_position(self, line: int, column: int) -> bool:
        """Check if position is within this range."""
        if line < self.start_line or line > self.end_line:
            return False
        
        if line == self.start_line and column < self.start_column:
            return False
        
        if line == self.end_line and column > self.end_column:
            return False
        
        return True
    
    def overlaps_with(self, other: 'CodeRange') -> bool:
        """Check if this range overlaps with another."""
        return not (
            self.end_line < other.start_line or
            other.end_line < self.start_line or
            (self.end_line == other.start_line and self.end_column < other.start_column) or
            (other.end_line == self.start_line and other.end_column < self.start_column)
        )


@dataclass
class CodeHighlight:
    """Represents a code highlight annotation."""
    range: CodeRange
    highlight_type: HighlightType
    style: HighlightStyle
    message: str
    severity: str
    rule_id: str
    tooltip: Optional[str] = None
    quick_fixes: List[str] = field(default_factory=list)
    related_ranges: List[CodeRange] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileHighlights:
    """All highlights for a single file."""
    file_path: str
    highlights: List[CodeHighlight] = field(default_factory=list)
    line_annotations: Dict[int, List[str]] = field(default_factory=dict)
    file_level_issues: List[str] = field(default_factory=list)


class CodeHighlighter:
    """Creates inline code highlighting for security issues."""
    
    def __init__(self):
        """Initialize code highlighter."""
        self.severity_to_highlight = {
            Severity.CRITICAL: HighlightType.ERROR,
            Severity.HIGH: HighlightType.ERROR,
            Severity.MEDIUM: HighlightType.WARNING,
            Severity.LOW: HighlightType.INFO,
            Severity.INFO: HighlightType.SUGGESTION
        }
        
        self.severity_to_style = {
            Severity.CRITICAL: HighlightStyle.SQUIGGLY,
            Severity.HIGH: HighlightStyle.SQUIGGLY,
            Severity.MEDIUM: HighlightStyle.UNDERLINE,
            Severity.LOW: HighlightStyle.DOTTED,
            Severity.INFO: HighlightStyle.DOTTED
        }
        
        # Pattern-based highlighting rules
        self.pattern_highlights = {
            r'password\s*=\s*["\'][^"\']+["\']': {
                'type': HighlightType.SECURITY,
                'style': HighlightStyle.BACKGROUND,
                'message': 'Potential hardcoded password'
            },
            r'api_key\s*=\s*["\'][^"\']+["\']': {
                'type': HighlightType.SECURITY,
                'style': HighlightStyle.BACKGROUND,
                'message': 'Potential hardcoded API key'
            },
            r'eval\s*\(': {
                'type': HighlightType.ERROR,
                'style': HighlightStyle.SQUIGGLY,
                'message': 'Dangerous eval() usage'
            },
            r'exec\s*\(': {
                'type': HighlightType.ERROR,
                'style': HighlightStyle.SQUIGGLY,
                'message': 'Dangerous exec() usage'
            },
            r'subprocess\.call\([^)]*shell\s*=\s*True': {
                'type': HighlightType.WARNING,
                'style': HighlightStyle.UNDERLINE,
                'message': 'Shell injection risk'
            }
        }
    
    def create_highlights(self, issues: List[SecurityIssue]) -> Dict[str, FileHighlights]:
        """Create code highlights from security issues."""
        highlights_by_file = {}
        
        for issue in issues:
            if issue.file_path not in highlights_by_file:
                highlights_by_file[issue.file_path] = FileHighlights(issue.file_path)
            
            file_highlights = highlights_by_file[issue.file_path]
            
            # Create main highlight
            highlight = self._create_highlight_from_issue(issue)
            file_highlights.highlights.append(highlight)
            
            # Add line annotation
            if issue.line_number not in file_highlights.line_annotations:
                file_highlights.line_annotations[issue.line_number] = []
            
            annotation = f"{issue.severity.value.upper()}: {issue.title}"
            file_highlights.line_annotations[issue.line_number].append(annotation)
            
            # Add related highlights if applicable
            related_highlights = self._create_related_highlights(issue)
            file_highlights.highlights.extend(related_highlights)
        
        # Optimize highlights (merge overlapping, etc.)
        for file_highlights in highlights_by_file.values():
            file_highlights.highlights = self._optimize_highlights(file_highlights.highlights)
        
        return highlights_by_file
    
    def _create_highlight_from_issue(self, issue: SecurityIssue) -> CodeHighlight:
        """Create a code highlight from a security issue."""
        # Determine highlight range
        range_info = self._calculate_highlight_range(issue)
        
        # Map severity to highlight type and style
        highlight_type = self.severity_to_highlight.get(issue.severity, HighlightType.INFO)
        style = self.severity_to_style.get(issue.severity, HighlightStyle.UNDERLINE)
        
        # Create tooltip content
        tooltip = self._create_tooltip(issue)
        
        # Extract quick fixes
        quick_fixes = []
        if issue.remediation:
            quick_fixes.append(f"Fix: {issue.remediation}")
        
        return CodeHighlight(
            range=range_info,
            highlight_type=highlight_type,
            style=style,
            message=issue.title,
            severity=issue.severity.value,
            rule_id=issue.rule_id,
            tooltip=tooltip,
            quick_fixes=quick_fixes,
            metadata={
                'confidence': issue.confidence,
                'cwe_id': issue.cwe_id,
                'references': issue.references,
                'description': issue.description
            }
        )
    
    def _calculate_highlight_range(self, issue: SecurityIssue) -> CodeRange:
        """Calculate the exact range to highlight for an issue."""
        start_line = issue.line_number
        start_column = issue.column_number
        
        # Try to determine end position from code snippet
        if issue.code_snippet:
            lines = issue.code_snippet.split('\n')
            if lines:
                # For single line, highlight the problematic part
                if len(lines) == 1:
                    end_line = start_line
                    end_column = start_column + len(lines[0])
                else:
                    # For multi-line, highlight entire block
                    end_line = start_line + len(lines) - 1
                    end_column = len(lines[-1])
            else:
                # Default to highlighting 10 characters
                end_line = start_line
                end_column = start_column + 10
        else:
            # Default highlighting range
            end_line = start_line
            end_column = start_column + 10
        
        # Apply issue-specific range adjustments
        if "hardcoded" in issue.title.lower():
            # For hardcoded secrets, try to highlight the entire value
            end_column = max(end_column, start_column + 20)
        elif "sql injection" in issue.title.lower():
            # For SQL injection, highlight the entire query construction
            end_column = max(end_column, start_column + 50)
        elif "xss" in issue.title.lower():
            # For XSS, highlight the output statement
            end_column = max(end_column, start_column + 30)
        
        return CodeRange(start_line, start_column, end_line, end_column)
    
    def _create_related_highlights(self, issue: SecurityIssue) -> List[CodeHighlight]:
        """Create related highlights for complex issues."""
        related_highlights = []
        
        # For certain issue types, create additional context highlights
        if "sql injection" in issue.title.lower():
            # Highlight variable usage in SQL context
            related_highlights.extend(self._find_sql_variable_usage(issue))
        elif "xss" in issue.title.lower():
            # Highlight user input sources
            related_highlights.extend(self._find_user_input_sources(issue))
        elif "command injection" in issue.title.lower():
            # Highlight command construction
            related_highlights.extend(self._find_command_construction(issue))
        
        return related_highlights
    
    def _find_sql_variable_usage(self, issue: SecurityIssue) -> List[CodeHighlight]:
        """Find related SQL variable usage for highlighting."""
        # This would analyze the code to find related SQL construction
        # For now, return empty list as this requires more complex analysis
        return []
    
    def _find_user_input_sources(self, issue: SecurityIssue) -> List[CodeHighlight]:
        """Find user input sources related to XSS issues."""
        # This would trace user input flow
        # For now, return empty list as this requires data flow analysis
        return []
    
    def _find_command_construction(self, issue: SecurityIssue) -> List[CodeHighlight]:
        """Find command construction patterns."""
        # This would find command building patterns
        # For now, return empty list as this requires more analysis
        return []
    
    def _create_tooltip(self, issue: SecurityIssue) -> str:
        """Create tooltip content for an issue."""
        tooltip_parts = []
        
        # Title and description
        tooltip_parts.append(f"**{issue.title}**")
        tooltip_parts.append(issue.description)
        
        # Severity and confidence
        tooltip_parts.append(f"Severity: {issue.severity.value.upper()}")
        tooltip_parts.append(f"Confidence: {issue.confidence}")
        
        # CWE information
        if issue.cwe_id:
            tooltip_parts.append(f"CWE-{issue.cwe_id}")
        
        # Remediation
        if issue.remediation:
            tooltip_parts.append(f"**Fix:** {issue.remediation}")
        
        # References
        if issue.references:
            tooltip_parts.append("**References:**")
            for ref in issue.references[:3]:  # Limit to first 3 references
                tooltip_parts.append(f"• {ref}")
        
        return "\n\n".join(tooltip_parts)
    
    def _optimize_highlights(self, highlights: List[CodeHighlight]) -> List[CodeHighlight]:
        """Optimize highlights by merging overlapping ones and removing duplicates."""
        if not highlights:
            return highlights
        
        # Sort highlights by position
        highlights.sort(key=lambda h: (h.range.start_line, h.range.start_column))
        
        optimized = []
        current = highlights[0]
        
        for next_highlight in highlights[1:]:
            if self._should_merge_highlights(current, next_highlight):
                current = self._merge_highlights(current, next_highlight)
            else:
                optimized.append(current)
                current = next_highlight
        
        optimized.append(current)
        return optimized
    
    def _should_merge_highlights(self, h1: CodeHighlight, h2: CodeHighlight) -> bool:
        """Determine if two highlights should be merged."""
        # Merge if they overlap and have the same severity
        return (
            h1.range.overlaps_with(h2.range) and
            h1.severity == h2.severity and
            h1.highlight_type == h2.highlight_type
        )
    
    def _merge_highlights(self, h1: CodeHighlight, h2: CodeHighlight) -> CodeHighlight:
        """Merge two overlapping highlights."""
        # Create merged range
        merged_range = CodeRange(
            start_line=min(h1.range.start_line, h2.range.start_line),
            start_column=min(h1.range.start_column, h2.range.start_column),
            end_line=max(h1.range.end_line, h2.range.end_line),
            end_column=max(h1.range.end_column, h2.range.end_column)
        )
        
        # Merge messages
        merged_message = f"{h1.message}; {h2.message}"
        
        # Merge tooltips
        merged_tooltip = f"{h1.tooltip}\n\n---\n\n{h2.tooltip}" if h1.tooltip and h2.tooltip else h1.tooltip or h2.tooltip
        
        # Merge quick fixes
        merged_quick_fixes = list(set(h1.quick_fixes + h2.quick_fixes))
        
        return CodeHighlight(
            range=merged_range,
            highlight_type=h1.highlight_type,
            style=h1.style,
            message=merged_message,
            severity=h1.severity,
            rule_id=f"{h1.rule_id},{h2.rule_id}",
            tooltip=merged_tooltip,
            quick_fixes=merged_quick_fixes,
            metadata={**h1.metadata, **h2.metadata}
        )
    
    def create_pattern_highlights(self, file_path: str, file_content: str) -> List[CodeHighlight]:
        """Create highlights based on pattern matching."""
        highlights = []
        lines = file_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, config in self.pattern_highlights.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    highlight = CodeHighlight(
                        range=CodeRange(
                            start_line=line_num,
                            start_column=match.start() + 1,
                            end_line=line_num,
                            end_column=match.end() + 1
                        ),
                        highlight_type=config['type'],
                        style=config['style'],
                        message=config['message'],
                        severity="medium",
                        rule_id="PATTERN_MATCH",
                        tooltip=f"Pattern match: {config['message']}\nMatched text: {match.group()}"
                    )
                    highlights.append(highlight)
        
        return highlights
    
    def export_vscode_decorations(self, file_highlights: FileHighlights) -> Dict[str, Any]:
        """Export highlights as VS Code decorations."""
        decorations = {
            "error": [],
            "warning": [],
            "info": [],
            "suggestion": []
        }
        
        for highlight in file_highlights.highlights:
            decoration_type = self._map_to_vscode_decoration_type(highlight.highlight_type)
            
            decoration = {
                "range": {
                    "start": {
                        "line": highlight.range.start_line - 1,
                        "character": highlight.range.start_column - 1
                    },
                    "end": {
                        "line": highlight.range.end_line - 1,
                        "character": highlight.range.end_column - 1
                    }
                },
                "hoverMessage": highlight.tooltip,
                "renderOptions": self._get_vscode_render_options(highlight)
            }
            
            decorations[decoration_type].append(decoration)
        
        return decorations
    
    def export_kiro_annotations(self, file_highlights: FileHighlights) -> Dict[str, Any]:
        """Export highlights as Kiro annotations."""
        annotations = []
        
        for highlight in file_highlights.highlights:
            annotation = {
                "type": "highlight",
                "range": {
                    "startLine": highlight.range.start_line,
                    "startColumn": highlight.range.start_column,
                    "endLine": highlight.range.end_line,
                    "endColumn": highlight.range.end_column
                },
                "severity": highlight.severity,
                "message": highlight.message,
                "tooltip": highlight.tooltip,
                "style": {
                    "highlightType": highlight.highlight_type.value,
                    "style": highlight.style.value
                },
                "quickFixes": highlight.quick_fixes,
                "metadata": highlight.metadata
            }
            annotations.append(annotation)
        
        # Add line annotations
        line_annotations = []
        for line_num, messages in file_highlights.line_annotations.items():
            line_annotations.append({
                "line": line_num,
                "messages": messages,
                "type": "gutter"
            })
        
        return {
            "file": file_highlights.file_path,
            "highlights": annotations,
            "lineAnnotations": line_annotations,
            "fileLevelIssues": file_highlights.file_level_issues
        }
    
    def _map_to_vscode_decoration_type(self, highlight_type: HighlightType) -> str:
        """Map highlight type to VS Code decoration type."""
        mapping = {
            HighlightType.ERROR: "error",
            HighlightType.WARNING: "warning",
            HighlightType.INFO: "info",
            HighlightType.SUGGESTION: "suggestion",
            HighlightType.SECURITY: "error",
            HighlightType.DEPRECATED: "warning"
        }
        return mapping.get(highlight_type, "info")
    
    def _get_vscode_render_options(self, highlight: CodeHighlight) -> Dict[str, Any]:
        """Get VS Code render options for highlight."""
        style_mapping = {
            HighlightStyle.UNDERLINE: {"textDecoration": "underline"},
            HighlightStyle.SQUIGGLY: {"textDecoration": "underline wavy"},
            HighlightStyle.BACKGROUND: {"backgroundColor": "rgba(255, 0, 0, 0.1)"},
            HighlightStyle.BORDER: {"border": "1px solid red"},
            HighlightStyle.DOTTED: {"textDecoration": "underline dotted"},
            HighlightStyle.SOLID: {"textDecoration": "underline solid"}
        }
        
        return style_mapping.get(highlight.style, {"textDecoration": "underline"})