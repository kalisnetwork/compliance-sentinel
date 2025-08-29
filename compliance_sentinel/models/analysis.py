"""Analysis request and response models for the Compliance Sentinel system."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from pathlib import Path
from enum import Enum
import uuid

from compliance_sentinel.core.interfaces import (
    SecurityIssue, 
    VulnerabilityReport, 
    Severity,
    SecurityCategory
)


class AnalysisStatus(Enum):
    """Status of an analysis operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisType(Enum):
    """Type of analysis to perform."""
    SECURITY_SCAN = "security_scan"
    DEPENDENCY_CHECK = "dependency_check"
    POLICY_VALIDATION = "policy_validation"
    COMPREHENSIVE = "comprehensive"


@dataclass
class AnalysisRequest:
    """Request for security analysis of code files."""
    
    # Required fields
    file_paths: List[str]
    analysis_type: AnalysisType
    
    # Optional configuration
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    priority: int = field(default=5)  # 1-10, higher is more urgent
    timeout_seconds: int = field(default=300)
    
    # Analysis options
    include_dependencies: bool = field(default=True)
    include_test_files: bool = field(default=False)
    severity_threshold: Severity = field(default=Severity.MEDIUM)
    custom_rules: List[str] = field(default_factory=list)
    
    # Context information
    project_root: Optional[str] = field(default=None)
    git_branch: Optional[str] = field(default=None)
    git_commit: Optional[str] = field(default=None)
    user_id: Optional[str] = field(default=None)
    
    def __post_init__(self):
        """Validate analysis request after initialization."""
        if not self.file_paths:
            raise ValueError("file_paths cannot be empty")
        
        if not (1 <= self.priority <= 10):
            raise ValueError("priority must be between 1 and 10")
        
        if self.timeout_seconds < 30:
            raise ValueError("timeout_seconds must be at least 30")
        
        # Validate file paths exist and are readable
        for file_path in self.file_paths:
            path = Path(file_path)
            if not path.exists():
                raise ValueError(f"File does not exist: {file_path}")
            if not path.is_file():
                raise ValueError(f"Path is not a file: {file_path}")
    
    def get_file_extensions(self) -> List[str]:
        """Get unique file extensions from the request."""
        extensions = set()
        for file_path in self.file_paths:
            ext = Path(file_path).suffix.lower()
            if ext:
                extensions.add(ext)
        return list(extensions)
    
    def is_high_priority(self) -> bool:
        """Check if this is a high priority request."""
        return self.priority >= 8
    
    def get_estimated_duration(self) -> int:
        """Estimate analysis duration in seconds based on file count and type."""
        base_time = 10  # Base time per file
        file_count = len(self.file_paths)
        
        # Adjust based on analysis type
        multiplier = {
            AnalysisType.SECURITY_SCAN: 1.0,
            AnalysisType.DEPENDENCY_CHECK: 0.5,
            AnalysisType.POLICY_VALIDATION: 0.3,
            AnalysisType.COMPREHENSIVE: 2.0
        }.get(self.analysis_type, 1.0)
        
        return int(base_time * file_count * multiplier)


@dataclass
class AnalysisResponse:
    """Response from security analysis operation."""
    
    # Request correlation
    request_id: str
    status: AnalysisStatus
    
    # Timing information
    started_at: datetime
    completed_at: Optional[datetime] = field(default=None)
    duration_seconds: Optional[float] = field(default=None)
    
    # Analysis results
    issues: List[SecurityIssue] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityReport] = field(default_factory=list)
    
    # Summary statistics
    total_files_analyzed: int = field(default=0)
    total_lines_analyzed: int = field(default=0)
    issues_by_severity: Dict[str, int] = field(default_factory=dict)
    
    # Analysis metadata
    tools_used: List[str] = field(default_factory=list)
    rules_applied: List[str] = field(default_factory=list)
    external_services_queried: List[str] = field(default_factory=list)
    
    # Error information
    error_message: Optional[str] = field(default=None)
    warnings: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate derived fields after initialization."""
        if self.completed_at and self.duration_seconds is None:
            self.duration_seconds = (self.completed_at - self.started_at).total_seconds()
        
        # Calculate issues by severity if not provided
        if not self.issues_by_severity and self.issues:
            self.issues_by_severity = self._calculate_severity_distribution()
    
    def _calculate_severity_distribution(self) -> Dict[str, int]:
        """Calculate distribution of issues by severity."""
        distribution = {severity.value: 0 for severity in Severity}
        
        for issue in self.issues:
            distribution[issue.severity.value] += 1
        
        return distribution
    
    def get_critical_issues(self) -> List[SecurityIssue]:
        """Get all critical severity issues."""
        return [issue for issue in self.issues if issue.severity == Severity.CRITICAL]
    
    def get_high_issues(self) -> List[SecurityIssue]:
        """Get all high severity issues."""
        return [issue for issue in self.issues if issue.severity == Severity.HIGH]
    
    def has_blocking_issues(self) -> bool:
        """Check if analysis found any blocking (critical/high) issues."""
        return any(issue.severity in [Severity.CRITICAL, Severity.HIGH] for issue in self.issues)
    
    def get_success_rate(self) -> float:
        """Calculate analysis success rate (0.0 to 1.0)."""
        if self.status == AnalysisStatus.COMPLETED:
            return 1.0
        elif self.status == AnalysisStatus.FAILED:
            return 0.0
        else:
            # Partial success based on files analyzed
            return min(1.0, self.total_files_analyzed / max(1, len(self.issues)))
    
    def get_summary(self) -> str:
        """Get a human-readable summary of the analysis."""
        if self.status == AnalysisStatus.FAILED:
            return f"Analysis failed: {self.error_message or 'Unknown error'}"
        
        if self.status != AnalysisStatus.COMPLETED:
            return f"Analysis {self.status.value}"
        
        total_issues = len(self.issues)
        total_vulns = len(self.vulnerabilities)
        
        if total_issues == 0 and total_vulns == 0:
            return "✅ No security issues found"
        
        summary_parts = []
        if total_issues > 0:
            critical = self.issues_by_severity.get('critical', 0)
            high = self.issues_by_severity.get('high', 0)
            
            if critical > 0:
                summary_parts.append(f"🚨 {critical} critical")
            if high > 0:
                summary_parts.append(f"⚠️ {high} high")
            
            summary_parts.append(f"{total_issues} total issues")
        
        if total_vulns > 0:
            summary_parts.append(f"{total_vulns} vulnerabilities")
        
        return ", ".join(summary_parts)


@dataclass
class BatchAnalysisResult:
    """Result of analyzing multiple files or projects."""
    
    # Batch metadata
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = field(default=None)
    
    # Individual analysis results
    results: List[AnalysisResponse] = field(default_factory=list)
    
    # Aggregate statistics
    total_requests: int = field(default=0)
    successful_analyses: int = field(default=0)
    failed_analyses: int = field(default=0)
    
    # Combined results
    all_issues: List[SecurityIssue] = field(default_factory=list)
    all_vulnerabilities: List[VulnerabilityReport] = field(default_factory=list)
    
    # Performance metrics
    average_duration: Optional[float] = field(default=None)
    total_files_processed: int = field(default=0)
    total_lines_processed: int = field(default=0)
    
    def __post_init__(self):
        """Calculate aggregate statistics."""
        if self.results:
            self._calculate_aggregates()
    
    def _calculate_aggregates(self):
        """Calculate aggregate statistics from individual results."""
        self.total_requests = len(self.results)
        self.successful_analyses = sum(1 for r in self.results if r.status == AnalysisStatus.COMPLETED)
        self.failed_analyses = sum(1 for r in self.results if r.status == AnalysisStatus.FAILED)
        
        # Combine all issues and vulnerabilities
        self.all_issues = []
        self.all_vulnerabilities = []
        
        durations = []
        for result in self.results:
            self.all_issues.extend(result.issues)
            self.all_vulnerabilities.extend(result.vulnerabilities)
            self.total_files_processed += result.total_files_analyzed
            self.total_lines_processed += result.total_lines_analyzed
            
            if result.duration_seconds:
                durations.append(result.duration_seconds)
        
        if durations:
            self.average_duration = sum(durations) / len(durations)
    
    def get_success_rate(self) -> float:
        """Get overall success rate for the batch."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_analyses / self.total_requests
    
    def get_critical_issues_count(self) -> int:
        """Get total count of critical issues across all analyses."""
        return sum(1 for issue in self.all_issues if issue.severity == Severity.CRITICAL)
    
    def get_high_issues_count(self) -> int:
        """Get total count of high severity issues across all analyses."""
        return sum(1 for issue in self.all_issues if issue.severity == Severity.HIGH)
    
    def has_any_blocking_issues(self) -> bool:
        """Check if any analysis in the batch found blocking issues."""
        return any(result.has_blocking_issues() for result in self.results)
    
    def get_batch_summary(self) -> str:
        """Get a summary of the entire batch analysis."""
        if self.total_requests == 0:
            return "No analyses performed"
        
        success_rate = self.get_success_rate() * 100
        critical_count = self.get_critical_issues_count()
        high_count = self.get_high_issues_count()
        total_issues = len(self.all_issues)
        total_vulns = len(self.all_vulnerabilities)
        
        summary = f"Batch: {self.successful_analyses}/{self.total_requests} successful ({success_rate:.1f}%)"
        
        if total_issues > 0 or total_vulns > 0:
            issue_parts = []
            if critical_count > 0:
                issue_parts.append(f"🚨 {critical_count} critical")
            if high_count > 0:
                issue_parts.append(f"⚠️ {high_count} high")
            if total_issues > 0:
                issue_parts.append(f"{total_issues} total issues")
            if total_vulns > 0:
                issue_parts.append(f"{total_vulns} vulnerabilities")
            
            summary += f" | {', '.join(issue_parts)}"
        else:
            summary += " | ✅ No issues found"
        
        return summary


@dataclass
class PolicyViolation:
    """Represents a violation of a security policy rule."""
    
    policy_id: str
    policy_name: str
    violation_type: str
    severity: Severity
    file_path: str
    line_number: int
    description: str
    rule_text: str
    remediation_steps: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = field(default=None)
    confidence_score: float = field(default=1.0)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate policy violation data."""
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError("confidence_score must be between 0.0 and 1.0")
        
        if self.line_number < 1:
            raise ValueError("line_number must be positive")
    
    def is_high_confidence(self) -> bool:
        """Check if this is a high confidence violation."""
        return self.confidence_score >= 0.8
    
    def get_severity_emoji(self) -> str:
        """Get emoji representation of severity."""
        return {
            Severity.LOW: "ℹ️",
            Severity.MEDIUM: "⚠️", 
            Severity.HIGH: "🚨",
            Severity.CRITICAL: "💥"
        }.get(self.severity, "❓")


# Type aliases for better code readability
AnalysisResults = Union[AnalysisResponse, BatchAnalysisResult]
SecurityFindings = Union[List[SecurityIssue], List[VulnerabilityReport], List[PolicyViolation]]