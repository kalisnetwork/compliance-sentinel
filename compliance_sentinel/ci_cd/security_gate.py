"""Security gate configuration and result handling for CI/CD pipelines."""

from typing import List, Dict, Optional, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import json
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class SecurityGateAction(Enum):
    """Actions to take when security gate conditions are met."""
    BLOCK = "block"
    WARN = "warn"
    IGNORE = "ignore"


class SecurityGateStatus(Enum):
    """Security gate evaluation status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


@dataclass
class SecurityGateRule:
    """Individual security gate rule configuration."""
    name: str
    severity_threshold: Severity
    max_issues: int
    categories: Optional[List[SecurityCategory]] = None
    action: SecurityGateAction = SecurityGateAction.BLOCK
    enabled: bool = True


@dataclass
class SecurityGateConfig:
    """Security gate configuration for CI/CD pipelines."""
    
    # Basic configuration
    enabled: bool = True
    fail_on_error: bool = True
    
    # Severity thresholds
    block_on_critical: bool = True
    block_on_high: bool = True
    block_on_medium: bool = False
    block_on_low: bool = False
    
    # Issue count limits
    max_critical_issues: int = 0
    max_high_issues: int = 5
    max_medium_issues: int = 20
    max_low_issues: int = 50
    
    # Category-specific rules
    rules: List[SecurityGateRule] = None
    
    # Exclusions
    excluded_files: List[str] = None
    excluded_categories: List[SecurityCategory] = None
    
    # Reporting
    generate_report: bool = True
    report_format: str = "json"  # json, xml, html, sarif
    report_path: str = "security-report"
    
    def __post_init__(self):
        """Initialize default values."""
        if self.rules is None:
            self.rules = []
        if self.excluded_files is None:
            self.excluded_files = []
        if self.excluded_categories is None:
            self.excluded_categories = []
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'SecurityGateConfig':
        """Create configuration from dictionary."""
        # Convert string severity values to enum
        if 'rules' in config_dict:
            for rule_dict in config_dict['rules']:
                if 'severity_threshold' in rule_dict:
                    rule_dict['severity_threshold'] = Severity(rule_dict['severity_threshold'])
                if 'categories' in rule_dict:
                    rule_dict['categories'] = [SecurityCategory(cat) for cat in rule_dict['categories']]
                if 'action' in rule_dict:
                    rule_dict['action'] = SecurityGateAction(rule_dict['action'])
        
        if 'excluded_categories' in config_dict:
            config_dict['excluded_categories'] = [SecurityCategory(cat) for cat in config_dict['excluded_categories']]
        
        return cls(**config_dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, list):
                if value and isinstance(value[0], (Severity, SecurityCategory, SecurityGateAction)):
                    result[key] = [item.value for item in value]
                elif value and isinstance(value[0], SecurityGateRule):
                    result[key] = [rule.__dict__ for rule in value]
                else:
                    result[key] = value
            elif isinstance(value, (Severity, SecurityCategory, SecurityGateAction)):
                result[key] = value.value
            else:
                result[key] = value
        return result


@dataclass
class SecurityGateResult:
    """Result of security gate evaluation."""
    
    status: SecurityGateStatus
    total_issues: int
    issues_by_severity: Dict[Severity, int]
    issues_by_category: Dict[SecurityCategory, int]
    blocked_issues: List[SecurityIssue]
    warning_issues: List[SecurityIssue]
    all_issues: List[SecurityIssue]
    
    # Execution details
    scan_duration: float
    files_scanned: int
    timestamp: datetime
    
    # Gate evaluation details
    failed_rules: List[str]
    passed_rules: List[str]
    
    # Messages
    summary_message: str
    detailed_messages: List[str]
    
    def __post_init__(self):
        """Initialize computed fields."""
        if not self.summary_message:
            self.summary_message = self._generate_summary()
    
    def _generate_summary(self) -> str:
        """Generate summary message."""
        if self.status == SecurityGateStatus.PASSED:
            return f"Security gate PASSED: {self.total_issues} issues found, all within acceptable limits"
        elif self.status == SecurityGateStatus.FAILED:
            critical_count = self.issues_by_severity.get(Severity.CRITICAL, 0)
            high_count = self.issues_by_severity.get(Severity.HIGH, 0)
            return f"Security gate FAILED: {critical_count} critical, {high_count} high severity issues found"
        else:
            return f"Security gate WARNING: {self.total_issues} issues found with warnings"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            'status': self.status.value,
            'total_issues': self.total_issues,
            'issues_by_severity': {sev.value: count for sev, count in self.issues_by_severity.items()},
            'issues_by_category': {cat.value: count for cat, count in self.issues_by_category.items()},
            'blocked_issues': [issue.__dict__ for issue in self.blocked_issues],
            'warning_issues': [issue.__dict__ for issue in self.warning_issues],
            'scan_duration': self.scan_duration,
            'files_scanned': self.files_scanned,
            'timestamp': self.timestamp.isoformat(),
            'failed_rules': self.failed_rules,
            'passed_rules': self.passed_rules,
            'summary_message': self.summary_message,
            'detailed_messages': self.detailed_messages
        }
    
    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class SecurityGateEvaluator:
    """Evaluates security issues against gate configuration."""
    
    def __init__(self, config: SecurityGateConfig):
        """Initialize evaluator with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def evaluate(self, issues: List[SecurityIssue], scan_duration: float, files_scanned: int) -> SecurityGateResult:
        """Evaluate security issues against gate configuration."""
        
        # Filter excluded issues
        filtered_issues = self._filter_excluded_issues(issues)
        
        # Count issues by severity and category
        issues_by_severity = self._count_by_severity(filtered_issues)
        issues_by_category = self._count_by_category(filtered_issues)
        
        # Evaluate rules
        blocked_issues = []
        warning_issues = []
        failed_rules = []
        passed_rules = []
        
        # Check severity thresholds
        if self.config.block_on_critical and issues_by_severity.get(Severity.CRITICAL, 0) > self.config.max_critical_issues:
            critical_issues = [issue for issue in filtered_issues if issue.severity == Severity.CRITICAL]
            blocked_issues.extend(critical_issues)
            failed_rules.append(f"Critical issues: {len(critical_issues)} > {self.config.max_critical_issues}")
        else:
            passed_rules.append("Critical issues threshold")
        
        if self.config.block_on_high and issues_by_severity.get(Severity.HIGH, 0) > self.config.max_high_issues:
            high_issues = [issue for issue in filtered_issues if issue.severity == Severity.HIGH]
            blocked_issues.extend(high_issues)
            failed_rules.append(f"High severity issues: {len(high_issues)} > {self.config.max_high_issues}")
        else:
            passed_rules.append("High severity issues threshold")
        
        if self.config.block_on_medium and issues_by_severity.get(Severity.MEDIUM, 0) > self.config.max_medium_issues:
            medium_issues = [issue for issue in filtered_issues if issue.severity == Severity.MEDIUM]
            if self.config.block_on_medium:
                blocked_issues.extend(medium_issues)
                failed_rules.append(f"Medium severity issues: {len(medium_issues)} > {self.config.max_medium_issues}")
            else:
                warning_issues.extend(medium_issues)
        else:
            passed_rules.append("Medium severity issues threshold")
        
        # Evaluate custom rules
        for rule in self.config.rules:
            if not rule.enabled:
                continue
            
            rule_issues = self._filter_issues_for_rule(filtered_issues, rule)
            
            if len(rule_issues) > rule.max_issues:
                if rule.action == SecurityGateAction.BLOCK:
                    blocked_issues.extend(rule_issues)
                    failed_rules.append(f"Rule '{rule.name}': {len(rule_issues)} > {rule.max_issues}")
                elif rule.action == SecurityGateAction.WARN:
                    warning_issues.extend(rule_issues)
                # IGNORE action does nothing
            else:
                passed_rules.append(f"Rule '{rule.name}'")
        
        # Determine overall status
        if blocked_issues:
            status = SecurityGateStatus.FAILED
        elif warning_issues:
            status = SecurityGateStatus.WARNING
        else:
            status = SecurityGateStatus.PASSED
        
        # Generate detailed messages
        detailed_messages = []
        if failed_rules:
            detailed_messages.append("Failed rules:")
            detailed_messages.extend([f"  - {rule}" for rule in failed_rules])
        
        if passed_rules:
            detailed_messages.append("Passed rules:")
            detailed_messages.extend([f"  - {rule}" for rule in passed_rules])
        
        return SecurityGateResult(
            status=status,
            total_issues=len(filtered_issues),
            issues_by_severity=issues_by_severity,
            issues_by_category=issues_by_category,
            blocked_issues=list(set(blocked_issues)),  # Remove duplicates
            warning_issues=list(set(warning_issues)),
            all_issues=filtered_issues,
            scan_duration=scan_duration,
            files_scanned=files_scanned,
            timestamp=datetime.now(),
            failed_rules=failed_rules,
            passed_rules=passed_rules,
            summary_message="",  # Will be generated in __post_init__
            detailed_messages=detailed_messages
        )
    
    def _filter_excluded_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Filter out excluded issues."""
        filtered = []
        
        for issue in issues:
            # Check excluded files
            if any(pattern in issue.file_path for pattern in self.config.excluded_files):
                continue
            
            # Check excluded categories
            if issue.category in self.config.excluded_categories:
                continue
            
            filtered.append(issue)
        
        return filtered
    
    def _count_by_severity(self, issues: List[SecurityIssue]) -> Dict[Severity, int]:
        """Count issues by severity."""
        counts = {severity: 0 for severity in Severity}
        for issue in issues:
            counts[issue.severity] += 1
        return counts
    
    def _count_by_category(self, issues: List[SecurityIssue]) -> Dict[SecurityCategory, int]:
        """Count issues by category."""
        counts = {}
        for issue in issues:
            counts[issue.category] = counts.get(issue.category, 0) + 1
        return counts
    
    def _filter_issues_for_rule(self, issues: List[SecurityIssue], rule: SecurityGateRule) -> List[SecurityIssue]:
        """Filter issues that match a specific rule."""
        filtered = []
        
        for issue in issues:
            # Check severity threshold
            if issue.severity.value < rule.severity_threshold.value:
                continue
            
            # Check categories if specified
            if rule.categories and issue.category not in rule.categories:
                continue
            
            filtered.append(issue)
        
        return filtered