"""Feedback and remediation engine for generating intelligent security guidance."""

import re
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
from pathlib import Path

from compliance_sentinel.core.interfaces import (
    FeedbackEngine as IFeedbackEngine,
    SecurityIssue,
    VulnerabilityReport,
    Severity,
    SecurityCategory
)
from compliance_sentinel.models.analysis import AnalysisResponse, PolicyViolation
from compliance_sentinel.models.config import FeedbackConfig
from compliance_sentinel.utils.cache import get_global_cache
from compliance_sentinel.utils.error_handler import get_global_error_handler
from compliance_sentinel.core.validation import InputSanitizer


logger = logging.getLogger(__name__)


class RemediationPriority(Enum):
    """Priority levels for remediation actions."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RemediationAction:
    """Represents a specific remediation action."""
    action_id: str
    title: str
    description: str
    priority: RemediationPriority
    effort_level: str  # "low", "medium", "high"
    impact_level: str  # "low", "medium", "high"
    code_example: Optional[str] = None
    documentation_links: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    estimated_time_minutes: Optional[int] = None
    automated_fix_available: bool = False
    
    def get_priority_score(self) -> int:
        """Calculate priority score for sorting."""
        priority_scores = {
            RemediationPriority.IMMEDIATE: 100,
            RemediationPriority.HIGH: 75,
            RemediationPriority.MEDIUM: 50,
            RemediationPriority.LOW: 25
        }
        
        effort_multiplier = {"low": 1.2, "medium": 1.0, "high": 0.8}
        impact_multiplier = {"low": 0.8, "medium": 1.0, "high": 1.2}
        
        base_score = priority_scores.get(self.priority, 25)
        effort_factor = effort_multiplier.get(self.effort_level, 1.0)
        impact_factor = impact_multiplier.get(self.impact_level, 1.0)
        
        return int(base_score * effort_factor * impact_factor)


@dataclass
class FeedbackReport:
    """Comprehensive feedback report for security analysis."""
    report_id: str
    generated_at: datetime
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    overall_security_score: float
    remediation_actions: List[RemediationAction]
    executive_summary: str
    detailed_findings: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    next_steps: List[str]
    estimated_fix_time_hours: float
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of issues by severity."""
        return {
            "critical": self.critical_issues,
            "high": self.high_issues,
            "medium": self.medium_issues,
            "low": self.low_issues
        }
    
    def get_risk_level(self) -> str:
        """Determine overall risk level."""
        if self.critical_issues > 0:
            return "CRITICAL"
        elif self.high_issues > 5:
            return "HIGH"
        elif self.high_issues > 0 or self.medium_issues > 10:
            return "MEDIUM"
        else:
            return "LOW"


class RemediationDatabase:
    """Database of remediation actions and security guidance."""
    
    def __init__(self):
        """Initialize remediation database."""
        self.remediation_templates = self._load_remediation_templates()
        self.code_examples = self._load_code_examples()
        self.documentation_links = self._load_documentation_links()
        
    def _load_remediation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load remediation templates for different security categories."""
        return {
            SecurityCategory.HARDCODED_SECRETS.value: {
                "immediate_actions": [
                    {
                        "title": "Remove Hardcoded Secrets",
                        "description": "Immediately remove all hardcoded secrets from source code",
                        "priority": RemediationPriority.IMMEDIATE,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 30
                    },
                    {
                        "title": "Implement Environment Variables",
                        "description": "Move secrets to environment variables or secure configuration",
                        "priority": RemediationPriority.HIGH,
                        "effort": "low",
                        "impact": "high",
                        "time_minutes": 15
                    }
                ],
                "long_term_actions": [
                    {
                        "title": "Deploy Secret Management System",
                        "description": "Implement HashiCorp Vault, AWS Secrets Manager, or similar",
                        "priority": RemediationPriority.MEDIUM,
                        "effort": "high",
                        "impact": "high",
                        "time_minutes": 480
                    }
                ]
            },
            SecurityCategory.SQL_INJECTION.value: {
                "immediate_actions": [
                    {
                        "title": "Implement Parameterized Queries",
                        "description": "Replace string concatenation with parameterized queries",
                        "priority": RemediationPriority.IMMEDIATE,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 45
                    },
                    {
                        "title": "Input Validation",
                        "description": "Add comprehensive input validation and sanitization",
                        "priority": RemediationPriority.HIGH,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 60
                    }
                ]
            },
            SecurityCategory.XSS.value: {
                "immediate_actions": [
                    {
                        "title": "Output Encoding",
                        "description": "Implement proper output encoding for all user data",
                        "priority": RemediationPriority.IMMEDIATE,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 30
                    },
                    {
                        "title": "Content Security Policy",
                        "description": "Implement and configure Content Security Policy headers",
                        "priority": RemediationPriority.HIGH,
                        "effort": "low",
                        "impact": "medium",
                        "time_minutes": 20
                    }
                ]
            },
            SecurityCategory.INSECURE_CRYPTO.value: {
                "immediate_actions": [
                    {
                        "title": "Update Cryptographic Algorithms",
                        "description": "Replace weak algorithms with secure alternatives",
                        "priority": RemediationPriority.HIGH,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 60
                    },
                    {
                        "title": "Enable SSL/TLS Verification",
                        "description": "Enable proper certificate verification for all connections",
                        "priority": RemediationPriority.HIGH,
                        "effort": "low",
                        "impact": "high",
                        "time_minutes": 15
                    }
                ]
            },
            SecurityCategory.AUTHENTICATION.value: {
                "immediate_actions": [
                    {
                        "title": "Implement Authentication",
                        "description": "Add authentication to unprotected endpoints",
                        "priority": RemediationPriority.IMMEDIATE,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 90
                    },
                    {
                        "title": "Session Management",
                        "description": "Implement secure session management with proper timeouts",
                        "priority": RemediationPriority.HIGH,
                        "effort": "medium",
                        "impact": "medium",
                        "time_minutes": 45
                    }
                ]
            },
            SecurityCategory.INPUT_VALIDATION.value: {
                "immediate_actions": [
                    {
                        "title": "Input Sanitization",
                        "description": "Implement comprehensive input validation and sanitization",
                        "priority": RemediationPriority.HIGH,
                        "effort": "medium",
                        "impact": "high",
                        "time_minutes": 60
                    }
                ]
            }
        }
    
    def _load_code_examples(self) -> Dict[str, Dict[str, str]]:
        """Load code examples for different remediation actions."""
        return {
            "environment_variables": {
                "python": '''# Before (Insecure)
API_KEY = "hardcoded_api_key_123"

# After (Secure)
import os
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")''',
                
                "javascript": '''// Before (Insecure)
const API_KEY = "hardcoded_api_key_123";

// After (Secure)
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
    throw new Error("API_KEY environment variable not set");
}''',
                
                "java": '''// Before (Insecure)
String apiKey = "hardcoded_api_key_123";

// After (Secure)
String apiKey = System.getenv("API_KEY");
if (apiKey == null) {
    throw new IllegalStateException("API_KEY environment variable not set");
}'''
            },
            "parameterized_queries": {
                "python": '''# Before (Vulnerable to SQL Injection)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# After (Secure)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))''',
                
                "java": '''// Before (Vulnerable to SQL Injection)
String query = "SELECT * FROM users WHERE id = " + userId;
statement.executeQuery(query);

// After (Secure)
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, userId);
pstmt.executeQuery();'''
            },
            "output_encoding": {
                "python": '''# Before (Vulnerable to XSS)
return f"<div>Hello {user_name}</div>"

# After (Secure)
import html
return f"<div>Hello {html.escape(user_name)}</div>"''',
                
                "javascript": '''// Before (Vulnerable to XSS)
element.innerHTML = "Hello " + userName;

// After (Secure)
element.textContent = "Hello " + userName;
// Or use a templating library with auto-escaping'''
            },
            "strong_crypto": {
                "python": '''# Before (Weak)
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# After (Strong)
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())''',
                
                "java": '''// Before (Weak)
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// After (Strong)
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);'''
            }
        }
    
    def _load_documentation_links(self) -> Dict[str, List[str]]:
        """Load documentation links for different security topics."""
        return {
            SecurityCategory.HARDCODED_SECRETS.value: [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                "https://docs.github.com/en/actions/security-guides/encrypted-secrets"
            ],
            SecurityCategory.SQL_INJECTION.value: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/sql-injection"
            ],
            SecurityCategory.XSS.value: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            ],
            SecurityCategory.INSECURE_CRYPTO.value: [
                "https://owasp.org/www-community/vulnerabilities/Insecure_Cryptographic_Storage",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
            ],
            SecurityCategory.AUTHENTICATION.value: [
                "https://owasp.org/www-community/controls/Authentication",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://auth0.com/docs/secure/security-guidance"
            ]
        }
    
    def get_remediation_actions(self, category: SecurityCategory, severity: Severity) -> List[Dict[str, Any]]:
        """Get remediation actions for a specific category and severity."""
        category_key = category.value
        actions = []
        
        if category_key in self.remediation_templates:
            template = self.remediation_templates[category_key]
            
            # Always include immediate actions for high/critical severity
            if severity in [Severity.HIGH, Severity.CRITICAL]:
                actions.extend(template.get("immediate_actions", []))
            
            # Include long-term actions for comprehensive remediation
            actions.extend(template.get("long_term_actions", []))
        
        return actions
    
    def get_code_example(self, action_type: str, language: str = "python") -> Optional[str]:
        """Get code example for a specific action type and language."""
        if action_type in self.code_examples:
            return self.code_examples[action_type].get(language)
        return None
    
    def get_documentation_links(self, category: SecurityCategory) -> List[str]:
        """Get documentation links for a security category."""
        return self.documentation_links.get(category.value, [])


class FeedbackEngine(IFeedbackEngine):
    """Main feedback and remediation engine."""
    
    def __init__(self, config: Optional[FeedbackConfig] = None):
        """Initialize feedback engine."""
        self.config = config or FeedbackConfig()
        self.remediation_db = RemediationDatabase()
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        
        logger.info("Feedback engine initialized")
    
    def generate_report(self, analysis_result: AnalysisResponse) -> str:
        """Generate a human-readable analysis report."""
        try:
            # Create comprehensive feedback report
            feedback_report = self._create_feedback_report(analysis_result)
            
            # Generate formatted report
            report = self._format_report(feedback_report)
            
            logger.info(f"Generated feedback report for request {analysis_result.request_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            self.error_handler.handle_analysis_error(e, "feedback_generation")
            return self._generate_error_report(str(e))
    
    def format_ide_feedback(self, issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Format feedback for IDE integration."""
        try:
            # Group issues by file and line
            grouped_issues = self._group_issues_by_location(issues)
            
            # Generate IDE-compatible feedback
            ide_feedback = {
                "version": "1.0",
                "timestamp": datetime.utcnow().isoformat(),
                "total_issues": len(issues),
                "files": {}
            }
            
            for file_path, file_issues in grouped_issues.items():
                ide_feedback["files"][file_path] = {
                    "issues": [],
                    "summary": {
                        "total": len(file_issues),
                        "critical": len([i for i in file_issues if i.severity == Severity.CRITICAL]),
                        "high": len([i for i in file_issues if i.severity == Severity.HIGH]),
                        "medium": len([i for i in file_issues if i.severity == Severity.MEDIUM]),
                        "low": len([i for i in file_issues if i.severity == Severity.LOW])
                    }
                }
                
                for issue in file_issues:
                    ide_issue = self._format_issue_for_ide(issue)
                    ide_feedback["files"][file_path]["issues"].append(ide_issue)
            
            logger.debug(f"Formatted IDE feedback for {len(issues)} issues")
            return ide_feedback
            
        except Exception as e:
            logger.error(f"Failed to format IDE feedback: {e}")
            self.error_handler.handle_analysis_error(e, "ide_feedback_formatting")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    def prioritize_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Prioritize issues by severity, confidence, and impact."""
        try:
            def priority_score(issue: SecurityIssue) -> Tuple[int, float, int, str]:
                # Severity weight (higher is more important)
                severity_weights = {
                    Severity.CRITICAL: 1000,
                    Severity.HIGH: 750,
                    Severity.MEDIUM: 500,
                    Severity.LOW: 250
                }
                
                # Category impact weight
                category_weights = {
                    SecurityCategory.SQL_INJECTION: 1.0,
                    SecurityCategory.HARDCODED_SECRETS: 0.9,
                    SecurityCategory.XSS: 0.8,
                    SecurityCategory.INSECURE_CRYPTO: 0.7,
                    SecurityCategory.AUTHENTICATION: 0.8,
                    SecurityCategory.INPUT_VALIDATION: 0.6,
                    SecurityCategory.DEPENDENCY_VULNERABILITY: 0.7
                }
                
                severity_score = severity_weights.get(issue.severity, 250)
                confidence_score = issue.confidence
                category_weight = category_weights.get(issue.category, 0.5)
                
                # Calculate final priority score
                final_score = int(severity_score * confidence_score * category_weight)
                
                return (
                    -final_score,  # Negative for descending sort
                    -confidence_score,  # Higher confidence first
                    issue.line_number,  # Earlier lines first
                    issue.file_path  # Alphabetical by file
                )
            
            prioritized = sorted(issues, key=priority_score)
            
            logger.debug(f"Prioritized {len(issues)} issues")
            return prioritized
            
        except Exception as e:
            logger.error(f"Failed to prioritize issues: {e}")
            return issues  # Return original list on error  
  
    def _create_feedback_report(self, analysis_result: AnalysisResponse) -> FeedbackReport:
        """Create comprehensive feedback report."""
        import uuid
        
        # Count issues by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in analysis_result.issues:
            severity_counts[issue.severity.value] += 1
        
        # Generate remediation actions
        remediation_actions = self._generate_remediation_actions(analysis_result.issues)
        
        # Calculate security score (0-100)
        security_score = self._calculate_security_score(analysis_result.issues)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(analysis_result, security_score)
        
        # Create detailed findings
        detailed_findings = self._create_detailed_findings(analysis_result.issues)
        
        # Generate next steps
        next_steps = self._generate_next_steps(remediation_actions)
        
        # Estimate fix time
        estimated_fix_time = self._estimate_fix_time(remediation_actions)
        
        return FeedbackReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            total_issues=len(analysis_result.issues),
            critical_issues=severity_counts["critical"],
            high_issues=severity_counts["high"],
            medium_issues=severity_counts["medium"],
            low_issues=severity_counts["low"],
            overall_security_score=security_score,
            remediation_actions=remediation_actions,
            executive_summary=executive_summary,
            detailed_findings=detailed_findings,
            compliance_status=self._assess_compliance_status(analysis_result.issues),
            next_steps=next_steps,
            estimated_fix_time_hours=estimated_fix_time
        )
    
    def _generate_remediation_actions(self, issues: List[SecurityIssue]) -> List[RemediationAction]:
        """Generate prioritized remediation actions."""
        actions = []
        action_counter = 1
        
        # Group issues by category
        issues_by_category = {}
        for issue in issues:
            category = issue.category
            if category not in issues_by_category:
                issues_by_category[category] = []
            issues_by_category[category].append(issue)
        
        # Generate actions for each category
        for category, category_issues in issues_by_category.items():
            # Determine highest severity in category
            max_severity = max(issue.severity for issue in category_issues)
            
            # Get remediation templates
            remediation_templates = self.remediation_db.get_remediation_actions(category, max_severity)
            
            for template in remediation_templates:
                # Create remediation action
                action = RemediationAction(
                    action_id=f"action_{action_counter}",
                    title=template["title"],
                    description=template["description"],
                    priority=template["priority"],
                    effort_level=template["effort"],
                    impact_level=template["impact"],
                    estimated_time_minutes=template.get("time_minutes"),
                    documentation_links=self.remediation_db.get_documentation_links(category)
                )
                
                # Add code example if available
                action_type = self._map_action_to_code_example(template["title"])
                if action_type:
                    code_example = self.remediation_db.get_code_example(action_type)
                    if code_example:
                        action.code_example = code_example
                
                actions.append(action)
                action_counter += 1
        
        # Sort by priority score
        actions.sort(key=lambda a: a.get_priority_score(), reverse=True)
        
        # Limit to top actions based on config
        max_actions = getattr(self.config, 'max_remediation_actions', 10) if self.config else 10
        return actions[:max_actions]
    
    def _calculate_security_score(self, issues: List[SecurityIssue]) -> float:
        """Calculate overall security score (0-100)."""
        if not issues:
            return 100.0
        
        # Weight issues by severity
        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3
        }
        
        total_penalty = 0
        for issue in issues:
            penalty = severity_weights.get(issue.severity, 3)
            # Adjust by confidence
            penalty *= issue.confidence
            total_penalty += penalty
        
        # Calculate score (max penalty of 100 points)
        max_penalty = 100
        score = max(0, 100 - min(total_penalty, max_penalty))
        
        return round(score, 1)
    
    def _generate_executive_summary(self, analysis_result: AnalysisResponse, security_score: float) -> str:
        """Generate executive summary of security analysis."""
        total_issues = len(analysis_result.issues)
        
        if total_issues == 0:
            return "✅ Excellent! No security issues were identified in the analyzed code. The codebase demonstrates good security practices."
        
        # Count critical and high issues
        critical_count = len([i for i in analysis_result.issues if i.severity == Severity.CRITICAL])
        high_count = len([i for i in analysis_result.issues if i.severity == Severity.HIGH])
        
        # Generate summary based on findings
        if critical_count > 0:
            summary = f"🚨 CRITICAL: {critical_count} critical security issues require immediate attention. "
        elif high_count > 0:
            summary = f"⚠️ HIGH PRIORITY: {high_count} high-severity security issues need prompt resolution. "
        else:
            summary = "ℹ️ MODERATE: Security issues identified require attention but pose lower immediate risk. "
        
        summary += f"Overall security score: {security_score}/100. "
        
        # Add category breakdown
        categories = set(issue.category for issue in analysis_result.issues)
        if len(categories) > 1:
            summary += f"Issues span {len(categories)} security categories, indicating need for comprehensive security review."
        else:
            category_name = list(categories)[0].value.replace('_', ' ').title()
            summary += f"Issues primarily relate to {category_name}."
        
        return summary
    
    def _create_detailed_findings(self, issues: List[SecurityIssue]) -> List[Dict[str, Any]]:
        """Create detailed findings for each issue."""
        findings = []
        
        for issue in issues:
            finding = {
                "issue_id": issue.id,
                "severity": issue.severity.value,
                "category": issue.category.value,
                "title": issue.description.split(':')[0] if ':' in issue.description else issue.description,
                "description": issue.description,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "confidence": f"{issue.confidence:.1%}",
                "rule_id": issue.rule_id,
                "remediation_suggestions": issue.remediation_suggestions,
                "severity_color": getattr(self.config, 'severity_colors', {}).get(issue.severity.value, "#666666") if self.config else "#666666",
                "category_icon": self._get_category_icon(issue.category),
                "estimated_fix_time": self._estimate_issue_fix_time(issue)
            }
            findings.append(finding)
        
        return findings
    
    def _assess_compliance_status(self, issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Assess compliance status against security frameworks."""
        compliance_status = {
            "owasp_top_10": {"compliant": True, "violations": []},
            "cwe_top_25": {"compliant": True, "violations": []},
            "overall_compliance": "COMPLIANT"
        }
        
        # Check OWASP Top 10 compliance
        owasp_violations = []
        for issue in issues:
            if issue.category in [SecurityCategory.SQL_INJECTION, SecurityCategory.XSS]:
                owasp_violations.append("A03:2021 - Injection")
            elif issue.category == SecurityCategory.HARDCODED_SECRETS:
                owasp_violations.append("A02:2021 - Cryptographic Failures")
            elif issue.category == SecurityCategory.AUTHENTICATION:
                owasp_violations.append("A01:2021 - Broken Access Control")
        
        if owasp_violations:
            compliance_status["owasp_top_10"]["compliant"] = False
            compliance_status["owasp_top_10"]["violations"] = list(set(owasp_violations))
            compliance_status["overall_compliance"] = "NON_COMPLIANT"
        
        # Check for critical issues affecting compliance
        critical_issues = [i for i in issues if i.severity == Severity.CRITICAL]
        if critical_issues:
            compliance_status["overall_compliance"] = "CRITICAL_NON_COMPLIANT"
        
        return compliance_status
    
    def _generate_next_steps(self, remediation_actions: List[RemediationAction]) -> List[str]:
        """Generate prioritized next steps."""
        next_steps = []
        
        # Group actions by priority
        immediate_actions = [a for a in remediation_actions if a.priority == RemediationPriority.IMMEDIATE]
        high_actions = [a for a in remediation_actions if a.priority == RemediationPriority.HIGH]
        
        if immediate_actions:
            next_steps.append(f"🚨 IMMEDIATE: Address {len(immediate_actions)} critical security issues requiring immediate attention")
            for action in immediate_actions[:3]:  # Top 3 immediate actions
                next_steps.append(f"   • {action.title}")
        
        if high_actions:
            next_steps.append(f"⚠️ HIGH PRIORITY: Plan remediation for {len(high_actions)} high-priority security issues")
        
        # Add general recommendations
        next_steps.extend([
            "📋 Review and implement security code review processes",
            "🔍 Consider automated security scanning in CI/CD pipeline",
            "📚 Provide security training for development team",
            "🔄 Schedule regular security assessments"
        ])
        
        return next_steps[:8]  # Limit to top 8 steps
    
    def _estimate_fix_time(self, remediation_actions: List[RemediationAction]) -> float:
        """Estimate total time to fix all issues."""
        total_minutes = 0
        
        for action in remediation_actions:
            if action.estimated_time_minutes:
                total_minutes += action.estimated_time_minutes
        
        return round(total_minutes / 60.0, 1)  # Convert to hours
    
    def _format_report(self, feedback_report: FeedbackReport) -> str:
        """Format feedback report as human-readable text."""
        report_lines = []
        
        # Header
        report_lines.extend([
            "=" * 80,
            "🛡️  COMPLIANCE SENTINEL SECURITY ANALYSIS REPORT",
            "=" * 80,
            f"Report ID: {feedback_report.report_id}",
            f"Generated: {feedback_report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Security Score: {feedback_report.overall_security_score}/100",
            f"Risk Level: {feedback_report.get_risk_level()}",
            ""
        ])
        
        # Executive Summary
        report_lines.extend([
            "📋 EXECUTIVE SUMMARY",
            "-" * 40,
            feedback_report.executive_summary,
            ""
        ])
        
        # Issue Summary
        if feedback_report.total_issues > 0:
            report_lines.extend([
                "📊 ISSUE SUMMARY",
                "-" * 40,
                f"Total Issues: {feedback_report.total_issues}",
                f"  🔴 Critical: {feedback_report.critical_issues}",
                f"  🟠 High: {feedback_report.high_issues}",
                f"  🟡 Medium: {feedback_report.medium_issues}",
                f"  🔵 Low: {feedback_report.low_issues}",
                ""
            ])
        
        # Top Remediation Actions
        if feedback_report.remediation_actions:
            report_lines.extend([
                "🔧 PRIORITY REMEDIATION ACTIONS",
                "-" * 40
            ])
            
            for i, action in enumerate(feedback_report.remediation_actions[:5], 1):
                priority_icon = {
                    RemediationPriority.IMMEDIATE: "🚨",
                    RemediationPriority.HIGH: "⚠️",
                    RemediationPriority.MEDIUM: "📋",
                    RemediationPriority.LOW: "ℹ️"
                }.get(action.priority, "📋")
                
                report_lines.extend([
                    f"{i}. {priority_icon} {action.title}",
                    f"   {action.description}",
                    f"   Effort: {action.effort_level.title()} | Impact: {action.impact_level.title()}"
                ])
                
                if action.estimated_time_minutes:
                    report_lines.append(f"   Estimated Time: {action.estimated_time_minutes} minutes")
                
                report_lines.append("")
        
        # Next Steps
        if feedback_report.next_steps:
            report_lines.extend([
                "🎯 NEXT STEPS",
                "-" * 40
            ])
            
            for step in feedback_report.next_steps:
                report_lines.append(f"• {step}")
            
            report_lines.append("")
        
        # Compliance Status
        compliance = feedback_report.compliance_status
        if compliance.get("overall_compliance") != "COMPLIANT":
            report_lines.extend([
                "⚖️ COMPLIANCE STATUS",
                "-" * 40,
                f"Overall Status: {compliance['overall_compliance']}",
                ""
            ])
            
            if not compliance.get("owasp_top_10", {}).get("compliant", True):
                violations = compliance["owasp_top_10"]["violations"]
                report_lines.extend([
                    "OWASP Top 10 Violations:",
                    *[f"  • {violation}" for violation in violations],
                    ""
                ])
        
        # Footer
        report_lines.extend([
            "=" * 80,
            f"Estimated Total Fix Time: {feedback_report.estimated_fix_time_hours} hours",
            "For detailed remediation guidance, refer to the provided documentation links.",
            "=" * 80
        ])
        
        return "\n".join(report_lines)
    
    def _group_issues_by_location(self, issues: List[SecurityIssue]) -> Dict[str, List[SecurityIssue]]:
        """Group issues by file path."""
        grouped = {}
        for issue in issues:
            file_path = issue.file_path
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(issue)
        return grouped
    
    def _format_issue_for_ide(self, issue: SecurityIssue) -> Dict[str, Any]:
        """Format a single issue for IDE display."""
        return {
            "id": issue.id,
            "severity": issue.severity.value,
            "category": issue.category.value,
            "line": issue.line_number,
            "message": issue.description,
            "rule_id": issue.rule_id,
            "confidence": issue.confidence,
            "remediation": issue.remediation_suggestions[:self.config.max_suggestions_per_issue],
            "color": self.config.severity_colors.get(issue.severity.value, "#666666"),
            "icon": self._get_category_icon(issue.category),
            "documentation_links": self.remediation_db.get_documentation_links(issue.category)[:3]
        }
    
    def _get_category_icon(self, category: SecurityCategory) -> str:
        """Get icon for security category."""
        icons = {
            SecurityCategory.HARDCODED_SECRETS: "🔑",
            SecurityCategory.SQL_INJECTION: "💉",
            SecurityCategory.XSS: "🕸️",
            SecurityCategory.INSECURE_CRYPTO: "🔒",
            SecurityCategory.AUTHENTICATION: "👤",
            SecurityCategory.INPUT_VALIDATION: "✅",
            SecurityCategory.DEPENDENCY_VULNERABILITY: "📦"
        }
        return icons.get(category, "⚠️")
    
    def _estimate_issue_fix_time(self, issue: SecurityIssue) -> str:
        """Estimate fix time for a single issue."""
        base_times = {
            Severity.CRITICAL: 60,  # 1 hour
            Severity.HIGH: 45,      # 45 minutes
            Severity.MEDIUM: 30,    # 30 minutes
            Severity.LOW: 15        # 15 minutes
        }
        
        base_time = base_times.get(issue.severity, 30)
        
        # Adjust by confidence (lower confidence = more investigation time)
        if issue.confidence < 0.7:
            base_time = int(base_time * 1.5)
        
        return f"{base_time} minutes"
    
    def _map_action_to_code_example(self, action_title: str) -> Optional[str]:
        """Map action title to code example type."""
        title_lower = action_title.lower()
        
        if "environment" in title_lower or "secret" in title_lower:
            return "environment_variables"
        elif "parameterized" in title_lower or "sql" in title_lower:
            return "parameterized_queries"
        elif "encoding" in title_lower or "xss" in title_lower:
            return "output_encoding"
        elif "crypto" in title_lower or "algorithm" in title_lower:
            return "strong_crypto"
        
        return None
    
    def _generate_error_report(self, error_message: str) -> str:
        """Generate error report when feedback generation fails."""
        return f"""
ERROR: Feedback Generation Failed
================================

An error occurred while generating the security analysis report:
{error_message}

Please check the logs for more details and try again.
If the problem persists, contact support.

Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
""" 
   
    def _group_issues_by_location(self, issues: List[SecurityIssue]) -> Dict[str, List[SecurityIssue]]:
        """Group issues by file path."""
        grouped = {}
        for issue in issues:
            file_path = issue.file_path
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(issue)
        return grouped
    
    def _format_issue_for_ide(self, issue: SecurityIssue) -> Dict[str, Any]:
        """Format a single issue for IDE display."""
        return {
            "id": issue.id,
            "severity": issue.severity.value,
            "category": issue.category.value,
            "title": issue.description.split(':')[0] if ':' in issue.description else issue.description,
            "description": issue.description,
            "line": issue.line_number,
            "column": getattr(issue, 'column_number', 0),
            "confidence": f"{issue.confidence:.1%}",
            "rule_id": issue.rule_id,
            "remediation": issue.remediation_suggestions[:3] if issue.remediation_suggestions else [],
            "severity_color": getattr(self.config, 'severity_colors', {}).get(issue.severity.value, "#666666") if self.config else "#666666",
            "category_icon": self._get_category_icon(issue.category),
            "documentation_links": self.remediation_db.get_documentation_links(issue.category)[:2]
        }
    
    def _get_category_icon(self, category: SecurityCategory) -> str:
        """Get icon for security category."""
        icons = {
            SecurityCategory.SQL_INJECTION: "🛡️",
            SecurityCategory.XSS: "🔒",
            SecurityCategory.HARDCODED_SECRETS: "🔑",
            SecurityCategory.INSECURE_CRYPTO: "🔐",
            SecurityCategory.AUTHENTICATION: "👤",
            SecurityCategory.INPUT_VALIDATION: "✅",
            SecurityCategory.DEPENDENCY_VULNERABILITY: "📦"
        }
        return icons.get(category, "⚠️")
    
    def _estimate_issue_fix_time(self, issue: SecurityIssue) -> str:
        """Estimate time to fix a specific issue."""
        base_times = {
            Severity.CRITICAL: 120,  # 2 hours
            Severity.HIGH: 60,       # 1 hour
            Severity.MEDIUM: 30,     # 30 minutes
            Severity.LOW: 15         # 15 minutes
        }
        
        category_multipliers = {
            SecurityCategory.HARDCODED_SECRETS: 0.5,  # Quick fix
            SecurityCategory.SQL_INJECTION: 1.5,      # More complex
            SecurityCategory.XSS: 1.2,
            SecurityCategory.INSECURE_CRYPTO: 1.8,    # Complex
            SecurityCategory.AUTHENTICATION: 2.0,     # Very complex
            SecurityCategory.INPUT_VALIDATION: 1.0,
            SecurityCategory.DEPENDENCY_VULNERABILITY: 0.3  # Usually just update
        }
        
        base_time = base_times.get(issue.severity, 30)
        multiplier = category_multipliers.get(issue.category, 1.0)
        estimated_minutes = int(base_time * multiplier)
        
        if estimated_minutes < 60:
            return f"{estimated_minutes} minutes"
        else:
            hours = estimated_minutes // 60
            minutes = estimated_minutes % 60
            if minutes == 0:
                return f"{hours} hour{'s' if hours > 1 else ''}"
            else:
                return f"{hours}h {minutes}m"
    
    def _format_report(self, feedback_report: FeedbackReport) -> str:
        """Format the comprehensive feedback report."""
        report_lines = []
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append("🛡️  SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {feedback_report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"Report ID: {feedback_report.report_id}")
        report_lines.append("")
        
        # Executive Summary
        report_lines.append("📋 EXECUTIVE SUMMARY")
        report_lines.append("-" * 40)
        report_lines.append(feedback_report.executive_summary)
        report_lines.append("")
        
        # Security Score
        score_color = "🟢" if feedback_report.overall_security_score >= 80 else "🟡" if feedback_report.overall_security_score >= 60 else "🔴"
        report_lines.append(f"🎯 SECURITY SCORE: {score_color} {feedback_report.overall_security_score}/100")
        report_lines.append("")
        
        # Issue Summary
        report_lines.append("📊 ISSUE SUMMARY")
        report_lines.append("-" * 40)
        report_lines.append(f"Total Issues: {feedback_report.total_issues}")
        if feedback_report.total_issues > 0:
            severity_dist = feedback_report.get_severity_distribution()
            report_lines.append(f"  🔴 Critical: {severity_dist['critical']}")
            report_lines.append(f"  🟠 High: {severity_dist['high']}")
            report_lines.append(f"  🟡 Medium: {severity_dist['medium']}")
            report_lines.append(f"  🔵 Low: {severity_dist['low']}")
        report_lines.append("")
        
        # Risk Level
        risk_level = feedback_report.get_risk_level()
        risk_emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "ℹ️", "LOW": "✅"}.get(risk_level, "❓")
        report_lines.append(f"🎚️  RISK LEVEL: {risk_emoji} {risk_level}")
        report_lines.append("")
        
        # Compliance Status
        if feedback_report.compliance_status:
            report_lines.append("📜 COMPLIANCE STATUS")
            report_lines.append("-" * 40)
            overall_compliance = feedback_report.compliance_status.get("overall_compliance", "UNKNOWN")
            compliance_emoji = {"COMPLIANT": "✅", "NON_COMPLIANT": "❌", "CRITICAL_NON_COMPLIANT": "🚨"}.get(overall_compliance, "❓")
            report_lines.append(f"Overall: {compliance_emoji} {overall_compliance}")
            
            # OWASP Top 10
            owasp_status = feedback_report.compliance_status.get("owasp_top_10", {})
            if not owasp_status.get("compliant", True):
                report_lines.append("OWASP Top 10 Violations:")
                for violation in owasp_status.get("violations", []):
                    report_lines.append(f"  • {violation}")
            report_lines.append("")
        
        # Top Priority Actions
        if feedback_report.remediation_actions:
            report_lines.append("🚀 TOP PRIORITY ACTIONS")
            report_lines.append("-" * 40)
            for i, action in enumerate(feedback_report.remediation_actions[:5], 1):
                priority_emoji = {"immediate": "🚨", "high": "⚠️", "medium": "ℹ️", "low": "💡"}.get(action.priority.value, "📝")
                report_lines.append(f"{i}. {priority_emoji} {action.title}")
                report_lines.append(f"   Priority: {action.priority.value.title()} | Effort: {action.effort_level.title()} | Impact: {action.impact_level.title()}")
                if action.estimated_time_minutes:
                    report_lines.append(f"   Estimated Time: {action.estimated_time_minutes} minutes")
                report_lines.append("")
        
        # Next Steps
        if feedback_report.next_steps:
            report_lines.append("📝 NEXT STEPS")
            report_lines.append("-" * 40)
            for i, step in enumerate(feedback_report.next_steps, 1):
                report_lines.append(f"{i}. {step}")
            report_lines.append("")
        
        # Time Estimate
        if feedback_report.estimated_fix_time_hours > 0:
            report_lines.append(f"⏱️  ESTIMATED FIX TIME: {feedback_report.estimated_fix_time_hours:.1f} hours")
            report_lines.append("")
        
        # Footer
        report_lines.append("=" * 80)
        report_lines.append("Generated by Compliance Sentinel - Intelligent Security Analysis")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)
    
    def _estimate_fix_time(self, remediation_actions: List[RemediationAction]) -> float:
        """Estimate total time to complete all remediation actions."""
        total_minutes = 0
        for action in remediation_actions:
            if action.estimated_time_minutes:
                total_minutes += action.estimated_time_minutes
            else:
                # Default estimates based on priority
                default_times = {
                    RemediationPriority.IMMEDIATE: 60,
                    RemediationPriority.HIGH: 45,
                    RemediationPriority.MEDIUM: 30,
                    RemediationPriority.LOW: 15
                }
                total_minutes += default_times.get(action.priority, 30)
        
        return total_minutes / 60.0  # Convert to hours