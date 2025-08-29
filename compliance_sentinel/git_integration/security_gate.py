"""Security gate configuration with customizable pass/fail criteria."""

import json
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory


logger = logging.getLogger(__name__)


class GateResult(Enum):
    """Security gate evaluation results."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    CONDITIONAL_PASS = "conditional_pass"


class PolicyOperator(Enum):
    """Policy condition operators."""
    EQUALS = "equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"


@dataclass
class PolicyCondition:
    """Individual policy condition."""
    metric: str  # e.g., "critical_count", "total_issues", "coverage_score"
    operator: PolicyOperator
    value: Union[int, float, str]
    description: str


@dataclass
class GatePolicy:
    """Security gate policy configuration."""
    name: str
    description: str
    conditions: List[PolicyCondition]
    action: GateResult  # What to do if conditions are met
    priority: int = 1  # Higher priority policies are evaluated first
    enabled: bool = True
    
    def evaluate(self, metrics: Dict[str, Any]) -> bool:
        """Evaluate if this policy's conditions are met."""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, metrics):
                return False
        return True
    
    def _evaluate_condition(self, condition: PolicyCondition, metrics: Dict[str, Any]) -> bool:
        """Evaluate a single condition."""
        metric_value = metrics.get(condition.metric)
        if metric_value is None:
            return False
        
        if condition.operator == PolicyOperator.EQUALS:
            return metric_value == condition.value
        elif condition.operator == PolicyOperator.GREATER_THAN:
            return metric_value > condition.value
        elif condition.operator == PolicyOperator.LESS_THAN:
            return metric_value < condition.value
        elif condition.operator == PolicyOperator.GREATER_EQUAL:
            return metric_value >= condition.value
        elif condition.operator == PolicyOperator.LESS_EQUAL:
            return metric_value <= condition.value
        elif condition.operator == PolicyOperator.CONTAINS:
            return str(condition.value) in str(metric_value)
        elif condition.operator == PolicyOperator.NOT_CONTAINS:
            return str(condition.value) not in str(metric_value)
        
        return False


@dataclass
class GateEvaluation:
    """Result of security gate evaluation."""
    result: GateResult
    triggered_policies: List[str]
    metrics: Dict[str, Any]
    message: str
    recommendations: List[str]
    can_override: bool
    evaluated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'result': self.result.value,
            'triggered_policies': self.triggered_policies,
            'metrics': self.metrics,
            'message': self.message,
            'recommendations': self.recommendations,
            'can_override': self.can_override,
            'evaluated_at': self.evaluated_at.isoformat()
        }


class SecurityGate:
    """Security gate with configurable policies for deployment decisions."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize security gate."""
        self.logger = logging.getLogger(f"{__name__}.security_gate")
        self.policies: List[GatePolicy] = []
        self.config = self._load_config(config_path)
        self._initialize_default_policies()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load security gate configuration."""
        default_config = {
            "enabled": True,
            "allow_overrides": False,
            "override_roles": ["security_admin", "release_manager"],
            "notification_channels": ["email", "slack"],
            "evaluation_timeout": 300,  # seconds
            "cache_results": True,
            "cache_duration": 3600  # seconds
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _initialize_default_policies(self) -> None:
        """Initialize default security gate policies."""
        # Critical issues policy - always fail
        self.add_policy(GatePolicy(
            name="critical_issues_block",
            description="Block deployment if any critical security issues are found",
            conditions=[
                PolicyCondition(
                    metric="critical_count",
                    operator=PolicyOperator.GREATER_THAN,
                    value=0,
                    description="Critical issues found"
                )
            ],
            action=GateResult.FAIL,
            priority=1
        ))
        
        # High severity threshold policy
        self.add_policy(GatePolicy(
            name="high_severity_threshold",
            description="Warn if more than 5 high severity issues are found",
            conditions=[
                PolicyCondition(
                    metric="high_count",
                    operator=PolicyOperator.GREATER_THAN,
                    value=5,
                    description="Too many high severity issues"
                )
            ],
            action=GateResult.WARNING,
            priority=2
        ))
        
        # Total issues threshold policy
        self.add_policy(GatePolicy(
            name="total_issues_threshold",
            description="Block deployment if more than 20 total issues are found",
            conditions=[
                PolicyCondition(
                    metric="total_issues",
                    operator=PolicyOperator.GREATER_THAN,
                    value=20,
                    description="Too many total security issues"
                )
            ],
            action=GateResult.FAIL,
            priority=3
        ))
        
        # Compliance score policy
        self.add_policy(GatePolicy(
            name="compliance_score_threshold",
            description="Warn if compliance score is below 80%",
            conditions=[
                PolicyCondition(
                    metric="compliance_score",
                    operator=PolicyOperator.LESS_THAN,
                    value=80.0,
                    description="Compliance score too low"
                )
            ],
            action=GateResult.WARNING,
            priority=4
        ))
        
        # Hardcoded secrets policy
        self.add_policy(GatePolicy(
            name="hardcoded_secrets_block",
            description="Block deployment if hardcoded secrets are detected",
            conditions=[
                PolicyCondition(
                    metric="hardcoded_secrets_count",
                    operator=PolicyOperator.GREATER_THAN,
                    value=0,
                    description="Hardcoded secrets detected"
                )
            ],
            action=GateResult.FAIL,
            priority=1
        ))
        
        self.logger.info(f"Initialized {len(self.policies)} default security policies")
    
    def add_policy(self, policy: GatePolicy) -> None:
        """Add a security gate policy."""
        self.policies.append(policy)
        # Sort by priority (higher priority first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
        self.logger.info(f"Added security policy: {policy.name}")
    
    def remove_policy(self, policy_name: str) -> bool:
        """Remove a security gate policy."""
        for i, policy in enumerate(self.policies):
            if policy.name == policy_name:
                del self.policies[i]
                self.logger.info(f"Removed security policy: {policy_name}")
                return True
        return False
    
    def evaluate(self, issues: List[SecurityIssue], additional_metrics: Dict[str, Any] = None) -> GateEvaluation:
        """Evaluate security gate against issues and metrics."""
        start_time = datetime.now()
        
        try:
            # Calculate metrics from issues
            metrics = self._calculate_metrics(issues)
            
            # Add additional metrics
            if additional_metrics:
                metrics.update(additional_metrics)
            
            # Evaluate policies
            triggered_policies = []
            final_result = GateResult.PASS
            recommendations = []
            
            for policy in self.policies:
                if not policy.enabled:
                    continue
                
                if policy.evaluate(metrics):
                    triggered_policies.append(policy.name)
                    
                    # Update final result based on policy action
                    if policy.action == GateResult.FAIL:
                        final_result = GateResult.FAIL
                    elif policy.action == GateResult.WARNING and final_result == GateResult.PASS:
                        final_result = GateResult.WARNING
                    elif policy.action == GateResult.CONDITIONAL_PASS and final_result == GateResult.PASS:
                        final_result = GateResult.CONDITIONAL_PASS
                    
                    # Add recommendations
                    recommendations.extend(self._get_policy_recommendations(policy, metrics))
            
            # Generate message
            message = self._generate_evaluation_message(final_result, triggered_policies, metrics)
            
            # Determine if override is allowed
            can_override = (
                self.config.get("allow_overrides", False) and 
                final_result in [GateResult.WARNING, GateResult.CONDITIONAL_PASS]
            )
            
            evaluation = GateEvaluation(
                result=final_result,
                triggered_policies=triggered_policies,
                metrics=metrics,
                message=message,
                recommendations=list(set(recommendations)),  # Remove duplicates
                can_override=can_override,
                evaluated_at=start_time
            )
            
            self.logger.info(f"Security gate evaluation: {final_result.value} ({len(triggered_policies)} policies triggered)")
            return evaluation
        
        except Exception as e:
            self.logger.error(f"Security gate evaluation failed: {e}")
            return GateEvaluation(
                result=GateResult.FAIL,
                triggered_policies=[],
                metrics={},
                message=f"Evaluation failed: {str(e)}",
                recommendations=["Fix evaluation errors and retry"],
                can_override=False,
                evaluated_at=start_time
            )
    
    def _calculate_metrics(self, issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Calculate metrics from security issues."""
        metrics = {
            "total_issues": len(issues),
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "hardcoded_secrets_count": 0,
            "sql_injection_count": 0,
            "xss_count": 0,
            "crypto_issues_count": 0,
            "unique_files": len(set(issue.file_path for issue in issues)),
            "avg_confidence": 0.0,
            "compliance_score": 100.0
        }
        
        if not issues:
            return metrics
        
        # Count by severity
        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                metrics["critical_count"] += 1
            elif issue.severity == Severity.HIGH:
                metrics["high_count"] += 1
            elif issue.severity == Severity.MEDIUM:
                metrics["medium_count"] += 1
            elif issue.severity == Severity.LOW:
                metrics["low_count"] += 1
            
            # Count by category
            if issue.category == SecurityCategory.HARDCODED_SECRETS:
                metrics["hardcoded_secrets_count"] += 1
            elif issue.category == SecurityCategory.INJECTION:
                metrics["sql_injection_count"] += 1
            elif issue.category == SecurityCategory.XSS:
                metrics["xss_count"] += 1
            elif issue.category == SecurityCategory.INSECURE_CRYPTO:
                metrics["crypto_issues_count"] += 1
        
        # Calculate average confidence
        metrics["avg_confidence"] = sum(issue.confidence for issue in issues) / len(issues)
        
        # Calculate compliance score (simplified)
        critical_weight = metrics["critical_count"] * 10
        high_weight = metrics["high_count"] * 5
        medium_weight = metrics["medium_count"] * 2
        low_weight = metrics["low_count"] * 1
        
        total_weight = critical_weight + high_weight + medium_weight + low_weight
        max_possible = len(issues) * 10  # If all were critical
        
        if max_possible > 0:
            metrics["compliance_score"] = max(0, 100 - (total_weight / max_possible * 100))
        
        return metrics
    
    def _get_policy_recommendations(self, policy: GatePolicy, metrics: Dict[str, Any]) -> List[str]:
        """Get recommendations for a triggered policy."""
        recommendations = []
        
        if policy.name == "critical_issues_block":
            recommendations.extend([
                "Fix all critical security issues before deployment",
                "Review code for security vulnerabilities",
                "Run security scans on dependencies"
            ])
        
        elif policy.name == "high_severity_threshold":
            recommendations.extend([
                "Reduce high severity security issues",
                "Prioritize fixing authentication and authorization flaws",
                "Implement input validation and sanitization"
            ])
        
        elif policy.name == "total_issues_threshold":
            recommendations.extend([
                "Reduce overall number of security issues",
                "Focus on fixing high-impact vulnerabilities first",
                "Implement security best practices in development"
            ])
        
        elif policy.name == "compliance_score_threshold":
            recommendations.extend([
                "Improve compliance score by fixing security issues",
                "Review compliance requirements and implementation",
                "Conduct security training for development team"
            ])
        
        elif policy.name == "hardcoded_secrets_block":
            recommendations.extend([
                "Remove all hardcoded secrets from code",
                "Use environment variables or secure vaults",
                "Implement secret scanning in CI/CD pipeline"
            ])
        
        return recommendations
    
    def _generate_evaluation_message(self, result: GateResult, triggered_policies: List[str], metrics: Dict[str, Any]) -> str:
        """Generate evaluation result message."""
        if result == GateResult.PASS:
            return f"✅ Security gate passed - {metrics['total_issues']} issues found, all within acceptable limits"
        
        elif result == GateResult.WARNING:
            return f"⚠️  Security gate warning - {len(triggered_policies)} policies triggered, review recommended"
        
        elif result == GateResult.FAIL:
            critical = metrics.get('critical_count', 0)
            high = metrics.get('high_count', 0)
            return f"❌ Security gate failed - {critical} critical, {high} high severity issues found"
        
        elif result == GateResult.CONDITIONAL_PASS:
            return f"🔶 Security gate conditional pass - {len(triggered_policies)} policies triggered, manual review required"
        
        return "Unknown evaluation result"
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of configured policies."""
        return {
            "total_policies": len(self.policies),
            "enabled_policies": len([p for p in self.policies if p.enabled]),
            "policies_by_action": {
                action.value: len([p for p in self.policies if p.action == action and p.enabled])
                for action in GateResult
            },
            "policies": [
                {
                    "name": policy.name,
                    "description": policy.description,
                    "action": policy.action.value,
                    "priority": policy.priority,
                    "enabled": policy.enabled,
                    "conditions": len(policy.conditions)
                }
                for policy in self.policies
            ]
        }
    
    def simulate_evaluation(self, test_metrics: Dict[str, Any]) -> GateEvaluation:
        """Simulate security gate evaluation with test metrics."""
        # Create mock issues based on test metrics
        mock_issues = []
        
        critical_count = test_metrics.get('critical_count', 0)
        high_count = test_metrics.get('high_count', 0)
        
        # Create mock critical issues
        for i in range(critical_count):
            mock_issues.append(SecurityIssue(
                id=f"mock_critical_{i}",
                severity=Severity.CRITICAL,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path=f"test_file_{i}.py",
                line_number=10,
                description="Mock critical issue",
                rule_id="mock_rule",
                confidence=0.9,
                remediation_suggestions=[],
                created_at=datetime.now()
            ))
        
        # Create mock high issues
        for i in range(high_count):
            mock_issues.append(SecurityIssue(
                id=f"mock_high_{i}",
                severity=Severity.HIGH,
                category=SecurityCategory.INJECTION,
                file_path=f"test_file_{i}.py",
                line_number=20,
                description="Mock high severity issue",
                rule_id="mock_rule",
                confidence=0.8,
                remediation_suggestions=[],
                created_at=datetime.now()
            ))
        
        return self.evaluate(mock_issues, test_metrics)
    
    def export_config(self) -> Dict[str, Any]:
        """Export security gate configuration."""
        return {
            "config": self.config,
            "policies": [
                {
                    "name": policy.name,
                    "description": policy.description,
                    "conditions": [
                        {
                            "metric": condition.metric,
                            "operator": condition.operator.value,
                            "value": condition.value,
                            "description": condition.description
                        }
                        for condition in policy.conditions
                    ],
                    "action": policy.action.value,
                    "priority": policy.priority,
                    "enabled": policy.enabled
                }
                for policy in self.policies
            ]
        }
    
    def import_config(self, config_data: Dict[str, Any]) -> None:
        """Import security gate configuration."""
        # Update config
        if "config" in config_data:
            self.config.update(config_data["config"])
        
        # Import policies
        if "policies" in config_data:
            self.policies = []
            for policy_data in config_data["policies"]:
                conditions = []
                for condition_data in policy_data.get("conditions", []):
                    conditions.append(PolicyCondition(
                        metric=condition_data["metric"],
                        operator=PolicyOperator(condition_data["operator"]),
                        value=condition_data["value"],
                        description=condition_data["description"]
                    ))
                
                policy = GatePolicy(
                    name=policy_data["name"],
                    description=policy_data["description"],
                    conditions=conditions,
                    action=GateResult(policy_data["action"]),
                    priority=policy_data.get("priority", 1),
                    enabled=policy_data.get("enabled", True)
                )
                
                self.policies.append(policy)
            
            # Sort by priority
            self.policies.sort(key=lambda p: p.priority, reverse=True)
        
        self.logger.info("Imported security gate configuration")


# Global security gate instance
_global_security_gate: Optional[SecurityGate] = None


def get_security_gate(config_path: Optional[str] = None) -> SecurityGate:
    """Get global security gate instance."""
    global _global_security_gate
    if _global_security_gate is None:
        _global_security_gate = SecurityGate(config_path)
    return _global_security_gate


def reset_security_gate() -> None:
    """Reset global security gate (for testing)."""
    global _global_security_gate
    _global_security_gate = None