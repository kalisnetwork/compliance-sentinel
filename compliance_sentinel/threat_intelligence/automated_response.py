"""Automated threat response engine."""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json

from .threat_intel_manager import ThreatMatch, IOCType, ThreatLevel, ThreatType


logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Automated response action types."""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_EMAIL = "block_email"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    CREATE_ALERT = "create_alert"
    CREATE_TICKET = "create_ticket"
    NOTIFY_ADMIN = "notify_admin"
    UPDATE_SIGNATURES = "update_signatures"
    SCAN_SYSTEMS = "scan_systems"
    COLLECT_FORENSICS = "collect_forensics"


class ResponseSeverity(Enum):
    """Response severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResponseRule:
    """Automated response rule definition."""
    
    # Rule identification
    rule_id: str
    name: str
    description: str
    
    # Trigger conditions
    threat_types: List[ThreatType] = field(default_factory=list)
    threat_levels: List[ThreatLevel] = field(default_factory=list)
    ioc_types: List[IOCType] = field(default_factory=list)
    min_confidence: float = 0.0
    min_risk_score: float = 0.0
    
    # Response actions
    actions: List[ResponseAction] = field(default_factory=list)
    severity: ResponseSeverity = ResponseSeverity.MEDIUM
    
    # Rule settings
    enabled: bool = True
    auto_execute: bool = False
    require_approval: bool = True
    
    # Timing and limits
    cooldown_minutes: int = 60
    max_executions_per_hour: int = 10
    
    # Custom conditions
    custom_conditions: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, match: ThreatMatch) -> bool:
        """Check if rule matches a threat match."""
        if not self.enabled:
            return False
        
        # Check threat type
        if self.threat_types and match.indicator.threat_type not in self.threat_types:
            return False
        
        # Check threat level
        if self.threat_levels and match.indicator.threat_level not in self.threat_levels:
            return False
        
        # Check IOC type
        if self.ioc_types and match.indicator.ioc_type not in self.ioc_types:
            return False
        
        # Check confidence threshold
        if match.confidence_score < self.min_confidence:
            return False
        
        # Check risk score threshold
        if match.risk_score < self.min_risk_score:
            return False
        
        # Check custom conditions
        if self.custom_conditions:
            if not self._evaluate_custom_conditions(match):
                return False
        
        return True
    
    def _evaluate_custom_conditions(self, match: ThreatMatch) -> bool:
        """Evaluate custom conditions (placeholder for complex logic)."""
        # This could be extended to support complex condition evaluation
        return True


@dataclass
class ResponseExecution:
    """Record of response execution."""
    
    execution_id: str
    rule_id: str
    match_id: str
    actions: List[ResponseAction]
    
    # Execution details
    executed_at: datetime = field(default_factory=datetime.now)
    executed_by: str = "automated_system"
    status: str = "pending"  # pending, success, failed, partial
    
    # Results
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    # Approval workflow
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert execution to dictionary."""
        return {
            'execution_id': self.execution_id,
            'rule_id': self.rule_id,
            'match_id': self.match_id,
            'actions': [action.value for action in self.actions],
            'executed_at': self.executed_at.isoformat(),
            'executed_by': self.executed_by,
            'status': self.status,
            'results': self.results,
            'errors': self.errors,
            'requires_approval': self.requires_approval,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None
        }


class AutomatedThreatResponse:
    """Automated threat response engine."""
    
    def __init__(self):
        """Initialize automated response engine."""
        self.logger = logging.getLogger(__name__)
        
        # Response rules
        self.rules = {}
        self.load_default_rules()
        
        # Action handlers
        self.action_handlers = {}
        self.register_default_handlers()
        
        # Execution tracking
        self.executions = {}
        self.execution_history = []
        
        # Rate limiting
        self.execution_counts = {}
        
        # Approval queue
        self.pending_approvals = {}
    
    def load_default_rules(self):
        """Load default response rules."""
        
        # Critical malware response
        self.rules['critical_malware'] = ResponseRule(
            rule_id='critical_malware',
            name='Critical Malware Response',
            description='Immediate response to critical malware indicators',
            threat_types=[ThreatType.MALWARE, ThreatType.RANSOMWARE, ThreatType.TROJAN],
            threat_levels=[ThreatLevel.CRITICAL, ThreatLevel.HIGH],
            min_confidence=0.8,
            min_risk_score=7.0,
            actions=[
                ResponseAction.QUARANTINE_FILE,
                ResponseAction.ISOLATE_ENDPOINT,
                ResponseAction.CREATE_ALERT,
                ResponseAction.NOTIFY_ADMIN,
                ResponseAction.COLLECT_FORENSICS
            ],
            severity=ResponseSeverity.CRITICAL,
            auto_execute=False,
            require_approval=True
        )\n        \n        # Network threat blocking\n        self.rules['network_blocking'] = ResponseRule(\n            rule_id='network_blocking',\n            name='Network Threat Blocking',\n            description='Block malicious network indicators',\n            ioc_types=[IOCType.IP_ADDRESS, IOCType.DOMAIN, IOCType.URL],\n            threat_levels=[ThreatLevel.HIGH, ThreatLevel.CRITICAL],\n            min_confidence=0.7,\n            min_risk_score=6.0,\n            actions=[\n                ResponseAction.BLOCK_IP,\n                ResponseAction.BLOCK_DOMAIN,\n                ResponseAction.BLOCK_URL,\n                ResponseAction.CREATE_ALERT\n            ],\n            severity=ResponseSeverity.HIGH,\n            auto_execute=True,\n            require_approval=False\n        )\n        \n        # Phishing response\n        self.rules['phishing_response'] = ResponseRule(\n            rule_id='phishing_response',\n            name='Phishing Response',\n            description='Response to phishing indicators',\n            threat_types=[ThreatType.PHISHING],\n            min_confidence=0.6,\n            min_risk_score=5.0,\n            actions=[\n                ResponseAction.BLOCK_EMAIL,\n                ResponseAction.BLOCK_URL,\n                ResponseAction.CREATE_ALERT,\n                ResponseAction.NOTIFY_ADMIN\n            ],\n            severity=ResponseSeverity.MEDIUM,\n            auto_execute=True,\n            require_approval=False\n        )\n        \n        # Low-level monitoring\n        self.rules['monitoring_alert'] = ResponseRule(\n            rule_id='monitoring_alert',\n            name='Monitoring Alert',\n            description='Create alerts for lower-level threats',\n            threat_levels=[ThreatLevel.LOW, ThreatLevel.MEDIUM],\n            min_confidence=0.5,\n            actions=[\n                ResponseAction.CREATE_ALERT,\n                ResponseAction.UPDATE_SIGNATURES\n            ],\n            severity=ResponseSeverity.LOW,\n            auto_execute=True,\n            require_approval=False\n        )\n    \n    def register_default_handlers(self):\n        \"\"\"Register default action handlers.\"\"\"\n        self.action_handlers[ResponseAction.BLOCK_IP] = self._handle_block_ip\n        self.action_handlers[ResponseAction.BLOCK_DOMAIN] = self._handle_block_domain\n        self.action_handlers[ResponseAction.BLOCK_URL] = self._handle_block_url\n        self.action_handlers[ResponseAction.QUARANTINE_FILE] = self._handle_quarantine_file\n        self.action_handlers[ResponseAction.BLOCK_EMAIL] = self._handle_block_email\n        self.action_handlers[ResponseAction.ISOLATE_ENDPOINT] = self._handle_isolate_endpoint\n        self.action_handlers[ResponseAction.CREATE_ALERT] = self._handle_create_alert\n        self.action_handlers[ResponseAction.CREATE_TICKET] = self._handle_create_ticket\n        self.action_handlers[ResponseAction.NOTIFY_ADMIN] = self._handle_notify_admin\n        self.action_handlers[ResponseAction.UPDATE_SIGNATURES] = self._handle_update_signatures\n        self.action_handlers[ResponseAction.SCAN_SYSTEMS] = self._handle_scan_systems\n        self.action_handlers[ResponseAction.COLLECT_FORENSICS] = self._handle_collect_forensics\n    \n    async def process_matches(self, matches: List[ThreatMatch]) -> List[str]:\n        \"\"\"Process threat matches and execute automated responses.\"\"\"\n        execution_ids = []\n        \n        for match in matches:\n            # Find matching rules\n            matching_rules = self._find_matching_rules(match)\n            \n            for rule in matching_rules:\n                # Check rate limits\n                if not self._check_rate_limits(rule):\n                    self.logger.warning(f\"Rate limit exceeded for rule {rule.rule_id}\")
                    continue\n                \n                # Execute response\n                execution_id = await self._execute_response(rule, match)\n                if execution_id:\n                    execution_ids.append(execution_id)\n        \n        return execution_ids\n    \n    def _find_matching_rules(self, match: ThreatMatch) -> List[ResponseRule]:\n        \"\"\"Find rules that match a threat match.\"\"\"\n        matching_rules = []\n        \n        for rule in self.rules.values():\n            if rule.matches(match):\n                matching_rules.append(rule)\n        \n        # Sort by severity (critical first)\n        severity_order = {\n            ResponseSeverity.CRITICAL: 0,\n            ResponseSeverity.HIGH: 1,\n            ResponseSeverity.MEDIUM: 2,\n            ResponseSeverity.LOW: 3\n        }\n        \n        matching_rules.sort(key=lambda r: severity_order.get(r.severity, 999))\n        return matching_rules\n    \n    def _check_rate_limits(self, rule: ResponseRule) -> bool:\n        \"\"\"Check if rule execution is within rate limits.\"\"\"\n        current_hour = datetime.now().hour\n        key = f\"{rule.rule_id}_{current_hour}\"\n        \n        current_count = self.execution_counts.get(key, 0)\n        return current_count < rule.max_executions_per_hour\n    \n    async def _execute_response(self, rule: ResponseRule, match: ThreatMatch) -> Optional[str]:\n        \"\"\"Execute automated response for a rule and match.\"\"\"\n        execution_id = f\"{rule.rule_id}_{match.match_id}_{datetime.now().timestamp()}\"\n        \n        execution = ResponseExecution(\n            execution_id=execution_id,\n            rule_id=rule.rule_id,\n            match_id=match.match_id,\n            actions=rule.actions,\n            requires_approval=rule.require_approval\n        )\n        \n        self.executions[execution_id] = execution\n        \n        try:\n            if rule.require_approval and not rule.auto_execute:\n                # Add to approval queue\n                self.pending_approvals[execution_id] = execution\n                execution.status = \"pending_approval\"\n                self.logger.info(f\"Response execution {execution_id} requires approval\")
                return execution_id\n            \n            # Execute actions\n            await self._execute_actions(execution, match)\n            \n            # Update rate limiting\n            self._update_rate_limits(rule)\n            \n            # Add to history\n            self.execution_history.append(execution)\n            \n            self.logger.info(f\"Response execution {execution_id} completed with status: {execution.status}\")
            return execution_id\n            \n        except Exception as e:\n            execution.status = \"failed\"\n            execution.errors.append(str(e))\n            self.logger.error(f\"Response execution {execution_id} failed: {e}\")
            return execution_id\n    \n    async def _execute_actions(self, execution: ResponseExecution, match: ThreatMatch):\n        \"\"\"Execute response actions.\"\"\"\n        successful_actions = []\n        failed_actions = []\n        \n        for action in execution.actions:\n            try:\n                handler = self.action_handlers.get(action)\n                if handler:\n                    result = await handler(match, execution)\n                    execution.results[action.value] = result\n                    successful_actions.append(action)\n                else:\n                    error_msg = f\"No handler found for action: {action.value}\"\n                    execution.errors.append(error_msg)\n                    failed_actions.append(action)\n                    \n            except Exception as e:\n                error_msg = f\"Action {action.value} failed: {str(e)}\"\n                execution.errors.append(error_msg)\n                failed_actions.append(action)\n        \n        # Determine overall status\n        if not failed_actions:\n            execution.status = \"success\"\n        elif not successful_actions:\n            execution.status = \"failed\"\n        else:\n            execution.status = \"partial\"\n    \n    def _update_rate_limits(self, rule: ResponseRule):\n        \"\"\"Update rate limiting counters.\"\"\"\n        current_hour = datetime.now().hour\n        key = f\"{rule.rule_id}_{current_hour}\"\n        self.execution_counts[key] = self.execution_counts.get(key, 0) + 1\n    \n    async def approve_execution(self, execution_id: str, approved_by: str) -> bool:\n        \"\"\"Approve a pending execution.\"\"\"\n        if execution_id not in self.pending_approvals:\n            return False\n        \n        execution = self.pending_approvals[execution_id]\n        execution.approved_by = approved_by\n        execution.approved_at = datetime.now()\n        \n        # Find the original match (this would need to be stored)\n        # For now, we'll skip actual execution and just mark as approved\n        execution.status = \"approved\"\n        \n        # Remove from pending queue\n        del self.pending_approvals[execution_id]\n        \n        self.logger.info(f\"Execution {execution_id} approved by {approved_by}\")
        return True\n    \n    async def reject_execution(self, execution_id: str, rejected_by: str, reason: str) -> bool:\n        \"\"\"Reject a pending execution.\"\"\"\n        if execution_id not in self.pending_approvals:\n            return False\n        \n        execution = self.pending_approvals[execution_id]\n        execution.status = \"rejected\"\n        execution.errors.append(f\"Rejected by {rejected_by}: {reason}\")
        \n        # Remove from pending queue\n        del self.pending_approvals[execution_id]\n        \n        self.logger.info(f\"Execution {execution_id} rejected by {rejected_by}: {reason}\")
        return True\n    \n    # Action handlers (placeholder implementations)\n    \n    async def _handle_block_ip(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle IP blocking action.\"\"\"\n        ip_address = match.matched_value\n        \n        # Placeholder: In real implementation, this would integrate with firewalls, etc.\n        self.logger.info(f\"Blocking IP address: {ip_address}\")
        \n        return {\n            'action': 'block_ip',\n            'ip_address': ip_address,\n            'status': 'success',\n            'message': f'IP {ip_address} blocked successfully'\n        }\n    \n    async def _handle_block_domain(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle domain blocking action.\"\"\"\n        domain = match.matched_value\n        \n        # Placeholder: In real implementation, this would integrate with DNS filtering\n        self.logger.info(f\"Blocking domain: {domain}\")
        \n        return {\n            'action': 'block_domain',\n            'domain': domain,\n            'status': 'success',\n            'message': f'Domain {domain} blocked successfully'\n        }\n    \n    async def _handle_block_url(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle URL blocking action.\"\"\"\n        url = match.matched_value\n        \n        # Placeholder: In real implementation, this would integrate with web filters\n        self.logger.info(f\"Blocking URL: {url}\")
        \n        return {\n            'action': 'block_url',\n            'url': url,\n            'status': 'success',\n            'message': f'URL {url} blocked successfully'\n        }\n    \n    async def _handle_quarantine_file(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle file quarantine action.\"\"\"\n        file_hash = match.matched_value\n        \n        # Placeholder: In real implementation, this would integrate with EDR/antivirus\n        self.logger.info(f\"Quarantining file with hash: {file_hash}\")
        \n        return {\n            'action': 'quarantine_file',\n            'file_hash': file_hash,\n            'status': 'success',\n            'message': f'File with hash {file_hash} quarantined successfully'\n        }\n    \n    async def _handle_block_email(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle email blocking action.\"\"\"\n        email = match.matched_value\n        \n        # Placeholder: In real implementation, this would integrate with email security\n        self.logger.info(f\"Blocking email: {email}\")
        \n        return {\n            'action': 'block_email',\n            'email': email,\n            'status': 'success',\n            'message': f'Email {email} blocked successfully'\n        }\n    \n    async def _handle_isolate_endpoint(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle endpoint isolation action.\"\"\"\n        # This would typically require additional context about which endpoint\n        self.logger.info(f\"Isolating endpoint related to match: {match.match_id}\")
        \n        return {\n            'action': 'isolate_endpoint',\n            'match_id': match.match_id,\n            'status': 'success',\n            'message': 'Endpoint isolation initiated'\n        }\n    \n    async def _handle_create_alert(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle alert creation action.\"\"\"\n        alert_data = {\n            'title': f'Threat Intelligence Match: {match.indicator.threat_type.value}',\n            'description': f'IOC {match.matched_value} matched threat intelligence',\n            'severity': match.indicator.threat_level.value,\n            'match_id': match.match_id,\n            'indicator_id': match.indicator.indicator_id,\n            'created_at': datetime.now().isoformat()\n        }\n        \n        # Placeholder: In real implementation, this would integrate with SIEM/alerting\n        self.logger.info(f\"Creating alert for match: {match.match_id}\")
        \n        return {\n            'action': 'create_alert',\n            'alert_data': alert_data,\n            'status': 'success',\n            'message': 'Alert created successfully'\n        }\n    \n    async def _handle_create_ticket(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle ticket creation action.\"\"\"\n        ticket_data = {\n            'title': f'Security Incident: {match.indicator.threat_type.value}',\n            'description': f'Threat intelligence match requires investigation: {match.matched_value}',\n            'priority': match.indicator.threat_level.value,\n            'match_id': match.match_id\n        }\n        \n        # Placeholder: In real implementation, this would integrate with ticketing system\n        self.logger.info(f\"Creating ticket for match: {match.match_id}\")
        \n        return {\n            'action': 'create_ticket',\n            'ticket_data': ticket_data,\n            'status': 'success',\n            'message': 'Ticket created successfully'\n        }\n    \n    async def _handle_notify_admin(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle admin notification action.\"\"\"\n        notification = {\n            'subject': f'Threat Intelligence Alert: {match.indicator.threat_type.value}',\n            'message': f'IOC {match.matched_value} matched threat intelligence with risk score {match.risk_score}',\n            'match_id': match.match_id,\n            'timestamp': datetime.now().isoformat()\n        }\n        \n        # Placeholder: In real implementation, this would send email/SMS/Slack notification\n        self.logger.info(f\"Notifying admin about match: {match.match_id}\")
        \n        return {\n            'action': 'notify_admin',\n            'notification': notification,\n            'status': 'success',\n            'message': 'Admin notification sent successfully'\n        }\n    \n    async def _handle_update_signatures(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle signature update action.\"\"\"\n        # Placeholder: In real implementation, this would update security tool signatures\n        self.logger.info(f\"Updating signatures based on match: {match.match_id}\")
        \n        return {\n            'action': 'update_signatures',\n            'match_id': match.match_id,\n            'status': 'success',\n            'message': 'Signatures updated successfully'\n        }\n    \n    async def _handle_scan_systems(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle system scan action.\"\"\"\n        # Placeholder: In real implementation, this would trigger system scans\n        self.logger.info(f\"Initiating system scan based on match: {match.match_id}\")
        \n        return {\n            'action': 'scan_systems',\n            'match_id': match.match_id,\n            'status': 'success',\n            'message': 'System scan initiated successfully'\n        }\n    \n    async def _handle_collect_forensics(self, match: ThreatMatch, execution: ResponseExecution) -> Dict[str, Any]:\n        \"\"\"Handle forensics collection action.\"\"\"\n        # Placeholder: In real implementation, this would collect forensic data\n        self.logger.info(f\"Collecting forensics for match: {match.match_id}\")
        \n        return {\n            'action': 'collect_forensics',\n            'match_id': match.match_id,\n            'status': 'success',\n            'message': 'Forensics collection initiated successfully'\n        }\n    \n    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:\n        \"\"\"Get status of a response execution.\"\"\"\n        execution = self.executions.get(execution_id)\n        return execution.to_dict() if execution else None\n    \n    def get_pending_approvals(self) -> List[Dict[str, Any]]:\n        \"\"\"Get list of pending approvals.\"\"\"\n        return [execution.to_dict() for execution in self.pending_approvals.values()]\n    \n    def get_execution_history(self, limit: int = 100) -> List[Dict[str, Any]]:\n        \"\"\"Get execution history.\"\"\"\n        return [execution.to_dict() for execution in self.execution_history[-limit:]]\n    \n    def add_custom_rule(self, rule: ResponseRule):\n        \"\"\"Add a custom response rule.\"\"\"\n        self.rules[rule.rule_id] = rule\n        self.logger.info(f\"Added custom response rule: {rule.rule_id}\")
    \n    def remove_rule(self, rule_id: str) -> bool:\n        \"\"\"Remove a response rule.\"\"\"\n        if rule_id in self.rules:\n            del self.rules[rule_id]\n            self.logger.info(f\"Removed response rule: {rule_id}\")
            return True\n        return False\n    \n    def register_action_handler(self, action: ResponseAction, handler: Callable):\n        \"\"\"Register a custom action handler.\"\"\"\n        self.action_handlers[action] = handler\n        self.logger.info(f\"Registered custom handler for action: {action.value}\")