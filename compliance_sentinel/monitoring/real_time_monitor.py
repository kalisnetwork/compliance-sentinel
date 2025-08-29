"""Real-time monitoring system with event processing and rule evaluation."""

import asyncio
import logging
import time
import json
from typing import Dict, List, Optional, Set, Any, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
from collections import deque, defaultdict
import queue

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of monitoring events."""
    SECURITY_SCAN_COMPLETED = "security_scan_completed"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SYSTEM_ERROR = "system_error"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    USER_ACTION = "user_action"
    DATA_ACCESS = "data_access"
    AUTHENTICATION_FAILURE = "authentication_failure"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"


class EventSeverity(Enum):
    """Severity levels for monitoring events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MonitoringEvent:
    """Represents a monitoring event."""
    
    event_id: str
    event_type: EventType
    severity: EventSeverity
    
    # Event details
    title: str
    description: str
    source: str
    
    # Event data
    data: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    
    # Timestamps
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Processing status
    processed: bool = False
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'data': self.data,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'processed': self.processed,
            'acknowledged': self.acknowledged
        }


@dataclass
class MonitoringRule:
    """Rule for monitoring event processing."""
    
    rule_id: str
    name: str
    description: str
    
    # Rule conditions
    event_types: Set[EventType] = field(default_factory=set)
    severity_threshold: EventSeverity = EventSeverity.MEDIUM
    
    # Rule logic
    condition_function: Optional[Callable[[MonitoringEvent], bool]] = None
    
    # Actions
    alert_channels: List[str] = field(default_factory=list)
    auto_escalate: bool = False
    escalation_delay_minutes: int = 30
    
    # Rule settings
    enabled: bool = True
    rate_limit_minutes: int = 5  # Minimum time between alerts
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    
    def matches_event(self, event: MonitoringEvent) -> bool:
        """Check if rule matches the given event."""
        
        if not self.enabled:
            return False
        
        # Check event type
        if self.event_types and event.event_type not in self.event_types:
            return False
        
        # Check severity threshold
        severity_levels = {
            EventSeverity.INFO: 1,
            EventSeverity.LOW: 2,
            EventSeverity.MEDIUM: 3,
            EventSeverity.HIGH: 4,
            EventSeverity.CRITICAL: 5
        }
        
        if severity_levels[event.severity] < severity_levels[self.severity_threshold]:
            return False
        
        # Check rate limiting
        if self.last_triggered:
            time_since_last = datetime.now() - self.last_triggered
            if time_since_last < timedelta(minutes=self.rate_limit_minutes):
                return False
        
        # Check custom condition
        if self.condition_function:
            try:
                return self.condition_function(event)
            except Exception as e:
                logger.error(f"Error evaluating rule condition {self.rule_id}: {e}")
                return False
        
        return True


class RealTimeMonitor:
    """Real-time monitoring system with event processing and alerting."""
    
    def __init__(self):
        """Initialize real-time monitor."""
        self.logger = logging.getLogger(__name__)
        
        # Event processing
        self.event_queue = queue.Queue(maxsize=10000)
        self.event_history = deque(maxlen=1000)
        
        # Rules and handlers
        self.rules = {}
        self.event_handlers = {}
        
        # Processing state
        self.is_running = False
        self.worker_threads = []
        self.processing_stats = {
            'events_processed': 0,
            'events_dropped': 0,
            'rules_triggered': 0,
            'alerts_sent': 0,
            'errors': 0
        }
        
        # Alert deduplication
        self.recent_alerts = defaultdict(list)
        
        # Load default rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default monitoring rules."""
        
        # Critical security events
        self.add_rule(MonitoringRule(
            rule_id="critical_security_events",
            name="Critical Security Events",
            description="Alert on critical security events",
            event_types={EventType.VULNERABILITY_DETECTED, EventType.AUTHENTICATION_FAILURE},
            severity_threshold=EventSeverity.CRITICAL,
            rate_limit_minutes=1
        ))
        
        # Compliance violations
        self.add_rule(MonitoringRule(
            rule_id="compliance_violations",
            name="Compliance Violations",
            description="Alert on compliance violations",
            event_types={EventType.COMPLIANCE_VIOLATION},
            severity_threshold=EventSeverity.HIGH,
            rate_limit_minutes=5
        ))
    
    def add_rule(self, rule: MonitoringRule):
        """Add monitoring rule."""
        self.rules[rule.rule_id] = rule
        self.logger.info(f"Added monitoring rule: {rule.rule_id}")
    
    def emit_event(self, event: MonitoringEvent) -> bool:
        """Emit monitoring event for processing."""
        
        try:
            # Add to queue for processing
            self.event_queue.put_nowait(event)
            return True
            
        except queue.Full:
            self.processing_stats['events_dropped'] += 1
            self.logger.warning(f"Event queue full, dropping event: {event.event_id}")
            return False
        
        except Exception as e:
            self.logger.error(f"Error emitting event {event.event_id}: {e}")
            return False
    
    def emit_security_issue(self, issue: SecurityIssue) -> bool:
        """Emit security issue as monitoring event."""
        
        # Map severity
        severity_mapping = {
            Severity.CRITICAL: EventSeverity.CRITICAL,
            Severity.HIGH: EventSeverity.HIGH,
            Severity.MEDIUM: EventSeverity.MEDIUM,
            Severity.LOW: EventSeverity.LOW
        }
        
        event = MonitoringEvent(
            event_id=f"security_{issue.id}",
            event_type=EventType.VULNERABILITY_DETECTED,
            severity=severity_mapping.get(issue.severity, EventSeverity.MEDIUM),
            title=f"Security Issue: {issue.rule_id}",
            description=issue.description,
            source="security_analyzer",
            data={
                'issue_id': issue.id,
                'rule_id': issue.rule_id,
                'category': issue.category.value,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'confidence': issue.confidence
            }
        )
        
        return self.emit_event(event)
    
    def start(self):
        """Start real-time monitoring."""
        
        if self.is_running:
            self.logger.warning("Monitor is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting real-time monitor")
        
        # Start worker threads
        for i in range(4):
            thread = threading.Thread(
                target=self._worker_thread,
                name=f"MonitorWorker-{i}",
                daemon=True
            )
            thread.start()
            self.worker_threads.append(thread)
    
    def stop(self):
        """Stop real-time monitoring."""
        
        if not self.is_running:
            return
        
        self.logger.info("Stopping real-time monitor")
        self.is_running = False
        
        # Wait for threads to finish
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.worker_threads.clear()
    
    def _worker_thread(self):
        """Worker thread for processing events."""
        
        while self.is_running:
            try:
                # Get events from queue
                events = []
                
                # Collect batch of events
                for _ in range(100):
                    try:
                        event = self.event_queue.get(timeout=1.0)
                        events.append(event)
                    except queue.Empty:
                        break
                
                # Process events
                if events:
                    self._process_events(events)
                
            except Exception as e:
                self.logger.error(f"Error in worker thread: {e}")
                self.processing_stats['errors'] += 1
    
    def _process_events(self, events: List[MonitoringEvent]):
        """Process batch of events."""
        
        for event in events:
            try:
                # Add to history
                self.event_history.append(event)
                
                # Evaluate rules
                self._evaluate_rules(event)
                
                # Mark as processed
                event.processed = True
                self.processing_stats['events_processed'] += 1
                
            except Exception as e:
                self.logger.error(f"Error processing event {event.event_id}: {e}")
                self.processing_stats['errors'] += 1
    
    def _evaluate_rules(self, event: MonitoringEvent):
        """Evaluate monitoring rules against event."""
        
        for rule in self.rules.values():
            try:
                if rule.matches_event(event):
                    self._trigger_rule(rule, event)
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
    
    def _trigger_rule(self, rule: MonitoringRule, event: MonitoringEvent):
        """Trigger monitoring rule."""
        
        # Update rule state
        rule.last_triggered = datetime.now()
        self.processing_stats['rules_triggered'] += 1
        
        # Log rule trigger
        self.logger.info(f"Rule triggered: {rule.rule_id} for event {event.event_id}")
    
    def get_recent_events(self, 
                         event_type: Optional[EventType] = None,
                         severity: Optional[EventSeverity] = None,
                         limit: int = 100) -> List[MonitoringEvent]:
        """Get recent events with filtering."""
        
        events = list(self.event_history)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        # Sort by timestamp (newest first) and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        
        return {
            'is_running': self.is_running,
            'queue_size': self.event_queue.qsize(),
            'events_in_history': len(self.event_history),
            'active_rules': len([r for r in self.rules.values() if r.enabled]),
            'total_rules': len(self.rules),
            'worker_threads': len(self.worker_threads),
            'processing_stats': self.processing_stats.copy()
        }