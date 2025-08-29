"""Security event correlation engine for runtime and static analysis."""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import logging
import hashlib
import json

from .monitoring_manager import SecurityEvent, EventType
from compliance_sentinel.core.interfaces import Severity, SecurityCategory


logger = logging.getLogger(__name__)


@dataclass
class CorrelationRule:
    """Defines a correlation rule for security events."""
    
    rule_id: str
    name: str
    description: str
    
    # Event matching criteria
    event_types: List[EventType] = field(default_factory=list)
    severities: List[Severity] = field(default_factory=list)
    categories: List[SecurityCategory] = field(default_factory=list)
    
    # Correlation criteria
    correlation_fields: List[str] = field(default_factory=list)  # Fields to correlate on
    time_window: timedelta = field(default_factory=lambda: timedelta(minutes=60))
    min_events: int = 2
    max_events: int = 100
    
    # Scoring
    confidence_threshold: float = 0.7
    risk_multiplier: float = 1.5
    
    # Actions
    create_incident: bool = True
    alert_severity: Severity = Severity.HIGH
    
    enabled: bool = True


@dataclass
class CorrelationResult:
    """Result of event correlation analysis."""
    
    correlation_id: str
    rule_id: str
    rule_name: str
    
    # Events in correlation
    events: List[SecurityEvent] = field(default_factory=list)
    
    # Timing
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)
    duration: timedelta = field(default_factory=lambda: timedelta(0))
    
    # Scoring
    confidence_score: float = 0.0
    risk_score: float = 0.0
    severity: Severity = Severity.MEDIUM
    
    # Analysis
    correlation_summary: str = ""
    attack_pattern: str = ""
    indicators: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert correlation result to dictionary."""
        return {
            'correlation_id': self.correlation_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'event_count': len(self.events),
            'event_ids': [e.event_id for e in self.events],
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': self.duration.total_seconds(),
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'severity': self.severity.value,
            'correlation_summary': self.correlation_summary,
            'attack_pattern': self.attack_pattern,
            'indicators': self.indicators,
            'created_at': self.created_at.isoformat()
        }


class CorrelationEngine:
    """Core correlation engine for security events."""
    
    def __init__(self):
        """Initialize correlation engine."""
        self.logger = logging.getLogger(__name__)
        self.rules = []
        self.event_cache = {}
        self.correlation_cache = {}
        
        # Load default correlation rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default correlation rules."""
        
        # Rule 1: Multiple failed authentication attempts
        auth_rule = CorrelationRule(
            rule_id="auth_brute_force",
            name="Authentication Brute Force",
            description="Multiple failed authentication attempts from same source",
            event_types=[EventType.AUTHENTICATION_FAILURE],
            correlation_fields=["source_ip", "user_id"],
            time_window=timedelta(minutes=15),
            min_events=5,
            confidence_threshold=0.8,
            risk_multiplier=2.0,
            alert_severity=Severity.HIGH
        )
        
        # Rule 2: Privilege escalation sequence
        privesc_rule = CorrelationRule(
            rule_id="privilege_escalation",
            name="Privilege Escalation Sequence",
            description="Sequence of events indicating privilege escalation attempt",
            event_types=[EventType.PRIVILEGE_ESCALATION, EventType.ACCESS_VIOLATION],
            correlation_fields=["user_id", "hostname"],
            time_window=timedelta(minutes=30),
            min_events=2,
            confidence_threshold=0.7,
            risk_multiplier=3.0,
            alert_severity=Severity.CRITICAL
        )
        
        # Rule 3: Data exfiltration pattern
        exfil_rule = CorrelationRule(
            rule_id="data_exfiltration",
            name="Data Exfiltration Pattern",
            description="Pattern indicating potential data exfiltration",
            event_types=[EventType.DATA_EXFILTRATION, EventType.NETWORK_ANOMALY],
            correlation_fields=["source_ip", "destination_ip"],
            time_window=timedelta(hours=2),
            min_events=3,
            confidence_threshold=0.6,
            risk_multiplier=2.5,
            alert_severity=Severity.CRITICAL
        )
        
        # Rule 4: Static analysis to runtime correlation
        static_runtime_rule = CorrelationRule(
            rule_id="static_runtime_correlation",
            name="Static Analysis to Runtime Correlation",
            description="Correlation between static analysis findings and runtime events",
            event_types=[EventType.STATIC_ANALYSIS, EventType.RUNTIME_DETECTION],
            correlation_fields=["file_path", "hostname"],
            time_window=timedelta(hours=24),
            min_events=2,
            confidence_threshold=0.8,
            risk_multiplier=1.8,
            alert_severity=Severity.HIGH
        )
        
        # Rule 5: Malware detection chain
        malware_rule = CorrelationRule(
            rule_id="malware_detection_chain",
            name="Malware Detection Chain",
            description="Chain of events indicating malware activity",
            event_types=[EventType.MALWARE_DETECTION, EventType.NETWORK_ANOMALY, EventType.ACCESS_VIOLATION],
            correlation_fields=["hostname", "process_name"],
            time_window=timedelta(hours=1),
            min_events=2,
            confidence_threshold=0.9,
            risk_multiplier=4.0,
            alert_severity=Severity.CRITICAL
        )
        
        self.rules = [auth_rule, privesc_rule, exfil_rule, static_runtime_rule, malware_rule]
    
    def add_rule(self, rule: CorrelationRule):
        """Add a custom correlation rule."""
        self.rules.append(rule)
        self.logger.info(f"Added correlation rule: {rule.name}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule."""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                del self.rules[i]
                self.logger.info(f"Removed correlation rule: {rule_id}")
                return True
        return False
    
    async def correlate_events(self, 
                              events: List[SecurityEvent],
                              time_window: timedelta = None) -> List[CorrelationResult]:
        """Correlate security events using defined rules."""
        
        if not events:
            return []
        
        correlations = []
        
        # Process each correlation rule
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            try:
                rule_correlations = await self._apply_correlation_rule(events, rule)
                correlations.extend(rule_correlations)
            except Exception as e:
                self.logger.error(f"Error applying correlation rule {rule.rule_id}: {e}")
        
        # Remove duplicate correlations
        unique_correlations = self._deduplicate_correlations(correlations)
        
        return unique_correlations
    
    async def _apply_correlation_rule(self, 
                                    events: List[SecurityEvent],
                                    rule: CorrelationRule) -> List[CorrelationResult]:
        """Apply a specific correlation rule to events."""
        
        # Filter events that match rule criteria
        matching_events = self._filter_events_for_rule(events, rule)
        
        if len(matching_events) < rule.min_events:
            return []
        
        # Group events by correlation fields
        event_groups = self._group_events_by_correlation_fields(matching_events, rule)
        
        correlations = []
        
        for group_key, group_events in event_groups.items():
            if len(group_events) < rule.min_events:
                continue
            
            # Check time window constraint
            time_filtered_events = self._filter_events_by_time_window(group_events, rule.time_window)
            
            if len(time_filtered_events) < rule.min_events:
                continue
            
            # Create correlation result
            correlation = await self._create_correlation_result(time_filtered_events, rule, group_key)
            
            if correlation.confidence_score >= rule.confidence_threshold:
                correlations.append(correlation)
        
        return correlations
    
    def _filter_events_for_rule(self, 
                               events: List[SecurityEvent],
                               rule: CorrelationRule) -> List[SecurityEvent]:
        """Filter events that match rule criteria."""
        
        filtered_events = []
        
        for event in events:
            # Check event type
            if rule.event_types and event.event_type not in rule.event_types:
                continue
            
            # Check severity
            if rule.severities and event.severity not in rule.severities:
                continue
            
            # Check category
            if rule.categories and event.category not in rule.categories:
                continue
            
            filtered_events.append(event)
        
        return filtered_events
    
    def _group_events_by_correlation_fields(self, 
                                          events: List[SecurityEvent],
                                          rule: CorrelationRule) -> Dict[str, List[SecurityEvent]]:
        """Group events by correlation fields."""
        
        groups = defaultdict(list)
        
        for event in events:
            # Build correlation key from specified fields
            key_parts = []
            
            for field in rule.correlation_fields:
                value = getattr(event, field, "")
                if value:
                    key_parts.append(f"{field}:{value}")
            
            if key_parts:
                correlation_key = "|".join(key_parts)
                groups[correlation_key].append(event)
        
        return dict(groups)
    
    def _filter_events_by_time_window(self, 
                                    events: List[SecurityEvent],
                                    time_window: timedelta) -> List[SecurityEvent]:
        """Filter events within the specified time window."""
        
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Find events within time window
        filtered_groups = []
        
        for i, start_event in enumerate(sorted_events):
            window_events = [start_event]
            
            for j in range(i + 1, len(sorted_events)):
                next_event = sorted_events[j]
                
                if next_event.timestamp - start_event.timestamp <= time_window:
                    window_events.append(next_event)
                else:
                    break
            
            if len(window_events) > len(filtered_groups):
                filtered_groups = window_events
        
        return filtered_groups
    
    async def _create_correlation_result(self, 
                                       events: List[SecurityEvent],
                                       rule: CorrelationRule,
                                       group_key: str) -> CorrelationResult:
        """Create correlation result from grouped events."""
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate timing
        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp
        duration = end_time - start_time
        
        # Generate correlation ID
        correlation_id = self._generate_correlation_id(rule.rule_id, group_key, start_time)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(events, rule)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(events, rule)
        
        # Determine severity
        severity = self._determine_correlation_severity(events, rule, confidence_score)
        
        # Generate summary and indicators
        correlation_summary = self._generate_correlation_summary(events, rule)
        attack_pattern = self._identify_attack_pattern(events, rule)
        indicators = self._extract_indicators(events)
        
        correlation = CorrelationResult(
            correlation_id=correlation_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            events=events,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            confidence_score=confidence_score,
            risk_score=risk_score,
            severity=severity,
            correlation_summary=correlation_summary,
            attack_pattern=attack_pattern,
            indicators=indicators
        )
        
        return correlation
    
    def _generate_correlation_id(self, rule_id: str, group_key: str, timestamp: datetime) -> str:
        """Generate unique correlation ID."""
        
        id_string = f"{rule_id}:{group_key}:{timestamp.isoformat()}"
        return hashlib.md5(id_string.encode()).hexdigest()[:16]
    
    def _calculate_confidence_score(self, events: List[SecurityEvent], rule: CorrelationRule) -> float:
        """Calculate confidence score for correlation."""
        
        base_confidence = 0.5
        
        # Factor 1: Number of events (more events = higher confidence)
        event_factor = min(len(events) / (rule.min_events * 2), 1.0) * 0.3
        
        # Factor 2: Time distribution (events spread over time = higher confidence)
        if len(events) > 1:
            time_span = (max(e.timestamp for e in events) - min(e.timestamp for e in events)).total_seconds()
            time_factor = min(time_span / rule.time_window.total_seconds(), 1.0) * 0.2
        else:
            time_factor = 0.0
        
        # Factor 3: Event confidence scores
        avg_event_confidence = sum(e.confidence_score for e in events) / len(events)
        confidence_factor = avg_event_confidence * 0.3
        
        # Factor 4: Severity distribution (higher severity = higher confidence)
        severity_weights = {Severity.CRITICAL: 1.0, Severity.HIGH: 0.8, Severity.MEDIUM: 0.6, Severity.LOW: 0.4}
        avg_severity_weight = sum(severity_weights.get(e.severity, 0.5) for e in events) / len(events)
        severity_factor = avg_severity_weight * 0.2
        
        total_confidence = base_confidence + event_factor + time_factor + confidence_factor + severity_factor
        
        return min(total_confidence, 1.0)
    
    def _calculate_risk_score(self, events: List[SecurityEvent], rule: CorrelationRule) -> float:
        """Calculate risk score for correlation."""
        
        # Base risk from individual events
        base_risk = sum(e.risk_score for e in events) / len(events)
        
        # Apply rule multiplier
        correlation_risk = base_risk * rule.risk_multiplier
        
        # Factor in event count (more events = higher risk)
        count_multiplier = 1.0 + (len(events) - rule.min_events) * 0.1
        
        total_risk = correlation_risk * count_multiplier
        
        return min(total_risk, 10.0)  # Cap at 10.0
    
    def _determine_correlation_severity(self, 
                                      events: List[SecurityEvent],
                                      rule: CorrelationRule,
                                      confidence_score: float) -> Severity:
        """Determine severity of correlation."""
        
        # Start with rule's alert severity
        base_severity = rule.alert_severity
        
        # Check if any events are more severe
        max_event_severity = max(e.severity for e in events)
        
        # Use the higher severity
        severity_values = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
        
        base_value = severity_values[base_severity]
        max_event_value = severity_values[max_event_severity]
        
        # High confidence correlations get severity boost
        if confidence_score > 0.9:
            final_value = max(base_value, max_event_value) + 1
        else:
            final_value = max(base_value, max_event_value)
        
        # Map back to severity
        value_to_severity = {1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH, 4: Severity.CRITICAL}
        
        return value_to_severity.get(min(final_value, 4), Severity.HIGH)
    
    def _generate_correlation_summary(self, events: List[SecurityEvent], rule: CorrelationRule) -> str:
        """Generate human-readable correlation summary."""
        
        event_count = len(events)
        time_span = (max(e.timestamp for e in events) - min(e.timestamp for e in events)).total_seconds() / 60
        
        # Get unique sources
        sources = set()
        for event in events:
            if event.source_ip:
                sources.add(event.source_ip)
            elif event.hostname:
                sources.add(event.hostname)
        
        summary = f"Detected {rule.name.lower()} involving {event_count} events over {time_span:.1f} minutes"
        
        if sources:
            summary += f" from {len(sources)} source(s): {', '.join(list(sources)[:3])}"
            if len(sources) > 3:
                summary += f" and {len(sources) - 3} more"
        
        return summary
    
    def _identify_attack_pattern(self, events: List[SecurityEvent], rule: CorrelationRule) -> str:
        """Identify potential attack pattern."""
        
        # Map rule types to attack patterns
        pattern_mapping = {
            "auth_brute_force": "Credential Stuffing / Brute Force Attack",
            "privilege_escalation": "Privilege Escalation Attack",
            "data_exfiltration": "Data Exfiltration / Data Theft",
            "static_runtime_correlation": "Exploitation of Known Vulnerability",
            "malware_detection_chain": "Malware Infection / Advanced Persistent Threat"
        }
        
        return pattern_mapping.get(rule.rule_id, "Unknown Attack Pattern")
    
    def _extract_indicators(self, events: List[SecurityEvent]) -> List[str]:
        """Extract indicators of compromise from events."""
        
        indicators = []
        
        # Extract unique IPs
        ips = set()
        for event in events:
            if event.source_ip:
                ips.add(event.source_ip)
            if event.destination_ip:
                ips.add(event.destination_ip)
        
        indicators.extend([f"IP: {ip}" for ip in ips])
        
        # Extract unique hostnames
        hostnames = set(event.hostname for event in events if event.hostname)
        indicators.extend([f"Host: {hostname}" for hostname in hostnames])
        
        # Extract unique user IDs
        users = set(event.user_id for event in events if event.user_id)
        indicators.extend([f"User: {user}" for user in users])
        
        # Extract unique file paths
        files = set(event.file_path for event in events if event.file_path)
        indicators.extend([f"File: {file}" for file in files])
        
        # Extract unique processes
        processes = set(event.process_name for event in events if event.process_name)
        indicators.extend([f"Process: {process}" for process in processes])
        
        return indicators[:20]  # Limit to 20 indicators
    
    def _deduplicate_correlations(self, correlations: List[CorrelationResult]) -> List[CorrelationResult]:
        """Remove duplicate correlations."""
        
        seen_ids = set()
        unique_correlations = []
        
        # Sort by confidence score (highest first)
        sorted_correlations = sorted(correlations, key=lambda c: c.confidence_score, reverse=True)
        
        for correlation in sorted_correlations:
            if correlation.correlation_id not in seen_ids:
                seen_ids.add(correlation.correlation_id)
                unique_correlations.append(correlation)
        
        return unique_correlations


class SecurityEventCorrelator:
    """High-level security event correlator."""
    
    def __init__(self):
        """Initialize security event correlator."""
        self.engine = CorrelationEngine()
        self.logger = logging.getLogger(__name__)
    
    async def correlate_events(self, 
                              events: List[SecurityEvent],
                              time_window: timedelta = None) -> List[List[SecurityEvent]]:
        """Correlate events and return grouped event lists."""
        
        correlations = await self.engine.correlate_events(events, time_window)
        
        # Return just the event groups
        return [correlation.events for correlation in correlations]
    
    async def analyze_correlations(self, 
                                  events: List[SecurityEvent],
                                  time_window: timedelta = None) -> List[CorrelationResult]:
        """Perform full correlation analysis and return detailed results."""
        
        return await self.engine.correlate_events(events, time_window)
    
    def add_custom_rule(self, rule: CorrelationRule):
        """Add a custom correlation rule."""
        self.engine.add_rule(rule)
    
    def get_correlation_rules(self) -> List[CorrelationRule]:
        """Get all correlation rules."""
        return self.engine.rules.copy()