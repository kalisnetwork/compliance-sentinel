"""Threat hunting engine for proactive threat detection."""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re
import json

from compliance_sentinel.core.interfaces import SecurityIssue, Severity
from compliance_sentinel.monitoring.monitoring_manager import SecurityEvent
from .threat_intel_manager import ThreatIndicator, IOCType, ThreatType, ThreatLevel
from .ioc_matcher import IOCMatcher


logger = logging.getLogger(__name__)


class HuntingRuleType(Enum):
    """Types of hunting rules."""
    PATTERN_MATCH = "pattern_match"
    BEHAVIORAL = "behavioral"
    STATISTICAL = "statistical"
    CORRELATION = "correlation"
    ANOMALY = "anomaly"


class HuntingStatus(Enum):
    """Hunting rule execution status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class HuntingRule:
    """Threat hunting rule definition."""
    
    # Rule identification
    rule_id: str
    name: str
    description: str
    rule_type: HuntingRuleType
    
    # Rule logic
    pattern: str = ""
    conditions: Dict[str, Any] = field(default_factory=dict)
    query: str = ""
    
    # Targeting
    target_data_types: List[str] = field(default_factory=list)  # security_issues, events, logs
    target_sources: List[str] = field(default_factory=list)
    
    # Execution settings
    enabled: bool = True
    schedule_minutes: int = 60
    lookback_hours: int = 24
    
    # Detection settings
    threshold: float = 0.7
    min_occurrences: int = 1
    time_window_minutes: int = 60
    
    # Output settings
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    
    # Metadata
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.now)
    last_executed: Optional[datetime] = None
    execution_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'rule_type': self.rule_type.value,
            'pattern': self.pattern,
            'conditions': self.conditions,
            'query': self.query,
            'target_data_types': self.target_data_types,
            'target_sources': self.target_sources,
            'enabled': self.enabled,
            'schedule_minutes': self.schedule_minutes,
            'lookback_hours': self.lookback_hours,
            'threshold': self.threshold,
            'min_occurrences': self.min_occurrences,
            'time_window_minutes': self.time_window_minutes,
            'severity': self.severity.value,
            'tags': self.tags,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'last_executed': self.last_executed.isoformat() if self.last_executed else None,
            'execution_count': self.execution_count
        }


@dataclass
class HuntingResult:
    """Result from threat hunting execution."""
    
    # Result identification
    result_id: str
    rule_id: str
    
    # Detection details
    detected_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    severity: Severity = Severity.MEDIUM
    
    # Evidence
    matched_data: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis
    description: str = ""
    recommendations: List[str] = field(default_factory=list)
    false_positive_likelihood: float = 0.0
    
    # Metadata
    execution_time_ms: float = 0.0
    data_sources: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'result_id': self.result_id,
            'rule_id': self.rule_id,
            'detected_at': self.detected_at.isoformat(),
            'confidence': self.confidence,
            'severity': self.severity.value,
            'matched_data': self.matched_data,
            'indicators': self.indicators,
            'context': self.context,
            'description': self.description,
            'recommendations': self.recommendations,
            'false_positive_likelihood': self.false_positive_likelihood,
            'execution_time_ms': self.execution_time_ms,
            'data_sources': self.data_sources
        }


class ThreatHuntingEngine:
    """Proactive threat hunting engine."""
    
    def __init__(self):
        """Initialize threat hunting engine."""
        self.logger = logging.getLogger(__name__)
        
        # Hunting rules
        self.rules = {}
        self.load_default_rules()
        
        # Rule processors
        self.rule_processors = {
            HuntingRuleType.PATTERN_MATCH: self._process_pattern_rule,
            HuntingRuleType.BEHAVIORAL: self._process_behavioral_rule,
            HuntingRuleType.STATISTICAL: self._process_statistical_rule,
            HuntingRuleType.CORRELATION: self._process_correlation_rule,
            HuntingRuleType.ANOMALY: self._process_anomaly_rule
        }
        
        # Data sources
        self.data_sources = {
            'security_issues': [],
            'security_events': [],
            'log_entries': []
        }
        
        # IOC matcher for pattern detection
        self.ioc_matcher = IOCMatcher()
        
        # Execution tracking
        self.execution_history = []
        self.active_hunts = {}
        
        # Scheduled tasks
        self.scheduled_tasks = {}
    
    def load_default_rules(self):
        """Load default hunting rules."""
        
        # Suspicious file execution patterns
        self.rules['suspicious_file_execution'] = HuntingRule(
            rule_id='suspicious_file_execution',
            name='Suspicious File Execution',
            description='Detect execution of files from suspicious locations',
            rule_type=HuntingRuleType.PATTERN_MATCH,
            pattern=r'(?i)(temp|tmp|appdata|public).*\.(exe|bat|cmd|scr|pif)',
            target_data_types=['security_issues', 'security_events'],
            threshold=0.8,
            severity=Severity.HIGH,
            tags=['malware', 'execution', 'suspicious-location']
        )
        
        # Command injection patterns
        self.rules['command_injection'] = HuntingRule(
            rule_id='command_injection',
            name='Command Injection Patterns',
            description='Detect potential command injection attempts',
            rule_type=HuntingRuleType.PATTERN_MATCH,
            pattern=r'(?i)(;|&&|\\||`|\\$\\(|\\${).*?(rm|del|format|net|cmd|powershell)',
            target_data_types=['security_issues'],
            threshold=0.9,
            severity=Severity.CRITICAL,
            tags=['injection', 'command-execution']
        )
        
        # Credential harvesting behavior
        self.rules['credential_harvesting'] = HuntingRule(
            rule_id='credential_harvesting',
            name='Credential Harvesting Behavior',
            description='Detect patterns indicative of credential harvesting',
            rule_type=HuntingRuleType.BEHAVIORAL,
            conditions={\n                'keywords': ['password', 'credential', 'token', 'key', 'secret'],\n                'file_operations': ['read', 'copy', 'exfiltrate'],\n                'time_window': 300  # 5 minutes\n            },\n            target_data_types=['security_events'],\n            min_occurrences=3,\n            threshold=0.7,\n            severity=Severity.HIGH,\n            tags=['credential-theft', 'data-exfiltration']\n        )\n        \n        # Lateral movement detection\n        self.rules['lateral_movement'] = HuntingRule(\n            rule_id='lateral_movement',\n            name='Lateral Movement Detection',\n            description='Detect lateral movement patterns across systems',\n            rule_type=HuntingRuleType.CORRELATION,\n            conditions={\n                'source_diversity': 3,  # Multiple source IPs\n                'target_diversity': 2,  # Multiple targets\n                'time_window': 3600,    # 1 hour\n                'protocols': ['smb', 'rdp', 'ssh', 'wmi']\n            },\n            target_data_types=['security_events'],\n            threshold=0.8,\n            severity=Severity.HIGH,\n            tags=['lateral-movement', 'network-activity']\n        )\n        \n        # Data exfiltration patterns\n        self.rules['data_exfiltration'] = HuntingRule(\n            rule_id='data_exfiltration',\n            name='Data Exfiltration Patterns',\n            description='Detect potential data exfiltration activities',\n            rule_type=HuntingRuleType.STATISTICAL,\n            conditions={\n                'data_volume_threshold': 100 * 1024 * 1024,  # 100MB\n                'external_destinations': True,\n                'unusual_hours': True,\n                'compression_indicators': ['zip', 'rar', '7z', 'tar']\n            },\n            target_data_types=['security_events'],\n            threshold=0.7,\n            severity=Severity.CRITICAL,\n            tags=['data-exfiltration', 'data-loss']\n        )\n        \n        # Persistence mechanism detection\n        self.rules['persistence_mechanisms'] = HuntingRule(\n            rule_id='persistence_mechanisms',\n            name='Persistence Mechanism Detection',\n            description='Detect establishment of persistence mechanisms',\n            rule_type=HuntingRuleType.PATTERN_MATCH,\n            pattern=r'(?i)(registry|startup|service|scheduled|cron|autorun)',\n            conditions={\n                'registry_keys': [\n                    'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',\n                    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',\n                    'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce'\n                ],\n                'file_locations': [\n                    'startup', 'autostart', '/etc/cron', '/etc/init'\n                ]\n            },\n            target_data_types=['security_issues', 'security_events'],\n            threshold=0.8,\n            severity=Severity.HIGH,\n            tags=['persistence', 'privilege-escalation']\n        )\n    \n    async def start_hunting(self):\n        \"\"\"Start automated threat hunting.\"\"\"\n        for rule_id, rule in self.rules.items():\n            if rule.enabled:\n                task = asyncio.create_task(\n                    self._hunting_loop(rule)\n                )\n                self.scheduled_tasks[rule_id] = task\n                self.logger.info(f\"Started hunting loop for rule: {rule_id}\")
    \n    async def _hunting_loop(self, rule: HuntingRule):\n        \"\"\"Continuous hunting loop for a rule.\"\"\"\n        while rule.enabled:\n            try:\n                await self.execute_hunt(rule.rule_id)\n                await asyncio.sleep(rule.schedule_minutes * 60)\n            except Exception as e:\n                self.logger.error(f\"Error in hunting loop for {rule.rule_id}: {e}\")
                await asyncio.sleep(300)  # Wait 5 minutes on error\n    \n    async def execute_hunt(self, rule_id: str) -> Optional[List[HuntingResult]]:\n        \"\"\"Execute a specific hunting rule.\"\"\"\n        if rule_id not in self.rules:\n            self.logger.error(f\"Hunting rule not found: {rule_id}\")
            return None\n        \n        rule = self.rules[rule_id]\n        if not rule.enabled:\n            return None\n        \n        start_time = datetime.now()\n        \n        try:\n            # Get processor for rule type\n            processor = self.rule_processors.get(rule.rule_type)\n            if not processor:\n                self.logger.error(f\"No processor for rule type: {rule.rule_type}\")
                return None\n            \n            # Execute the hunt\n            results = await processor(rule)\n            \n            # Update rule execution metadata\n            rule.last_executed = datetime.now()\n            rule.execution_count += 1\n            \n            # Calculate execution time\n            execution_time = (datetime.now() - start_time).total_seconds() * 1000\n            \n            # Update results with execution time\n            for result in results:\n                result.execution_time_ms = execution_time\n            \n            # Log results\n            if results:\n                self.logger.info(f\"Hunt {rule_id} found {len(results)} potential threats\")
                self.execution_history.extend(results)\n            \n            return results\n            \n        except Exception as e:\n            self.logger.error(f\"Failed to execute hunt {rule_id}: {e}\")
            return None\n    \n    async def _process_pattern_rule(self, rule: HuntingRule) -> List[HuntingResult]:\n        \"\"\"Process pattern matching hunting rule.\"\"\"\n        results = []\n        pattern = re.compile(rule.pattern, re.IGNORECASE)\n        \n        # Get data within lookback window\n        cutoff_time = datetime.now() - timedelta(hours=rule.lookback_hours)\n        \n        # Search in security issues\n        if 'security_issues' in rule.target_data_types:\n            for issue in self.data_sources.get('security_issues', []):\n                if hasattr(issue, 'created_at') and issue.created_at < cutoff_time:\n                    continue\n                \n                # Check pattern match\n                text_content = f\"{issue.description} {issue.file_path}\"\n                if hasattr(issue, 'code_snippet'):\n                    text_content += f\" {issue.code_snippet}\"\n                \n                matches = pattern.findall(text_content)\n                if matches:\n                    result = self._create_pattern_result(rule, issue, matches, 'security_issue')\n                    results.append(result)\n        \n        # Search in security events\n        if 'security_events' in rule.target_data_types:\n            for event in self.data_sources.get('security_events', []):\n                if hasattr(event, 'timestamp') and event.timestamp < cutoff_time:\n                    continue\n                \n                text_content = f\"{event.description}\"\n                if hasattr(event, 'details'):\n                    text_content += f\" {event.details}\"\n                \n                matches = pattern.findall(text_content)\n                if matches:\n                    result = self._create_pattern_result(rule, event, matches, 'security_event')\n                    results.append(result)\n        \n        return self._filter_results_by_threshold(results, rule.threshold)\n    \n    async def _process_behavioral_rule(self, rule: HuntingRule) -> List[HuntingResult]:\n        \"\"\"Process behavioral hunting rule.\"\"\"\n        results = []\n        conditions = rule.conditions\n        \n        # Get data within time window\n        cutoff_time = datetime.now() - timedelta(minutes=rule.time_window_minutes)\n        \n        # Analyze behavioral patterns\n        if 'security_events' in rule.target_data_types:\n            events = [e for e in self.data_sources.get('security_events', []) \n                     if hasattr(e, 'timestamp') and e.timestamp >= cutoff_time]\n            \n            # Group events by source/user for behavioral analysis\n            event_groups = self._group_events_by_source(events)\n            \n            for source, source_events in event_groups.items():\n                behavior_score = self._analyze_behavior(source_events, conditions)\n                \n                if behavior_score >= rule.threshold and len(source_events) >= rule.min_occurrences:\n                    result = self._create_behavioral_result(rule, source, source_events, behavior_score)\n                    results.append(result)\n        \n        return results\n    \n    async def _process_statistical_rule(self, rule: HuntingRule) -> List[HuntingResult]:\n        \"\"\"Process statistical hunting rule.\"\"\"\n        results = []\n        conditions = rule.conditions\n        \n        # Get data for statistical analysis\n        cutoff_time = datetime.now() - timedelta(hours=rule.lookback_hours)\n        \n        if 'security_events' in rule.target_data_types:\n            events = [e for e in self.data_sources.get('security_events', []) \n                     if hasattr(e, 'timestamp') and e.timestamp >= cutoff_time]\n            \n            # Perform statistical analysis\n            anomalies = self._detect_statistical_anomalies(events, conditions)\n            \n            for anomaly in anomalies:\n                if anomaly['score'] >= rule.threshold:\n                    result = self._create_statistical_result(rule, anomaly)\n                    results.append(result)\n        \n        return results\n    \n    async def _process_correlation_rule(self, rule: HuntingRule) -> List[HuntingResult]:\n        \"\"\"Process correlation hunting rule.\"\"\"\n        results = []\n        conditions = rule.conditions\n        \n        # Get data for correlation analysis\n        cutoff_time = datetime.now() - timedelta(minutes=conditions.get('time_window', 60))\n        \n        if 'security_events' in rule.target_data_types:\n            events = [e for e in self.data_sources.get('security_events', []) \n                     if hasattr(e, 'timestamp') and e.timestamp >= cutoff_time]\n            \n            # Perform correlation analysis\n            correlations = self._detect_correlations(events, conditions)\n            \n            for correlation in correlations:\n                if correlation['score'] >= rule.threshold:\n                    result = self._create_correlation_result(rule, correlation)\n                    results.append(result)\n        \n        return results\n    \n    async def _process_anomaly_rule(self, rule: HuntingRule) -> List[HuntingResult]:\n        \"\"\"Process anomaly detection hunting rule.\"\"\"\n        results = []\n        \n        # Get baseline data\n        baseline_start = datetime.now() - timedelta(days=7)\n        baseline_end = datetime.now() - timedelta(hours=rule.lookback_hours)\n        \n        # Get current data\n        current_start = datetime.now() - timedelta(hours=rule.lookback_hours)\n        \n        if 'security_events' in rule.target_data_types:\n            baseline_events = [e for e in self.data_sources.get('security_events', []) \n                             if hasattr(e, 'timestamp') and baseline_start <= e.timestamp <= baseline_end]\n            \n            current_events = [e for e in self.data_sources.get('security_events', []) \n                            if hasattr(e, 'timestamp') and e.timestamp >= current_start]\n            \n            # Detect anomalies\n            anomalies = self._detect_anomalies(baseline_events, current_events, rule.conditions)\n            \n            for anomaly in anomalies:\n                if anomaly['score'] >= rule.threshold:\n                    result = self._create_anomaly_result(rule, anomaly)\n                    results.append(result)\n        \n        return results\n    \n    def _create_pattern_result(self, rule: HuntingRule, data_item: Any, \n                              matches: List[str], data_type: str) -> HuntingResult:\n        \"\"\"Create hunting result for pattern match.\"\"\"\n        result_id = f\"{rule.rule_id}_{datetime.now().timestamp()}\"\n        \n        # Calculate confidence based on match quality\n        confidence = min(len(matches) * 0.3 + 0.4, 1.0)\n        \n        # Extract indicators\n        indicators = []\n        if hasattr(data_item, 'description'):\n            ioc_matches = self.ioc_matcher.extract_iocs_from_text(data_item.description)\n            indicators.extend([match.value for match in ioc_matches])\n        \n        return HuntingResult(\n            result_id=result_id,\n            rule_id=rule.rule_id,\n            confidence=confidence,\n            severity=rule.severity,\n            matched_data=[{\n                'type': data_type,\n                'id': getattr(data_item, 'id', 'unknown'),\n                'matches': matches,\n                'content': str(data_item)[:500]  # Truncate for storage\n            }],\n            indicators=indicators,\n            description=f\"Pattern '{rule.pattern}' matched in {data_type}\",\n            recommendations=[\n                f\"Investigate {data_type} for potential threat activity\",\n                \"Review matched patterns for false positives\",\n                \"Consider implementing additional monitoring\"\n            ],\n            data_sources=[data_type]\n        )\n    \n    def _create_behavioral_result(self, rule: HuntingRule, source: str, \n                                 events: List[Any], score: float) -> HuntingResult:\n        \"\"\"Create hunting result for behavioral detection.\"\"\"\n        result_id = f\"{rule.rule_id}_{source}_{datetime.now().timestamp()}\"\n        \n        return HuntingResult(\n            result_id=result_id,\n            rule_id=rule.rule_id,\n            confidence=score,\n            severity=rule.severity,\n            matched_data=[{\n                'type': 'behavioral_pattern',\n                'source': source,\n                'event_count': len(events),\n                'time_span': rule.time_window_minutes,\n                'score': score\n            }],\n            context={\n                'source': source,\n                'behavior_type': 'suspicious_activity',\n                'event_count': len(events)\n            },\n            description=f\"Suspicious behavioral pattern detected from source: {source}\",\n            recommendations=[\n                f\"Investigate activities from source: {source}\",\n                \"Review user/system behavior for anomalies\",\n                \"Consider implementing additional access controls\"\n            ],\n            data_sources=['security_events']\n        )\n    \n    def _create_statistical_result(self, rule: HuntingRule, anomaly: Dict[str, Any]) -> HuntingResult:\n        \"\"\"Create hunting result for statistical detection.\"\"\"\n        result_id = f\"{rule.rule_id}_stat_{datetime.now().timestamp()}\"\n        \n        return HuntingResult(\n            result_id=result_id,\n            rule_id=rule.rule_id,\n            confidence=anomaly['score'],\n            severity=rule.severity,\n            matched_data=[anomaly],\n            description=f\"Statistical anomaly detected: {anomaly.get('description', 'Unknown')}\",\n            recommendations=[\n                \"Investigate statistical anomaly for potential threats\",\n                \"Review baseline metrics and thresholds\",\n                \"Consider adjusting detection parameters\"\n            ],\n            data_sources=['security_events']\n        )\n    \n    def _create_correlation_result(self, rule: HuntingRule, correlation: Dict[str, Any]) -> HuntingResult:\n        \"\"\"Create hunting result for correlation detection.\"\"\"\n        result_id = f\"{rule.rule_id}_corr_{datetime.now().timestamp()}\"\n        \n        return HuntingResult(\n            result_id=result_id,\n            rule_id=rule.rule_id,\n            confidence=correlation['score'],\n            severity=rule.severity,\n            matched_data=[correlation],\n            description=f\"Correlated events detected: {correlation.get('description', 'Unknown')}\",\n            recommendations=[\n                \"Investigate correlated events for attack patterns\",\n                \"Review event timeline and relationships\",\n                \"Consider implementing correlation rules in SIEM\"\n            ],\n            data_sources=['security_events']\n        )\n    \n    def _create_anomaly_result(self, rule: HuntingRule, anomaly: Dict[str, Any]) -> HuntingResult:\n        \"\"\"Create hunting result for anomaly detection.\"\"\"\n        result_id = f\"{rule.rule_id}_anom_{datetime.now().timestamp()}\"\n        \n        return HuntingResult(\n            result_id=result_id,\n            rule_id=rule.rule_id,\n            confidence=anomaly['score'],\n            severity=rule.severity,\n            matched_data=[anomaly],\n            description=f\"Anomaly detected: {anomaly.get('description', 'Unknown')}\",\n            recommendations=[\n                \"Investigate anomalous behavior for potential threats\",\n                \"Review baseline patterns and normal behavior\",\n                \"Consider updating anomaly detection models\"\n            ],\n            data_sources=['security_events']\n        )\n    \n    def _filter_results_by_threshold(self, results: List[HuntingResult], threshold: float) -> List[HuntingResult]:\n        \"\"\"Filter results by confidence threshold.\"\"\"\n        return [result for result in results if result.confidence >= threshold]\n    \n    def _group_events_by_source(self, events: List[Any]) -> Dict[str, List[Any]]:\n        \"\"\"Group events by source for behavioral analysis.\"\"\"\n        groups = {}\n        \n        for event in events:\n            source = getattr(event, 'source_ip', getattr(event, 'user_id', 'unknown'))\n            if source not in groups:\n                groups[source] = []\n            groups[source].append(event)\n        \n        return groups\n    \n    def _analyze_behavior(self, events: List[Any], conditions: Dict[str, Any]) -> float:\n        \"\"\"Analyze behavioral patterns in events.\"\"\"\n        score = 0.0\n        \n        # Check for suspicious keywords\n        keywords = conditions.get('keywords', [])\n        keyword_matches = 0\n        \n        for event in events:\n            event_text = getattr(event, 'description', '')\n            for keyword in keywords:\n                if keyword.lower() in event_text.lower():\n                    keyword_matches += 1\n        \n        # Calculate keyword score\n        if keywords:\n            keyword_score = min(keyword_matches / len(keywords), 1.0)\n            score += keyword_score * 0.4\n        \n        # Check event frequency\n        event_frequency = len(events)\n        frequency_score = min(event_frequency / 10.0, 1.0)  # Normalize to 10 events\n        score += frequency_score * 0.3\n        \n        # Check time distribution\n        if len(events) > 1:\n            time_distribution_score = self._analyze_time_distribution(events)\n            score += time_distribution_score * 0.3\n        \n        return min(score, 1.0)\n    \n    def _analyze_time_distribution(self, events: List[Any]) -> float:\n        \"\"\"Analyze time distribution of events for suspicious patterns.\"\"\"\n        if len(events) < 2:\n            return 0.0\n        \n        # Calculate time intervals between events\n        timestamps = [getattr(event, 'timestamp', datetime.now()) for event in events]\n        timestamps.sort()\n        \n        intervals = []\n        for i in range(1, len(timestamps)):\n            interval = (timestamps[i] - timestamps[i-1]).total_seconds()\n            intervals.append(interval)\n        \n        # Check for regular intervals (potential automation)\n        if len(intervals) > 2:\n            avg_interval = sum(intervals) / len(intervals)\n            variance = sum((interval - avg_interval) ** 2 for interval in intervals) / len(intervals)\n            \n            # Low variance indicates regular intervals (suspicious)\n            if variance < avg_interval * 0.1:  # Less than 10% variance\n                return 0.8\n        \n        return 0.2\n    \n    def _detect_statistical_anomalies(self, events: List[Any], conditions: Dict[str, Any]) -> List[Dict[str, Any]]:\n        \"\"\"Detect statistical anomalies in events.\"\"\"\n        anomalies = []\n        \n        # Volume-based anomalies\n        if 'data_volume_threshold' in conditions:\n            threshold = conditions['data_volume_threshold']\n            \n            # Group events by source and calculate volumes\n            volume_by_source = {}\n            for event in events:\n                source = getattr(event, 'source_ip', 'unknown')\n                volume = getattr(event, 'data_size', 0)\n                \n                if source not in volume_by_source:\n                    volume_by_source[source] = 0\n                volume_by_source[source] += volume\n            \n            # Check for volume anomalies\n            for source, volume in volume_by_source.items():\n                if volume > threshold:\n                    anomalies.append({\n                        'type': 'volume_anomaly',\n                        'source': source,\n                        'volume': volume,\n                        'threshold': threshold,\n                        'score': min(volume / threshold, 2.0) / 2.0,\n                        'description': f'High data volume from {source}: {volume} bytes'\n                    })\n        \n        return anomalies\n    \n    def _detect_correlations(self, events: List[Any], conditions: Dict[str, Any]) -> List[Dict[str, Any]]:\n        \"\"\"Detect correlations between events.\"\"\"\n        correlations = []\n        \n        # Source diversity correlation\n        if 'source_diversity' in conditions:\n            min_sources = conditions['source_diversity']\n            \n            # Group events by target\n            events_by_target = {}\n            for event in events:\n                target = getattr(event, 'hostname', getattr(event, 'target_ip', 'unknown'))\n                if target not in events_by_target:\n                    events_by_target[target] = []\n                events_by_target[target].append(event)\n            \n            # Check for multiple sources targeting same target\n            for target, target_events in events_by_target.items():\n                sources = set(getattr(event, 'source_ip', 'unknown') for event in target_events)\n                \n                if len(sources) >= min_sources:\n                    score = min(len(sources) / min_sources, 2.0) / 2.0\n                    correlations.append({\n                        'type': 'source_diversity',\n                        'target': target,\n                        'source_count': len(sources),\n                        'event_count': len(target_events),\n                        'score': score,\n                        'description': f'Multiple sources ({len(sources)}) targeting {target}'\n                    })\n        \n        return correlations\n    \n    def _detect_anomalies(self, baseline_events: List[Any], current_events: List[Any], \n                         conditions: Dict[str, Any]) -> List[Dict[str, Any]]:\n        \"\"\"Detect anomalies compared to baseline.\"\"\"\n        anomalies = []\n        \n        # Event frequency anomaly\n        baseline_count = len(baseline_events)\n        current_count = len(current_events)\n        \n        if baseline_count > 0:\n            # Calculate expected count (normalize for time period)\n            baseline_days = 7\n            current_hours = conditions.get('lookback_hours', 24)\n            expected_count = (baseline_count / baseline_days) * (current_hours / 24)\n            \n            # Check for significant deviation\n            if current_count > expected_count * 2:  # More than 2x expected\n                score = min(current_count / (expected_count * 2), 2.0) / 2.0\n                anomalies.append({\n                    'type': 'frequency_anomaly',\n                    'baseline_count': baseline_count,\n                    'current_count': current_count,\n                    'expected_count': expected_count,\n                    'score': score,\n                    'description': f'Event frequency anomaly: {current_count} vs expected {expected_count:.1f}'\n                })\n        \n        return anomalies\n    \n    def add_data_source(self, data_type: str, data: List[Any]):\n        \"\"\"Add data to hunting data sources.\"\"\"\n        if data_type not in self.data_sources:\n            self.data_sources[data_type] = []\n        \n        self.data_sources[data_type].extend(data)\n        \n        # Keep only recent data to prevent memory issues\n        cutoff_time = datetime.now() - timedelta(days=7)\n        self.data_sources[data_type] = [\n            item for item in self.data_sources[data_type]\n            if getattr(item, 'timestamp', getattr(item, 'created_at', datetime.now())) >= cutoff_time\n        ]\n    \n    def add_hunting_rule(self, rule: HuntingRule):\n        \"\"\"Add a custom hunting rule.\"\"\"\n        self.rules[rule.rule_id] = rule\n        self.logger.info(f\"Added hunting rule: {rule.rule_id}\")
        \n        # Start hunting loop if engine is running\n        if rule.enabled and rule.rule_id not in self.scheduled_tasks:\n            task = asyncio.create_task(self._hunting_loop(rule))\n            self.scheduled_tasks[rule.rule_id] = task\n    \n    def remove_hunting_rule(self, rule_id: str) -> bool:\n        \"\"\"Remove a hunting rule.\"\"\"\n        if rule_id in self.rules:\n            # Stop scheduled task\n            if rule_id in self.scheduled_tasks:\n                self.scheduled_tasks[rule_id].cancel()\n                del self.scheduled_tasks[rule_id]\n            \n            del self.rules[rule_id]\n            self.logger.info(f\"Removed hunting rule: {rule_id}\")
            return True\n        return False\n    \n    def get_hunting_results(self, limit: int = 100) -> List[Dict[str, Any]]:\n        \"\"\"Get recent hunting results.\"\"\"\n        return [result.to_dict() for result in self.execution_history[-limit:]]\n    \n    def get_rule_statistics(self) -> Dict[str, Any]:\n        \"\"\"Get hunting rule statistics.\"\"\"\n        total_rules = len(self.rules)\n        active_rules = sum(1 for rule in self.rules.values() if rule.enabled)\n        \n        # Count by rule type\n        by_type = {}\n        for rule in self.rules.values():\n            rule_type = rule.rule_type.value\n            by_type[rule_type] = by_type.get(rule_type, 0) + 1\n        \n        # Recent results\n        recent_results = len([r for r in self.execution_history \n                            if r.detected_at >= datetime.now() - timedelta(hours=24)])\n        \n        return {\n            'total_rules': total_rules,\n            'active_rules': active_rules,\n            'rules_by_type': by_type,\n            'recent_results_24h': recent_results,\n            'total_results': len(self.execution_history)\n        }\n    \n    async def shutdown(self):\n        \"\"\"Gracefully shutdown hunting engine.\"\"\"\n        # Cancel all scheduled tasks\n        for rule_id, task in self.scheduled_tasks.items():\n            task.cancel()\n            try:\n                await task\n            except asyncio.CancelledError:\n                pass\n            self.logger.info(f\"Stopped hunting loop for rule: {rule_id}\")
        \n        self.scheduled_tasks.clear()\n        self.logger.info(\"Threat hunting engine shutdown complete\")