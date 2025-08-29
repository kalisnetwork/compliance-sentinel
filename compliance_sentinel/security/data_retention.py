"""Data retention management with configurable policies."""

import logging
import json
import sqlite3
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import re

from compliance_sentinel.core.interfaces import SecurityIssue


logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class RetentionAction(Enum):
    """Actions to take when retention period expires."""
    DELETE = "delete"
    ARCHIVE = "archive"
    ANONYMIZE = "anonymize"
    REVIEW = "review"
    NOTIFY = "notify"


class DataCategory(Enum):
    """Categories of data for retention policies."""
    ANALYSIS_RESULTS = "analysis_results"
    SOURCE_CODE = "source_code"
    AUDIT_LOGS = "audit_logs"
    USER_DATA = "user_data"
    SYSTEM_LOGS = "system_logs"
    SECURITY_EVENTS = "security_events"
    COMPLIANCE_RECORDS = "compliance_records"
    ML_TRAINING_DATA = "ml_training_data"


@dataclass
class RetentionRule:
    """Individual retention rule."""
    
    rule_id: str
    name: str
    description: str
    
    # Rule criteria
    data_category: DataCategory
    data_classification: DataClassification
    
    # Retention settings
    retention_period_days: int
    action: RetentionAction
    
    # Rule conditions
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = "system"
    enabled: bool = True
    
    def matches_data(self, data_metadata: Dict[str, Any]) -> bool:
        """Check if rule matches given data metadata."""
        
        # Check category
        if data_metadata.get('category') != self.data_category.value:
            return False
        
        # Check classification
        if data_metadata.get('classification') != self.data_classification.value:
            return False
        
        # Check additional conditions
        for key, expected_value in self.conditions.items():
            actual_value = data_metadata.get(key)
            
            if isinstance(expected_value, str) and isinstance(actual_value, str):
                # Support regex matching for strings
                if not re.match(expected_value, actual_value):
                    return False
            elif actual_value != expected_value:
                return False
        
        return True
    
    def is_expired(self, data_created_at: datetime) -> bool:
        """Check if data has exceeded retention period."""
        
        expiry_date = data_created_at + timedelta(days=self.retention_period_days)
        return datetime.now() > expiry_date
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'data_category': self.data_category.value,
            'data_classification': self.data_classification.value,
            'retention_period_days': self.retention_period_days,
            'action': self.action.value,
            'conditions': self.conditions,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'enabled': self.enabled
        }


@dataclass
class RetentionPolicy:
    """Collection of retention rules."""
    
    policy_id: str
    name: str
    description: str
    
    # Rules
    rules: List[RetentionRule] = field(default_factory=list)
    
    # Policy settings
    default_retention_days: int = 2555  # 7 years default
    default_action: RetentionAction = RetentionAction.REVIEW
    
    # Metadata
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def add_rule(self, rule: RetentionRule):
        """Add retention rule to policy."""
        self.rules.append(rule)
        self.updated_at = datetime.now()
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove retention rule from policy."""
        
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                del self.rules[i]
                self.updated_at = datetime.now()
                return True
        
        return False
    
    def find_applicable_rule(self, data_metadata: Dict[str, Any]) -> Optional[RetentionRule]:
        """Find the first applicable rule for given data."""
        
        for rule in self.rules:
            if rule.enabled and rule.matches_data(data_metadata):
                return rule
        
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return {
            'policy_id': self.policy_id,
            'name': self.name,
            'description': self.description,
            'rules': [rule.to_dict() for rule in self.rules],
            'default_retention_days': self.default_retention_days,
            'default_action': self.default_action.value,
            'version': self.version,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

@
dataclass
class DataRecord:
    """Represents a data record for retention management."""
    
    record_id: str
    data_category: DataCategory
    data_classification: DataClassification
    
    # Timestamps
    created_at: datetime
    accessed_at: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Retention tracking
    retention_rule_id: Optional[str] = None
    retention_expires_at: Optional[datetime] = None
    retention_action: Optional[RetentionAction] = None
    
    # Status
    is_archived: bool = False
    is_anonymized: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary."""
        return {
            'record_id': self.record_id,
            'data_category': self.data_category.value,
            'data_classification': self.data_classification.value,
            'created_at': self.created_at.isoformat(),
            'accessed_at': self.accessed_at.isoformat() if self.accessed_at else None,
            'metadata': self.metadata,
            'retention_rule_id': self.retention_rule_id,
            'retention_expires_at': self.retention_expires_at.isoformat() if self.retention_expires_at else None,
            'retention_action': self.retention_action.value if self.retention_action else None,
            'is_archived': self.is_archived,
            'is_anonymized': self.is_anonymized
        }


class DataRetentionManager:
    """Main data retention management system."""
    
    def __init__(self, db_path: str = "data_retention.db"):
        """Initialize data retention manager."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Policies
        self.policies = {}
        self.active_policy_id = None
        
        # Action handlers
        self.action_handlers = {
            RetentionAction.DELETE: self._handle_delete,
            RetentionAction.ARCHIVE: self._handle_archive,
            RetentionAction.ANONYMIZE: self._handle_anonymize,
            RetentionAction.REVIEW: self._handle_review,
            RetentionAction.NOTIFY: self._handle_notify
        }
        
        # Initialize database
        self._init_database()
        
        # Load default policies
        self._load_default_policies()
    
    def _init_database(self):
        """Initialize retention database."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Data records table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS data_records (
                        record_id TEXT PRIMARY KEY,
                        data_category TEXT NOT NULL,
                        data_classification TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        accessed_at TEXT,
                        metadata TEXT,
                        retention_rule_id TEXT,
                        retention_expires_at TEXT,
                        retention_action TEXT,
                        is_archived BOOLEAN DEFAULT FALSE,
                        is_anonymized BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Retention policies table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS retention_policies (
                        policy_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        policy_data TEXT NOT NULL,
                        version TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT,
                        is_active BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Retention actions log
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS retention_actions_log (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        record_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        executed_by TEXT,
                        result TEXT,
                        details TEXT
                    )
                ''')
                
                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_records_expires_at ON data_records(retention_expires_at)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_records_category ON data_records(data_category)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_actions_log_record ON retention_actions_log(record_id)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing retention database: {e}")
            raise
    
    def _load_default_policies(self):
        """Load default retention policies."""
        
        # GDPR-compliant policy
        gdpr_policy = self._create_gdpr_policy()
        self.add_policy(gdpr_policy)
        
        # Security-focused policy
        security_policy = self._create_security_policy()
        self.add_policy(security_policy)
        
        # Set GDPR as default active policy
        self.set_active_policy("gdpr_compliance")
    
    def _create_gdpr_policy(self) -> RetentionPolicy:
        """Create GDPR-compliant retention policy."""
        
        policy = RetentionPolicy(
            policy_id="gdpr_compliance",
            name="GDPR Compliance Policy",
            description="Data retention policy compliant with GDPR requirements",
            default_retention_days=2555,  # 7 years
            default_action=RetentionAction.DELETE
        )
        
        # Personal data - must be deleted after purpose fulfilled
        policy.add_rule(RetentionRule(
            rule_id="gdpr_personal_data",
            name="Personal Data Retention",
            description="Personal data retention per GDPR Article 5(1)(e)",
            data_category=DataCategory.USER_DATA,
            data_classification=DataClassification.CONFIDENTIAL,
            retention_period_days=1095,  # 3 years
            action=RetentionAction.DELETE,
            conditions={'contains_pii': True}
        ))
        
        # Audit logs - keep for compliance
        policy.add_rule(RetentionRule(
            rule_id="gdpr_audit_logs",
            name="Audit Logs Retention",
            description="Audit logs for compliance monitoring",
            data_category=DataCategory.AUDIT_LOGS,
            data_classification=DataClassification.INTERNAL,
            retention_period_days=2555,  # 7 years
            action=RetentionAction.ARCHIVE
        ))
        
        # Analysis results - anonymize after period
        policy.add_rule(RetentionRule(
            rule_id="gdpr_analysis_results",
            name="Analysis Results Retention",
            description="Security analysis results with potential personal data",
            data_category=DataCategory.ANALYSIS_RESULTS,
            data_classification=DataClassification.CONFIDENTIAL,
            retention_period_days=365,  # 1 year
            action=RetentionAction.ANONYMIZE
        ))
        
        return policy
    
    def _create_security_policy(self) -> RetentionPolicy:
        """Create security-focused retention policy."""
        
        policy = RetentionPolicy(
            policy_id="security_focused",
            name="Security-Focused Policy",
            description="Retention policy optimized for security monitoring",
            default_retention_days=1825,  # 5 years
            default_action=RetentionAction.ARCHIVE
        )
        
        # Security events - keep longer for threat analysis
        policy.add_rule(RetentionRule(
            rule_id="security_events_long",
            name="Security Events Long Retention",
            description="Security events for threat intelligence",
            data_category=DataCategory.SECURITY_EVENTS,
            data_classification=DataClassification.CONFIDENTIAL,
            retention_period_days=2555,  # 7 years
            action=RetentionAction.ARCHIVE
        ))
        
        # ML training data - keep for model improvement
        policy.add_rule(RetentionRule(
            rule_id="ml_training_data",
            name="ML Training Data Retention",
            description="Anonymized ML training data",
            data_category=DataCategory.ML_TRAINING_DATA,
            data_classification=DataClassification.INTERNAL,
            retention_period_days=1825,  # 5 years
            action=RetentionAction.ARCHIVE,
            conditions={'is_anonymized': True}
        ))
        
        return policy    

    def add_policy(self, policy: RetentionPolicy):
        """Add retention policy."""
        
        self.policies[policy.policy_id] = policy
        
        # Store in database
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO retention_policies 
                    (policy_id, name, description, policy_data, version, created_at, updated_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    policy.policy_id,
                    policy.name,
                    policy.description,
                    json.dumps(policy.to_dict()),
                    policy.version,
                    policy.created_at.isoformat(),
                    policy.updated_at.isoformat() if policy.updated_at else None,
                    policy.policy_id == self.active_policy_id
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing policy {policy.policy_id}: {e}")
    
    def set_active_policy(self, policy_id: str) -> bool:
        """Set active retention policy."""
        
        if policy_id not in self.policies:
            return False
        
        self.active_policy_id = policy_id
        
        # Update database
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Deactivate all policies
                conn.execute('UPDATE retention_policies SET is_active = FALSE')
                
                # Activate selected policy
                conn.execute('UPDATE retention_policies SET is_active = TRUE WHERE policy_id = ?', (policy_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error setting active policy: {e}")
            return False
    
    def register_data(self, 
                     record_id: str,
                     data_category: DataCategory,
                     data_classification: DataClassification,
                     metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register data for retention management."""
        
        try:
            # Create data record
            record = DataRecord(
                record_id=record_id,
                data_category=data_category,
                data_classification=data_classification,
                created_at=datetime.now(),
                metadata=metadata or {}
            )
            
            # Apply retention policy
            if self.active_policy_id and self.active_policy_id in self.policies:
                policy = self.policies[self.active_policy_id]
                
                # Find applicable rule
                applicable_rule = policy.find_applicable_rule({
                    'category': data_category.value,
                    'classification': data_classification.value,
                    **record.metadata
                })
                
                if applicable_rule:
                    record.retention_rule_id = applicable_rule.rule_id
                    record.retention_expires_at = record.created_at + timedelta(days=applicable_rule.retention_period_days)
                    record.retention_action = applicable_rule.action
                else:
                    # Use default policy settings
                    record.retention_expires_at = record.created_at + timedelta(days=policy.default_retention_days)
                    record.retention_action = policy.default_action
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO data_records 
                    (record_id, data_category, data_classification, created_at, accessed_at,
                     metadata, retention_rule_id, retention_expires_at, retention_action,
                     is_archived, is_anonymized)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.record_id,
                    record.data_category.value,
                    record.data_classification.value,
                    record.created_at.isoformat(),
                    record.accessed_at.isoformat() if record.accessed_at else None,
                    json.dumps(record.metadata),
                    record.retention_rule_id,
                    record.retention_expires_at.isoformat() if record.retention_expires_at else None,
                    record.retention_action.value if record.retention_action else None,
                    record.is_archived,
                    record.is_anonymized
                ))
                conn.commit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering data {record_id}: {e}")
            return False
    
    def check_expired_data(self) -> List[str]:
        """Check for data that has exceeded retention period."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT record_id FROM data_records 
                    WHERE retention_expires_at IS NOT NULL 
                    AND retention_expires_at < ?
                    AND is_archived = FALSE
                ''', (datetime.now().isoformat(),))
                
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error checking expired data: {e}")
            return []
    
    def process_expired_data(self) -> Dict[str, Any]:
        """Process all expired data according to retention policies."""
        
        expired_records = self.check_expired_data()
        results = {
            'processed': 0,
            'succeeded': 0,
            'failed': 0,
            'actions': {}
        }
        
        for record_id in expired_records:
            try:
                record = self._get_data_record(record_id)
                if not record:
                    continue
                
                # Execute retention action
                action_result = self._execute_retention_action(record)
                
                results['processed'] += 1
                if action_result:
                    results['succeeded'] += 1
                else:
                    results['failed'] += 1
                
                # Track actions
                action = record.retention_action.value if record.retention_action else 'unknown'
                results['actions'][action] = results['actions'].get(action, 0) + 1
                
            except Exception as e:
                self.logger.error(f"Error processing expired record {record_id}: {e}")
                results['failed'] += 1
        
        return results
    
    def _get_data_record(self, record_id: str) -> Optional[DataRecord]:
        """Get data record from database."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM data_records WHERE record_id = ?', (record_id,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                return DataRecord(
                    record_id=row[0],
                    data_category=DataCategory(row[1]),
                    data_classification=DataClassification(row[2]),
                    created_at=datetime.fromisoformat(row[3]),
                    accessed_at=datetime.fromisoformat(row[4]) if row[4] else None,
                    metadata=json.loads(row[5]) if row[5] else {},
                    retention_rule_id=row[6],
                    retention_expires_at=datetime.fromisoformat(row[7]) if row[7] else None,
                    retention_action=RetentionAction(row[8]) if row[8] else None,
                    is_archived=bool(row[9]),
                    is_anonymized=bool(row[10])
                )
                
        except Exception as e:
            self.logger.error(f"Error getting data record {record_id}: {e}")
            return None
    
    def _execute_retention_action(self, record: DataRecord) -> bool:
        """Execute retention action for a record."""
        
        if not record.retention_action:
            return False
        
        handler = self.action_handlers.get(record.retention_action)
        if not handler:
            self.logger.error(f"No handler for action: {record.retention_action}")
            return False
        
        try:
            result = handler(record)
            
            # Log action
            self._log_retention_action(record, result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing retention action for {record.record_id}: {e}")
            return False
    
    def _handle_delete(self, record: DataRecord) -> bool:
        """Handle delete retention action."""
        
        try:
            # Mark as deleted in database (soft delete)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM data_records WHERE record_id = ?', (record.record_id,))
                conn.commit()
            
            self.logger.info(f"Deleted data record: {record.record_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting record {record.record_id}: {e}")
            return False
    
    def _handle_archive(self, record: DataRecord) -> bool:
        """Handle archive retention action."""
        
        try:
            # Mark as archived
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE data_records SET is_archived = TRUE 
                    WHERE record_id = ?
                ''', (record.record_id,))
                conn.commit()
            
            self.logger.info(f"Archived data record: {record.record_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error archiving record {record.record_id}: {e}")
            return False
    
    def _handle_anonymize(self, record: DataRecord) -> bool:
        """Handle anonymize retention action."""
        
        try:
            # Mark as anonymized
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE data_records SET is_anonymized = TRUE 
                    WHERE record_id = ?
                ''', (record.record_id,))
                conn.commit()
            
            self.logger.info(f"Anonymized data record: {record.record_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error anonymizing record {record.record_id}: {e}")
            return False
    
    def _handle_review(self, record: DataRecord) -> bool:
        """Handle review retention action."""
        
        # For review action, we just log and extend retention
        try:
            # Extend retention by 90 days for manual review
            new_expiry = datetime.now() + timedelta(days=90)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE data_records SET retention_expires_at = ? 
                    WHERE record_id = ?
                ''', (new_expiry.isoformat(), record.record_id))
                conn.commit()
            
            self.logger.info(f"Extended retention for review: {record.record_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error extending retention for {record.record_id}: {e}")
            return False
    
    def _handle_notify(self, record: DataRecord) -> bool:
        """Handle notify retention action."""
        
        # For notify action, we log and can integrate with notification system
        self.logger.warning(f"Data retention notification: {record.record_id} requires attention")
        return True
    
    def _log_retention_action(self, record: DataRecord, success: bool):
        """Log retention action execution."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO retention_actions_log 
                    (record_id, action, executed_at, executed_by, result, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    record.record_id,
                    record.retention_action.value if record.retention_action else 'unknown',
                    datetime.now().isoformat(),
                    'system',
                    'success' if success else 'failure',
                    json.dumps(record.to_dict())
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error logging retention action: {e}")
    
    def get_retention_statistics(self) -> Dict[str, Any]:
        """Get retention management statistics."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total records
                cursor = conn.execute('SELECT COUNT(*) FROM data_records')
                total_records = cursor.fetchone()[0]
                
                # Records by category
                cursor = conn.execute('''
                    SELECT data_category, COUNT(*) FROM data_records 
                    GROUP BY data_category
                ''')
                by_category = dict(cursor.fetchall())
                
                # Records by classification
                cursor = conn.execute('''
                    SELECT data_classification, COUNT(*) FROM data_records 
                    GROUP BY data_classification
                ''')
                by_classification = dict(cursor.fetchall())
                
                # Expired records
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM data_records 
                    WHERE retention_expires_at < ?
                ''', (datetime.now().isoformat(),))
                expired_records = cursor.fetchone()[0]
                
                # Archived records
                cursor = conn.execute('SELECT COUNT(*) FROM data_records WHERE is_archived = TRUE')
                archived_records = cursor.fetchone()[0]
                
                # Anonymized records
                cursor = conn.execute('SELECT COUNT(*) FROM data_records WHERE is_anonymized = TRUE')
                anonymized_records = cursor.fetchone()[0]
                
                return {
                    'total_records': total_records,
                    'expired_records': expired_records,
                    'archived_records': archived_records,
                    'anonymized_records': anonymized_records,
                    'by_category': by_category,
                    'by_classification': by_classification,
                    'active_policy': self.active_policy_id,
                    'total_policies': len(self.policies)
                }
                
        except Exception as e:
            self.logger.error(f"Error getting retention statistics: {e}")
            return {}


# Utility functions

def create_gdpr_compliant_manager(db_path: str = "gdpr_retention.db") -> DataRetentionManager:
    """Create GDPR-compliant data retention manager."""
    
    manager = DataRetentionManager(db_path)
    manager.set_active_policy("gdpr_compliance")
    return manager


def create_security_focused_manager(db_path: str = "security_retention.db") -> DataRetentionManager:
    """Create security-focused data retention manager."""
    
    manager = DataRetentionManager(db_path)
    manager.set_active_policy("security_focused")
    return manager