"""Audit logging system for all security events and user actions."""

import logging
import json
import sqlite3
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import threading


class AuditLevel(Enum):
    """Audit event levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditEventType(Enum):
    """Types of audit events."""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    SECURITY_SCAN = "security_scan"
    POLICY_CHANGE = "policy_change"
    SYSTEM_ERROR = "system_error"
    COMPLIANCE_CHECK = "compliance_check"
    GDPR_REQUEST = "gdpr_request"


@dataclass
class AuditEvent:
    """Represents an audit event."""
    
    event_id: str
    event_type: AuditEventType
    level: AuditLevel
    
    # Event details
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Timestamps
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Integrity
    checksum: Optional[str] = None
    
    def calculate_checksum(self) -> str:
        """Calculate event checksum for integrity."""
        data = f"{self.event_id}{self.timestamp.isoformat()}{self.message}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'level': self.level.value,
            'message': self.message,
            'details': self.details,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat(),
            'checksum': self.checksum
        }


class AuditLogger:
    """Main audit logging system."""
    
    def __init__(self, db_path: str = "audit.db"):
        """Initialize audit logger."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize audit database."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        details TEXT,
                        user_id TEXT,
                        session_id TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TEXT NOT NULL,
                        checksum TEXT
                    )
                ''')
                
                conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing audit database: {e}")
            raise
    
    def log_event(self, 
                  event_type: AuditEventType,
                  message: str,
                  level: AuditLevel = AuditLevel.INFO,
                  details: Optional[Dict[str, Any]] = None,
                  user_id: Optional[str] = None,
                  session_id: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None) -> str:
        """Log an audit event."""
        
        import uuid
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            level=level,
            message=message,
            details=details or {},
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Calculate checksum for integrity
        event.checksum = event.calculate_checksum()
        
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO audit_events 
                        (event_id, event_type, level, message, details, user_id,
                         session_id, ip_address, user_agent, timestamp, checksum)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event.event_id,
                        event.event_type.value,
                        event.level.value,
                        event.message,
                        json.dumps(event.details),
                        event.user_id,
                        event.session_id,
                        event.ip_address,
                        event.user_agent,
                        event.timestamp.isoformat(),
                        event.checksum
                    ))
                    conn.commit()
            
            return event.event_id
            
        except Exception as e:
            self.logger.error(f"Error logging audit event: {e}")
            raise
    
    def get_events(self, 
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   event_type: Optional[AuditEventType] = None,
                   user_id: Optional[str] = None,
                   level: Optional[AuditLevel] = None,
                   limit: int = 1000) -> List[AuditEvent]:
        """Get audit events with filtering."""
        
        query = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if level:
            query += " AND level = ?"
            params.append(level.value)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                
                events = []
                for row in cursor.fetchall():
                    event = AuditEvent(
                        event_id=row[0],
                        event_type=AuditEventType(row[1]),
                        level=AuditLevel(row[2]),
                        message=row[3],
                        details=json.loads(row[4]) if row[4] else {},
                        user_id=row[5],
                        session_id=row[6],
                        ip_address=row[7],
                        user_agent=row[8],
                        timestamp=datetime.fromisoformat(row[9]),
                        checksum=row[10]
                    )
                    events.append(event)
                
                return events
                
        except Exception as e:
            self.logger.error(f"Error getting audit events: {e}")
            return []


class SecurityAuditLogger(AuditLogger):
    """Specialized audit logger for security events."""
    
    def log_security_scan(self, scan_id: str, files_scanned: int, issues_found: int, user_id: Optional[str] = None):
        """Log security scan event."""
        self.log_event(
            event_type=AuditEventType.SECURITY_SCAN,
            message=f"Security scan completed: {scan_id}",
            details={
                'scan_id': scan_id,
                'files_scanned': files_scanned,
                'issues_found': issues_found
            },
            user_id=user_id
        )
    
    def log_policy_change(self, policy_name: str, change_type: str, user_id: Optional[str] = None):
        """Log security policy change."""
        self.log_event(
            event_type=AuditEventType.POLICY_CHANGE,
            message=f"Security policy changed: {policy_name}",
            level=AuditLevel.WARNING,
            details={
                'policy_name': policy_name,
                'change_type': change_type
            },
            user_id=user_id
        )


class PrivacyAuditLogger(AuditLogger):
    """Specialized audit logger for privacy events."""
    
    def log_gdpr_request(self, request_id: str, request_type: str, data_subject_id: str):
        """Log GDPR request event."""
        self.log_event(
            event_type=AuditEventType.GDPR_REQUEST,
            message=f"GDPR request submitted: {request_type}",
            details={
                'request_id': request_id,
                'request_type': request_type,
                'data_subject_id': data_subject_id
            }
        )
    
    def log_data_access(self, data_type: str, data_id: str, user_id: Optional[str] = None):
        """Log data access event."""
        self.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            message=f"Data accessed: {data_type}",
            details={
                'data_type': data_type,
                'data_id': data_id
            },
            user_id=user_id
        )