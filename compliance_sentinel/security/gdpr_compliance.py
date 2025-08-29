"""GDPR compliance features for user data handling and deletion."""

import logging
import json
import sqlite3
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import uuid

from compliance_sentinel.core.interfaces import SecurityIssue


logger = logging.getLogger(__name__)


class DataSubjectRightType(Enum):
    """Types of data subject rights under GDPR."""
    ACCESS = "access"  # Article 15
    RECTIFICATION = "rectification"  # Article 16
    ERASURE = "erasure"  # Article 17 (Right to be forgotten)
    RESTRICT_PROCESSING = "restrict_processing"  # Article 18
    DATA_PORTABILITY = "data_portability"  # Article 20
    OBJECT = "object"  # Article 21
    WITHDRAW_CONSENT = "withdraw_consent"  # Article 7(3)


class ProcessingLawfulBasis(Enum):
    """Lawful basis for processing under GDPR Article 6."""
    CONSENT = "consent"  # Article 6(1)(a)
    CONTRACT = "contract"  # Article 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c)
    VITAL_INTERESTS = "vital_interests"  # Article 6(1)(d)
    PUBLIC_TASK = "public_task"  # Article 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f)


class ConsentStatus(Enum):
    """Status of user consent."""
    GIVEN = "given"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    PENDING = "pending"


class RequestStatus(Enum):
    """Status of data subject requests."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class DataSubjectRequest:
    """Represents a data subject request under GDPR."""
    
    request_id: str
    data_subject_id: str
    request_type: DataSubjectRightType
    
    # Request details
    description: str
    requested_data_categories: List[str] = field(default_factory=list)
    
    # Status tracking
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Processing details
    assigned_to: Optional[str] = None
    processing_notes: List[str] = field(default_factory=list)
    
    # Response
    response_data: Optional[Dict[str, Any]] = None
    response_format: str = "json"
    
    def add_note(self, note: str, author: str = "system"):
        """Add processing note."""
        timestamp = datetime.now().isoformat()
        self.processing_notes.append(f"[{timestamp}] {author}: {note}")
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary."""
        return {
            'request_id': self.request_id,
            'data_subject_id': self.data_subject_id,
            'request_type': self.request_type.value,
            'description': self.description,
            'requested_data_categories': self.requested_data_categories,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'assigned_to': self.assigned_to,
            'processing_notes': self.processing_notes,
            'response_format': self.response_format,
            'has_response_data': self.response_data is not None
        }


@dataclass
class ConsentRecord:
    """Represents user consent record."""
    
    consent_id: str
    data_subject_id: str
    
    # Consent details
    purpose: str
    data_categories: List[str]
    lawful_basis: ProcessingLawfulBasis
    
    # Consent status
    status: ConsentStatus = ConsentStatus.GIVEN
    given_at: datetime = field(default_factory=datetime.now)
    withdrawn_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    # Consent mechanism
    consent_method: str = "explicit"  # explicit, implicit, etc.
    consent_evidence: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if consent is currently valid."""
        
        if self.status != ConsentStatus.GIVEN:
            return False
        
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        
        return True
    
    def withdraw(self):
        """Withdraw consent."""
        self.status = ConsentStatus.WITHDRAWN
        self.withdrawn_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert consent to dictionary."""
        return {
            'consent_id': self.consent_id,
            'data_subject_id': self.data_subject_id,
            'purpose': self.purpose,
            'data_categories': self.data_categories,
            'lawful_basis': self.lawful_basis.value,
            'status': self.status.value,
            'given_at': self.given_at.isoformat(),
            'withdrawn_at': self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'consent_method': self.consent_method,
            'consent_evidence': self.consent_evidence,
            'is_valid': self.is_valid()
        }


@dataclass
class DataProcessingRecord:
    """Record of data processing activities (Article 30)."""
    
    record_id: str
    controller_name: str
    
    # Processing details
    purpose: str
    data_categories: List[str]
    data_subject_categories: List[str]
    lawful_basis: ProcessingLawfulBasis
    
    # Recipients and transfers
    recipients: List[str] = field(default_factory=list)
    third_country_transfers: List[str] = field(default_factory=list)
    
    # Retention and security
    retention_period: Optional[str] = None
    security_measures: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert processing record to dictionary."""
        return {
            'record_id': self.record_id,
            'controller_name': self.controller_name,
            'purpose': self.purpose,
            'data_categories': self.data_categories,
            'data_subject_categories': self.data_subject_categories,
            'lawful_basis': self.lawful_basis.value,
            'recipients': self.recipients,
            'third_country_transfers': self.third_country_transfers,
            'retention_period': self.retention_period,
            'security_measures': self.security_measures,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


@dataclass
class PrivacyImpactAssessment:
    """Privacy Impact Assessment (DPIA) record."""
    
    pia_id: str
    title: str
    description: str
    
    # Assessment details
    data_categories: List[str]
    processing_purposes: List[str]
    risks_identified: List[str]
    mitigation_measures: List[str]
    
    # Assessment results
    risk_level: str = "medium"  # low, medium, high
    requires_consultation: bool = False
    
    # Metadata
    conducted_by: str = "system"
    conducted_at: datetime = field(default_factory=datetime.now)
    reviewed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert PIA to dictionary."""
        return {
            'pia_id': self.pia_id,
            'title': self.title,
            'description': self.description,
            'data_categories': self.data_categories,
            'processing_purposes': self.processing_purposes,
            'risks_identified': self.risks_identified,
            'mitigation_measures': self.mitigation_measures,
            'risk_level': self.risk_level,
            'requires_consultation': self.requires_consultation,
            'conducted_by': self.conducted_by,
            'conducted_at': self.conducted_at.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None
        }
class Co
nsentManager:
    """Manages user consent under GDPR."""
    
    def __init__(self, db_path: str = "gdpr_consent.db"):
        """Initialize consent manager."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize consent database."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS consent_records (
                        consent_id TEXT PRIMARY KEY,
                        data_subject_id TEXT NOT NULL,
                        purpose TEXT NOT NULL,
                        data_categories TEXT NOT NULL,
                        lawful_basis TEXT NOT NULL,
                        status TEXT NOT NULL,
                        given_at TEXT NOT NULL,
                        withdrawn_at TEXT,
                        expires_at TEXT,
                        consent_method TEXT NOT NULL,
                        consent_evidence TEXT
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_consent_subject 
                    ON consent_records(data_subject_id)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing consent database: {e}")
            raise
    
    def record_consent(self, 
                      data_subject_id: str,
                      purpose: str,
                      data_categories: List[str],
                      lawful_basis: ProcessingLawfulBasis = ProcessingLawfulBasis.CONSENT,
                      consent_method: str = "explicit",
                      consent_evidence: Optional[Dict[str, Any]] = None,
                      expires_at: Optional[datetime] = None) -> str:
        """Record user consent."""
        
        consent_id = str(uuid.uuid4())
        
        consent_record = ConsentRecord(
            consent_id=consent_id,
            data_subject_id=data_subject_id,
            purpose=purpose,
            data_categories=data_categories,
            lawful_basis=lawful_basis,
            consent_method=consent_method,
            consent_evidence=consent_evidence or {},
            expires_at=expires_at
        )
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO consent_records 
                    (consent_id, data_subject_id, purpose, data_categories, lawful_basis,
                     status, given_at, withdrawn_at, expires_at, consent_method, consent_evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    consent_record.consent_id,
                    consent_record.data_subject_id,
                    consent_record.purpose,
                    json.dumps(consent_record.data_categories),
                    consent_record.lawful_basis.value,
                    consent_record.status.value,
                    consent_record.given_at.isoformat(),
                    consent_record.withdrawn_at.isoformat() if consent_record.withdrawn_at else None,
                    consent_record.expires_at.isoformat() if consent_record.expires_at else None,
                    consent_record.consent_method,
                    json.dumps(consent_record.consent_evidence)
                ))
                conn.commit()
            
            self.logger.info(f"Recorded consent: {consent_id} for subject {data_subject_id}")
            return consent_id
            
        except Exception as e:
            self.logger.error(f"Error recording consent: {e}")
            raise
    
    def withdraw_consent(self, consent_id: str) -> bool:
        """Withdraw user consent."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE consent_records 
                    SET status = ?, withdrawn_at = ?
                    WHERE consent_id = ?
                ''', (ConsentStatus.WITHDRAWN.value, datetime.now().isoformat(), consent_id))
                
                conn.commit()
                
                if conn.total_changes > 0:
                    self.logger.info(f"Withdrew consent: {consent_id}")
                    return True
                else:
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error withdrawing consent {consent_id}: {e}")
            return False
    
    def get_valid_consents(self, data_subject_id: str) -> List[ConsentRecord]:
        """Get all valid consents for a data subject."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM consent_records 
                    WHERE data_subject_id = ? AND status = ?
                ''', (data_subject_id, ConsentStatus.GIVEN.value))
                
                consents = []
                for row in cursor.fetchall():
                    consent = ConsentRecord(
                        consent_id=row[0],
                        data_subject_id=row[1],
                        purpose=row[2],
                        data_categories=json.loads(row[3]),
                        lawful_basis=ProcessingLawfulBasis(row[4]),
                        status=ConsentStatus(row[5]),
                        given_at=datetime.fromisoformat(row[6]),
                        withdrawn_at=datetime.fromisoformat(row[7]) if row[7] else None,
                        expires_at=datetime.fromisoformat(row[8]) if row[8] else None,
                        consent_method=row[9],
                        consent_evidence=json.loads(row[10]) if row[10] else {}
                    )
                    
                    # Only return if still valid
                    if consent.is_valid():
                        consents.append(consent)
                
                return consents
                
        except Exception as e:
            self.logger.error(f"Error getting consents for {data_subject_id}: {e}")
            return []
    
    def has_consent_for_purpose(self, data_subject_id: str, purpose: str) -> bool:
        """Check if data subject has valid consent for specific purpose."""
        
        valid_consents = self.get_valid_consents(data_subject_id)
        return any(consent.purpose == purpose for consent in valid_consents)


class GDPRComplianceManager:
    """Main GDPR compliance management system."""
    
    def __init__(self, db_path: str = "gdpr_compliance.db"):
        """Initialize GDPR compliance manager."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.consent_manager = ConsentManager(db_path.replace('.db', '_consent.db'))
        
        # Request handlers
        self.request_handlers = {
            DataSubjectRightType.ACCESS: self._handle_access_request,
            DataSubjectRightType.RECTIFICATION: self._handle_rectification_request,
            DataSubjectRightType.ERASURE: self._handle_erasure_request,
            DataSubjectRightType.RESTRICT_PROCESSING: self._handle_restriction_request,
            DataSubjectRightType.DATA_PORTABILITY: self._handle_portability_request,
            DataSubjectRightType.OBJECT: self._handle_objection_request,
            DataSubjectRightType.WITHDRAW_CONSENT: self._handle_consent_withdrawal
        }
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize GDPR compliance database."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Data subject requests
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS data_subject_requests (
                        request_id TEXT PRIMARY KEY,
                        data_subject_id TEXT NOT NULL,
                        request_type TEXT NOT NULL,
                        description TEXT NOT NULL,
                        requested_data_categories TEXT,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT,
                        completed_at TEXT,
                        assigned_to TEXT,
                        processing_notes TEXT,
                        response_data TEXT,
                        response_format TEXT
                    )
                ''')
                
                # Processing records (Article 30)
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS processing_records (
                        record_id TEXT PRIMARY KEY,
                        controller_name TEXT NOT NULL,
                        purpose TEXT NOT NULL,
                        data_categories TEXT NOT NULL,
                        data_subject_categories TEXT NOT NULL,
                        lawful_basis TEXT NOT NULL,
                        recipients TEXT,
                        third_country_transfers TEXT,
                        retention_period TEXT,
                        security_measures TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT
                    )
                ''')
                
                # Privacy Impact Assessments
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS privacy_impact_assessments (
                        pia_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        data_categories TEXT NOT NULL,
                        processing_purposes TEXT NOT NULL,
                        risks_identified TEXT NOT NULL,
                        mitigation_measures TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        requires_consultation BOOLEAN NOT NULL,
                        conducted_by TEXT NOT NULL,
                        conducted_at TEXT NOT NULL,
                        reviewed_at TEXT
                    )
                ''')
                
                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_requests_subject ON data_subject_requests(data_subject_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_requests_status ON data_subject_requests(status)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing GDPR database: {e}")
            raise
    
    def submit_data_subject_request(self, 
                                  data_subject_id: str,
                                  request_type: DataSubjectRightType,
                                  description: str,
                                  requested_data_categories: Optional[List[str]] = None) -> str:
        """Submit a data subject request."""
        
        request_id = str(uuid.uuid4())
        
        request = DataSubjectRequest(
            request_id=request_id,
            data_subject_id=data_subject_id,
            request_type=request_type,
            description=description,
            requested_data_categories=requested_data_categories or []
        )
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO data_subject_requests 
                    (request_id, data_subject_id, request_type, description,
                     requested_data_categories, status, created_at, updated_at,
                     completed_at, assigned_to, processing_notes, response_data, response_format)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    request.request_id,
                    request.data_subject_id,
                    request.request_type.value,
                    request.description,
                    json.dumps(request.requested_data_categories),
                    request.status.value,
                    request.created_at.isoformat(),
                    request.updated_at.isoformat() if request.updated_at else None,
                    request.completed_at.isoformat() if request.completed_at else None,
                    request.assigned_to,
                    json.dumps(request.processing_notes),
                    json.dumps(request.response_data) if request.response_data else None,
                    request.response_format
                ))
                conn.commit()
            
            self.logger.info(f"Submitted data subject request: {request_id}")
            
            # Auto-process if possible
            self._auto_process_request(request)
            
            return request_id
            
        except Exception as e:
            self.logger.error(f"Error submitting data subject request: {e}")
            raise
    
    def _auto_process_request(self, request: DataSubjectRequest):
        """Automatically process request if possible."""
        
        try:
            handler = self.request_handlers.get(request.request_type)
            if handler:
                handler(request)
            
        except Exception as e:
            self.logger.error(f"Error auto-processing request {request.request_id}: {e}")
    
    def _handle_access_request(self, request: DataSubjectRequest):
        """Handle data access request (Article 15)."""
        
        try:
            # Collect all data for the subject
            collected_data = {
                'personal_data': self._collect_personal_data(request.data_subject_id),
                'processing_purposes': self._get_processing_purposes(request.data_subject_id),
                'data_categories': self._get_data_categories(request.data_subject_id),
                'recipients': self._get_data_recipients(request.data_subject_id),
                'retention_periods': self._get_retention_periods(request.data_subject_id),
                'rights_information': self._get_rights_information(),
                'consents': [c.to_dict() for c in self.consent_manager.get_valid_consents(request.data_subject_id)]
            }
            
            # Update request with response
            self._update_request_response(request.request_id, collected_data, RequestStatus.COMPLETED)
            
            self.logger.info(f"Processed access request: {request.request_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling access request {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    def _handle_erasure_request(self, request: DataSubjectRequest):
        """Handle data erasure request (Article 17 - Right to be forgotten)."""
        
        try:
            # Check if erasure is legally required
            if self._can_erase_data(request.data_subject_id):
                # Perform data erasure
                erased_data = self._erase_personal_data(request.data_subject_id)
                
                response_data = {
                    'erasure_completed': True,
                    'erased_data_categories': erased_data,
                    'erasure_date': datetime.now().isoformat()
                }
                
                self._update_request_response(request.request_id, response_data, RequestStatus.COMPLETED)
                self.logger.info(f"Processed erasure request: {request.request_id}")
            else:
                # Erasure not possible due to legal obligations
                response_data = {
                    'erasure_completed': False,
                    'reason': 'Legal obligations prevent erasure',
                    'retention_basis': 'Legal compliance requirements'
                }
                
                self._update_request_response(request.request_id, response_data, RequestStatus.REJECTED)
                
        except Exception as e:
            self.logger.error(f"Error handling erasure request {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    def _handle_rectification_request(self, request: DataSubjectRequest):
        """Handle data rectification request (Article 16)."""
        
        # For rectification, we need additional information from the user
        # This would typically require manual intervention
        
        request.add_note("Rectification request requires manual review for data accuracy verification")
        self._update_request_status(request.request_id, RequestStatus.IN_PROGRESS)
    
    def _handle_restriction_request(self, request: DataSubjectRequest):
        """Handle processing restriction request (Article 18)."""
        
        try:
            # Mark data for restricted processing
            self._restrict_data_processing(request.data_subject_id)
            
            response_data = {
                'processing_restricted': True,
                'restriction_date': datetime.now().isoformat(),
                'restricted_categories': request.requested_data_categories or ['all']
            }
            
            self._update_request_response(request.request_id, response_data, RequestStatus.COMPLETED)
            self.logger.info(f"Processed restriction request: {request.request_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling restriction request {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    def _handle_portability_request(self, request: DataSubjectRequest):
        """Handle data portability request (Article 20)."""
        
        try:
            # Export data in structured format
            portable_data = self._export_portable_data(request.data_subject_id)
            
            response_data = {
                'data_export': portable_data,
                'export_format': 'json',
                'export_date': datetime.now().isoformat()
            }
            
            self._update_request_response(request.request_id, response_data, RequestStatus.COMPLETED)
            self.logger.info(f"Processed portability request: {request.request_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling portability request {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    def _handle_objection_request(self, request: DataSubjectRequest):
        """Handle objection to processing request (Article 21)."""
        
        try:
            # Stop processing based on legitimate interests
            self._stop_legitimate_interest_processing(request.data_subject_id)
            
            response_data = {
                'objection_processed': True,
                'processing_stopped': True,
                'stop_date': datetime.now().isoformat()
            }
            
            self._update_request_response(request.request_id, response_data, RequestStatus.COMPLETED)
            self.logger.info(f"Processed objection request: {request.request_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling objection request {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    def _handle_consent_withdrawal(self, request: DataSubjectRequest):
        """Handle consent withdrawal request."""
        
        try:
            # Withdraw all consents for the data subject
            valid_consents = self.consent_manager.get_valid_consents(request.data_subject_id)
            
            withdrawn_consents = []
            for consent in valid_consents:
                if self.consent_manager.withdraw_consent(consent.consent_id):
                    withdrawn_consents.append(consent.consent_id)
            
            response_data = {
                'consent_withdrawn': True,
                'withdrawn_consents': withdrawn_consents,
                'withdrawal_date': datetime.now().isoformat()
            }
            
            self._update_request_response(request.request_id, response_data, RequestStatus.COMPLETED)
            self.logger.info(f"Processed consent withdrawal: {request.request_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling consent withdrawal {request.request_id}: {e}")
            self._update_request_status(request.request_id, RequestStatus.REJECTED)
    
    # Helper methods (simplified implementations)
    
    def _collect_personal_data(self, data_subject_id: str) -> Dict[str, Any]:
        """Collect all personal data for a data subject."""
        # This would integrate with actual data storage systems
        return {
            'user_profile': f"Profile data for {data_subject_id}",
            'analysis_history': f"Analysis history for {data_subject_id}",
            'audit_logs': f"Audit logs for {data_subject_id}"
        }
    
    def _get_processing_purposes(self, data_subject_id: str) -> List[str]:
        """Get processing purposes for data subject."""
        return ["Security analysis", "Compliance monitoring", "System improvement"]
    
    def _get_data_categories(self, data_subject_id: str) -> List[str]:
        """Get data categories for data subject."""
        return ["Identity data", "Usage data", "Technical data"]
    
    def _get_data_recipients(self, data_subject_id: str) -> List[str]:
        """Get data recipients for data subject."""
        return ["Internal security team", "Compliance officers"]
    
    def _get_retention_periods(self, data_subject_id: str) -> Dict[str, str]:
        """Get retention periods for data categories."""
        return {
            "Identity data": "3 years",
            "Usage data": "1 year",
            "Technical data": "2 years"
        }
    
    def _get_rights_information(self) -> Dict[str, str]:
        """Get information about data subject rights."""
        return {
            "access": "You have the right to access your personal data",
            "rectification": "You have the right to correct inaccurate data",
            "erasure": "You have the right to request deletion of your data",
            "restriction": "You have the right to restrict processing",
            "portability": "You have the right to receive your data in a portable format",
            "objection": "You have the right to object to processing"
        }
    
    def _can_erase_data(self, data_subject_id: str) -> bool:
        """Check if data can be erased (considering legal obligations)."""
        # This would check for legal retention requirements
        return True  # Simplified
    
    def _erase_personal_data(self, data_subject_id: str) -> List[str]:
        """Erase personal data for data subject."""
        # This would integrate with actual data storage systems
        return ["user_profile", "preferences", "non_essential_logs"]
    
    def _restrict_data_processing(self, data_subject_id: str):
        """Restrict processing for data subject."""
        # This would mark data as restricted in storage systems
        pass
    
    def _export_portable_data(self, data_subject_id: str) -> Dict[str, Any]:
        """Export data in portable format."""
        return self._collect_personal_data(data_subject_id)
    
    def _stop_legitimate_interest_processing(self, data_subject_id: str):
        """Stop processing based on legitimate interests."""
        # This would update processing flags in storage systems
        pass
    
    def _update_request_status(self, request_id: str, status: RequestStatus):
        """Update request status."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE data_subject_requests 
                    SET status = ?, updated_at = ?
                    WHERE request_id = ?
                ''', (status.value, datetime.now().isoformat(), request_id))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating request status: {e}")
    
    def _update_request_response(self, request_id: str, response_data: Dict[str, Any], status: RequestStatus):
        """Update request with response data."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE data_subject_requests 
                    SET response_data = ?, status = ?, updated_at = ?, completed_at = ?
                    WHERE request_id = ?
                ''', (
                    json.dumps(response_data),
                    status.value,
                    datetime.now().isoformat(),
                    datetime.now().isoformat() if status == RequestStatus.COMPLETED else None,
                    request_id
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating request response: {e}")
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get GDPR compliance dashboard data."""
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Request statistics
                cursor = conn.execute('''
                    SELECT request_type, status, COUNT(*) 
                    FROM data_subject_requests 
                    GROUP BY request_type, status
                ''')
                request_stats = {}
                for row in cursor.fetchall():
                    request_type, status, count = row
                    if request_type not in request_stats:
                        request_stats[request_type] = {}
                    request_stats[request_type][status] = count
                
                # Pending requests
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM data_subject_requests 
                    WHERE status IN (?, ?)
                ''', (RequestStatus.PENDING.value, RequestStatus.IN_PROGRESS.value))
                pending_requests = cursor.fetchone()[0]
                
                # Overdue requests (older than 30 days)
                thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM data_subject_requests 
                    WHERE status IN (?, ?) AND created_at < ?
                ''', (RequestStatus.PENDING.value, RequestStatus.IN_PROGRESS.value, thirty_days_ago))
                overdue_requests = cursor.fetchone()[0]
                
                return {
                    'request_statistics': request_stats,
                    'pending_requests': pending_requests,
                    'overdue_requests': overdue_requests,
                    'compliance_status': 'compliant' if overdue_requests == 0 else 'attention_required'
                }
                
        except Exception as e:
            self.logger.error(f"Error getting compliance dashboard: {e}")
            return {}


# Utility functions

def create_gdpr_manager(db_path: str = "gdpr_compliance.db") -> GDPRComplianceManager:
    """Create GDPR compliance manager."""
    return GDPRComplianceManager(db_path)


def submit_erasure_request(manager: GDPRComplianceManager, data_subject_id: str) -> str:
    """Quick function to submit erasure request."""
    return manager.submit_data_subject_request(
        data_subject_id=data_subject_id,
        request_type=DataSubjectRightType.ERASURE,
        description="Request for data erasure under GDPR Article 17"
    )