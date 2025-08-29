"""Security and privacy protection framework for Compliance Sentinel."""

from .code_anonymizer import (
    CodeAnonymizer, AnonymizationConfig, AnonymizationResult,
    IdentifierAnonymizer, CommentAnonymizer, StringAnonymizer
)
from .encrypted_storage import (
    EncryptedStorage, EncryptionConfig, StorageBackend,
    FileSystemBackend, DatabaseBackend, CloudStorageBackend
)
from .data_retention import (
    DataRetentionManager, RetentionPolicy, RetentionRule,
    DataClassification, RetentionAction
)
from .gdpr_compliance import (
    GDPRComplianceManager, DataSubjectRequest, ConsentManager,
    DataProcessingRecord, PrivacyImpactAssessment
)
from .audit_logger import (
    AuditLogger, AuditEvent, AuditLevel, AuditEventType,
    SecurityAuditLogger, PrivacyAuditLogger
)
from .threat_model import (
    ThreatModelValidator, ThreatModel, SecurityAssessment,
    ThreatCategory, RiskLevel, SecurityControl
)
from .secure_communication import (
    SecureCommunicationManager, CommunicationProtocol,
    TLSConfig, CertificateManager, MessageEncryption
)

__all__ = [
    # Code anonymization
    'CodeAnonymizer',
    'AnonymizationConfig',
    'AnonymizationResult',
    'IdentifierAnonymizer',
    'CommentAnonymizer',
    'StringAnonymizer',
    
    # Encrypted storage
    'EncryptedStorage',
    'EncryptionConfig',
    'StorageBackend',
    'FileSystemBackend',
    'DatabaseBackend',
    'CloudStorageBackend',
    
    # Data retention
    'DataRetentionManager',
    'RetentionPolicy',
    'RetentionRule',
    'DataClassification',
    'RetentionAction',
    
    # GDPR compliance
    'GDPRComplianceManager',
    'DataSubjectRequest',
    'ConsentManager',
    'DataProcessingRecord',
    'PrivacyImpactAssessment',
    
    # Audit logging
    'AuditLogger',
    'AuditEvent',
    'AuditLevel',
    'AuditEventType',
    'SecurityAuditLogger',
    'PrivacyAuditLogger',
    
    # Threat modeling
    'ThreatModelValidator',
    'ThreatModel',
    'SecurityAssessment',
    'ThreatCategory',
    'RiskLevel',
    'SecurityControl',
    
    # Secure communication
    'SecureCommunicationManager',
    'CommunicationProtocol',
    'TLSConfig',
    'CertificateManager',
    'MessageEncryption'
]