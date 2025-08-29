"""Threat model validation with security assessment procedures."""

import logging
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ThreatCategory(Enum):
    """Categories of security threats."""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class RiskLevel(Enum):
    """Risk levels for threats."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class SecurityControl:
    """Security control implementation."""
    
    control_id: str
    name: str
    description: str
    control_type: str  # preventive, detective, corrective
    implementation_status: str = "planned"
    effectiveness: float = 0.0  # 0-1 scale
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'control_id': self.control_id,
            'name': self.name,
            'description': self.description,
            'control_type': self.control_type,
            'implementation_status': self.implementation_status,
            'effectiveness': self.effectiveness
        }


@dataclass
class ThreatModel:
    """Threat model for security assessment."""
    
    model_id: str
    name: str
    description: str
    
    # Threats and controls
    threats: List[Dict[str, Any]] = field(default_factory=list)
    controls: List[SecurityControl] = field(default_factory=list)
    
    # Assessment results
    overall_risk_level: RiskLevel = RiskLevel.MEDIUM
    residual_risk: float = 0.5  # 0-1 scale
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: Optional[datetime] = None
    
    def add_threat(self, threat_id: str, category: ThreatCategory, description: str, 
                   likelihood: float, impact: float):
        """Add threat to model."""
        
        risk_score = likelihood * impact
        
        if risk_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NEGLIGIBLE
        
        threat = {
            'threat_id': threat_id,
            'category': category.value,
            'description': description,
            'likelihood': likelihood,
            'impact': impact,
            'risk_score': risk_score,
            'risk_level': risk_level.value
        }
        
        self.threats.append(threat)
        self.last_updated = datetime.now()
    
    def add_control(self, control: SecurityControl):
        """Add security control."""
        self.controls.append(control)
        self.last_updated = datetime.now()
    
    def calculate_residual_risk(self) -> float:
        """Calculate residual risk after controls."""
        
        if not self.threats:
            return 0.0
        
        total_risk = sum(threat['risk_score'] for threat in self.threats)
        
        # Apply control effectiveness
        control_effectiveness = sum(control.effectiveness for control in self.controls) / len(self.controls) if self.controls else 0
        
        residual_risk = total_risk * (1 - control_effectiveness)
        self.residual_risk = min(residual_risk / len(self.threats), 1.0)
        
        return self.residual_risk


class ThreatModelValidator:
    """Validates threat models and security assessments."""
    
    def __init__(self):
        """Initialize threat model validator."""
        self.logger = logging.getLogger(__name__)
        self.models = {}
    
    def create_compliance_sentinel_model(self) -> ThreatModel:
        """Create threat model for Compliance Sentinel."""
        
        model = ThreatModel(
            model_id="compliance_sentinel_v1",
            name="Compliance Sentinel Threat Model",
            description="Security threat model for Compliance Sentinel system"
        )
        
        # Add common threats
        model.add_threat(
            "T001", ThreatCategory.INFORMATION_DISCLOSURE,
            "Unauthorized access to source code analysis results", 0.6, 0.8
        )
        
        model.add_threat(
            "T002", ThreatCategory.TAMPERING,
            "Modification of security analysis results", 0.4, 0.9
        )
        
        model.add_threat(
            "T003", ThreatCategory.ELEVATION_OF_PRIVILEGE,
            "Privilege escalation in analysis engine", 0.3, 0.8
        )
        
        # Add security controls
        model.add_control(SecurityControl(
            "C001", "Encrypted Storage", "All analysis results encrypted at rest",
            "preventive", "implemented", 0.9
        ))
        
        model.add_control(SecurityControl(
            "C002", "Access Control", "Role-based access control for all data",
            "preventive", "implemented", 0.8
        ))
        
        model.add_control(SecurityControl(
            "C003", "Audit Logging", "Comprehensive audit logging of all actions",
            "detective", "implemented", 0.7
        ))
        
        # Calculate residual risk
        model.calculate_residual_risk()
        
        self.models[model.model_id] = model
        return model
    
    def validate_model(self, model: ThreatModel) -> Dict[str, Any]:
        """Validate threat model completeness."""
        
        validation_results = {
            'is_valid': True,
            'issues': [],
            'recommendations': [],
            'completeness_score': 0.0
        }
        
        # Check threat coverage
        threat_categories = set(threat['category'] for threat in model.threats)
        missing_categories = set(cat.value for cat in ThreatCategory) - threat_categories
        
        if missing_categories:
            validation_results['issues'].append(f"Missing threat categories: {missing_categories}")
            validation_results['recommendations'].append("Consider threats from all STRIDE categories")
        
        # Check control coverage
        if len(model.controls) < 3:
            validation_results['issues'].append("Insufficient security controls")
            validation_results['recommendations'].append("Implement additional security controls")
        
        # Check risk levels
        high_risk_threats = [t for t in model.threats if t['risk_level'] in ['critical', 'high']]
        if high_risk_threats and not model.controls:
            validation_results['issues'].append("High-risk threats without controls")
            validation_results['is_valid'] = False
        
        # Calculate completeness score
        category_coverage = len(threat_categories) / len(ThreatCategory)
        control_coverage = min(len(model.controls) / 5, 1.0)  # Assume 5 controls is good coverage
        validation_results['completeness_score'] = (category_coverage + control_coverage) / 2
        
        return validation_results


@dataclass
class SecurityAssessment:
    """Security assessment results."""
    
    assessment_id: str
    target_system: str
    
    # Assessment results
    threat_model: ThreatModel
    validation_results: Dict[str, Any]
    
    # Recommendations
    priority_actions: List[str] = field(default_factory=list)
    
    # Metadata
    conducted_at: datetime = field(default_factory=datetime.now)
    conducted_by: str = "system"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'assessment_id': self.assessment_id,
            'target_system': self.target_system,
            'overall_risk_level': self.threat_model.overall_risk_level.value,
            'residual_risk': self.threat_model.residual_risk,
            'threat_count': len(self.threat_model.threats),
            'control_count': len(self.threat_model.controls),
            'validation_score': self.validation_results.get('completeness_score', 0),
            'priority_actions': self.priority_actions,
            'conducted_at': self.conducted_at.isoformat(),
            'conducted_by': self.conducted_by
        }