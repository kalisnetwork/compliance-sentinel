"""Compliance framework validation with regulatory requirement mapping."""

import logging
import re
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    SOC2_TYPE2 = "soc2_type2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    CIS_CONTROLS = "cis_controls"


class ComplianceStatus(Enum):
    """Compliance test status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    REQUIRES_REVIEW = "requires_review"


@dataclass
class ComplianceRequirement:
    """Represents a compliance requirement."""
    
    requirement_id: str
    framework: ComplianceFramework
    title: str
    description: str
    
    # Requirement details
    control_objective: str
    implementation_guidance: str
    evidence_required: List[str] = field(default_factory=list)
    
    # Testing
    test_procedures: List[str] = field(default_factory=list)
    automated_checks: List[str] = field(default_factory=list)
    
    # Metadata
    category: str = ""
    subcategory: str = ""
    risk_level: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert requirement to dictionary."""
        return {
            'requirement_id': self.requirement_id,
            'framework': self.framework.value,
            'title': self.title,
            'description': self.description,
            'control_objective': self.control_objective,
            'implementation_guidance': self.implementation_guidance,
            'evidence_required': self.evidence_required,
            'test_procedures': self.test_procedures,
            'automated_checks': self.automated_checks,
            'category': self.category,
            'subcategory': self.subcategory,
            'risk_level': self.risk_level
        }


@dataclass
class ComplianceTestResult:
    """Result of compliance requirement testing."""
    
    requirement_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    
    # Test details
    test_date: datetime = field(default_factory=datetime.now)
    tested_by: str = "automated"
    
    # Results
    findings: List[str] = field(default_factory=list)
    evidence_collected: List[str] = field(default_factory=list)
    
    # Issues
    security_issues: List[SecurityIssue] = field(default_factory=list)
    gaps_identified: List[str] = field(default_factory=list)
    
    # Recommendations
    remediation_steps: List[str] = field(default_factory=list)
    
    # Scoring
    compliance_score: float = 0.0  # 0-100
    risk_score: float = 0.0  # 0-10
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'requirement_id': self.requirement_id,
            'framework': self.framework.value,
            'status': self.status.value,
            'test_date': self.test_date.isoformat(),
            'tested_by': self.tested_by,
            'findings': self.findings,
            'evidence_collected': self.evidence_collected,
            'security_issues_count': len(self.security_issues),
            'gaps_identified': self.gaps_identified,
            'remediation_steps': self.remediation_steps,
            'compliance_score': self.compliance_score,
            'risk_score': self.risk_score
        }


class ComplianceValidator:
    """Base class for compliance framework validators."""
    
    def __init__(self, framework: ComplianceFramework):
        """Initialize compliance validator."""
        self.framework = framework
        self.logger = logging.getLogger(__name__)
        
        # Load requirements
        self.requirements = {}
        self.results = {}
        
        # Load framework-specific requirements
        self._load_requirements()
    
    def _load_requirements(self):
        """Load compliance requirements (to be implemented by subclasses)."""
        pass
    
    def add_requirement(self, requirement: ComplianceRequirement):
        """Add a compliance requirement."""
        self.requirements[requirement.requirement_id] = requirement
    
    def validate_requirement(self, 
                           requirement_id: str,
                           codebase_analyzer: Callable,
                           file_paths: List[str]) -> ComplianceTestResult:
        """Validate a specific compliance requirement."""
        if requirement_id not in self.requirements:
            return ComplianceTestResult(
                requirement_id=requirement_id,
                framework=self.framework,
                status=ComplianceStatus.NOT_APPLICABLE,
                findings=["Requirement not found"]
            )
        
        requirement = self.requirements[requirement_id]
        result = ComplianceTestResult(
            requirement_id=requirement_id,
            framework=self.framework,
            status=ComplianceStatus.REQUIRES_REVIEW
        )
        
        try:
            # Perform automated checks
            for check in requirement.automated_checks:
                check_result = self._perform_automated_check(
                    check, codebase_analyzer, file_paths
                )
                result.findings.extend(check_result['findings'])
                result.security_issues.extend(check_result['issues'])
            
            # Determine compliance status
            result.status = self._determine_compliance_status(result, requirement)
            
            # Calculate scores
            result.compliance_score = self._calculate_compliance_score(result, requirement)
            result.risk_score = self._calculate_risk_score(result, requirement)
            
            # Generate remediation steps
            result.remediation_steps = self._generate_remediation_steps(result, requirement)
            
            self.results[requirement_id] = result
            
        except Exception as e:
            self.logger.error(f"Error validating requirement {requirement_id}: {e}")
            result.status = ComplianceStatus.REQUIRES_REVIEW
            result.findings.append(f"Validation error: {str(e)}")
        
        return result
    
    def validate_all_requirements(self,
                                codebase_analyzer: Callable,
                                file_paths: List[str]) -> Dict[str, ComplianceTestResult]:
        """Validate all requirements in the framework."""
        results = {}
        
        for requirement_id in self.requirements:
            result = self.validate_requirement(requirement_id, codebase_analyzer, file_paths)
            results[requirement_id] = result
        
        return results
    
    def _perform_automated_check(self,
                                check: str,
                                codebase_analyzer: Callable,
                                file_paths: List[str]) -> Dict[str, Any]:
        """Perform an automated compliance check."""
        findings = []
        issues = []
        
        # Parse check specification
        check_parts = check.split(':')
        check_type = check_parts[0]
        check_params = check_parts[1:] if len(check_parts) > 1 else []
        
        if check_type == "security_scan":
            # Run security analysis on codebase
            for file_path in file_paths:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    file_issues = codebase_analyzer(content, file_path)
                    issues.extend(file_issues)
                    
                    if file_issues:
                        findings.append(f"Security issues found in {file_path}: {len(file_issues)} issues")
                
                except Exception as e:
                    findings.append(f"Error analyzing {file_path}: {str(e)}")
        
        elif check_type == "pattern_search":
            # Search for specific patterns in code
            if check_params:
                pattern = check_params[0]
                findings.extend(self._search_pattern_in_files(pattern, file_paths))
        
        elif check_type == "configuration_check":
            # Check configuration files
            if check_params:
                config_type = check_params[0]
                findings.extend(self._check_configuration(config_type, file_paths))
        
        return {
            'findings': findings,
            'issues': issues
        }
    
    def _search_pattern_in_files(self, pattern: str, file_paths: List[str]) -> List[str]:
        """Search for pattern in files."""
        findings = []
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            
            for file_path in file_paths:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    matches = regex.findall(content)
                    if matches:
                        findings.append(f"Pattern '{pattern}' found in {file_path}: {len(matches)} matches")
                
                except Exception as e:
                    findings.append(f"Error searching {file_path}: {str(e)}")
        
        except re.error as e:
            findings.append(f"Invalid regex pattern '{pattern}': {str(e)}")
        
        return findings
    
    def _check_configuration(self, config_type: str, file_paths: List[str]) -> List[str]:
        """Check configuration files for compliance."""
        findings = []
        
        config_files = {
            'ssl_tls': ['*.conf', '*.config', 'nginx.conf', 'apache.conf'],
            'database': ['*.sql', '*.db', 'database.yml'],
            'authentication': ['auth.config', 'security.xml', 'web.config'],
            'logging': ['log4j.properties', 'logback.xml', 'logging.conf']
        }
        
        if config_type in config_files:
            patterns = config_files[config_type]
            
            for file_path in file_paths:
                for pattern in patterns:
                    if pattern.replace('*', '') in file_path.lower():
                        findings.append(f"Configuration file found: {file_path}")
                        # Additional configuration-specific checks would go here
        
        return findings
    
    def _determine_compliance_status(self,
                                   result: ComplianceTestResult,
                                   requirement: ComplianceRequirement) -> ComplianceStatus:
        """Determine compliance status based on test results."""
        # Count security issues by severity
        critical_issues = sum(1 for issue in result.security_issues if issue.severity == Severity.CRITICAL)
        high_issues = sum(1 for issue in result.security_issues if issue.severity == Severity.HIGH)
        
        # Determine status based on issues found
        if critical_issues > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif high_issues > 2:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        elif high_issues > 0 or len(result.gaps_identified) > 0:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        elif len(result.security_issues) == 0 and len(result.findings) == 0:
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.REQUIRES_REVIEW
    
    def _calculate_compliance_score(self,
                                  result: ComplianceTestResult,
                                  requirement: ComplianceRequirement) -> float:
        """Calculate compliance score (0-100)."""
        base_score = 100.0
        
        # Deduct points for security issues
        for issue in result.security_issues:
            if issue.severity == Severity.CRITICAL:
                base_score -= 25
            elif issue.severity == Severity.HIGH:
                base_score -= 15
            elif issue.severity == Severity.MEDIUM:
                base_score -= 10
            elif issue.severity == Severity.LOW:
                base_score -= 5
        
        # Deduct points for gaps
        base_score -= len(result.gaps_identified) * 10
        
        return max(0.0, base_score)
    
    def _calculate_risk_score(self,
                            result: ComplianceTestResult,
                            requirement: ComplianceRequirement) -> float:
        """Calculate risk score (0-10)."""
        risk_score = 0.0
        
        # Add risk based on security issues
        for issue in result.security_issues:
            if issue.severity == Severity.CRITICAL:
                risk_score += 3.0
            elif issue.severity == Severity.HIGH:
                risk_score += 2.0
            elif issue.severity == Severity.MEDIUM:
                risk_score += 1.0
            elif issue.severity == Severity.LOW:
                risk_score += 0.5
        
        # Add risk based on requirement risk level
        risk_multipliers = {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8
        }
        
        multiplier = risk_multipliers.get(requirement.risk_level, 1.0)
        risk_score *= multiplier
        
        return min(10.0, risk_score)
    
    def _generate_remediation_steps(self,
                                  result: ComplianceTestResult,
                                  requirement: ComplianceRequirement) -> List[str]:
        """Generate remediation steps based on findings."""
        steps = []
        
        # Generic remediation based on status
        if result.status == ComplianceStatus.NON_COMPLIANT:
            steps.append("Immediate action required to address critical compliance gaps")
            steps.append("Review and implement security controls as specified in requirement")
        
        elif result.status == ComplianceStatus.PARTIALLY_COMPLIANT:
            steps.append("Address identified security issues and gaps")
            steps.append("Implement additional controls to achieve full compliance")
        
        # Specific remediation based on security issues
        issue_types = set(issue.category for issue in result.security_issues)
        
        for issue_type in issue_types:
            if issue_type == "authentication":
                steps.append("Implement strong authentication mechanisms")
            elif issue_type == "encryption":
                steps.append("Implement proper encryption for data at rest and in transit")
            elif issue_type == "access_control":
                steps.append("Review and strengthen access control mechanisms")
            elif issue_type == "logging":
                steps.append("Implement comprehensive logging and monitoring")
        
        return steps
    
    def get_framework_summary(self) -> Dict[str, Any]:
        """Get summary of framework validation results."""
        if not self.results:
            return {
                'framework': self.framework.value,
                'total_requirements': len(self.requirements),
                'tested_requirements': 0
            }
        
        total_requirements = len(self.requirements)
        tested_requirements = len(self.results)
        
        # Count by status
        status_counts = {}
        for status in ComplianceStatus:
            status_counts[status.value] = sum(
                1 for result in self.results.values() 
                if result.status == status
            )
        
        # Calculate overall scores
        compliance_scores = [r.compliance_score for r in self.results.values()]
        risk_scores = [r.risk_score for r in self.results.values()]
        
        avg_compliance = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            'framework': self.framework.value,
            'total_requirements': total_requirements,
            'tested_requirements': tested_requirements,
            'status_counts': status_counts,
            'average_compliance_score': avg_compliance,
            'average_risk_score': avg_risk,
            'compliant_percentage': (status_counts.get('compliant', 0) / tested_requirements * 100) if tested_requirements > 0 else 0
        }


class SOC2Validator(ComplianceValidator):
    """SOC 2 Type II compliance validator."""
    
    def __init__(self):
        """Initialize SOC 2 validator."""
        super().__init__(ComplianceFramework.SOC2_TYPE2)
    
    def _load_requirements(self):
        """Load SOC 2 Type II requirements."""
        
        # Security - Access Controls
        self.add_requirement(ComplianceRequirement(
            requirement_id="CC6.1",
            framework=ComplianceFramework.SOC2_TYPE2,
            title="Logical and Physical Access Controls",
            description="The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.",
            control_objective="Restrict logical and physical access to system resources to authorized users",
            implementation_guidance="Implement authentication mechanisms, access control lists, and physical security controls",
            evidence_required=["Access control policies", "Authentication logs", "Physical security documentation"],
            test_procedures=["Review access control configurations", "Test authentication mechanisms"],
            automated_checks=["security_scan", "pattern_search:password|authentication|access"],
            category="Security",
            subcategory="Access Controls",
            risk_level="high"
        ))
        
        # Security - System Operations
        self.add_requirement(ComplianceRequirement(
            requirement_id="CC6.2",
            framework=ComplianceFramework.SOC2_TYPE2,
            title="System Operations Controls",
            description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
            control_objective="Ensure proper user registration and authorization processes",
            implementation_guidance="Implement user provisioning workflows and approval processes",
            evidence_required=["User provisioning procedures", "Access approval records"],
            test_procedures=["Review user registration process", "Test access approval workflows"],
            automated_checks=["security_scan", "pattern_search:user.*registration|provisioning"],
            category="Security",
            subcategory="User Management",
            risk_level="high"
        ))
        
        # Security - Data Protection
        self.add_requirement(ComplianceRequirement(
            requirement_id="CC6.7",
            framework=ComplianceFramework.SOC2_TYPE2,
            title="Data Transmission and Disposal",
            description="The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
            control_objective="Protect data during transmission and ensure secure disposal",
            implementation_guidance="Implement encryption for data in transit and secure data disposal procedures",
            evidence_required=["Encryption policies", "Data disposal procedures", "Transmission logs"],
            test_procedures=["Verify encryption implementation", "Test data disposal processes"],
            automated_checks=["security_scan", "pattern_search:encrypt|ssl|tls", "configuration_check:ssl_tls"],
            category="Security",
            subcategory="Data Protection",
            risk_level="critical"
        ))


class PCIDSSValidator(ComplianceValidator):
    """PCI DSS compliance validator."""
    
    def __init__(self):
        """Initialize PCI DSS validator."""
        super().__init__(ComplianceFramework.PCI_DSS)
    
    def _load_requirements(self):
        """Load PCI DSS requirements."""
        
        # Requirement 2: Do not use vendor-supplied defaults
        self.add_requirement(ComplianceRequirement(
            requirement_id="PCI_2.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Change Vendor-Supplied Defaults",
            description="Always change vendor-supplied defaults and remove or disable unnecessary default accounts before installing a system on the network.",
            control_objective="Eliminate default credentials and unnecessary accounts",
            implementation_guidance="Change all default passwords, remove default accounts, disable unnecessary services",
            evidence_required=["System hardening procedures", "Default account inventory"],
            test_procedures=["Scan for default credentials", "Review account configurations"],
            automated_checks=["security_scan", "pattern_search:default.*password|admin.*admin"],
            category="System Hardening",
            subcategory="Default Credentials",
            risk_level="high"
        ))
        
        # Requirement 3: Protect stored cardholder data
        self.add_requirement(ComplianceRequirement(
            requirement_id="PCI_3.4",
            framework=ComplianceFramework.PCI_DSS,
            title="Protect Cardholder Data",
            description="Render PAN unreadable anywhere it is stored by using strong cryptography and security protocols.",
            control_objective="Encrypt cardholder data at rest",
            implementation_guidance="Use strong encryption algorithms (AES-256) for stored cardholder data",
            evidence_required=["Encryption implementation", "Key management procedures"],
            test_procedures=["Verify encryption strength", "Test key management"],
            automated_checks=["security_scan", "pattern_search:credit.*card|pan|cardholder", "configuration_check:database"],
            category="Data Protection",
            subcategory="Encryption",
            risk_level="critical"
        ))
        
        # Requirement 6: Develop and maintain secure systems
        self.add_requirement(ComplianceRequirement(
            requirement_id="PCI_6.5.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Injection Flaws",
            description="Address common vulnerabilities in public-facing web applications, particularly injection flaws such as SQL injection.",
            control_objective="Prevent injection attacks in web applications",
            implementation_guidance="Use parameterized queries, input validation, and output encoding",
            evidence_required=["Secure coding standards", "Code review results", "Vulnerability scan reports"],
            test_procedures=["Code review for injection flaws", "Dynamic application testing"],
            automated_checks=["security_scan"],
            category="Application Security",
            subcategory="Injection Prevention",
            risk_level="critical"
        ))


class HIPAAValidator(ComplianceValidator):
    """HIPAA compliance validator."""
    
    def __init__(self):
        """Initialize HIPAA validator."""
        super().__init__(ComplianceFramework.HIPAA)
    
    def _load_requirements(self):
        """Load HIPAA requirements."""
        
        # Administrative Safeguards
        self.add_requirement(ComplianceRequirement(
            requirement_id="HIPAA_164.308_a_1",
            framework=ComplianceFramework.HIPAA,
            title="Security Officer",
            description="Assign security responsibilities to an individual, and conduct periodic security evaluations.",
            control_objective="Establish security governance and oversight",
            implementation_guidance="Designate a security officer and implement regular security assessments",
            evidence_required=["Security officer designation", "Security assessment reports"],
            test_procedures=["Verify security officer role", "Review assessment procedures"],
            automated_checks=["pattern_search:security.*officer|privacy.*officer"],
            category="Administrative Safeguards",
            subcategory="Security Management",
            risk_level="medium"
        ))
        
        # Physical Safeguards
        self.add_requirement(ComplianceRequirement(
            requirement_id="HIPAA_164.310_a_1",
            framework=ComplianceFramework.HIPAA,
            title="Facility Access Controls",
            description="Implement procedures to control physical access to facilities while ensuring appropriate access is allowed.",
            control_objective="Control physical access to systems containing PHI",
            implementation_guidance="Implement physical access controls, visitor management, and facility monitoring",
            evidence_required=["Physical security procedures", "Access logs", "Facility monitoring records"],
            test_procedures=["Review physical access controls", "Test facility security"],
            automated_checks=["pattern_search:physical.*access|facility.*security"],
            category="Physical Safeguards",
            subcategory="Facility Access",
            risk_level="high"
        ))
        
        # Technical Safeguards
        self.add_requirement(ComplianceRequirement(
            requirement_id="HIPAA_164.312_a_1",
            framework=ComplianceFramework.HIPAA,
            title="Access Control",
            description="Implement technical policies and procedures for electronic information systems that maintain electronic protected health information.",
            control_objective="Control access to electronic PHI",
            implementation_guidance="Implement user authentication, authorization, and access logging",
            evidence_required=["Access control policies", "Authentication systems", "Access logs"],
            test_procedures=["Test access controls", "Review authentication mechanisms"],
            automated_checks=["security_scan", "pattern_search:phi|protected.*health|medical.*record"],
            category="Technical Safeguards",
            subcategory="Access Control",
            risk_level="critical"
        ))


class GDPRValidator(ComplianceValidator):
    """GDPR compliance validator."""
    
    def __init__(self):
        """Initialize GDPR validator."""
        super().__init__(ComplianceFramework.GDPR)
    
    def _load_requirements(self):
        """Load GDPR requirements."""
        
        # Article 25: Data protection by design and by default
        self.add_requirement(ComplianceRequirement(
            requirement_id="GDPR_Art25",
            framework=ComplianceFramework.GDPR,
            title="Data Protection by Design and by Default",
            description="Implement appropriate technical and organizational measures to ensure data protection principles are integrated into processing activities.",
            control_objective="Embed privacy protection into system design",
            implementation_guidance="Implement privacy-by-design principles, data minimization, and purpose limitation",
            evidence_required=["Privacy impact assessments", "System design documentation"],
            test_procedures=["Review system architecture for privacy controls", "Verify data minimization"],
            automated_checks=["security_scan", "pattern_search:personal.*data|gdpr|privacy"],
            category="Data Protection",
            subcategory="Privacy by Design",
            risk_level="high"
        ))
        
        # Article 32: Security of processing
        self.add_requirement(ComplianceRequirement(
            requirement_id="GDPR_Art32",
            framework=ComplianceFramework.GDPR,
            title="Security of Processing",
            description="Implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.",
            control_objective="Secure personal data processing",
            implementation_guidance="Implement encryption, access controls, and security monitoring",
            evidence_required=["Security measures documentation", "Risk assessments"],
            test_procedures=["Verify security controls", "Test encryption implementation"],
            automated_checks=["security_scan", "pattern_search:encrypt|pseudonymization", "configuration_check:ssl_tls"],
            category="Security Measures",
            subcategory="Technical Safeguards",
            risk_level="critical"
        ))
        
        # Article 33: Notification of data breach
        self.add_requirement(ComplianceRequirement(
            requirement_id="GDPR_Art33",
            framework=ComplianceFramework.GDPR,
            title="Data Breach Notification",
            description="Notify the supervisory authority of a personal data breach within 72 hours of becoming aware of it.",
            control_objective="Ensure timely breach notification",
            implementation_guidance="Implement breach detection and notification procedures",
            evidence_required=["Breach response procedures", "Notification templates"],
            test_procedures=["Review breach response plan", "Test notification procedures"],
            automated_checks=["pattern_search:breach.*notification|incident.*response", "configuration_check:logging"],
            category="Incident Response",
            subcategory="Breach Notification",
            risk_level="high"
        ))


class ISO27001Validator(ComplianceValidator):
    """ISO 27001 compliance validator."""
    
    def __init__(self):
        """Initialize ISO 27001 validator."""
        super().__init__(ComplianceFramework.ISO27001)
    
    def _load_requirements(self):
        """Load ISO 27001 requirements."""
        
        # A.9.1.1 Access control policy
        self.add_requirement(ComplianceRequirement(
            requirement_id="ISO_A.9.1.1",
            framework=ComplianceFramework.ISO27001,
            title="Access Control Policy",
            description="An access control policy shall be established, documented and reviewed based on business and information security requirements.",
            control_objective="Establish comprehensive access control governance",
            implementation_guidance="Develop and maintain access control policies aligned with business requirements",
            evidence_required=["Access control policy", "Policy review records"],
            test_procedures=["Review access control policy", "Verify policy implementation"],
            automated_checks=["security_scan", "pattern_search:access.*control.*policy"],
            category="Access Control",
            subcategory="Policy",
            risk_level="medium"
        ))
        
        # A.10.1.1 Cryptographic controls policy
        self.add_requirement(ComplianceRequirement(
            requirement_id="ISO_A.10.1.1",
            framework=ComplianceFramework.ISO27001,
            title="Cryptographic Controls Policy",
            description="A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
            control_objective="Establish cryptographic governance and standards",
            implementation_guidance="Develop cryptographic policies covering key management, algorithms, and implementation",
            evidence_required=["Cryptographic policy", "Key management procedures"],
            test_procedures=["Review cryptographic policy", "Verify implementation standards"],
            automated_checks=["security_scan", "pattern_search:crypto|encryption|key.*management"],
            category="Cryptography",
            subcategory="Policy",
            risk_level="high"
        ))
        
        # A.12.6.1 Management of technical vulnerabilities
        self.add_requirement(ComplianceRequirement(
            requirement_id="ISO_A.12.6.1",
            framework=ComplianceFramework.ISO27001,
            title="Management of Technical Vulnerabilities",
            description="Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion.",
            control_objective="Establish vulnerability management processes",
            implementation_guidance="Implement vulnerability scanning, assessment, and remediation processes",
            evidence_required=["Vulnerability management procedures", "Scan reports", "Remediation records"],
            test_procedures=["Review vulnerability management process", "Verify scanning coverage"],
            automated_checks=["security_scan"],
            category="Vulnerability Management",
            subcategory="Technical Vulnerabilities",
            risk_level="high"
        ))


# Utility functions for compliance validation

def validate_multiple_frameworks(codebase_analyzer: Callable,
                               file_paths: List[str],
                               frameworks: List[ComplianceFramework]) -> Dict[str, Dict[str, ComplianceTestResult]]:
    """Validate against multiple compliance frameworks."""
    results = {}
    
    validators = {
        ComplianceFramework.SOC2_TYPE2: SOC2Validator(),
        ComplianceFramework.PCI_DSS: PCIDSSValidator(),
        ComplianceFramework.HIPAA: HIPAAValidator(),
        ComplianceFramework.GDPR: GDPRValidator(),
        ComplianceFramework.ISO27001: ISO27001Validator()
    }
    
    for framework in frameworks:
        if framework in validators:
            validator = validators[framework]
            framework_results = validator.validate_all_requirements(codebase_analyzer, file_paths)
            results[framework.value] = framework_results
    
    return results


def generate_compliance_report(validator: ComplianceValidator) -> str:
    """Generate a comprehensive compliance report."""
    summary = validator.get_framework_summary()
    
    report = f"""
# {summary['framework'].upper()} Compliance Report

## Executive Summary
- **Framework**: {summary['framework'].upper()}
- **Total Requirements**: {summary['total_requirements']}
- **Requirements Tested**: {summary['tested_requirements']}
- **Compliance Percentage**: {summary['compliant_percentage']:.1f}%
- **Average Compliance Score**: {summary['average_compliance_score']:.1f}/100
- **Average Risk Score**: {summary['average_risk_score']:.1f}/10

## Status Distribution
"""
    
    for status, count in summary['status_counts'].items():
        percentage = (count / summary['tested_requirements'] * 100) if summary['tested_requirements'] > 0 else 0
        report += f"- **{status.replace('_', ' ').title()}**: {count} ({percentage:.1f}%)\n"
    
    report += "\n## Detailed Results\n"
    
    for req_id, result in validator.results.items():
        requirement = validator.requirements[req_id]
        
        report += f"""
### {req_id}: {requirement.title}
- **Status**: {result.status.value.replace('_', ' ').title()}
- **Compliance Score**: {result.compliance_score:.1f}/100
- **Risk Score**: {result.risk_score:.1f}/10
- **Security Issues**: {len(result.security_issues)}
- **Gaps Identified**: {len(result.gaps_identified)}

"""
        
        if result.findings:
            report += "**Key Findings**:\n"
            for finding in result.findings[:3]:  # Show top 3 findings
                report += f"- {finding}\n"
        
        if result.remediation_steps:
            report += "**Remediation Steps**:\n"
            for step in result.remediation_steps[:3]:  # Show top 3 steps
                report += f"- {step}\n"
        
        report += "\n"
    
    return report


def create_compliance_dashboard_data(validators: Dict[str, ComplianceValidator]) -> Dict[str, Any]:
    """Create data for compliance dashboard visualization."""
    dashboard_data = {
        'frameworks': [],
        'overall_compliance': 0.0,
        'total_requirements': 0,
        'compliant_requirements': 0,
        'high_risk_items': 0
    }
    
    total_score = 0.0
    framework_count = 0
    
    for framework_name, validator in validators.items():
        summary = validator.get_framework_summary()
        
        framework_data = {
            'name': framework_name,
            'compliance_percentage': summary['compliant_percentage'],
            'average_score': summary['average_compliance_score'],
            'risk_score': summary['average_risk_score'],
            'status_counts': summary['status_counts']
        }
        
        dashboard_data['frameworks'].append(framework_data)
        
        # Aggregate totals
        total_score += summary['average_compliance_score']
        framework_count += 1
        dashboard_data['total_requirements'] += summary['total_requirements']
        dashboard_data['compliant_requirements'] += summary['status_counts'].get('compliant', 0)
        
        # Count high-risk items
        for result in validator.results.values():
            if result.risk_score >= 7.0:
                dashboard_data['high_risk_items'] += 1
    
    # Calculate overall compliance
    if framework_count > 0:
        dashboard_data['overall_compliance'] = total_score / framework_count
    
    return dashboard_data