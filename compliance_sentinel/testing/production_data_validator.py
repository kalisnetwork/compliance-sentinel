"""Production data validator for ensuring data quality and security in production environments."""

import logging
import asyncio
import time
import hashlib
import json
from typing import Dict, List, Optional, Any, Set, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
import os
from pathlib import Path

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, AnalysisResult


logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Production validation levels."""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


class DataSensitivity(Enum):
    """Data sensitivity levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ValidationStatus(Enum):
    """Validation status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ProductionValidationRule:
    """Represents a production validation rule."""
    
    rule_id: str
    name: str
    description: str
    
    # Rule configuration
    validation_level: ValidationLevel
    data_sensitivity: DataSensitivity
    
    # Rule logic
    pattern: Optional[str] = None
    validator_function: Optional[Callable] = None
    
    # Thresholds
    max_violations: int = 0
    severity: Severity = Severity.MEDIUM
    
    # Metadata
    tags: Set[str] = field(default_factory=set)
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'validation_level': self.validation_level.value,
            'data_sensitivity': self.data_sensitivity.value,
            'pattern': self.pattern,
            'max_violations': self.max_violations,
            'severity': self.severity.value,
            'tags': list(self.tags),
            'enabled': self.enabled
        }


@dataclass
class ValidationResult:
    """Result of production data validation."""
    
    rule_id: str
    rule_name: str
    status: ValidationStatus
    
    # Validation details
    validated_at: datetime = field(default_factory=datetime.now)
    validation_time_ms: float = 0.0
    
    # Results
    violations_found: int = 0
    violations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Data metrics
    data_processed: int = 0
    data_size_bytes: int = 0
    
    # Issues
    security_issues: List[SecurityIssue] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Error information
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'status': self.status.value,
            'validated_at': self.validated_at.isoformat(),
            'validation_time_ms': self.validation_time_ms,
            'violations_found': self.violations_found,
            'data_processed': self.data_processed,
            'data_size_bytes': self.data_size_bytes,
            'security_issues_count': len(self.security_issues),
            'recommendations_count': len(self.recommendations),
            'error_message': self.error_message
        }


class ProductionDataValidator:
    """Main production data validation framework."""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STANDARD):
        """Initialize production data validator."""
        self.logger = logging.getLogger(__name__)
        self.validation_level = validation_level
        
        # Validation rules
        self.rules = {}
        self.results = {}
        
        # Configuration
        self.max_file_size_mb = 100
        self.max_validation_time_seconds = 300
        self.enable_sampling = True
        self.sample_rate = 0.1  # 10% sampling for large datasets
        
        # Load built-in rules
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """Load built-in production validation rules."""
        
        # PII Detection Rules
        self._add_pii_detection_rules()
        
        # Security Pattern Rules
        self._add_security_pattern_rules()
        
        # Data Quality Rules
        self._add_data_quality_rules()
        
        # Compliance Rules
        self._add_compliance_rules()
        
        # Performance Rules
        self._add_performance_rules()
    
    def _add_pii_detection_rules(self):
        """Add PII detection rules."""
        
        # Social Security Number detection
        self.add_rule(ProductionValidationRule(
            rule_id="pii_ssn_detection",
            name="Social Security Number Detection",
            description="Detect Social Security Numbers in production data",
            validation_level=ValidationLevel.BASIC,
            data_sensitivity=DataSensitivity.RESTRICTED,
            pattern=r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
            max_violations=0,
            severity=Severity.CRITICAL,
            tags={"pii", "ssn", "privacy"}
        ))
        
        # Credit card number detection
        self.add_rule(ProductionValidationRule(
            rule_id="pii_credit_card_detection",
            name="Credit Card Number Detection",
            description="Detect credit card numbers in production data",
            validation_level=ValidationLevel.BASIC,
            data_sensitivity=DataSensitivity.RESTRICTED,
            pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            max_violations=0,
            severity=Severity.CRITICAL,
            tags={"pii", "credit_card", "financial"}
        ))
        
        # Email address detection
        self.add_rule(ProductionValidationRule(
            rule_id="pii_email_detection",
            name="Email Address Detection",
            description="Detect email addresses in production data",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            max_violations=10,  # Allow some emails in logs
            severity=Severity.MEDIUM,
            tags={"pii", "email", "contact"}
        ))
        
        # Phone number detection
        self.add_rule(ProductionValidationRule(
            rule_id="pii_phone_detection",
            name="Phone Number Detection",
            description="Detect phone numbers in production data",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            pattern=r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            max_violations=5,
            severity=Severity.MEDIUM,
            tags={"pii", "phone", "contact"}
        ))
    
    def _add_security_pattern_rules(self):
        """Add security pattern detection rules."""
        
        # API key detection
        self.add_rule(ProductionValidationRule(
            rule_id="security_api_key_detection",
            name="API Key Detection",
            description="Detect API keys in production data",
            validation_level=ValidationLevel.BASIC,
            data_sensitivity=DataSensitivity.RESTRICTED,
            pattern=r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\s]*[:=][\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            max_violations=0,
            severity=Severity.CRITICAL,
            tags={"security", "api_key", "secrets"}
        ))
        
        # Password detection
        self.add_rule(ProductionValidationRule(
            rule_id="security_password_detection",
            name="Password Detection",
            description="Detect passwords in production data",
            validation_level=ValidationLevel.BASIC,
            data_sensitivity=DataSensitivity.RESTRICTED,
            pattern=r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*["\']?([^\s"\']{6,})["\']?',
            max_violations=0,
            severity=Severity.HIGH,
            tags={"security", "password", "credentials"}
        ))
        
        # Database connection string detection
        self.add_rule(ProductionValidationRule(
            rule_id="security_db_connection_detection",
            name="Database Connection String Detection",
            description="Detect database connection strings in production data",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.RESTRICTED,
            pattern=r'(?i)(mongodb|mysql|postgresql|oracle|sqlserver)://[^\s]+',
            max_violations=0,
            severity=Severity.HIGH,
            tags={"security", "database", "connection_string"}
        ))
        
        # JWT token detection
        self.add_rule(ProductionValidationRule(
            rule_id="security_jwt_detection",
            name="JWT Token Detection",
            description="Detect JWT tokens in production data",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            pattern=r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            max_violations=0,
            severity=Severity.HIGH,
            tags={"security", "jwt", "token"}
        ))
    
    def _add_data_quality_rules(self):
        """Add data quality validation rules."""
        
        # Null/empty value detection
        self.add_rule(ProductionValidationRule(
            rule_id="quality_null_values",
            name="Null Value Detection",
            description="Detect excessive null or empty values",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.INTERNAL,
            validator_function=self._validate_null_values,
            max_violations=1000,  # Allow some null values
            severity=Severity.LOW,
            tags={"quality", "null_values", "completeness"}
        ))
        
        # Data format consistency
        self.add_rule(ProductionValidationRule(
            rule_id="quality_format_consistency",
            name="Data Format Consistency",
            description="Validate data format consistency",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.INTERNAL,
            validator_function=self._validate_format_consistency,
            max_violations=100,
            severity=Severity.MEDIUM,
            tags={"quality", "format", "consistency"}
        ))
        
        # Duplicate detection
        self.add_rule(ProductionValidationRule(
            rule_id="quality_duplicate_detection",
            name="Duplicate Data Detection",
            description="Detect duplicate records in production data",
            validation_level=ValidationLevel.STRICT,
            data_sensitivity=DataSensitivity.INTERNAL,
            validator_function=self._validate_duplicates,
            max_violations=50,
            severity=Severity.MEDIUM,
            tags={"quality", "duplicates", "integrity"}
        ))
    
    def _add_compliance_rules(self):
        """Add compliance validation rules."""
        
        # GDPR compliance - data retention
        self.add_rule(ProductionValidationRule(
            rule_id="compliance_gdpr_retention",
            name="GDPR Data Retention Compliance",
            description="Validate GDPR data retention compliance",
            validation_level=ValidationLevel.STRICT,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            validator_function=self._validate_gdpr_retention,
            max_violations=0,
            severity=Severity.HIGH,
            tags={"compliance", "gdpr", "retention"}
        ))
        
        # PCI DSS compliance - cardholder data
        self.add_rule(ProductionValidationRule(
            rule_id="compliance_pci_cardholder_data",
            name="PCI DSS Cardholder Data Compliance",
            description="Validate PCI DSS cardholder data compliance",
            validation_level=ValidationLevel.STRICT,
            data_sensitivity=DataSensitivity.RESTRICTED,
            validator_function=self._validate_pci_compliance,
            max_violations=0,
            severity=Severity.CRITICAL,
            tags={"compliance", "pci_dss", "cardholder_data"}
        ))
        
        # HIPAA compliance - PHI detection
        self.add_rule(ProductionValidationRule(
            rule_id="compliance_hipaa_phi",
            name="HIPAA PHI Compliance",
            description="Validate HIPAA Protected Health Information compliance",
            validation_level=ValidationLevel.STRICT,
            data_sensitivity=DataSensitivity.RESTRICTED,
            validator_function=self._validate_hipaa_phi,
            max_violations=0,
            severity=Severity.CRITICAL,
            tags={"compliance", "hipaa", "phi"}
        ))
    
    def _add_performance_rules(self):
        """Add performance validation rules."""
        
        # File size validation
        self.add_rule(ProductionValidationRule(
            rule_id="performance_file_size",
            name="File Size Validation",
            description="Validate production file sizes",
            validation_level=ValidationLevel.BASIC,
            data_sensitivity=DataSensitivity.INTERNAL,
            validator_function=self._validate_file_size,
            max_violations=10,
            severity=Severity.LOW,
            tags={"performance", "file_size", "resources"}
        ))
        
        # Memory usage validation
        self.add_rule(ProductionValidationRule(
            rule_id="performance_memory_usage",
            name="Memory Usage Validation",
            description="Validate memory usage during data processing",
            validation_level=ValidationLevel.STANDARD,
            data_sensitivity=DataSensitivity.INTERNAL,
            validator_function=self._validate_memory_usage,
            max_violations=5,
            severity=Severity.MEDIUM,
            tags={"performance", "memory", "resources"}
        ))
    
    def add_rule(self, rule: ProductionValidationRule):
        """Add a validation rule."""
        self.rules[rule.rule_id] = rule
        self.logger.debug(f"Added validation rule: {rule.rule_id}")
    
    async def validate_data(self, 
                          data: Union[str, bytes, Dict, List],
                          data_type: str = "text",
                          metadata: Optional[Dict[str, Any]] = None) -> Dict[str, ValidationResult]:
        """Validate production data against all applicable rules."""
        
        results = {}
        
        # Filter rules based on validation level
        applicable_rules = [
            rule for rule in self.rules.values()
            if rule.enabled and self._is_rule_applicable(rule)
        ]
        
        # Process data sampling if enabled
        if self.enable_sampling and self._should_sample_data(data):
            data = self._sample_data(data)
        
        # Validate against each applicable rule
        for rule in applicable_rules:
            try:
                result = await self._validate_against_rule(rule, data, data_type, metadata)
                results[rule.rule_id] = result
                
            except Exception as e:
                self.logger.error(f"Error validating rule {rule.rule_id}: {e}")
                results[rule.rule_id] = ValidationResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=ValidationStatus.ERROR,
                    error_message=str(e)
                )
        
        return results
    
    async def _validate_against_rule(self, 
                                   rule: ProductionValidationRule,
                                   data: Any,
                                   data_type: str,
                                   metadata: Optional[Dict[str, Any]]) -> ValidationResult:
        """Validate data against a specific rule."""
        
        start_time = time.time()
        
        result = ValidationResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            status=ValidationStatus.PASSED
        )
        
        try:
            # Convert data to string for pattern matching
            if isinstance(data, (dict, list)):
                data_str = json.dumps(data)
            elif isinstance(data, bytes):
                data_str = data.decode('utf-8', errors='ignore')
            else:
                data_str = str(data)
            
            result.data_processed = len(data_str)
            result.data_size_bytes = len(data_str.encode('utf-8'))
            
            # Apply validation logic
            if rule.pattern:
                violations = self._validate_pattern(rule, data_str)
                result.violations.extend(violations)
                result.violations_found = len(violations)
            
            elif rule.validator_function:
                violations = await self._validate_function(rule, data, metadata)
                result.violations.extend(violations)
                result.violations_found = len(violations)
            
            # Determine validation status
            if result.violations_found > rule.max_violations:
                result.status = ValidationStatus.FAILED
                
                # Create security issues for violations
                for violation in result.violations:
                    issue = SecurityIssue(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=f"{rule.name}: {violation.get('message', 'Violation detected')}",
                        file_path=metadata.get('file_path', 'unknown') if metadata else 'unknown',
                        line_number=violation.get('line_number', 0),
                        category=list(rule.tags)[0] if rule.tags else 'validation'
                    )
                    result.security_issues.append(issue)
            
            elif result.violations_found > 0:
                result.status = ValidationStatus.WARNING
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(rule, result)
            
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
        
        finally:
            result.validation_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def _validate_pattern(self, rule: ProductionValidationRule, data: str) -> List[Dict[str, Any]]:
        """Validate data against a regex pattern."""
        
        violations = []
        
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            matches = pattern.finditer(data)
            
            for match in matches:
                # Find line number
                line_number = data[:match.start()].count('\n') + 1
                
                violation = {
                    'match': match.group(),
                    'start_position': match.start(),
                    'end_position': match.end(),
                    'line_number': line_number,
                    'message': f"Pattern '{rule.pattern}' matched: {match.group()[:50]}..."
                }
                violations.append(violation)
        
        except re.error as e:
            self.logger.error(f"Invalid regex pattern in rule {rule.rule_id}: {e}")
        
        return violations
    
    async def _validate_function(self, 
                                rule: ProductionValidationRule,
                                data: Any,
                                metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate data using a custom function."""
        
        try:
            if asyncio.iscoroutinefunction(rule.validator_function):
                return await rule.validator_function(data, metadata)
            else:
                return rule.validator_function(data, metadata)
        
        except Exception as e:
            self.logger.error(f"Error in validator function for rule {rule.rule_id}: {e}")
            return []
    
    def _validate_null_values(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate null/empty values in data."""
        
        violations = []
        
        if isinstance(data, str):
            # Count empty lines
            lines = data.split('\n')
            empty_lines = sum(1 for line in lines if not line.strip())
            
            if empty_lines > len(lines) * 0.5:  # More than 50% empty lines
                violations.append({
                    'message': f"High percentage of empty lines: {empty_lines}/{len(lines)}",
                    'empty_lines': empty_lines,
                    'total_lines': len(lines)
                })
        
        elif isinstance(data, (dict, list)):
            # Count null/empty values in structured data
            null_count = self._count_null_values(data)
            total_count = self._count_total_values(data)
            
            if null_count > total_count * 0.3:  # More than 30% null values
                violations.append({
                    'message': f"High percentage of null values: {null_count}/{total_count}",
                    'null_values': null_count,
                    'total_values': total_count
                })
        
        return violations
    
    def _validate_format_consistency(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate data format consistency."""
        
        violations = []
        
        if isinstance(data, str):
            # Check for mixed line endings
            crlf_count = data.count('\r\n')
            lf_count = data.count('\n') - crlf_count
            cr_count = data.count('\r') - crlf_count
            
            if sum(x > 0 for x in [crlf_count, lf_count, cr_count]) > 1:
                violations.append({
                    'message': "Mixed line endings detected",
                    'crlf_count': crlf_count,
                    'lf_count': lf_count,
                    'cr_count': cr_count
                })
        
        return violations
    
    def _validate_duplicates(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate for duplicate data."""
        
        violations = []
        
        if isinstance(data, list):
            # Check for duplicate items
            seen = set()
            duplicates = set()
            
            for item in data:
                item_str = str(item)
                if item_str in seen:
                    duplicates.add(item_str)
                else:
                    seen.add(item_str)
            
            if duplicates:
                violations.append({
                    'message': f"Duplicate items found: {len(duplicates)}",
                    'duplicate_count': len(duplicates),
                    'total_items': len(data)
                })
        
        elif isinstance(data, str):
            # Check for duplicate lines
            lines = data.split('\n')
            seen_lines = set()
            duplicate_lines = set()
            
            for line in lines:
                line = line.strip()
                if line and line in seen_lines:
                    duplicate_lines.add(line)
                else:
                    seen_lines.add(line)
            
            if duplicate_lines:
                violations.append({
                    'message': f"Duplicate lines found: {len(duplicate_lines)}",
                    'duplicate_lines': len(duplicate_lines),
                    'total_lines': len(lines)
                })
        
        return violations
    
    def _validate_gdpr_retention(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate GDPR data retention compliance."""
        
        violations = []
        
        # Check if metadata contains creation date
        if metadata and 'created_at' in metadata:
            try:
                created_at = datetime.fromisoformat(metadata['created_at'])
                retention_period = timedelta(days=365 * 7)  # 7 years default
                
                if datetime.now() - created_at > retention_period:
                    violations.append({
                        'message': "Data exceeds GDPR retention period",
                        'created_at': created_at.isoformat(),
                        'age_days': (datetime.now() - created_at).days
                    })
            
            except (ValueError, TypeError):
                violations.append({
                    'message': "Invalid or missing creation date for GDPR compliance"
                })
        
        return violations
    
    def _validate_pci_compliance(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate PCI DSS compliance."""
        
        violations = []
        
        # Check for unencrypted cardholder data
        if isinstance(data, str):
            # Look for credit card patterns
            cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
            matches = re.findall(cc_pattern, data)
            
            if matches:
                violations.append({
                    'message': f"Unencrypted cardholder data detected: {len(matches)} instances",
                    'cardholder_data_count': len(matches)
                })
        
        return violations
    
    def _validate_hipaa_phi(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate HIPAA PHI compliance."""
        
        violations = []
        
        if isinstance(data, str):
            # Check for PHI patterns
            phi_patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'  # Phone
            ]
            
            total_matches = 0
            for pattern in phi_patterns:
                matches = re.findall(pattern, data)
                total_matches += len(matches)
            
            if total_matches > 0:
                violations.append({
                    'message': f"Potential PHI detected: {total_matches} instances",
                    'phi_instances': total_matches
                })
        
        return violations
    
    def _validate_file_size(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate file size."""
        
        violations = []
        
        if metadata and 'file_size_mb' in metadata:
            file_size_mb = metadata['file_size_mb']
            
            if file_size_mb > self.max_file_size_mb:
                violations.append({
                    'message': f"File size exceeds limit: {file_size_mb}MB > {self.max_file_size_mb}MB",
                    'file_size_mb': file_size_mb,
                    'max_size_mb': self.max_file_size_mb
                })
        
        return violations
    
    def _validate_memory_usage(self, data: Any, metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate memory usage."""
        
        violations = []
        
        # Estimate memory usage
        if isinstance(data, str):
            memory_mb = len(data.encode('utf-8')) / (1024 * 1024)
        elif isinstance(data, (dict, list)):
            memory_mb = len(json.dumps(data).encode('utf-8')) / (1024 * 1024)
        else:
            memory_mb = 0
        
        if memory_mb > 50:  # 50MB threshold
            violations.append({
                'message': f"High memory usage: {memory_mb:.1f}MB",
                'memory_usage_mb': memory_mb
            })
        
        return violations
    
    def _is_rule_applicable(self, rule: ProductionValidationRule) -> bool:
        """Check if rule is applicable based on validation level."""
        
        level_hierarchy = {
            ValidationLevel.BASIC: 1,
            ValidationLevel.STANDARD: 2,
            ValidationLevel.STRICT: 3,
            ValidationLevel.PARANOID: 4
        }
        
        return level_hierarchy[rule.validation_level] <= level_hierarchy[self.validation_level]
    
    def _should_sample_data(self, data: Any) -> bool:
        """Determine if data should be sampled."""
        
        if isinstance(data, str):
            return len(data) > 1024 * 1024  # 1MB threshold
        elif isinstance(data, (list, dict)):
            return len(json.dumps(data)) > 1024 * 1024
        
        return False
    
    def _sample_data(self, data: Any) -> Any:
        """Sample data for validation."""
        
        if isinstance(data, str):
            # Sample lines
            lines = data.split('\n')
            sample_size = max(100, int(len(lines) * self.sample_rate))
            sampled_lines = lines[:sample_size]
            return '\n'.join(sampled_lines)
        
        elif isinstance(data, list):
            # Sample list items
            sample_size = max(100, int(len(data) * self.sample_rate))
            return data[:sample_size]
        
        return data
    
    def _count_null_values(self, data: Any) -> int:
        """Count null/empty values in structured data."""
        
        count = 0
        
        if isinstance(data, dict):
            for value in data.values():
                if value is None or value == "":
                    count += 1
                elif isinstance(value, (dict, list)):
                    count += self._count_null_values(value)
        
        elif isinstance(data, list):
            for item in data:
                if item is None or item == "":
                    count += 1
                elif isinstance(item, (dict, list)):
                    count += self._count_null_values(item)
        
        return count
    
    def _count_total_values(self, data: Any) -> int:
        """Count total values in structured data."""
        
        count = 0
        
        if isinstance(data, dict):
            count += len(data)
            for value in data.values():
                if isinstance(value, (dict, list)):
                    count += self._count_total_values(value)
        
        elif isinstance(data, list):
            count += len(data)
            for item in data:
                if isinstance(item, (dict, list)):
                    count += self._count_total_values(item)
        
        return count
    
    def _generate_recommendations(self, 
                                rule: ProductionValidationRule,
                                result: ValidationResult) -> List[str]:
        """Generate recommendations based on validation results."""
        
        recommendations = []
        
        if result.violations_found > 0:
            if "pii" in rule.tags:
                recommendations.extend([
                    "Implement data anonymization or pseudonymization",
                    "Review data collection and retention policies",
                    "Consider using data masking in non-production environments"
                ])
            
            elif "security" in rule.tags:
                recommendations.extend([
                    "Remove or encrypt sensitive data",
                    "Implement proper secret management",
                    "Review access controls and data handling procedures"
                ])
            
            elif "quality" in rule.tags:
                recommendations.extend([
                    "Implement data validation at ingestion",
                    "Review data processing pipelines",
                    "Consider data cleansing procedures"
                ])
            
            elif "compliance" in rule.tags:
                recommendations.extend([
                    "Review compliance policies and procedures",
                    "Implement automated compliance monitoring",
                    "Consider legal and regulatory requirements"
                ])
        
        return recommendations
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation results."""
        
        if not self.results:
            return {
                'total_rules': len(self.rules),
                'executed_rules': 0
            }
        
        total_rules = len(self.rules)
        executed_rules = len(self.results)
        
        passed = sum(1 for r in self.results.values() if r.status == ValidationStatus.PASSED)
        failed = sum(1 for r in self.results.values() if r.status == ValidationStatus.FAILED)
        warnings = sum(1 for r in self.results.values() if r.status == ValidationStatus.WARNING)
        errors = sum(1 for r in self.results.values() if r.status == ValidationStatus.ERROR)
        
        total_violations = sum(r.violations_found for r in self.results.values())
        total_security_issues = sum(len(r.security_issues) for r in self.results.values())
        
        return {
            'total_rules': total_rules,
            'executed_rules': executed_rules,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'errors': errors,
            'pass_rate': (passed / executed_rules * 100) if executed_rules > 0 else 0,
            'total_violations': total_violations,
            'total_security_issues': total_security_issues,
            'validation_level': self.validation_level.value
        }


# Utility functions

def create_production_validation_report(results: Dict[str, ValidationResult]) -> str:
    """Create comprehensive production validation report."""
    
    report = """
# Production Data Validation Report

## Executive Summary

"""
    
    total_rules = len(results)
    failed_rules = sum(1 for r in results.values() if r.status == ValidationStatus.FAILED)
    warning_rules = sum(1 for r in results.values() if r.status == ValidationStatus.WARNING)
    total_violations = sum(r.violations_found for r in results.values())
    
    report += f"- **Total Rules Executed**: {total_rules}\n"
    report += f"- **Failed Rules**: {failed_rules}\n"
    report += f"- **Warning Rules**: {warning_rules}\n"
    report += f"- **Total Violations**: {total_violations}\n"
    report += f"- **Overall Status**: {'FAILED' if failed_rules > 0 else 'WARNING' if warning_rules > 0 else 'PASSED'}\n\n"
    
    # Critical findings
    critical_findings = [r for r in results.values() if r.status == ValidationStatus.FAILED]
    
    if critical_findings:
        report += "## Critical Findings\n\n"
        for result in critical_findings:
            report += f"### ❌ {result.rule_name}\n"
            report += f"- **Violations**: {result.violations_found}\n"
            report += f"- **Security Issues**: {len(result.security_issues)}\n"
            
            if result.recommendations:
                report += "- **Recommendations**:\n"
                for rec in result.recommendations[:3]:  # Show top 3
                    report += f"  - {rec}\n"
            
            report += "\n"
    
    # Warnings
    warning_findings = [r for r in results.values() if r.status == ValidationStatus.WARNING]
    
    if warning_findings:
        report += "## Warnings\n\n"
        for result in warning_findings:
            report += f"### ⚠️ {result.rule_name}\n"
            report += f"- **Violations**: {result.violations_found}\n"
            report += "\n"
    
    # Summary by category
    report += "## Summary by Category\n\n"
    
    categories = {}
    for result in results.values():
        # Extract category from rule tags (simplified)
        category = "General"
        if any("pii" in str(issue.category) for issue in result.security_issues):
            category = "PII/Privacy"
        elif any("security" in str(issue.category) for issue in result.security_issues):
            category = "Security"
        elif any("compliance" in str(issue.category) for issue in result.security_issues):
            category = "Compliance"
        elif any("quality" in str(issue.category) for issue in result.security_issues):
            category = "Data Quality"
        
        if category not in categories:
            categories[category] = {'total': 0, 'failed': 0, 'violations': 0}
        
        categories[category]['total'] += 1
        if result.status == ValidationStatus.FAILED:
            categories[category]['failed'] += 1
        categories[category]['violations'] += result.violations_found
    
    for category, stats in categories.items():
        report += f"- **{category}**: {stats['failed']}/{stats['total']} failed, {stats['violations']} violations\n"
    
    return report


async def validate_production_environment(data_sources: List[Dict[str, Any]],
                                        validation_level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, Any]:
    """Validate entire production environment."""
    
    validator = ProductionDataValidator(validation_level)
    all_results = {}
    
    for source in data_sources:
        source_name = source.get('name', 'unknown')
        data = source.get('data', '')
        data_type = source.get('type', 'text')
        metadata = source.get('metadata', {})
        
        try:
            results = await validator.validate_data(data, data_type, metadata)
            all_results[source_name] = results
            
        except Exception as e:
            logger.error(f"Error validating source {source_name}: {e}")
            all_results[source_name] = {
                'error': {
                    'rule_id': 'validation_error',
                    'rule_name': 'Validation Error',
                    'status': ValidationStatus.ERROR,
                    'error_message': str(e)
                }
            }
    
    # Generate summary and report
    summary = validator.get_validation_summary()
    
    # Flatten results for report generation
    flattened_results = {}
    for source_name, source_results in all_results.items():
        for rule_id, result in source_results.items():
            flattened_results[f"{source_name}_{rule_id}"] = result
    
    report = create_production_validation_report(flattened_results)
    
    return {
        'results': all_results,
        'summary': summary,
        'report': report
    }