"""Security and privacy test suite with compliance validation."""

import asyncio
import logging
import tempfile
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import os

from compliance_sentinel.security.code_anonymizer import CodeAnonymizer, create_ml_training_config
from compliance_sentinel.security.encrypted_storage import create_file_storage, create_secure_config
from compliance_sentinel.security.data_retention import create_gdpr_compliant_manager
from compliance_sentinel.security.gdpr_compliance import create_gdpr_manager
from compliance_sentinel.security.audit_logger import SecurityAuditLogger, PrivacyAuditLogger
from compliance_sentinel.security.threat_model import ThreatModelValidator
from compliance_sentinel.security.secure_communication import SecureCommunicationManager


logger = logging.getLogger(__name__)


class SecurityTestSuite:
    """Comprehensive security and privacy test suite."""
    
    def __init__(self):
        """Initialize security test suite."""
        self.logger = logging.getLogger(__name__)
        self.test_results = {}
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all security and privacy tests."""
        
        self.logger.info("Starting comprehensive security test suite")
        
        # Test code anonymization
        anonymization_results = await self._test_code_anonymization()
        self.test_results['code_anonymization'] = anonymization_results
        
        # Test encrypted storage
        storage_results = await self._test_encrypted_storage()
        self.test_results['encrypted_storage'] = storage_results
        
        # Test data retention
        retention_results = await self._test_data_retention()
        self.test_results['data_retention'] = retention_results
        
        # Test GDPR compliance
        gdpr_results = await self._test_gdpr_compliance()
        self.test_results['gdpr_compliance'] = gdpr_results
        
        # Test audit logging
        audit_results = await self._test_audit_logging()
        self.test_results['audit_logging'] = audit_results
        
        # Test threat modeling
        threat_results = await self._test_threat_modeling()
        self.test_results['threat_modeling'] = threat_results
        
        # Test secure communication
        comm_results = await self._test_secure_communication()
        self.test_results['secure_communication'] = comm_results
        
        # Generate summary
        summary = self._generate_test_summary()
        
        return {
            'test_results': self.test_results,
            'summary': summary,
            'executed_at': datetime.now().isoformat()
        }
    
    async def _test_code_anonymization(self) -> Dict[str, Any]:
        """Test code anonymization functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            # Test basic anonymization
            config = create_ml_training_config()
            anonymizer = CodeAnonymizer(config)
            
            test_code = '''
            function getUserData(userId) {
                // Get user information from database
                const email = "user@example.com";
                const password = "secret123";
                return {userId, email, password};
            }
            '''
            
            result = anonymizer.anonymize_code(test_code, "javascript")
            
            # Verify anonymization worked
            if result.identifiers_anonymized > 0:
                results['tests'].append({'name': 'Basic Anonymization', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'Basic Anonymization', 'status': 'failed'})
                results['failed'] += 1
            
            # Test batch anonymization
            code_samples = [test_code, "var x = 'test';", "print('hello world')"]
            batch_results = anonymizer.anonymize_batch(code_samples)
            
            if len(batch_results) == len(code_samples):
                results['tests'].append({'name': 'Batch Anonymization', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'Batch Anonymization', 'status': 'failed'})
                results['failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Code anonymization test failed: {e}")
            results['tests'].append({'name': 'Anonymization Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_encrypted_storage(self) -> Dict[str, Any]:
        """Test encrypted storage functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            # Create temporary storage
            with tempfile.TemporaryDirectory() as temp_dir:
                config = create_secure_config()
                storage = create_file_storage(temp_dir, config)
                
                # Test data storage and retrieval
                test_data = {'sensitive': 'information', 'user_id': '12345'}
                
                if storage.store('test_data', test_data):
                    results['tests'].append({'name': 'Data Storage', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Data Storage', 'status': 'failed'})
                    results['failed'] += 1
                
                # Test data retrieval
                retrieved_data = storage.retrieve('test_data')
                
                if retrieved_data == test_data:
                    results['tests'].append({'name': 'Data Retrieval', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Data Retrieval', 'status': 'failed'})
                    results['failed'] += 1
                
                # Test data deletion
                if storage.delete('test_data'):
                    results['tests'].append({'name': 'Data Deletion', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Data Deletion', 'status': 'failed'})
                    results['failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Encrypted storage test failed: {e}")
            results['tests'].append({'name': 'Storage Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_data_retention(self) -> Dict[str, Any]:
        """Test data retention management."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            # Create temporary retention manager
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
                temp_db_path = temp_db.name
            
            try:
                manager = create_gdpr_compliant_manager(temp_db_path)
                
                # Test data registration
                from compliance_sentinel.security.data_retention import DataCategory, DataClassification
                
                success = manager.register_data(
                    'test_record_1',
                    DataCategory.USER_DATA,
                    DataClassification.CONFIDENTIAL,
                    {'contains_pii': True}
                )
                
                if success:
                    results['tests'].append({'name': 'Data Registration', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Data Registration', 'status': 'failed'})
                    results['failed'] += 1
                
                # Test retention statistics
                stats = manager.get_retention_statistics()
                
                if stats.get('total_records', 0) > 0:
                    results['tests'].append({'name': 'Retention Statistics', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Retention Statistics', 'status': 'failed'})
                    results['failed'] += 1
            
            finally:
                os.unlink(temp_db_path)
            
        except Exception as e:
            self.logger.error(f"Data retention test failed: {e}")
            results['tests'].append({'name': 'Retention Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_gdpr_compliance(self) -> Dict[str, Any]:
        """Test GDPR compliance functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            # Create temporary GDPR manager
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
                temp_db_path = temp_db.name
            
            try:
                manager = create_gdpr_manager(temp_db_path)
                
                # Test data subject request submission
                from compliance_sentinel.security.gdpr_compliance import DataSubjectRightType
                
                request_id = manager.submit_data_subject_request(
                    'test_subject_123',
                    DataSubjectRightType.ACCESS,
                    'Request for data access under GDPR Article 15'
                )
                
                if request_id:
                    results['tests'].append({'name': 'GDPR Request Submission', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'GDPR Request Submission', 'status': 'failed'})
                    results['failed'] += 1
                
                # Test consent management
                consent_id = manager.consent_manager.record_consent(
                    'test_subject_123',
                    'Security analysis',
                    ['usage_data', 'technical_data']
                )
                
                if consent_id:
                    results['tests'].append({'name': 'Consent Management', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Consent Management', 'status': 'failed'})
                    results['failed'] += 1
            
            finally:
                os.unlink(temp_db_path)
            
        except Exception as e:
            self.logger.error(f"GDPR compliance test failed: {e}")
            results['tests'].append({'name': 'GDPR Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_audit_logging(self) -> Dict[str, Any]:
        """Test audit logging functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            # Create temporary audit loggers
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
                temp_db_path = temp_db.name
            
            try:
                security_logger = SecurityAuditLogger(temp_db_path)
                
                # Test security event logging
                security_logger.log_security_scan('scan_123', 100, 5, 'user_456')
                
                # Test event retrieval
                from compliance_sentinel.security.audit_logger import AuditEventType
                events = security_logger.get_events(event_type=AuditEventType.SECURITY_SCAN, limit=10)
                
                if len(events) > 0:
                    results['tests'].append({'name': 'Audit Event Logging', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Audit Event Logging', 'status': 'failed'})
                    results['failed'] += 1
                
                # Test privacy logging
                privacy_logger = PrivacyAuditLogger(temp_db_path)
                privacy_logger.log_gdpr_request('req_789', 'access', 'subject_123')
                
                privacy_events = privacy_logger.get_events(event_type=AuditEventType.GDPR_REQUEST, limit=10)
                
                if len(privacy_events) > 0:
                    results['tests'].append({'name': 'Privacy Event Logging', 'status': 'passed'})
                    results['passed'] += 1
                else:
                    results['tests'].append({'name': 'Privacy Event Logging', 'status': 'failed'})
                    results['failed'] += 1
            
            finally:
                os.unlink(temp_db_path)
            
        except Exception as e:
            self.logger.error(f"Audit logging test failed: {e}")
            results['tests'].append({'name': 'Audit Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_threat_modeling(self) -> Dict[str, Any]:
        """Test threat modeling functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            validator = ThreatModelValidator()
            
            # Test threat model creation
            model = validator.create_compliance_sentinel_model()
            
            if model and len(model.threats) > 0:
                results['tests'].append({'name': 'Threat Model Creation', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'Threat Model Creation', 'status': 'failed'})
                results['failed'] += 1
            
            # Test model validation
            validation_results = validator.validate_model(model)
            
            if validation_results.get('completeness_score', 0) > 0.5:
                results['tests'].append({'name': 'Threat Model Validation', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'Threat Model Validation', 'status': 'failed'})
                results['failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Threat modeling test failed: {e}")
            results['tests'].append({'name': 'Threat Model Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    async def _test_secure_communication(self) -> Dict[str, Any]:
        """Test secure communication functionality."""
        
        results = {'passed': 0, 'failed': 0, 'tests': []}
        
        try:
            comm_manager = SecureCommunicationManager()
            
            # Test SSL context creation
            from compliance_sentinel.security.secure_communication import CommunicationProtocol
            
            context = comm_manager.create_secure_context(CommunicationProtocol.HTTPS)
            
            if context:
                results['tests'].append({'name': 'SSL Context Creation', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'SSL Context Creation', 'status': 'failed'})
                results['failed'] += 1
            
            # Test security recommendations
            recommendations = comm_manager.get_security_recommendations()
            
            if len(recommendations) > 5:
                results['tests'].append({'name': 'Security Recommendations', 'status': 'passed'})
                results['passed'] += 1
            else:
                results['tests'].append({'name': 'Security Recommendations', 'status': 'failed'})
                results['failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Secure communication test failed: {e}")
            results['tests'].append({'name': 'Communication Error', 'status': 'failed', 'error': str(e)})
            results['failed'] += 1
        
        return results
    
    def _generate_test_summary(self) -> Dict[str, Any]:
        """Generate test summary."""
        
        total_passed = sum(result.get('passed', 0) for result in self.test_results.values())
        total_failed = sum(result.get('failed', 0) for result in self.test_results.values())
        total_tests = total_passed + total_failed
        
        pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        return {
            'total_tests': total_tests,
            'passed': total_passed,
            'failed': total_failed,
            'pass_rate': pass_rate,
            'overall_status': 'PASSED' if total_failed == 0 else 'FAILED',
            'components_tested': len(self.test_results),
            'test_categories': list(self.test_results.keys())
        }


# Utility function for running tests
async def run_security_tests() -> Dict[str, Any]:
    """Run comprehensive security and privacy tests."""
    
    test_suite = SecurityTestSuite()
    return await test_suite.run_all_tests()