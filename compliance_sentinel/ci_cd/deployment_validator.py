"""Deployment security validation for production releases."""

import os
import json
import yaml
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import logging

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.ci_cd.security_gate import SecurityGateConfig, SecurityGateEvaluator, SecurityGateResult
from compliance_sentinel.analyzers.project_analyzer import ProjectAnalyzer


logger = logging.getLogger(__name__)


class DeploymentSecurityValidator:
    """Validates security requirements before production deployment."""
    
    def __init__(self, config: Optional[SecurityGateConfig] = None):
        """Initialize deployment validator."""
        self.config = config or SecurityGateConfig()
        self.evaluator = SecurityGateEvaluator(self.config)
        self.logger = logging.getLogger(__name__)
    
    def validate_deployment(self, 
                          deployment_path: str,
                          environment: str = "production",
                          previous_scan_results: Optional[str] = None) -> Tuple[bool, SecurityGateResult]:
        """
        Validate deployment security requirements.
        
        Args:
            deployment_path: Path to deployment artifacts
            environment: Target environment (production, staging, etc.)
            previous_scan_results: Path to previous scan results for comparison
            
        Returns:
            Tuple of (is_deployment_approved, security_gate_result)
        """
        try:
            self.logger.info(f"Validating deployment security for {environment} environment")
            
            # Perform security scan
            analyzer = ProjectAnalyzer()
            scan_result = analyzer.scan_project(deployment_path)
            
            # Extract issues and metadata
            issues = scan_result.get('issues', [])
            scan_duration = scan_result.get('summary', {}).get('scan_duration', 0.0)
            files_scanned = scan_result.get('summary', {}).get('files_scanned', 0)
            
            # Apply environment-specific rules
            environment_config = self._get_environment_config(environment)
            environment_evaluator = SecurityGateEvaluator(environment_config)
            
            # Evaluate against security gate
            gate_result = environment_evaluator.evaluate(issues, scan_duration, files_scanned)
            
            # Additional deployment validations
            deployment_checks = self._perform_deployment_checks(
                issues, deployment_path, environment, previous_scan_results
            )
            
            # Combine results
            is_approved = (
                gate_result.status.value == 'passed' and
                deployment_checks['all_checks_passed']
            )
            
            # Add deployment-specific information to result
            gate_result.detailed_messages.extend(deployment_checks['messages'])
            
            # Generate deployment report
            self._generate_deployment_report(gate_result, deployment_checks, environment)
            
            return is_approved, gate_result
            
        except Exception as e:
            self.logger.error(f"Deployment validation failed: {e}")
            raise
    
    def _get_environment_config(self, environment: str) -> SecurityGateConfig:
        """Get environment-specific security configuration."""
        # Production environments have stricter requirements
        if environment.lower() in ['production', 'prod']:
            config = SecurityGateConfig(
                enabled=True,
                fail_on_error=True,
                block_on_critical=True,
                block_on_high=True,
                block_on_medium=True,  # Stricter for production
                block_on_low=False,
                max_critical_issues=0,
                max_high_issues=0,     # No high severity issues in production
                max_medium_issues=2,   # Very limited medium issues
                max_low_issues=10
            )
        elif environment.lower() in ['staging', 'stage']:
            config = SecurityGateConfig(
                enabled=True,
                fail_on_error=True,
                block_on_critical=True,
                block_on_high=True,
                block_on_medium=False,
                block_on_low=False,
                max_critical_issues=0,
                max_high_issues=3,
                max_medium_issues=10,
                max_low_issues=25
            )
        else:
            # Development/testing environments are more permissive
            config = self.config
        
        return config
    
    def _perform_deployment_checks(self, 
                                 issues: List[SecurityIssue],
                                 deployment_path: str,
                                 environment: str,
                                 previous_scan_results: Optional[str]) -> Dict[str, Any]:
        """Perform additional deployment-specific security checks."""
        checks = {
            'all_checks_passed': True,
            'messages': [],
            'checks': {}
        }
        
        # Check 1: No new critical/high issues since last deployment
        if previous_scan_results:
            regression_check = self._check_security_regression(issues, previous_scan_results)
            checks['checks']['security_regression'] = regression_check
            if not regression_check['passed']:
                checks['all_checks_passed'] = False
                checks['messages'].append(f"Security regression detected: {regression_check['message']}")
        
        # Check 2: Validate deployment artifacts
        artifacts_check = self._validate_deployment_artifacts(deployment_path)
        checks['checks']['deployment_artifacts'] = artifacts_check
        if not artifacts_check['passed']:
            checks['all_checks_passed'] = False
            checks['messages'].append(f"Deployment artifacts validation failed: {artifacts_check['message']}")
        
        # Check 3: Environment-specific security requirements
        env_check = self._validate_environment_requirements(issues, environment)
        checks['checks']['environment_requirements'] = env_check
        if not env_check['passed']:
            checks['all_checks_passed'] = False
            checks['messages'].append(f"Environment requirements not met: {env_check['message']}")
        
        # Check 4: Compliance framework requirements
        compliance_check = self._validate_compliance_requirements(issues, environment)
        checks['checks']['compliance_requirements'] = compliance_check
        if not compliance_check['passed']:
            checks['all_checks_passed'] = False
            checks['messages'].append(f"Compliance requirements not met: {compliance_check['message']}")
        
        # Check 5: Dependency security validation
        dependency_check = self._validate_dependencies(deployment_path)
        checks['checks']['dependency_security'] = dependency_check
        if not dependency_check['passed']:
            checks['all_checks_passed'] = False
            checks['messages'].append(f"Dependency security validation failed: {dependency_check['message']}")
        
        return checks
    
    def _check_security_regression(self, 
                                 current_issues: List[SecurityIssue],
                                 previous_results_path: str) -> Dict[str, Any]:
        """Check for security regressions compared to previous scan."""
        try:
            with open(previous_results_path, 'r') as f:
                previous_data = json.load(f)
            
            previous_issues = previous_data.get('all_issues', [])
            
            # Convert to comparable format
            current_issue_keys = set()
            for issue in current_issues:
                key = f"{issue.file_path}:{issue.line_number}:{issue.rule_id}"
                current_issue_keys.add(key)
            
            previous_issue_keys = set()
            for issue_data in previous_issues:
                key = f"{issue_data['file_path']}:{issue_data['line_number']}:{issue_data['rule_id']}"
                previous_issue_keys.add(key)
            
            # Find new issues
            new_issues = current_issue_keys - previous_issue_keys
            
            # Count new critical/high issues
            new_critical_high = 0
            for issue in current_issues:
                key = f"{issue.file_path}:{issue.line_number}:{issue.rule_id}"
                if key in new_issues and issue.severity.value in ['CRITICAL', 'HIGH']:
                    new_critical_high += 1
            
            if new_critical_high > 0:
                return {
                    'passed': False,
                    'message': f"{new_critical_high} new critical/high severity issues introduced",
                    'new_issues_count': len(new_issues),
                    'new_critical_high_count': new_critical_high
                }
            
            return {
                'passed': True,
                'message': "No security regression detected",
                'new_issues_count': len(new_issues),
                'new_critical_high_count': 0
            }
            
        except Exception as e:
            self.logger.warning(f"Could not check security regression: {e}")
            return {
                'passed': True,  # Don't block deployment if we can't check
                'message': f"Could not verify regression (previous results unavailable): {e}",
                'new_issues_count': 0,
                'new_critical_high_count': 0
            }
    
    def _validate_deployment_artifacts(self, deployment_path: str) -> Dict[str, Any]:
        """Validate deployment artifacts for security issues."""
        deployment_path = Path(deployment_path)
        issues = []
        
        # Check for sensitive files that shouldn't be deployed
        sensitive_patterns = [
            '*.env',
            '*.key',
            '*.pem',
            '*.p12',
            '*.pfx',
            'id_rsa*',
            'config.json',
            'secrets.yml',
            '.aws/credentials',
            '.ssh/*'
        ]
        
        for pattern in sensitive_patterns:
            matches = list(deployment_path.rglob(pattern))
            if matches:
                issues.append(f"Sensitive files found: {[str(m) for m in matches]}")
        
        # Check for development/debug files
        debug_patterns = [
            '*.debug',
            '*.log',
            'debug.py',
            'test_*.py',
            '*.test.js',
            'Dockerfile.dev',
            'docker-compose.dev.yml'
        ]
        
        for pattern in debug_patterns:
            matches = list(deployment_path.rglob(pattern))
            if matches:
                issues.append(f"Debug/development files found: {[str(m) for m in matches]}")
        
        # Check for proper file permissions (if on Unix-like system)
        if os.name != 'nt':  # Not Windows
            executable_files = []
            for file_path in deployment_path.rglob('*'):
                if file_path.is_file() and os.access(file_path, os.X_OK):
                    # Check if it should be executable
                    if not any(file_path.name.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb']):
                        executable_files.append(str(file_path))
            
            if executable_files:
                issues.append(f"Unexpected executable files: {executable_files}")
        
        if issues:
            return {
                'passed': False,
                'message': '; '.join(issues),
                'issues': issues
            }
        
        return {
            'passed': True,
            'message': "Deployment artifacts validation passed",
            'issues': []
        }
    
    def _validate_environment_requirements(self, 
                                        issues: List[SecurityIssue],
                                        environment: str) -> Dict[str, Any]:
        """Validate environment-specific security requirements."""
        
        if environment.lower() in ['production', 'prod']:
            # Production-specific requirements
            
            # No hardcoded secrets allowed in production
            secret_issues = [i for i in issues if i.category == SecurityCategory.HARDCODED_SECRETS]
            if secret_issues:
                return {
                    'passed': False,
                    'message': f"Hardcoded secrets not allowed in production ({len(secret_issues)} found)",
                    'blocking_issues': len(secret_issues)
                }
            
            # No debug/development code
            debug_patterns = ['debug', 'test', 'dev', 'localhost']
            debug_issues = []
            for issue in issues:
                if any(pattern in issue.description.lower() for pattern in debug_patterns):
                    debug_issues.append(issue)
            
            if debug_issues:
                return {
                    'passed': False,
                    'message': f"Debug/development code not allowed in production ({len(debug_issues)} found)",
                    'blocking_issues': len(debug_issues)
                }
        
        return {
            'passed': True,
            'message': f"Environment requirements for {environment} satisfied",
            'blocking_issues': 0
        }
    
    def _validate_compliance_requirements(self, 
                                        issues: List[SecurityIssue],
                                        environment: str) -> Dict[str, Any]:
        """Validate compliance framework requirements."""
        
        # Check if any compliance-related issues exist
        compliance_issues = []
        
        for issue in issues:
            # Check for compliance-related rule IDs
            if any(framework in issue.rule_id.lower() for framework in ['soc2', 'pci', 'hipaa', 'gdpr', 'iso']):
                compliance_issues.append(issue)
        
        if compliance_issues and environment.lower() in ['production', 'prod']:
            critical_compliance = [i for i in compliance_issues if i.severity.value in ['CRITICAL', 'HIGH']]
            if critical_compliance:
                return {
                    'passed': False,
                    'message': f"Critical compliance issues not allowed in production ({len(critical_compliance)} found)",
                    'blocking_issues': len(critical_compliance)
                }
        
        return {
            'passed': True,
            'message': "Compliance requirements satisfied",
            'blocking_issues': 0
        }
    
    def _validate_dependencies(self, deployment_path: str) -> Dict[str, Any]:
        """Validate dependency security."""
        deployment_path = Path(deployment_path)
        issues = []
        
        # Check for known vulnerable dependency files
        dependency_files = [
            'package.json',
            'requirements.txt',
            'Gemfile',
            'pom.xml',
            'build.gradle',
            'Cargo.toml',
            'composer.json'
        ]
        
        for dep_file in dependency_files:
            dep_path = deployment_path / dep_file
            if dep_path.exists():
                # Basic check for known vulnerable patterns
                content = dep_path.read_text()
                
                # Check for development dependencies in production
                if dep_file == 'package.json':
                    try:
                        package_data = json.loads(content)
                        dev_deps = package_data.get('devDependencies', {})
                        if dev_deps:
                            issues.append(f"Development dependencies found in {dep_file}")
                    except json.JSONDecodeError:
                        pass
                
                # Check for version pinning
                if 'latest' in content or '*' in content:
                    issues.append(f"Unpinned dependencies found in {dep_file}")
        
        if issues:
            return {
                'passed': False,
                'message': '; '.join(issues),
                'issues': issues
            }
        
        return {
            'passed': True,
            'message': "Dependency validation passed",
            'issues': []
        }
    
    def _generate_deployment_report(self, 
                                  gate_result: SecurityGateResult,
                                  deployment_checks: Dict[str, Any],
                                  environment: str):
        """Generate deployment validation report."""
        
        report = {
            'deployment_validation': {
                'environment': environment,
                'timestamp': datetime.now().isoformat(),
                'approved': gate_result.status.value == 'passed' and deployment_checks['all_checks_passed'],
                'security_gate_result': gate_result.to_dict(),
                'deployment_checks': deployment_checks
            }
        }
        
        # Write deployment report
        report_path = Path('deployment-validation-report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate deployment summary
        summary_path = Path('deployment-summary.md')
        self._generate_deployment_summary(report, summary_path)
        
        self.logger.info(f"Deployment validation report generated: {report_path}")
    
    def _generate_deployment_summary(self, report: Dict[str, Any], output_path: Path):
        """Generate deployment summary in markdown format."""
        
        validation = report['deployment_validation']
        gate_result = validation['security_gate_result']
        checks = validation['deployment_checks']
        
        status_emoji = '✅' if validation['approved'] else '❌'
        
        summary = f'''# 🚀 Deployment Validation Summary

## {status_emoji} Status: {"APPROVED" if validation['approved'] else "REJECTED"}

**Environment:** {validation['environment']}  
**Validation Time:** {validation['timestamp']}  

## 🛡️ Security Gate Results

- **Total Issues:** {gate_result['total_issues']}
- **Critical:** {gate_result['issues_by_severity'].get('CRITICAL', 0)}
- **High:** {gate_result['issues_by_severity'].get('HIGH', 0)}
- **Medium:** {gate_result['issues_by_severity'].get('MEDIUM', 0)}
- **Low:** {gate_result['issues_by_severity'].get('LOW', 0)}

## 📋 Deployment Checks

'''
        
        for check_name, check_result in checks['checks'].items():
            check_emoji = '✅' if check_result['passed'] else '❌'
            summary += f"- {check_emoji} **{check_name.replace('_', ' ').title()}:** {check_result['message']}\\n"
        
        if not validation['approved']:
            summary += '''
## ⚠️ Action Required

The deployment has been **REJECTED** due to security issues. Please address the following:

'''
            for message in checks['messages']:
                summary += f"- {message}\\n"
            
            summary += '''
Please fix these issues and re-run the deployment validation.
'''
        else:
            summary += '''
## 🎉 Deployment Approved

All security checks have passed. The deployment is approved for the target environment.
'''
        
        with open(output_path, 'w') as f:
            f.write(summary)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Deployment Security Validator')
    parser.add_argument('--deployment-path', required=True, help='Path to deployment artifacts')
    parser.add_argument('--environment', default='production', help='Target environment')
    parser.add_argument('--config', help='Security gate configuration file')
    parser.add_argument('--previous-results', help='Path to previous scan results for regression check')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = SecurityGateConfig()
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config_dict = yaml.safe_load(f)
            config = SecurityGateConfig.from_dict(config_dict)
    
    # Execute deployment validation
    validator = DeploymentSecurityValidator(config)
    is_approved, result = validator.validate_deployment(
        args.deployment_path,
        args.environment,
        args.previous_results
    )
    
    # Exit with appropriate code
    if not is_approved:
        print(f"Deployment REJECTED: {result.summary_message}")
        exit(1)
    else:
        print(f"Deployment APPROVED: {result.summary_message}")
        exit(0)