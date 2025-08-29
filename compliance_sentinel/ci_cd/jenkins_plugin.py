"""Jenkins plugin for Compliance Sentinel security gate integration."""

import os
import json
import subprocess
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging
from datetime import datetime

from compliance_sentinel.core.interfaces import SecurityIssue
from compliance_sentinel.ci_cd.security_gate import SecurityGateConfig, SecurityGateEvaluator, SecurityGateResult
from compliance_sentinel.analyzers.project_analyzer import ProjectAnalyzer


logger = logging.getLogger(__name__)


class JenkinsSecurityGate:
    """Jenkins plugin for security gate integration."""
    
    def __init__(self, config: Optional[SecurityGateConfig] = None):
        """Initialize Jenkins security gate."""
        self.config = config or SecurityGateConfig()
        self.evaluator = SecurityGateEvaluator(self.config)
        self.logger = logging.getLogger(__name__)
    
    def execute_security_scan(self, workspace_path: str) -> SecurityGateResult:
        """Execute security scan in Jenkins workspace."""
        try:
            self.logger.info(f"Starting security scan in workspace: {workspace_path}")
            
            # Initialize project analyzer
            analyzer = ProjectAnalyzer()
            
            # Scan the workspace
            scan_result = analyzer.scan_project(workspace_path)
            
            # Extract issues and metadata
            issues = scan_result.get('issues', [])
            scan_duration = scan_result.get('summary', {}).get('scan_duration', 0.0)
            files_scanned = scan_result.get('summary', {}).get('files_scanned', 0)
            
            # Evaluate against security gate
            gate_result = self.evaluator.evaluate(issues, scan_duration, files_scanned)
            
            # Generate reports
            generate_report = getattr(self.config, 'generate_report', True)
            if generate_report:
                self._generate_jenkins_reports(gate_result, workspace_path)
            
            # Set Jenkins environment variables
            self._set_jenkins_environment(gate_result)
            
            return gate_result
            
        except Exception as e:
            self.logger.error(f"Security scan failed: {e}")
            raise
    
    def _generate_jenkins_reports(self, result: SecurityGateResult, workspace_path: str):
        """Generate reports for Jenkins."""
        reports_dir = Path(workspace_path) / "security-reports"
        reports_dir.mkdir(exist_ok=True)
        
        # Get report path safely
        report_path = getattr(self.config, 'report_path', 'security-report')
        
        # JSON report
        json_report_path = reports_dir / f"{report_path}.json"
        with open(json_report_path, 'w') as f:
            if hasattr(result, 'to_json'):
                f.write(result.to_json())
            else:
                # Fallback: create basic JSON report
                basic_report = {
                    'status': getattr(result, 'status', {}).get('value', 'unknown') if hasattr(getattr(result, 'status', {}), 'get') else 'unknown',
                    'total_issues': getattr(result, 'total_issues', 0),
                    'scan_duration': getattr(result, 'scan_duration', 0.0),
                    'files_scanned': getattr(result, 'files_scanned', 0)
                }
                json.dump(basic_report, f, indent=2)
        
        # JUnit XML report for Jenkins test results
        junit_report_path = reports_dir / f"{report_path}-junit.xml"
        self._generate_junit_xml(result, junit_report_path)
        
        # HTML report
        html_report_path = reports_dir / f"{report_path}.html"
        self._generate_html_report(result, html_report_path)
        
        # SARIF report for security tools integration
        sarif_report_path = reports_dir / f"{report_path}.sarif"
        self._generate_sarif_report(result, sarif_report_path)
        
        self.logger.info(f"Reports generated in {reports_dir}")
    
    def _generate_junit_xml(self, result: SecurityGateResult, output_path: Path):
        """Generate JUnit XML report for Jenkins test integration."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        # Create test suite
        testsuite = Element('testsuite')
        testsuite.set('name', 'Security Gate')
        
        # Get issues safely
        all_issues = getattr(result, 'all_issues', getattr(result, 'issues', []))
        blocked_issues = getattr(result, 'blocked_issues', [])
        scan_duration = getattr(result, 'scan_duration', 0.0)
        timestamp = getattr(result, 'timestamp', datetime.now())
        
        testsuite.set('tests', str(len(all_issues) + 1))  # +1 for overall gate test
        testsuite.set('failures', str(len(blocked_issues)))
        testsuite.set('time', str(scan_duration))
        testsuite.set('timestamp', timestamp.isoformat())
        
        # Overall security gate test
        gate_test = SubElement(testsuite, 'testcase')
        gate_test.set('classname', 'SecurityGate')
        gate_test.set('name', 'OverallSecurityGate')
        gate_test.set('time', str(scan_duration))
        
        status = getattr(result, 'status', None)
        if status and hasattr(status, 'value') and status.value != 'passed':
            failure = SubElement(gate_test, 'failure')
            summary_message = getattr(result, 'summary_message', 'Security gate failed')
            detailed_messages = getattr(result, 'detailed_messages', [])
            failure.set('message', summary_message)
            failure.text = '\n'.join(detailed_messages) if detailed_messages else summary_message
        
        # Individual issue tests
        for issue in all_issues:
            testcase = SubElement(testsuite, 'testcase')
            
            # Safely get issue attributes
            category = getattr(issue, 'category', None)
            category_value = category.value if category and hasattr(category, 'value') else 'Unknown'
            rule_id = getattr(issue, 'rule_id', 'unknown_rule')
            line_number = getattr(issue, 'line_number', 0)
            file_path = getattr(issue, 'file_path', 'unknown_file')
            description = getattr(issue, 'description', 'Security issue detected')
            severity = getattr(issue, 'severity', None)
            severity_value = severity.value if severity and hasattr(severity, 'value') else 'MEDIUM'
            
            testcase.set('classname', f'SecurityIssue.{category_value}')
            testcase.set('name', f'{rule_id}_{line_number}')
            testcase.set('file', file_path)
            testcase.set('line', str(line_number))
            
            if issue in blocked_issues:
                failure = SubElement(testcase, 'failure')
                failure.set('message', description)
                failure.set('type', severity_value)
                failure.text = f"File: {file_path}\nLine: {line_number}\nRule: {rule_id}"
        
        # Write XML file
        xml_str = minidom.parseString(tostring(testsuite)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
    
    def _generate_html_report(self, result: SecurityGateResult, output_path: Path):
        """Generate HTML report for Jenkins."""
        # Safely get result attributes
        status = getattr(result, 'status', None)
        status_value = status.value if status and hasattr(status, 'value') else 'unknown'
        summary_message = getattr(result, 'summary_message', 'Security scan completed')
        timestamp = getattr(result, 'timestamp', datetime.now())
        total_issues = getattr(result, 'total_issues', 0)
        files_scanned = getattr(result, 'files_scanned', 0)
        scan_duration = getattr(result, 'scan_duration', 0.0)
        issues_by_severity = getattr(result, 'issues_by_severity', {})
        all_issues = getattr(result, 'all_issues', getattr(result, 'issues', []))
        
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Sentinel Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .status-passed {{ color: #28a745; }}
        .status-failed {{ color: #dc3545; }}
        .status-warning {{ color: #ffc107; }}
        .summary {{ margin: 20px 0; }}
        .issues {{ margin: 20px 0; }}
        .issue {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #6c757d; }}
        .metrics {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Sentinel Security Report</h1>
        <h2 class="status-{status_value}">Status: {status_value.upper()}</h2>
        <p>{summary_message}</p>
        <p>Scan completed at: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>{total_issues}</h3>
            <p>Total Issues</p>
        </div>
        <div class="metric">
            <h3>{files_scanned}</h3>
            <p>Files Scanned</p>
        </div>
        <div class="metric">
            <h3>{scan_duration:.2f}s</h3>
            <p>Scan Duration</p>
        </div>
    </div>
    
    <div class="summary">
        <h3>Issues by Severity</h3>
        <ul>
'''
        
        for severity, count in issues_by_severity.items():
            if count > 0:
                severity_name = severity.value if hasattr(severity, 'value') else str(severity)
                html_content += f'<li>{severity_name.title()}: {count}</li>'
        
        html_content += '''
        </ul>
    </div>
    
    <div class="issues">
        <h3>Security Issues</h3>
'''
        
        for issue in all_issues:
            # Safely get issue attributes
            severity = getattr(issue, 'severity', None)
            severity_value = severity.value if severity and hasattr(severity, 'value') else 'medium'
            severity_class = severity_value.lower()
            
            description = getattr(issue, 'description', 'Security issue detected')
            file_path = getattr(issue, 'file_path', 'unknown')
            line_number = getattr(issue, 'line_number', 0)
            category = getattr(issue, 'category', None)
            category_value = category.value if category and hasattr(category, 'value') else 'Unknown'
            rule_id = getattr(issue, 'rule_id', 'unknown')
            confidence = getattr(issue, 'confidence', 0.0)
            remediation_suggestions = getattr(issue, 'remediation_suggestions', [])
            
            html_content += f'''
        <div class="issue {severity_class}">
            <h4>{description}</h4>
            <p><strong>File:</strong> {file_path}:{line_number}</p>
            <p><strong>Severity:</strong> {severity_value}</p>
            <p><strong>Category:</strong> {category_value}</p>
            <p><strong>Rule:</strong> {rule_id}</p>
            <p><strong>Confidence:</strong> {confidence:.2f}</p>
'''
            if remediation_suggestions:
                html_content += '<p><strong>Remediation:</strong></p><ul>'
                for suggestion in remediation_suggestions:
                    html_content += f'<li>{suggestion}</li>'
                html_content += '</ul>'
            
            html_content += '</div>'
        
        html_content += '''
    </div>
</body>
</html>
'''
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _generate_sarif_report(self, result: SecurityGateResult, output_path: Path):
        """Generate SARIF report for security tools integration."""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Compliance Sentinel",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/compliance-sentinel/compliance-sentinel"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        all_issues = getattr(result, 'all_issues', getattr(result, 'issues', []))
        
        for issue in all_issues:
            # Safely get issue attributes
            rule_id = getattr(issue, 'rule_id', 'unknown_rule')
            description = getattr(issue, 'description', 'Security issue detected')
            severity = getattr(issue, 'severity', None)
            file_path = getattr(issue, 'file_path', 'unknown')
            line_number = getattr(issue, 'line_number', 1)
            category = getattr(issue, 'category', None)
            category_value = category.value if category and hasattr(category, 'value') else 'Unknown'
            confidence = getattr(issue, 'confidence', 0.0)
            remediation_suggestions = getattr(issue, 'remediation_suggestions', [])
            
            sarif_result = {
                "ruleId": rule_id,
                "message": {
                    "text": description
                },
                "level": self._severity_to_sarif_level(severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": line_number
                            }
                        }
                    }
                ],
                "properties": {
                    "category": category_value,
                    "confidence": confidence,
                    "remediation": remediation_suggestions
                }
            }
            sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(output_path, 'w') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _severity_to_sarif_level(self, severity):
        """Convert severity to SARIF level."""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note'
        }
        
        if severity is None:
            return 'warning'
        
        severity_value = severity.value if hasattr(severity, 'value') else str(severity)
        return mapping.get(severity_value, 'warning')
    
    def _set_jenkins_environment(self, result: SecurityGateResult):
        """Set Jenkins environment variables."""
        # Safely get result attributes
        status = getattr(result, 'status', None)
        status_value = status.value if status and hasattr(status, 'value') else 'unknown'
        total_issues = getattr(result, 'total_issues', 0)
        issues_by_severity = getattr(result, 'issues_by_severity', {})
        scan_duration = getattr(result, 'scan_duration', 0.0)
        files_scanned = getattr(result, 'files_scanned', 0)
        
        env_vars = {
            'SECURITY_GATE_STATUS': status_value,
            'SECURITY_GATE_TOTAL_ISSUES': str(total_issues),
            'SECURITY_GATE_CRITICAL_ISSUES': str(issues_by_severity.get('CRITICAL', 0)),
            'SECURITY_GATE_HIGH_ISSUES': str(issues_by_severity.get('HIGH', 0)),
            'SECURITY_GATE_MEDIUM_ISSUES': str(issues_by_severity.get('MEDIUM', 0)),
            'SECURITY_GATE_LOW_ISSUES': str(issues_by_severity.get('LOW', 0)),
            'SECURITY_GATE_SCAN_DURATION': str(scan_duration),
            'SECURITY_GATE_FILES_SCANNED': str(files_scanned)
        }
        
        # Write to Jenkins properties file
        properties_file = Path(os.environ.get('WORKSPACE', '.')) / 'security-gate.properties'
        with open(properties_file, 'w') as f:
            for key, value in env_vars.items():
                f.write(f'{key}={value}\n')
        
        self.logger.info(f"Jenkins environment variables written to {properties_file}")


def create_jenkins_pipeline_script() -> str:
    """Create Jenkins pipeline script for security gate integration."""
    return r'''
pipeline {
    agent any
    
    environment {
        SECURITY_GATE_CONFIG = 'security-gate.yml'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    // Run Compliance Sentinel security scan
                    sh """
python -m compliance_sentinel.ci_cd.jenkins_plugin \\
    --workspace \${WORKSPACE} \\
    --config \${SECURITY_GATE_CONFIG} \\
    --output security-reports/
                    """
                    
                    // Load security gate results
                    def props = readProperties file: 'security-gate.properties'
                    env.SECURITY_GATE_STATUS = props.SECURITY_GATE_STATUS
                    env.SECURITY_GATE_TOTAL_ISSUES = props.SECURITY_GATE_TOTAL_ISSUES
                    
                    // Check if security gate passed
                    if (env.SECURITY_GATE_STATUS != 'passed') {
                        currentBuild.result = 'FAILURE'
                        error("Security gate failed: \${props.SECURITY_GATE_TOTAL_ISSUES} issues found")
                    }
                }
            }
            post {
                always {
                    // Archive security reports
                    archiveArtifacts artifacts: 'security-reports/**', allowEmptyArchive: true
                    
                    // Publish test results
                    publishTestResults testResultsPattern: 'security-reports/*-junit.xml'
                    
                    // Publish HTML report
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: '*.html',
                        reportName: 'Security Report'
                    ])
                }
                failure {
                    // Send notifications on security gate failure
                    emailext (
                        subject: "Security Gate Failed: \${env.JOB_NAME} - \${env.BUILD_NUMBER}",
                        body: """
                        Security gate failed for build \${env.BUILD_NUMBER}.
                        
                        Total Issues: \${env.SECURITY_GATE_TOTAL_ISSUES}
                        Critical: \${env.SECURITY_GATE_CRITICAL_ISSUES}
                        High: \${env.SECURITY_GATE_HIGH_ISSUES}
                        
                        View full report: \${env.BUILD_URL}Security_Report/
                        """,
                        to: "\${env.CHANGE_AUTHOR_EMAIL}"
                    )
                }
            }
        }
        
        stage('Deploy') {
            when {
                expression { env.SECURITY_GATE_STATUS == 'passed' }
            }
            steps {
                echo 'Deploying application...'
                // Add deployment steps here
            }
        }
    }
}
'''


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Jenkins Security Gate Plugin')
    parser.add_argument('--workspace', required=True, help='Jenkins workspace path')
    parser.add_argument('--config', help='Security gate configuration file')
    parser.add_argument('--output', default='security-reports/', help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = SecurityGateConfig()
    if args.config and os.path.exists(args.config):
        try:
            import yaml
            with open(args.config, 'r') as f:
                config_dict = yaml.safe_load(f)
                if hasattr(SecurityGateConfig, 'from_dict'):
                    config = SecurityGateConfig.from_dict(config_dict)
                else:
                    # Fallback: manually set config attributes
                    for key, value in config_dict.items():
                        if hasattr(config, key):
                            setattr(config, key, value)
        except ImportError:
            print("Warning: PyYAML not installed, using default configuration")
        except Exception as e:
            print(f"Warning: Could not load configuration: {e}")
    
    # Execute security gate
    jenkins_gate = JenkinsSecurityGate(config)
    result = jenkins_gate.execute_security_scan(args.workspace)
    
    # Exit with appropriate code
    status = getattr(result, 'status', None)
    status_value = status.value if status and hasattr(status, 'value') else 'unknown'
    fail_on_error = getattr(config, 'fail_on_error', True)
    
    if status_value == 'failed' and fail_on_error:
        exit(1)
    else:
        exit(0)