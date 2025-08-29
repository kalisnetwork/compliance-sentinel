"""Azure DevOps extension for Compliance Sentinel."""

import os
import json
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

from compliance_sentinel.core.interfaces import SecurityIssue
from compliance_sentinel.ci_cd.security_gate import SecurityGateConfig, SecurityGateEvaluator, SecurityGateResult
from compliance_sentinel.analyzers.project_analyzer import ProjectAnalyzer


logger = logging.getLogger(__name__)


class AzureDevOpsExtension:
    """Azure DevOps extension for security scanning."""
    
    def __init__(self, config: Optional[SecurityGateConfig] = None):
        """Initialize Azure DevOps extension."""
        self.config = config or SecurityGateConfig()
        self.evaluator = SecurityGateEvaluator(self.config)
        self.logger = logging.getLogger(__name__)
    
    def execute_pipeline_task(self, source_path: str = None) -> SecurityGateResult:
        """Execute security scan as Azure DevOps pipeline task."""
        source_path = source_path or os.environ.get('BUILD_SOURCESDIRECTORY', '.')
        
        try:
            self.logger.info(f"Starting Azure DevOps security scan in: {source_path}")
            
            # Get Azure DevOps context
            azure_context = self._get_azure_context()
            
            # Initialize project analyzer
            analyzer = ProjectAnalyzer()
            
            # Scan the project
            scan_result = analyzer.scan_project(source_path)
            
            # Extract issues and metadata
            issues = scan_result.get('issues', [])
            scan_duration = scan_result.get('summary', {}).get('scan_duration', 0.0)
            files_scanned = scan_result.get('summary', {}).get('files_scanned', 0)
            
            # Evaluate against security gate
            gate_result = self.evaluator.evaluate(issues, scan_duration, files_scanned)
            
            # Generate Azure DevOps outputs
            self._generate_azure_outputs(gate_result, source_path)
            self._set_azure_variables(gate_result)
            
            # Create work items for critical issues if configured
            if self.config.generate_report and gate_result.blocked_issues:
                self._create_work_items(gate_result, azure_context)
            
            return gate_result
            
        except Exception as e:
            self.logger.error(f"Azure DevOps security scan failed: {e}")
            raise
    
    def _get_azure_context(self) -> Dict[str, Any]:
        """Get Azure DevOps context from environment variables."""
        return {
            'build_id': os.environ.get('BUILD_BUILDID'),
            'build_number': os.environ.get('BUILD_BUILDNUMBER'),
            'build_uri': os.environ.get('BUILD_BUILDURI'),
            'pipeline_name': os.environ.get('BUILD_DEFINITIONNAME'),
            'project_name': os.environ.get('SYSTEM_TEAMPROJECT'),
            'collection_uri': os.environ.get('SYSTEM_COLLECTIONURI'),
            'repository_name': os.environ.get('BUILD_REPOSITORY_NAME'),
            'repository_uri': os.environ.get('BUILD_REPOSITORY_URI'),
            'source_branch': os.environ.get('BUILD_SOURCEBRANCH'),
            'source_version': os.environ.get('BUILD_SOURCEVERSION'),
            'pull_request_id': os.environ.get('SYSTEM_PULLREQUEST_PULLREQUESTID'),
            'pull_request_number': os.environ.get('SYSTEM_PULLREQUEST_PULLREQUESTNUMBER'),
            'requested_for': os.environ.get('BUILD_REQUESTEDFOR'),
            'requested_for_email': os.environ.get('BUILD_REQUESTEDFOREMAIL'),
            'agent_name': os.environ.get('AGENT_NAME'),
            'agent_job_name': os.environ.get('AGENT_JOBNAME')
        }
    
    def _generate_azure_outputs(self, result: SecurityGateResult, source_path: str):
        """Generate outputs for Azure DevOps."""
        outputs_dir = Path(source_path) / "security-reports"
        outputs_dir.mkdir(exist_ok=True)
        
        # JSON report
        json_report_path = outputs_dir / "security-report.json"
        with open(json_report_path, 'w') as f:
            f.write(result.to_json())
        
        # Azure DevOps Test Results (VSTest format)
        vstest_report_path = outputs_dir / "security-test-results.trx"
        self._generate_vstest_report(result, vstest_report_path)
        
        # SARIF report for Azure Security Center integration
        sarif_report_path = outputs_dir / "security-report.sarif"
        self._generate_sarif_report(result, sarif_report_path)
        
        # Azure DevOps Code Coverage format (for security coverage metrics)
        coverage_report_path = outputs_dir / "security-coverage.xml"
        self._generate_coverage_report(result, coverage_report_path)
        
        # HTML report for Azure DevOps tabs
        html_report_path = outputs_dir / "security-report.html"
        self._generate_html_report(result, html_report_path)
        
        self.logger.info(f"Azure DevOps outputs generated in {outputs_dir}")
    
    def _generate_vstest_report(self, result: SecurityGateResult, output_path: Path):
        """Generate VSTest (TRX) format report for Azure DevOps Test Results."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        import uuid
        from datetime import datetime
        
        # Create test run
        test_run = Element('TestRun')
        test_run.set('id', str(uuid.uuid4()))
        test_run.set('name', 'Security Gate Tests')
        test_run.set('xmlns', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
        
        # Test settings
        test_settings = SubElement(test_run, 'TestSettings')
        test_settings.set('name', 'Security Gate Settings')
        test_settings.set('id', str(uuid.uuid4()))
        
        # Times
        times = SubElement(test_run, 'Times')
        times.set('creation', result.timestamp.isoformat())
        times.set('queuing', result.timestamp.isoformat())
        times.set('start', result.timestamp.isoformat())
        times.set('finish', result.timestamp.isoformat())
        
        # Results
        results = SubElement(test_run, 'Results')
        
        # Overall security gate test
        gate_test_id = str(uuid.uuid4())
        gate_result_elem = SubElement(results, 'UnitTestResult')
        gate_result_elem.set('testId', gate_test_id)
        gate_result_elem.set('testName', 'OverallSecurityGate')
        gate_result_elem.set('outcome', 'Passed' if result.status.value == 'passed' else 'Failed')
        gate_result_elem.set('duration', f'00:00:{result.scan_duration:06.3f}')
        
        if result.status.value != 'passed':
            output_elem = SubElement(gate_result_elem, 'Output')
            error_info = SubElement(output_elem, 'ErrorInfo')
            message = SubElement(error_info, 'Message')
            message.text = result.summary_message
            stack_trace = SubElement(error_info, 'StackTrace')
            stack_trace.text = '\\n'.join(result.detailed_messages)
        
        # Individual issue tests
        for issue in result.all_issues:
            test_id = str(uuid.uuid4())
            test_result = SubElement(results, 'UnitTestResult')
            test_result.set('testId', test_id)
            test_result.set('testName', f'{issue.rule_id}_{issue.line_number}')
            test_result.set('outcome', 'Failed' if issue in result.blocked_issues else 'Passed')
            test_result.set('duration', '00:00:00.001')
            
            if issue in result.blocked_issues:
                output_elem = SubElement(test_result, 'Output')
                error_info = SubElement(output_elem, 'ErrorInfo')
                message = SubElement(error_info, 'Message')
                message.text = issue.description
                stack_trace = SubElement(error_info, 'StackTrace')
                stack_trace.text = f"File: {issue.file_path}\\nLine: {issue.line_number}\\nRule: {issue.rule_id}"
        
        # Test definitions
        test_definitions = SubElement(test_run, 'TestDefinitions')
        
        # Overall gate test definition
        gate_test_def = SubElement(test_definitions, 'UnitTest')
        gate_test_def.set('name', 'OverallSecurityGate')
        gate_test_def.set('id', gate_test_id)
        
        execution = SubElement(gate_test_def, 'Execution')
        execution.set('id', str(uuid.uuid4()))
        
        test_method = SubElement(gate_test_def, 'TestMethod')
        test_method.set('codeBase', 'SecurityGate')
        test_method.set('className', 'SecurityGate')
        test_method.set('name', 'OverallSecurityGate')
        
        # Write TRX file
        xml_str = minidom.parseString(tostring(test_run)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
    
    def _generate_sarif_report(self, result: SecurityGateResult, output_path: Path):
        """Generate SARIF report for Azure Security Center."""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Compliance Sentinel",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/compliance-sentinel/compliance-sentinel",
                            "rules": []
                        }
                    },
                    "results": [],
                    "properties": {
                        "scanDuration": result.scan_duration,
                        "filesScanned": result.files_scanned,
                        "totalIssues": result.total_issues
                    }
                }
            ]
        }
        
        # Add rules
        rules_added = set()
        for issue in result.all_issues:
            if issue.rule_id not in rules_added:
                rule = {
                    "id": issue.rule_id,
                    "name": issue.rule_id,
                    "shortDescription": {"text": issue.description},
                    "fullDescription": {"text": issue.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(issue.severity)
                    },
                    "properties": {
                        "category": issue.category.value,
                        "tags": [issue.category.value, issue.severity.value]
                    }
                }
                sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)
                rules_added.add(issue.rule_id)
        
        # Add results
        for issue in result.all_issues:
            sarif_result = {
                "ruleId": issue.rule_id,
                "message": {"text": issue.description},
                "level": self._severity_to_sarif_level(issue.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": issue.file_path},
                            "region": {"startLine": issue.line_number}
                        }
                    }
                ],
                "properties": {
                    "category": issue.category.value,
                    "confidence": issue.confidence,
                    "remediation": issue.remediation_suggestions
                }
            }
            sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(output_path, 'w') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _generate_coverage_report(self, result: SecurityGateResult, output_path: Path):
        """Generate security coverage report in Cobertura XML format."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        # Calculate coverage metrics
        total_files = result.files_scanned
        files_with_issues = len(set(issue.file_path for issue in result.all_issues))
        coverage_rate = (total_files - files_with_issues) / total_files if total_files > 0 else 1.0
        
        # Create coverage report
        coverage = Element('coverage')
        coverage.set('line-rate', f'{coverage_rate:.4f}')
        coverage.set('branch-rate', f'{coverage_rate:.4f}')
        coverage.set('lines-covered', str(total_files - files_with_issues))
        coverage.set('lines-valid', str(total_files))
        coverage.set('timestamp', str(int(result.timestamp.timestamp())))
        
        sources = SubElement(coverage, 'sources')
        source = SubElement(sources, 'source')
        source.text = '.'
        
        packages = SubElement(coverage, 'packages')
        package = SubElement(packages, 'package')
        package.set('name', 'security-scan')
        package.set('line-rate', f'{coverage_rate:.4f}')
        package.set('branch-rate', f'{coverage_rate:.4f}')
        
        classes = SubElement(package, 'classes')
        
        # Group issues by file
        files_issues = {}
        for issue in result.all_issues:
            if issue.file_path not in files_issues:
                files_issues[issue.file_path] = []
            files_issues[issue.file_path].append(issue)
        
        # Add class for each file
        for file_path in set(issue.file_path for issue in result.all_issues):
            class_elem = SubElement(classes, 'class')
            class_elem.set('name', file_path.replace('/', '.').replace('.py', ''))
            class_elem.set('filename', file_path)
            class_elem.set('line-rate', '0.0')  # Files with issues have 0% coverage
            class_elem.set('branch-rate', '0.0')
            
            methods = SubElement(class_elem, 'methods')
            lines = SubElement(class_elem, 'lines')
            
            # Add line for each issue
            for issue in files_issues[file_path]:
                line = SubElement(lines, 'line')
                line.set('number', str(issue.line_number))
                line.set('hits', '0')  # Issues are "uncovered"
        
        # Write XML file
        xml_str = minidom.parseString(tostring(coverage)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
    
    def _generate_html_report(self, result: SecurityGateResult, output_path: Path):
        """Generate HTML report for Azure DevOps."""
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Sentinel Security Report</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f3f2f1; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 4px; box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.132); }}
        .header {{ background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%); color: white; padding: 30px; }}
        .status {{ font-size: 28px; font-weight: 600; margin: 15px 0; }}
        .status.passed {{ color: #107c10; }}
        .status.failed {{ color: #d13438; }}
        .status.warning {{ color: #ff8c00; }}
        .content {{ padding: 30px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .metric {{ background: #faf9f8; padding: 20px; border-radius: 4px; text-align: center; border: 1px solid #edebe9; }}
        .metric h3 {{ margin: 0 0 10px 0; font-size: 36px; color: #323130; font-weight: 600; }}
        .metric p {{ margin: 0; color: #605e5c; }}
        .issues {{ margin: 30px 0; }}
        .issue {{ border: 1px solid #edebe9; margin: 15px 0; padding: 20px; border-radius: 4px; }}
        .issue.critical {{ border-left: 4px solid #d13438; background: #fdf6f6; }}
        .issue.high {{ border-left: 4px solid #ff8c00; background: #fff9f5; }}
        .issue.medium {{ border-left: 4px solid #ffaa44; background: #fffbf7; }}
        .issue.low {{ border-left: 4px solid #605e5c; background: #faf9f8; }}
        .issue h4 {{ margin: 0 0 10px 0; color: #323130; font-weight: 600; }}
        .issue-meta {{ color: #605e5c; font-size: 14px; margin: 10px 0; }}
        .remediation {{ background: #f3f9fd; padding: 15px; border-radius: 4px; margin: 10px 0; border: 1px solid #c7e0f4; }}
        .remediation h5 {{ margin: 0 0 10px 0; color: #0078d4; }}
        .remediation ul {{ margin: 0; padding-left: 20px; }}
        .summary-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .summary-table th, .summary-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #edebe9; }}
        .summary-table th {{ background: #faf9f8; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Compliance Sentinel Security Report</h1>
            <div class="status {result.status.value}">{result.status.value.upper()}</div>
            <p>{result.summary_message}</p>
            <p>Scan completed: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="content">
            <div class="metrics">
                <div class="metric">
                    <h3>{result.total_issues}</h3>
                    <p>Total Issues</p>
                </div>
                <div class="metric">
                    <h3>{result.files_scanned}</h3>
                    <p>Files Scanned</p>
                </div>
                <div class="metric">
                    <h3>{result.scan_duration:.2f}s</h3>
                    <p>Scan Duration</p>
                </div>
                <div class="metric">
                    <h3>{len(result.blocked_issues)}</h3>
                    <p>Blocking Issues</p>
                </div>
            </div>
            
            <h2>📊 Issues Summary</h2>
            <table class="summary-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = result.issues_by_severity.get(severity, 0)
            percentage = (count / result.total_issues * 100) if result.total_issues > 0 else 0
            if count > 0:
                html_content += f'''
                    <tr>
                        <td>{severity.title()}</td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
'''
        
        html_content += '''
                </tbody>
            </table>
            
            <h2>🚨 Security Issues</h2>
            <div class="issues">
'''
        
        for issue in result.all_issues:
            severity_class = issue.severity.value.lower()
            html_content += f'''
                <div class="issue {severity_class}">
                    <h4>{issue.description}</h4>
                    <div class="issue-meta">
                        <strong>File:</strong> {issue.file_path}:{issue.line_number} |
                        <strong>Severity:</strong> {issue.severity.value} |
                        <strong>Category:</strong> {issue.category.value} |
                        <strong>Rule:</strong> {issue.rule_id} |
                        <strong>Confidence:</strong> {issue.confidence:.2f}
                    </div>
'''
            
            if issue.remediation_suggestions:
                html_content += '''
                    <div class="remediation">
                        <h5>💡 Remediation Suggestions</h5>
                        <ul>
'''
                for suggestion in issue.remediation_suggestions:
                    html_content += f'<li>{suggestion}</li>'
                
                html_content += '''
                        </ul>
                    </div>
'''
            
            html_content += '</div>'
        
        html_content += '''
            </div>
        </div>
    </div>
</body>
</html>
'''
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _set_azure_variables(self, result: SecurityGateResult):
        """Set Azure DevOps pipeline variables."""
        variables = {
            'SecurityGate.Status': result.status.value,
            'SecurityGate.TotalIssues': str(result.total_issues),
            'SecurityGate.CriticalIssues': str(result.issues_by_severity.get('CRITICAL', 0)),
            'SecurityGate.HighIssues': str(result.issues_by_severity.get('HIGH', 0)),
            'SecurityGate.MediumIssues': str(result.issues_by_severity.get('MEDIUM', 0)),
            'SecurityGate.LowIssues': str(result.issues_by_severity.get('LOW', 0)),
            'SecurityGate.ScanDuration': str(result.scan_duration),
            'SecurityGate.FilesScanned': str(result.files_scanned)
        }
        
        # Output Azure DevOps logging commands
        for key, value in variables.items():
            print(f"##vso[task.setvariable variable={key}]{value}")
        
        # Also set as environment variables
        for key, value in variables.items():
            os.environ[key.replace('.', '_').upper()] = value
    
    def _create_work_items(self, result: SecurityGateResult, azure_context: Dict[str, Any]):
        """Create work items for critical security issues."""
        # This would integrate with Azure DevOps REST API to create work items
        # For now, we'll create a work items specification file
        
        work_items = []
        
        for issue in result.blocked_issues:
            work_item = {
                "op": "add",
                "path": "/fields/System.WorkItemType",
                "value": "Bug"
            }
            
            fields = {
                "System.Title": f"Security Issue: {issue.description}",
                "System.Description": f'''
<div>
<h3>Security Issue Details</h3>
<p><strong>File:</strong> {issue.file_path}:{issue.line_number}</p>
<p><strong>Severity:</strong> {issue.severity.value}</p>
<p><strong>Category:</strong> {issue.category.value}</p>
<p><strong>Rule:</strong> {issue.rule_id}</p>
<p><strong>Confidence:</strong> {issue.confidence:.2f}</p>

<h4>Remediation Suggestions</h4>
<ul>
''',
                "System.Tags": f"security;{issue.severity.value.lower()};{issue.category.value}",
                "Microsoft.VSTS.Common.Priority": self._severity_to_priority(issue.severity),
                "Microsoft.VSTS.Common.Severity": self._severity_to_azure_severity(issue.severity)
            }
            
            # Add remediation suggestions to description
            for suggestion in issue.remediation_suggestions:
                fields["System.Description"] += f"<li>{suggestion}</li>"
            
            fields["System.Description"] += "</ul></div>"
            
            work_items.append({
                "fields": fields,
                "issue_id": issue.id
            })
        
        # Write work items specification
        with open('security-work-items.json', 'w') as f:
            json.dump(work_items, f, indent=2)
        
        self.logger.info(f"Created work items specification for {len(work_items)} critical issues")
    
    def _severity_to_sarif_level(self, severity):
        """Convert severity to SARIF level."""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning', 
            'LOW': 'note'
        }
        return mapping.get(severity.value, 'warning')
    
    def _severity_to_priority(self, severity):
        """Convert severity to Azure DevOps priority."""
        mapping = {
            'CRITICAL': 1,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3
        }
        return mapping.get(severity.value, 2)
    
    def _severity_to_azure_severity(self, severity):
        """Convert severity to Azure DevOps severity."""
        mapping = {
            'CRITICAL': "1 - Critical",
            'HIGH': "2 - High",
            'MEDIUM': "3 - Medium",
            'LOW': "4 - Low"
        }
        return mapping.get(severity.value, "3 - Medium")


def create_azure_pipeline_template() -> str:
    """Create Azure DevOps pipeline template."""
    return '''
# Azure DevOps pipeline template for Compliance Sentinel

trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  securityGateConfig: 'security-gate.yml'

stages:
- stage: SecurityScan
  displayName: 'Security Scan'
  jobs:
  - job: ComplianceSentinel
    displayName: 'Compliance Sentinel Security Scan'
    
    steps:
    - checkout: self
      fetchDepth: 0
    
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.9'
        addToPath: true
      displayName: 'Set up Python'
    
    - script: |
        pip install compliance-sentinel
      displayName: 'Install Compliance Sentinel'
    
    - script: |
        python -m compliance_sentinel.ci_cd.azure_devops --config $(securityGateConfig)
      displayName: 'Run Security Scan'
      continueOnError: true
    
    - task: PublishTestResults@2
      condition: always()
      inputs:
        testResultsFormat: 'VSTest'
        testResultsFiles: 'security-reports/security-test-results.trx'
        testRunTitle: 'Security Gate Tests'
      displayName: 'Publish Security Test Results'
    
    - task: PublishCodeCoverageResults@1
      condition: always()
      inputs:
        codeCoverageTool: 'Cobertura'
        summaryFileLocation: 'security-reports/security-coverage.xml'
        reportDirectory: 'security-reports'
      displayName: 'Publish Security Coverage'
    
    - task: PublishBuildArtifacts@1
      condition: always()
      inputs:
        pathToPublish: 'security-reports'
        artifactName: 'SecurityReports'
      displayName: 'Publish Security Reports'
    
    - task: PublishSecurityAnalysisLogs@3
      condition: always()
      inputs:
        artifactName: 'CodeAnalysisLogs'
        allTools: false
        sarif: true
        sarifFile: 'security-reports/security-report.sarif'
      displayName: 'Publish Security Analysis Logs'
    
    - script: |
        if [ "$(SecurityGate.Status)" = "failed" ]; then
          echo "##vso[task.logissue type=error]Security gate failed with $(SecurityGate.TotalIssues) issues"
          echo "Critical: $(SecurityGate.CriticalIssues), High: $(SecurityGate.HighIssues)"
          exit 1
        fi
      displayName: 'Check Security Gate Status'
      condition: always()

- stage: Deploy
  displayName: 'Deploy'
  dependsOn: SecurityScan
  condition: and(succeeded(), eq(variables['SecurityGate.Status'], 'passed'))
  jobs:
  - deployment: DeployToProduction
    displayName: 'Deploy to Production'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - script: echo "Deploying to production..."
            displayName: 'Deploy Application'
'''


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Azure DevOps Security Extension')
    parser.add_argument('--source-path', help='Source path (defaults to BUILD_SOURCESDIRECTORY)')
    parser.add_argument('--config', help='Security gate configuration file')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = SecurityGateConfig()
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config_dict = yaml.safe_load(f)
            config = SecurityGateConfig.from_dict(config_dict)
    
    # Execute Azure DevOps task
    azure_devops = AzureDevOpsExtension(config)
    result = azure_devops.execute_pipeline_task(args.source_path)
    
    # Exit with appropriate code
    if result.status.value == 'failed' and config.fail_on_error:
        exit(1)
    else:
        exit(0)