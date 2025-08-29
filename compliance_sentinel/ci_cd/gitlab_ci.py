"""GitLab CI integration for Compliance Sentinel."""

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


class GitLabCIIntegration:
    """GitLab CI integration for security scanning."""
    
    def __init__(self, config: Optional[SecurityGateConfig] = None):
        """Initialize GitLab CI integration."""
        self.config = config or SecurityGateConfig()
        self.evaluator = SecurityGateEvaluator(self.config)
        self.logger = logging.getLogger(__name__)
    
    def execute_security_job(self, project_path: str = None) -> SecurityGateResult:
        """Execute security scan as GitLab CI job."""
        project_path = project_path or os.environ.get('CI_PROJECT_DIR', '.')
        
        try:
            self.logger.info(f"Starting GitLab CI security scan in: {project_path}")
            
            # Get GitLab CI context
            gitlab_context = self._get_gitlab_context()
            
            # Initialize project analyzer
            analyzer = ProjectAnalyzer()
            
            # Scan the project
            scan_result = analyzer.scan_project(project_path)
            
            # Extract issues and metadata
            issues = scan_result.get('issues', [])
            scan_duration = scan_result.get('summary', {}).get('scan_duration', 0.0)
            files_scanned = scan_result.get('summary', {}).get('files_scanned', 0)
            
            # Evaluate against security gate
            gate_result = self.evaluator.evaluate(issues, scan_duration, files_scanned)
            
            # Generate GitLab-specific outputs
            self._generate_gitlab_outputs(gate_result, project_path)
            self._create_gitlab_reports(gate_result, gitlab_context)
            
            # Create merge request notes if applicable
            if gitlab_context.get('merge_request_iid'):
                self._create_mr_note(gate_result, gitlab_context)
            
            return gate_result
            
        except Exception as e:
            self.logger.error(f"GitLab CI security scan failed: {e}")
            raise
    
    def _get_gitlab_context(self) -> Dict[str, Any]:
        """Get GitLab CI context from environment variables."""
        return {
            'project_id': os.environ.get('CI_PROJECT_ID'),
            'project_name': os.environ.get('CI_PROJECT_NAME'),
            'project_path': os.environ.get('CI_PROJECT_PATH'),
            'project_url': os.environ.get('CI_PROJECT_URL'),
            'pipeline_id': os.environ.get('CI_PIPELINE_ID'),
            'pipeline_url': os.environ.get('CI_PIPELINE_URL'),
            'job_id': os.environ.get('CI_JOB_ID'),
            'job_name': os.environ.get('CI_JOB_NAME'),
            'job_url': os.environ.get('CI_JOB_URL'),
            'commit_sha': os.environ.get('CI_COMMIT_SHA'),
            'commit_ref_name': os.environ.get('CI_COMMIT_REF_NAME'),
            'merge_request_iid': os.environ.get('CI_MERGE_REQUEST_IID'),
            'merge_request_title': os.environ.get('CI_MERGE_REQUEST_TITLE'),
            'runner_description': os.environ.get('CI_RUNNER_DESCRIPTION'),
            'gitlab_user_login': os.environ.get('GITLAB_USER_LOGIN')
        }
    
    def _generate_gitlab_outputs(self, result: SecurityGateResult, project_path: str):
        """Generate outputs for GitLab CI."""
        outputs_dir = Path(project_path) / "security-reports"
        outputs_dir.mkdir(exist_ok=True)
        
        # JSON report
        json_report_path = outputs_dir / "gl-security-report.json"
        with open(json_report_path, 'w') as f:
            f.write(result.to_json())
        
        # GitLab Security Report format
        gitlab_security_report = self._generate_gitlab_security_report(result)
        gitlab_report_path = outputs_dir / "gl-sast-report.json"
        with open(gitlab_report_path, 'w') as f:
            json.dump(gitlab_security_report, f, indent=2)
        
        # JUnit XML for test reports
        junit_report_path = outputs_dir / "gl-junit-report.xml"
        self._generate_junit_xml(result, junit_report_path)
        
        # Code Quality report
        code_quality_report = self._generate_code_quality_report(result)
        code_quality_path = outputs_dir / "gl-code-quality-report.json"
        with open(code_quality_path, 'w') as f:
            json.dump(code_quality_report, f, indent=2)
        
        self.logger.info(f"GitLab CI outputs generated in {outputs_dir}")
    
    def _generate_gitlab_security_report(self, result: SecurityGateResult) -> Dict[str, Any]:
        """Generate GitLab Security Report format."""
        vulnerabilities = []
        
        for issue in result.all_issues:
            vulnerability = {
                "id": issue.id,
                "category": "sast",
                "name": issue.description,
                "message": issue.description,
                "description": issue.description,
                "severity": self._severity_to_gitlab_severity(issue.severity),
                "confidence": self._confidence_to_gitlab_confidence(issue.confidence),
                "scanner": {
                    "id": "compliance-sentinel",
                    "name": "Compliance Sentinel"
                },
                "location": {
                    "file": issue.file_path,
                    "start_line": issue.line_number,
                    "end_line": issue.line_number
                },
                "identifiers": [
                    {
                        "type": "compliance_sentinel_rule_id",
                        "name": issue.rule_id,
                        "value": issue.rule_id
                    }
                ],
                "details": {
                    "category": issue.category.value,
                    "remediation_suggestions": issue.remediation_suggestions
                }
            }
            vulnerabilities.append(vulnerability)
        
        return {
            "version": "14.0.0",
            "vulnerabilities": vulnerabilities,
            "remediations": [],
            "scan": {
                "scanner": {
                    "id": "compliance-sentinel",
                    "name": "Compliance Sentinel",
                    "version": "1.0.0"
                },
                "type": "sast",
                "start_time": result.timestamp.isoformat(),
                "end_time": result.timestamp.isoformat(),
                "status": "success"
            }
        }
    
    def _generate_code_quality_report(self, result: SecurityGateResult) -> List[Dict[str, Any]]:
        """Generate GitLab Code Quality report format."""
        code_quality_issues = []
        
        for issue in result.all_issues:
            code_quality_issue = {
                "description": issue.description,
                "check_name": issue.rule_id,
                "fingerprint": issue.id,
                "severity": self._severity_to_code_quality_severity(issue.severity),
                "location": {
                    "path": issue.file_path,
                    "lines": {
                        "begin": issue.line_number,
                        "end": issue.line_number
                    }
                },
                "categories": [issue.category.value],
                "remediation_points": self._calculate_remediation_points(issue.severity)
            }
            code_quality_issues.append(code_quality_issue)
        
        return code_quality_issues
    
    def _generate_junit_xml(self, result: SecurityGateResult, output_path: Path):
        """Generate JUnit XML report for GitLab test reports."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        # Create test suite
        testsuite = Element('testsuite')
        testsuite.set('name', 'Security Gate')
        testsuite.set('tests', str(len(result.all_issues) + 1))
        testsuite.set('failures', str(len(result.blocked_issues)))
        testsuite.set('time', str(result.scan_duration))
        testsuite.set('timestamp', result.timestamp.isoformat())
        
        # Overall security gate test
        gate_test = SubElement(testsuite, 'testcase')
        gate_test.set('classname', 'SecurityGate')
        gate_test.set('name', 'OverallSecurityGate')
        gate_test.set('time', str(result.scan_duration))
        
        if result.status.value != 'passed':
            failure = SubElement(gate_test, 'failure')
            failure.set('message', result.summary_message)
            failure.text = '\\n'.join(result.detailed_messages)
        
        # Individual issue tests
        for issue in result.all_issues:
            testcase = SubElement(testsuite, 'testcase')
            testcase.set('classname', f'SecurityIssue.{issue.category.value}')
            testcase.set('name', f'{issue.rule_id}_{issue.line_number}')
            
            if issue in result.blocked_issues:
                failure = SubElement(testcase, 'failure')
                failure.set('message', issue.description)
                failure.set('type', issue.severity.value)
                failure.text = f"File: {issue.file_path}\\nLine: {issue.line_number}\\nRule: {issue.rule_id}"
        
        # Write XML file
        xml_str = minidom.parseString(tostring(testsuite)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
    
    def _create_gitlab_reports(self, result: SecurityGateResult, gitlab_context: Dict[str, Any]):
        """Create GitLab-specific report artifacts."""
        # Create dotenv file for GitLab CI variables
        dotenv_content = f'''SECURITY_GATE_STATUS={result.status.value}
SECURITY_GATE_TOTAL_ISSUES={result.total_issues}
SECURITY_GATE_CRITICAL_ISSUES={result.issues_by_severity.get('CRITICAL', 0)}
SECURITY_GATE_HIGH_ISSUES={result.issues_by_severity.get('HIGH', 0)}
SECURITY_GATE_MEDIUM_ISSUES={result.issues_by_severity.get('MEDIUM', 0)}
SECURITY_GATE_LOW_ISSUES={result.issues_by_severity.get('LOW', 0)}
SECURITY_GATE_SCAN_DURATION={result.scan_duration}
SECURITY_GATE_FILES_SCANNED={result.files_scanned}
'''
        
        with open('security-gate.env', 'w') as f:
            f.write(dotenv_content)
        
        # Create GitLab Pages report
        self._create_gitlab_pages_report(result)
    
    def _create_gitlab_pages_report(self, result: SecurityGateResult):
        """Create HTML report for GitLab Pages."""
        pages_dir = Path("public")
        pages_dir.mkdir(exist_ok=True)
        
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #fafafa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .status {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
        .status.passed {{ color: #28a745; }}
        .status.failed {{ color: #dc3545; }}
        .status.warning {{ color: #ffc107; }}
        .content {{ padding: 30px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }}
        .metric h3 {{ margin: 0 0 10px 0; font-size: 32px; color: #333; }}
        .metric p {{ margin: 0; color: #666; }}
        .issues {{ margin: 30px 0; }}
        .issue {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 8px; }}
        .issue.critical {{ border-left: 5px solid #dc3545; background: #fff5f5; }}
        .issue.high {{ border-left: 5px solid #fd7e14; background: #fff8f0; }}
        .issue.medium {{ border-left: 5px solid #ffc107; background: #fffbf0; }}
        .issue.low {{ border-left: 5px solid #6c757d; background: #f8f9fa; }}
        .issue h4 {{ margin: 0 0 10px 0; color: #333; }}
        .issue-meta {{ color: #666; font-size: 14px; margin: 10px 0; }}
        .remediation {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .remediation h5 {{ margin: 0 0 10px 0; color: #0366d6; }}
        .remediation ul {{ margin: 0; padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
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
                    <h3>{result.issues_by_severity.get('CRITICAL', 0) + result.issues_by_severity.get('HIGH', 0)}</h3>
                    <p>Critical + High</p>
                </div>
            </div>
            
            <h2>📊 Issues by Severity</h2>
            <div class="metrics">
'''
        
        severity_colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#6c757d'}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = result.issues_by_severity.get(severity, 0)
            if count > 0:
                color = severity_colors[severity]
                html_content += f'''
                <div class="metric" style="border-left-color: {color};">
                    <h3>{count}</h3>
                    <p>{severity.title()}</p>
                </div>
'''
        
        html_content += '''
            </div>
            
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
        
        with open(pages_dir / "index.html", 'w') as f:
            f.write(html_content)
    
    def _create_mr_note(self, result: SecurityGateResult, gitlab_context: Dict[str, Any]):
        """Create merge request note (would require GitLab API integration)."""
        # This would post a note to the merge request via GitLab API
        # For now, we'll create a note file that can be used by other tools
        
        status_emoji = {'passed': '✅', 'failed': '❌', 'warning': '⚠️'}
        
        note_content = f'''## {status_emoji.get(result.status.value, '❓')} Security Scan Results

**Status:** {result.status.value.upper()}  
**Issues Found:** {result.total_issues}  
**Files Scanned:** {result.files_scanned}  
**Scan Duration:** {result.scan_duration:.2f}s  

'''
        
        if result.blocked_issues:
            note_content += f'''
### 🚨 Blocking Issues ({len(result.blocked_issues)})

These issues must be resolved before merging:

'''
            for issue in result.blocked_issues[:5]:
                note_content += f'- **{issue.description}** in `{issue.file_path}:{issue.line_number}` ({issue.severity.value})\\n'
            
            if len(result.blocked_issues) > 5:
                note_content += f'- *... and {len(result.blocked_issues) - 5} more issues*\\n'
        
        if result.warning_issues:
            note_content += f'''
### ⚠️ Warning Issues ({len(result.warning_issues)})

Consider addressing these issues:

'''
            for issue in result.warning_issues[:3]:
                note_content += f'- **{issue.description}** in `{issue.file_path}:{issue.line_number}`\\n'
        
        note_content += f'''
---
📊 [View Full Report]({gitlab_context.get('job_url', '')}/artifacts/file/public/index.html)
'''
        
        with open('mr-note.md', 'w') as f:
            f.write(note_content)
    
    def _severity_to_gitlab_severity(self, severity):
        """Convert severity to GitLab Security Report severity."""
        mapping = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        }
        return mapping.get(severity.value, 'Unknown')
    
    def _confidence_to_gitlab_confidence(self, confidence: float):
        """Convert confidence to GitLab Security Report confidence."""
        if confidence >= 0.9:
            return 'High'
        elif confidence >= 0.7:
            return 'Medium'
        else:
            return 'Low'
    
    def _severity_to_code_quality_severity(self, severity):
        """Convert severity to Code Quality severity."""
        mapping = {
            'CRITICAL': 'blocker',
            'HIGH': 'critical',
            'MEDIUM': 'major',
            'LOW': 'minor'
        }
        return mapping.get(severity.value, 'info')
    
    def _calculate_remediation_points(self, severity):
        """Calculate remediation points for Code Quality."""
        mapping = {
            'CRITICAL': 50000,
            'HIGH': 10000,
            'MEDIUM': 5000,
            'LOW': 1000
        }
        return mapping.get(severity.value, 1000)


def create_gitlab_ci_template() -> str:
    """Create GitLab CI template for security scanning."""
    return '''
# GitLab CI template for Compliance Sentinel security scanning

stages:
  - security
  - deploy

variables:
  SECURITY_GATE_CONFIG: "security-gate.yml"

security_scan:
  stage: security
  image: python:3.9
  
  before_script:
    - pip install compliance-sentinel
  
  script:
    - python -m compliance_sentinel.ci_cd.gitlab_ci --config $SECURITY_GATE_CONFIG
  
  artifacts:
    when: always
    expire_in: 1 week
    paths:
      - security-reports/
      - public/
    reports:
      junit: security-reports/gl-junit-report.xml
      sast: security-reports/gl-sast-report.json
      codequality: security-reports/gl-code-quality-report.json
    dotenv: security-gate.env
  
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Optional: Deploy security report to GitLab Pages
pages:
  stage: deploy
  dependencies:
    - security_scan
  script:
    - echo "Deploying security report to GitLab Pages"
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  needs:
    - security_scan

# Optional: Block deployment on security issues
deploy_production:
  stage: deploy
  script:
    - |
      if [ "$SECURITY_GATE_STATUS" = "failed" ]; then
        echo "Deployment blocked due to security issues"
        echo "Critical issues: $SECURITY_GATE_CRITICAL_ISSUES"
        echo "High issues: $SECURITY_GATE_HIGH_ISSUES"
        exit 1
      fi
    - echo "Deploying to production..."
    # Add your deployment commands here
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  needs:
    - security_scan
'''


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='GitLab CI Security Integration')
    parser.add_argument('--project-path', help='Project path (defaults to CI_PROJECT_DIR)')
    parser.add_argument('--config', help='Security gate configuration file')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = SecurityGateConfig()
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config_dict = yaml.safe_load(f)
            config = SecurityGateConfig.from_dict(config_dict)
    
    # Execute GitLab CI job
    gitlab_ci = GitLabCIIntegration(config)
    result = gitlab_ci.execute_security_job(args.project_path)
    
    # Exit with appropriate code
    if result.status.value == 'failed' and config.fail_on_error:
        exit(1)
    else:
        exit(0)