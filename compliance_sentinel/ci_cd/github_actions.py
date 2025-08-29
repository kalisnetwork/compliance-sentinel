"""GitHub Actions workflow integration for Compliance Sentinel."""

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


class GitHubActionsWorkflow:
    """GitHub Actions integration for security scanning."""
    
    def __init__(self, config: Optional[SecurityGateConfig] = None):
        """Initialize GitHub Actions workflow."""
        self.config = config or SecurityGateConfig()
        self.evaluator = SecurityGateEvaluator(self.config)
        self.logger = logging.getLogger(__name__)
    
    def execute_action(self, workspace_path: str = None) -> SecurityGateResult:
        """Execute security scan as GitHub Action."""
        workspace_path = workspace_path or os.environ.get('GITHUB_WORKSPACE', '.')
        
        try:
            self.logger.info(f"Starting GitHub Actions security scan in: {workspace_path}")
            
            # Get GitHub context
            github_context = self._get_github_context()
            
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
            
            # Generate reports and outputs
            self._generate_github_outputs(gate_result, workspace_path)
            self._set_github_outputs(gate_result)
            
            # Create PR comments if applicable
            if github_context.get('event_name') == 'pull_request':
                self._create_pr_comment(gate_result, github_context)
            
            # Create check run
            self._create_check_run(gate_result, github_context)
            
            return gate_result
            
        except Exception as e:
            self.logger.error(f"GitHub Actions security scan failed: {e}")
            raise
    
    def _get_github_context(self) -> Dict[str, Any]:
        """Get GitHub Actions context from environment."""
        context = {
            'event_name': os.environ.get('GITHUB_EVENT_NAME'),
            'repository': os.environ.get('GITHUB_REPOSITORY'),
            'ref': os.environ.get('GITHUB_REF'),
            'sha': os.environ.get('GITHUB_SHA'),
            'actor': os.environ.get('GITHUB_ACTOR'),
            'workflow': os.environ.get('GITHUB_WORKFLOW'),
            'run_id': os.environ.get('GITHUB_RUN_ID'),
            'run_number': os.environ.get('GITHUB_RUN_NUMBER')
        }
        
        # Load event payload if available
        event_path = os.environ.get('GITHUB_EVENT_PATH')
        if event_path and os.path.exists(event_path):
            with open(event_path, 'r') as f:
                context['event'] = json.load(f)
        
        return context
    
    def _generate_github_outputs(self, result: SecurityGateResult, workspace_path: str):
        """Generate outputs for GitHub Actions."""
        outputs_dir = Path(workspace_path) / "security-reports"
        outputs_dir.mkdir(exist_ok=True)
        
        # JSON report
        json_report_path = outputs_dir / "security-report.json"
        with open(json_report_path, 'w') as f:
            f.write(result.to_json())
        
        # SARIF report for GitHub Security tab
        sarif_report_path = outputs_dir / "security-report.sarif"
        self._generate_sarif_report(result, sarif_report_path)
        
        # Markdown summary for job summary
        markdown_path = outputs_dir / "security-summary.md"
        self._generate_markdown_summary(result, markdown_path)
        
        self.logger.info(f"GitHub Actions outputs generated in {outputs_dir}")
    
    def _set_github_outputs(self, result: SecurityGateResult):
        """Set GitHub Actions outputs."""
        outputs = {
            'status': result.status.value,
            'total-issues': str(result.total_issues),
            'critical-issues': str(result.issues_by_severity.get('CRITICAL', 0)),
            'high-issues': str(result.issues_by_severity.get('HIGH', 0)),
            'medium-issues': str(result.issues_by_severity.get('MEDIUM', 0)),
            'low-issues': str(result.issues_by_severity.get('LOW', 0)),
            'scan-duration': str(result.scan_duration),
            'files-scanned': str(result.files_scanned),
            'summary': result.summary_message
        }
        
        # Write to GitHub Actions output file
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                for key, value in outputs.items():
                    f.write(f'{key}={value}\\n')
        
        # Also set as environment variables
        for key, value in outputs.items():
            env_key = f'SECURITY_GATE_{key.upper().replace("-", "_")}'
            os.environ[env_key] = value
    
    def _generate_sarif_report(self, result: SecurityGateResult, output_path: Path):
        """Generate SARIF report for GitHub Security tab."""
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
                    "results": []
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
                    "shortDescription": {
                        "text": issue.description
                    },
                    "fullDescription": {
                        "text": issue.description
                    },
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
                "message": {
                    "text": issue.description
                },
                "level": self._severity_to_sarif_level(issue.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": issue.file_path
                            },
                            "region": {
                                "startLine": issue.line_number
                            }
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
    
    def _generate_markdown_summary(self, result: SecurityGateResult, output_path: Path):
        """Generate markdown summary for GitHub Actions job summary."""
        status_emoji = {
            'passed': '✅',
            'failed': '❌',
            'warning': '⚠️'
        }
        
        markdown = f'''# 🛡️ Compliance Sentinel Security Report

## {status_emoji.get(result.status.value, '❓')} Status: {result.status.value.upper()}

{result.summary_message}

### 📊 Summary

| Metric | Value |
|--------|-------|
| Total Issues | {result.total_issues} |
| Files Scanned | {result.files_scanned} |
| Scan Duration | {result.scan_duration:.2f}s |

### 🚨 Issues by Severity

| Severity | Count |
|----------|-------|
'''
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = result.issues_by_severity.get(severity, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                markdown += f'| {emoji} {severity.title()} | {count} |\\n'
        
        if result.blocked_issues:
            markdown += f'''
### ❌ Blocking Issues ({len(result.blocked_issues)})

'''
            for issue in result.blocked_issues[:10]:  # Limit to first 10
                markdown += f'''
**{issue.description}**
- File: `{issue.file_path}:{issue.line_number}`
- Severity: {issue.severity.value}
- Rule: {issue.rule_id}
'''
            
            if len(result.blocked_issues) > 10:
                markdown += f'\\n*... and {len(result.blocked_issues) - 10} more issues*\\n'
        
        if result.warning_issues:
            markdown += f'''
### ⚠️ Warning Issues ({len(result.warning_issues)})

'''
            for issue in result.warning_issues[:5]:  # Limit to first 5
                markdown += f'''
**{issue.description}**
- File: `{issue.file_path}:{issue.line_number}`
- Severity: {issue.severity.value}
'''
        
        markdown += '''
### 📋 Next Steps

'''
        if result.status.value == 'failed':
            markdown += '''
1. Review and fix the blocking security issues listed above
2. Re-run the security scan to verify fixes
3. Consider implementing additional security controls
'''
        elif result.status.value == 'warning':
            markdown += '''
1. Review the warning issues when possible
2. Consider if any warnings should be promoted to blocking
3. Monitor trends in security issues over time
'''
        else:
            markdown += '''
1. Great job! No security issues found
2. Continue following secure coding practices
3. Regular security scans help maintain code quality
'''
        
        with open(output_path, 'w') as f:
            f.write(markdown)
        
        # Also write to GitHub Actions job summary
        github_step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if github_step_summary:
            with open(github_step_summary, 'a') as f:
                f.write(markdown)
    
    def _create_pr_comment(self, result: SecurityGateResult, github_context: Dict[str, Any]):
        """Create PR comment with security scan results."""
        # This would integrate with GitHub API to post comments
        # For now, we'll create a comment file that can be used by other actions
        
        comment_file = Path("security-pr-comment.md")
        
        status_emoji = {
            'passed': '✅',
            'failed': '❌', 
            'warning': '⚠️'
        }
        
        comment = f'''## {status_emoji.get(result.status.value, '❓')} Security Scan Results

**Status:** {result.status.value.upper()}  
**Issues Found:** {result.total_issues}  
**Files Scanned:** {result.files_scanned}  

'''
        
        if result.blocked_issues:
            comment += f'''
### 🚨 Critical Issues ({len(result.blocked_issues)})

These issues must be fixed before merging:

'''
            for issue in result.blocked_issues[:5]:
                comment += f'- **{issue.description}** in `{issue.file_path}:{issue.line_number}`\\n'
            
            if len(result.blocked_issues) > 5:
                comment += f'- *... and {len(result.blocked_issues) - 5} more*\\n'
        
        comment += '''
<details>
<summary>View Full Report</summary>

'''
        comment += f'Scan completed in {result.scan_duration:.2f} seconds\\n\\n'
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = result.issues_by_severity.get(severity, 0)
            if count > 0:
                comment += f'- {severity.title()}: {count}\\n'
        
        comment += '\\n</details>'
        
        with open(comment_file, 'w') as f:
            f.write(comment)
    
    def _create_check_run(self, result: SecurityGateResult, github_context: Dict[str, Any]):
        """Create GitHub check run (would require GitHub API integration)."""
        # This would create a check run via GitHub API
        # For now, we'll create a check run summary file
        
        check_run = {
            'name': 'Compliance Sentinel Security Scan',
            'head_sha': github_context.get('sha'),
            'status': 'completed',
            'conclusion': 'success' if result.status.value == 'passed' else 'failure',
            'output': {
                'title': f'Security Scan {result.status.value.title()}',
                'summary': result.summary_message,
                'text': '\\n'.join(result.detailed_messages)
            }
        }
        
        with open('security-check-run.json', 'w') as f:
            json.dump(check_run, f, indent=2)
    
    def _severity_to_sarif_level(self, severity):
        """Convert severity to SARIF level."""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error', 
            'MEDIUM': 'warning',
            'LOW': 'note'
        }
        return mapping.get(severity.value, 'warning')


def create_github_workflow() -> str:
    """Create GitHub Actions workflow YAML."""
    return '''
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      checks: write
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install Compliance Sentinel
      run: |
        pip install compliance-sentinel
    
    - name: Run Security Scan
      id: security-scan
      run: |
        python -m compliance_sentinel.ci_cd.github_actions
      continue-on-error: true
    
    - name: Upload SARIF results
      if: always()
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-reports/security-report.sarif
    
    - name: Upload security reports
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: security-reports/
    
    - name: Comment PR
      if: github.event_name == 'pull_request' && always()
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          if (fs.existsSync('security-pr-comment.md')) {
            const comment = fs.readFileSync('security-pr-comment.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
          }
    
    - name: Fail on security issues
      if: steps.security-scan.outputs.status == 'failed'
      run: |
        echo "Security scan failed with ${{ steps.security-scan.outputs.total-issues }} issues"
        echo "Critical: ${{ steps.security-scan.outputs.critical-issues }}"
        echo "High: ${{ steps.security-scan.outputs.high-issues }}"
        exit 1
'''


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='GitHub Actions Security Scan')
    parser.add_argument('--workspace', help='Workspace path (defaults to GITHUB_WORKSPACE)')
    parser.add_argument('--config', help='Security gate configuration file')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = SecurityGateConfig()
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config_dict = yaml.safe_load(f)
            config = SecurityGateConfig.from_dict(config_dict)
    
    # Execute GitHub Actions workflow
    github_workflow = GitHubActionsWorkflow(config)
    result = github_workflow.execute_action(args.workspace)
    
    # Exit with appropriate code
    if result.status.value == 'failed' and config.fail_on_error:
        exit(1)
    else:
        exit(0)