"""CLI command for running comprehensive analysis workflow."""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional
import click
import json

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.models.analysis import AnalysisType
from compliance_sentinel.utils.logging_config import setup_logging


@click.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True))
@click.option('--project', '-p', is_flag=True, help='Analyze entire project')
@click.option('--type', '-t', 'analysis_type', 
              type=click.Choice(['security', 'compliance', 'comprehensive']),
              default='comprehensive', help='Type of analysis to run')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'text', 'summary']),
              default='text', help='Output format')
@click.option('--timeout', type=int, default=60, help='Analysis timeout in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--no-feedback', is_flag=True, help='Disable feedback generation')
def analyze(
    paths: tuple,
    project: bool,
    analysis_type: str,
    output: Optional[str],
    output_format: str,
    timeout: int,
    verbose: bool,
    no_feedback: bool
):
    """Run comprehensive security and compliance analysis.
    
    Examples:
        compliance-sentinel analyze file1.py file2.py
        compliance-sentinel analyze --project
        compliance-sentinel analyze --type security src/
    """
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging({"log_level": log_level})
    
    # Run analysis
    asyncio.run(_run_analysis(
        paths=list(paths),
        project=project,
        analysis_type=analysis_type,
        output=output,
        output_format=output_format,
        timeout=timeout,
        no_feedback=no_feedback
    ))


async def _run_analysis(
    paths: List[str],
    project: bool,
    analysis_type: str,
    output: Optional[str],
    output_format: str,
    timeout: int,
    no_feedback: bool
):
    """Run the analysis workflow."""
    try:
        # Configure agent
        config = SystemConfiguration()
        config.hooks_enabled = False  # Disable hooks for CLI
        config.ide_feedback_enabled = not no_feedback
        config.summary_reports_enabled = True
        config.analysis_timeout = timeout
        
        # Map analysis type
        type_mapping = {
            'security': AnalysisType.SECURITY_SCAN,
            'compliance': AnalysisType.POLICY_VALIDATION,
            'comprehensive': AnalysisType.COMPREHENSIVE
        }
        analysis_type_enum = type_mapping[analysis_type]
        
        # Create and start agent
        agent = ComplianceAgent(config)
        
        async with agent:
            click.echo("🔍 Starting Compliance Sentinel analysis...")
            
            # Run analysis
            if project:
                result = await agent.analyze_project(".")
            elif paths:
                result = await agent.analyze_files(list(paths), analysis_type_enum)
            else:
                click.echo("❌ No files specified. Use --project or provide file paths.")
                sys.exit(1)
            
            # Output results
            if output:
                _save_results(result, output, output_format)
                click.echo(f"📄 Results saved to {output}")
            else:
                _display_results(result, output_format)
            
            # Exit with appropriate code
            if not result.success:
                sys.exit(1)
            elif result.has_blocking_issues:
                click.echo("\n⚠️  Blocking issues found. Consider fixing critical/high severity issues.")
                sys.exit(2)
            else:
                click.echo("\n✅ Analysis completed successfully!")
                sys.exit(0)
                
    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}", err=True)
        sys.exit(1)


def _display_results(result, output_format: str):
    """Display analysis results to console."""
    if output_format == 'json':
        _display_json_results(result)
    elif output_format == 'summary':
        _display_summary_results(result)
    else:
        _display_text_results(result)


def _display_text_results(result):
    """Display detailed text results."""
    click.echo("\n" + "="*60)
    click.echo("📊 COMPLIANCE SENTINEL ANALYSIS RESULTS")
    click.echo("="*60)
    
    # Basic info
    click.echo(f"Request ID: {result.request_id}")
    click.echo(f"Files analyzed: {len(result.file_paths)}")
    click.echo(f"Analysis duration: {result.analysis_duration_ms:.2f}ms")
    click.echo(f"Success: {'✅' if result.success else '❌'}")
    
    if result.error_message:
        click.echo(f"Error: {result.error_message}")
        return
    
    # Issue summary
    click.echo(f"\n📈 ISSUE SUMMARY")
    click.echo(f"Total issues: {result.total_issues}")
    
    if result.total_issues > 0:
        click.echo(f"  🔴 Critical: {result.critical_issues}")
        click.echo(f"  🟠 High: {result.high_issues}")
        click.echo(f"  🟡 Medium: {result.medium_issues}")
        click.echo(f"  🟢 Low: {result.low_issues}")
        
        click.echo(f"\n📋 BREAKDOWN")
        click.echo(f"  Policy violations: {result.policy_violations}")
        click.echo(f"  Dependency vulnerabilities: {result.dependency_vulnerabilities}")
        
        if result.has_blocking_issues:
            click.echo(f"\n⚠️  BLOCKING ISSUES DETECTED")
            click.echo(f"  This code has critical or high severity issues that should be addressed.")
    else:
        click.echo("  🎉 No security issues found!")
    
    # Files analyzed
    click.echo(f"\n📁 FILES ANALYZED")
    for file_path in result.file_paths:
        click.echo(f"  • {file_path}")
    
    # Feedback status
    if result.feedback_generated:
        click.echo(f"\n💬 Feedback generated and delivered")
    
    click.echo("="*60)


def _display_summary_results(result):
    """Display summary results."""
    status_icon = "✅" if result.success and not result.has_blocking_issues else "⚠️" if result.success else "❌"
    
    click.echo(f"\n{status_icon} Analysis Summary:")
    click.echo(f"  Files: {len(result.file_paths)}")
    click.echo(f"  Issues: {result.total_issues}")
    
    if result.total_issues > 0:
        click.echo(f"  Severity: {result.critical_issues}C/{result.high_issues}H/{result.medium_issues}M/{result.low_issues}L")
        
        if result.has_blocking_issues:
            click.echo(f"  ⚠️  Has blocking issues")
    
    click.echo(f"  Duration: {result.analysis_duration_ms:.0f}ms")


def _display_json_results(result):
    """Display JSON results."""
    result_dict = {
        'request_id': result.request_id,
        'success': result.success,
        'files_analyzed': len(result.file_paths),
        'file_paths': result.file_paths,
        'total_issues': result.total_issues,
        'severity_breakdown': result.severity_breakdown,
        'policy_violations': result.policy_violations,
        'dependency_vulnerabilities': result.dependency_vulnerabilities,
        'has_blocking_issues': result.has_blocking_issues,
        'analysis_duration_ms': result.analysis_duration_ms,
        'feedback_generated': result.feedback_generated,
        'error_message': result.error_message,
        'created_at': result.created_at.isoformat()
    }
    
    click.echo(json.dumps(result_dict, indent=2))


def _save_results(result, output_path: str, output_format: str):
    """Save results to file."""
    output_file = Path(output_path)
    
    if output_format == 'json':
        result_dict = {
            'request_id': result.request_id,
            'success': result.success,
            'files_analyzed': len(result.file_paths),
            'file_paths': result.file_paths,
            'total_issues': result.total_issues,
            'severity_breakdown': result.severity_breakdown,
            'policy_violations': result.policy_violations,
            'dependency_vulnerabilities': result.dependency_vulnerabilities,
            'has_blocking_issues': result.has_blocking_issues,
            'analysis_duration_ms': result.analysis_duration_ms,
            'feedback_generated': result.feedback_generated,
            'error_message': result.error_message,
            'created_at': result.created_at.isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(result_dict, f, indent=2)
    
    else:
        # Save as text
        with open(output_file, 'w') as f:
            f.write("COMPLIANCE SENTINEL ANALYSIS RESULTS\n")
            f.write("="*50 + "\n\n")
            f.write(f"Request ID: {result.request_id}\n")
            f.write(f"Files analyzed: {len(result.file_paths)}\n")
            f.write(f"Analysis duration: {result.analysis_duration_ms:.2f}ms\n")
            f.write(f"Success: {result.success}\n\n")
            
            if result.error_message:
                f.write(f"Error: {result.error_message}\n")
            else:
                f.write(f"ISSUE SUMMARY\n")
                f.write(f"Total issues: {result.total_issues}\n")
                f.write(f"  Critical: {result.critical_issues}\n")
                f.write(f"  High: {result.high_issues}\n")
                f.write(f"  Medium: {result.medium_issues}\n")
                f.write(f"  Low: {result.low_issues}\n\n")
                
                f.write(f"BREAKDOWN\n")
                f.write(f"  Policy violations: {result.policy_violations}\n")
                f.write(f"  Dependency vulnerabilities: {result.dependency_vulnerabilities}\n\n")
                
                f.write(f"FILES ANALYZED\n")
                for file_path in result.file_paths:
                    f.write(f"  • {file_path}\n")


if __name__ == '__main__':
    analyze()