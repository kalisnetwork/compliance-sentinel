"""CLI commands for configuration management."""

import click
import json
import yaml
from pathlib import Path
from typing import Optional

from compliance_sentinel.config.config_manager import (
    ConfigManager, ProjectConfig, AnalysisRuleConfig, 
    SeverityThresholdConfig, MCPServerConfig
)
from compliance_sentinel.config.validator import ConfigValidator


@click.group(name='config')
def config_group():
    """Configuration management commands."""
    pass


@config_group.command()
@click.option('--project-name', '-n', required=True, help='Name of the project')
@click.option('--description', '-d', help='Project description')
@click.option('--scope', type=click.Choice(['local', 'project', 'user']), 
              default='project', help='Configuration scope')
def init(project_name: str, description: Optional[str], scope: str):
    """Initialize a new configuration file."""
    try:
        config_manager = ConfigManager()
        
        # Create default configuration
        config = config_manager.create_default_config(project_name)
        if description:
            config.description = description
        
        # Save configuration
        if config_manager.save_project_config(config, scope):
            click.echo(f"✅ Configuration initialized for project '{project_name}' in {scope} scope")
        else:
            click.echo("❌ Failed to initialize configuration", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error initializing configuration: {e}", err=True)


@config_group.command()
@click.option('--format', '-f', type=click.Choice(['yaml', 'json']), 
              default='yaml', help='Output format')
def show(format: str):
    """Show current configuration."""
    try:
        config_manager = ConfigManager()
        config = config_manager.load_project_config()
        
        if format == 'json':
            config_dict = config_manager._config_to_dict(config)
            click.echo(json.dumps(config_dict, indent=2, default=str))
        else:
            config_dict = config_manager._config_to_dict(config)
            click.echo(yaml.dump(config_dict, default_flow_style=False, indent=2))
            
    except Exception as e:
        click.echo(f"❌ Error showing configuration: {e}", err=True)


@config_group.command()
def validate():
    """Validate current configuration."""
    try:
        config_manager = ConfigManager()
        config = config_manager.load_project_config()
        
        validator = ConfigValidator()
        result = validator.validate_project_config(config)
        
        if result['valid']:
            click.echo("✅ Configuration is valid")
        else:
            click.echo("❌ Configuration validation failed:")
            for error in result['errors']:
                click.echo(f"  • {error}")
        
        if result['warnings']:
            click.echo("\n⚠️  Warnings:")
            for warning in result['warnings']:
                click.echo(f"  • {warning}")
                
    except Exception as e:
        click.echo(f"❌ Error validating configuration: {e}", err=True)


@config_group.command()
@click.argument('output_file', type=click.Path())
@click.option('--format', '-f', type=click.Choice(['yaml', 'json']), 
              default='yaml', help='Export format')
def export(output_file: str, format: str):
    """Export configuration to file."""
    try:
        config_manager = ConfigManager()
        output_path = Path(output_file)
        
        if config_manager.export_config(output_path, format):
            click.echo(f"✅ Configuration exported to {output_file}")
        else:
            click.echo("❌ Failed to export configuration", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error exporting configuration: {e}", err=True)


@config_group.command()
@click.argument('input_file', type=click.Path(exists=True))
def import_config(input_file: str):
    """Import configuration from file."""
    try:
        config_manager = ConfigManager()
        input_path = Path(input_file)
        
        if config_manager.import_config(input_path):
            click.echo(f"✅ Configuration imported from {input_file}")
        else:
            click.echo("❌ Failed to import configuration", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error importing configuration: {e}", err=True)


@config_group.group(name='rules')
def rules_group():
    """Custom rules management."""
    pass


@rules_group.command()
def list():
    """List custom analysis rules."""
    try:
        config_manager = ConfigManager()
        rules = config_manager.get_custom_rules()
        
        if not rules:
            click.echo("No custom rules configured")
            return
        
        click.echo(f"📋 Custom Analysis Rules ({len(rules)} total):")
        click.echo("=" * 50)
        
        for rule in rules:
            status = "✅ Enabled" if rule.enabled else "❌ Disabled"
            click.echo(f"\n{rule.rule_id}: {rule.name}")
            click.echo(f"  Status: {status}")
            click.echo(f"  Severity: {rule.severity.upper()}")
            click.echo(f"  Description: {rule.description}")
            if rule.pattern:
                click.echo(f"  Pattern: {rule.pattern}")
            if rule.file_patterns:
                click.echo(f"  File patterns: {', '.join(rule.file_patterns)}")
                
    except Exception as e:
        click.echo(f"❌ Error listing rules: {e}", err=True)


@rules_group.command()
@click.option('--rule-id', '-i', required=True, help='Rule ID')
@click.option('--name', '-n', required=True, help='Rule name')
@click.option('--description', '-d', required=True, help='Rule description')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']),
              required=True, help='Rule severity')
@click.option('--pattern', '-p', help='Regex pattern to match')
@click.option('--file-pattern', '-f', multiple=True, help='File patterns to apply rule to')
@click.option('--message', '-m', help='Custom violation message')
@click.option('--remediation', '-r', help='Remediation guidance')
def add(rule_id: str, name: str, description: str, severity: str, 
        pattern: Optional[str], file_pattern: tuple, 
        message: Optional[str], remediation: Optional[str]):
    """Add a custom analysis rule."""
    try:
        config_manager = ConfigManager()
        
        rule = AnalysisRuleConfig(
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            pattern=pattern,
            file_patterns=list(file_pattern),
            custom_message=message,
            remediation_guidance=remediation
        )
        
        if config_manager.add_custom_rule(rule):
            click.echo(f"✅ Added custom rule '{rule_id}'")
        else:
            click.echo("❌ Failed to add custom rule", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error adding rule: {e}", err=True)


@rules_group.command()
@click.argument('rule_id')
def remove(rule_id: str):
    """Remove a custom analysis rule."""
    try:
        config_manager = ConfigManager()
        
        if config_manager.remove_custom_rule(rule_id):
            click.echo(f"✅ Removed custom rule '{rule_id}'")
        else:
            click.echo(f"❌ Rule '{rule_id}' not found", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error removing rule: {e}", err=True)


@config_group.group(name='thresholds')
def thresholds_group():
    """Severity thresholds management."""
    pass


@thresholds_group.command()
def show():
    """Show current severity thresholds."""
    try:
        config_manager = ConfigManager()
        thresholds = config_manager.get_effective_severity_thresholds()
        
        click.echo("📊 Severity Thresholds:")
        click.echo("=" * 30)
        click.echo(f"Critical: {thresholds.critical_threshold} (score: {thresholds.critical_score})")
        click.echo(f"High: {thresholds.high_threshold} (score: {thresholds.high_score})")
        click.echo(f"Medium: {thresholds.medium_threshold} (score: {thresholds.medium_score})")
        click.echo(f"Low: {thresholds.low_threshold} (score: {thresholds.low_score})")
        click.echo(f"Max total score: {thresholds.max_total_score}")
        
    except Exception as e:
        click.echo(f"❌ Error showing thresholds: {e}", err=True)


@thresholds_group.command()
@click.option('--critical', type=int, help='Critical issues threshold')
@click.option('--high', type=int, help='High issues threshold')
@click.option('--medium', type=int, help='Medium issues threshold')
@click.option('--low', type=int, help='Low issues threshold')
@click.option('--max-score', type=int, help='Maximum total score threshold')
def set(critical: Optional[int], high: Optional[int], medium: Optional[int], 
        low: Optional[int], max_score: Optional[int]):
    """Set severity thresholds."""
    try:
        config_manager = ConfigManager()
        current_thresholds = config_manager.get_effective_severity_thresholds()
        
        # Update only provided values
        if critical is not None:
            current_thresholds.critical_threshold = critical
        if high is not None:
            current_thresholds.high_threshold = high
        if medium is not None:
            current_thresholds.medium_threshold = medium
        if low is not None:
            current_thresholds.low_threshold = low
        if max_score is not None:
            current_thresholds.max_total_score = max_score
        
        if config_manager.update_severity_thresholds(current_thresholds):
            click.echo("✅ Severity thresholds updated")
        else:
            click.echo("❌ Failed to update thresholds", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error setting thresholds: {e}", err=True)


@config_group.group(name='mcp')
def mcp_group():
    """MCP server configuration."""
    pass


@mcp_group.command()
def list():
    """List configured MCP servers."""
    try:
        config_manager = ConfigManager()
        servers = config_manager.get_mcp_servers()
        
        if not servers:
            click.echo("No MCP servers configured")
            return
        
        click.echo(f"🔗 MCP Servers ({len(servers)} total):")
        click.echo("=" * 40)
        
        for server in servers:
            status = "✅ Enabled" if server.enabled else "❌ Disabled"
            click.echo(f"\n{server.server_name}")
            click.echo(f"  Status: {status}")
            click.echo(f"  URL: {server.endpoint_url}")
            click.echo(f"  Timeout: {server.timeout_seconds}s")
            click.echo(f"  Rate limit: {server.rate_limit_requests}/{server.rate_limit_window}s")
            
    except Exception as e:
        click.echo(f"❌ Error listing MCP servers: {e}", err=True)


@mcp_group.command()
@click.option('--name', '-n', required=True, help='Server name')
@click.option('--url', '-u', required=True, help='Endpoint URL')
@click.option('--api-key', '-k', help='API key')
@click.option('--timeout', '-t', type=int, default=30, help='Timeout in seconds')
@click.option('--rate-limit', '-r', type=int, default=100, help='Rate limit requests per window')
@click.option('--rate-window', '-w', type=int, default=60, help='Rate limit window in seconds')
def add(name: str, url: str, api_key: Optional[str], timeout: int, 
        rate_limit: int, rate_window: int):
    """Add an MCP server configuration."""
    try:
        config_manager = ConfigManager()
        
        server = MCPServerConfig(
            server_name=name,
            endpoint_url=url,
            api_key=api_key,
            timeout_seconds=timeout,
            rate_limit_requests=rate_limit,
            rate_limit_window=rate_window
        )
        
        if config_manager.add_mcp_server(server):
            click.echo(f"✅ Added MCP server '{name}'")
        else:
            click.echo("❌ Failed to add MCP server", err=True)
            
    except Exception as e:
        click.echo(f"❌ Error adding MCP server: {e}", err=True)