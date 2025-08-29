"""Command-line interface for the Compliance Sentinel system with dynamic configuration."""

import os
import click
import json
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

from compliance_sentinel.engines.policy_engine import PolicyEngine
from compliance_sentinel.utils.config_loader import ConfigLoader
from compliance_sentinel.utils.error_handler import get_global_error_handler
from compliance_sentinel.core.validation import SecurityValidator
from compliance_sentinel.cli.hook_commands import hooks_cli
from compliance_sentinel.config import get_config_manager, get_config_value
from compliance_sentinel.logging.environment_logger import configure_logging, get_logger


# Initialize rich console for beautiful output
console = Console()

# Configure environment-aware logging
configure_logging()
logger = get_logger(__name__)


def get_cli_config() -> Dict[str, Any]:
    """Get CLI configuration from environment variables."""
    return {
        "max_files_default": int(os.getenv("COMPLIANCE_SENTINEL_CLI_MAX_FILES", "100")),
        "default_pattern": os.getenv("COMPLIANCE_SENTINEL_CLI_DEFAULT_PATTERN", "**/*.py"),
        "default_output_format": os.getenv("COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT", "text"),
        "config_dir": os.getenv("COMPLIANCE_SENTINEL_CONFIG_DIR", ".kiro/compliance-sentinel"),
        "verbose_logging": os.getenv("COMPLIANCE_SENTINEL_CLI_VERBOSE", "false").lower() == "true",
        "enable_colors": os.getenv("COMPLIANCE_SENTINEL_CLI_COLORS", "true").lower() == "true",
        "progress_enabled": os.getenv("COMPLIANCE_SENTINEL_CLI_PROGRESS", "true").lower() == "true"
    }


@click.group()
@click.option('--verbose', '-v', is_flag=True, 
              help='Enable verbose logging (overrides COMPLIANCE_SENTINEL_CLI_VERBOSE)')
@click.option('--config-dir', type=click.Path(), 
              help='Custom configuration directory (overrides COMPLIANCE_SENTINEL_CONFIG_DIR)')
@click.option('--environment', type=click.Choice(['development', 'staging', 'production']),
              help='Environment to run in (overrides COMPLIANCE_SENTINEL_ENVIRONMENT)')
@click.option('--no-colors', is_flag=True, help='Disable colored output')
def main(verbose: bool, config_dir: Optional[str], environment: Optional[str], no_colors: bool):
    """Compliance Sentinel - Proactive Security and Compliance Enforcement System."""
    cli_config = get_cli_config()
    
    # Set environment if provided
    if environment:
        os.environ["COMPLIANCE_SENTINEL_ENVIRONMENT"] = environment
    
    # Configure verbose logging
    if verbose or cli_config["verbose_logging"]:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Set custom config directory
    if config_dir:
        os.environ["COMPLIANCE_SENTINEL_CONFIG_DIR"] = config_dir
        logger.debug(f"Using custom config directory: {config_dir}")
    
    # Configure console colors
    global console
    if no_colors or not cli_config["enable_colors"]:
        console = Console(color_system=None)
    
    # Display banner
    env_name = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
    console.print(Panel.fit(
        f"[bold blue]Compliance Sentinel[/bold blue]\n"
        f"[dim]Proactive Security and Compliance Enforcement[/dim]\n"
        f"[dim]Environment: {env_name}[/dim]",
        border_style="blue"
    ))


@main.command()
@click.option('--force', is_flag=True, help='Overwrite existing configuration')
def init(force: bool):
    """Initialize Compliance Sentinel configuration."""
    console.print("[bold green]Initializing Compliance Sentinel...[/bold green]")
    
    try:
        config_loader = ConfigLoader()
        
        # Create configuration directories
        config_dir = Path.cwd() / ".kiro" / "compliance-sentinel"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        steering_dir = Path.cwd() / ".kiro" / "steering"
        steering_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize configurations
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Creating configuration files...", total=5)
            
            # System configuration
            system_config = config_loader.load_system_config()
            config_loader.save_system_config(system_config)
            progress.advance(task)
            
            # Hook settings
            hook_settings = config_loader.load_hook_settings()
            config_loader.save_hook_settings(hook_settings)
            progress.advance(task)
            
            # MCP configuration
            mcp_config = config_loader.load_mcp_config()
            config_loader.save_mcp_config(mcp_config)
            progress.advance(task)
            
            # Analysis configuration
            analysis_config = config_loader.load_analysis_config()
            config_loader.save_analysis_config(analysis_config)
            progress.advance(task)
            
            # Feedback configuration
            feedback_config = config_loader.load_feedback_config()
            config_loader.save_feedback_config(feedback_config)
            progress.advance(task)
        
        # Check if security policy exists
        security_policy_path = steering_dir / "security.md"
        if not security_policy_path.exists() or force:
            console.print("[yellow]Security policy not found. Please create .kiro/steering/security.md[/yellow]")
            console.print("[dim]See README.md for example security policy content.[/dim]")
        
        console.print("[bold green]✅ Initialization complete![/bold green]")
        console.print(f"[dim]Configuration saved to: {config_dir}[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Initialization failed: {e}[/bold red]")
        sys.exit(1)


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Choice(['text', 'json']), 
              help='Output format (overrides COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT)')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Minimum severity level')
def analyze(file_path: str, output: Optional[str], severity: Optional[str]):
    """Analyze a specific file for security issues with dynamic configuration."""
    try:
        cli_config = get_cli_config()
        
        # Use configuration default if not provided
        if output is None:
            output = cli_config["default_output_format"]
        
        file_path_obj = Path(file_path)
        logger.debug(f"Analyzing file: {file_path_obj}, output: {output}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task(f"Analyzing {file_path_obj.name}...", total=3)
            
            # Initialize policy engine
            policy_engine = PolicyEngine()
            progress.advance(task)
            
            # Read file content
            with open(file_path_obj, 'r', encoding='utf-8') as f:
                content = f.read()
            progress.advance(task)
            
            # Apply policies
            file_type = file_path_obj.suffix
            issues = policy_engine.apply_policies_to_content(content, str(file_path_obj), file_type)
            progress.advance(task)
        
        # Filter by severity if specified
        if severity:
            from compliance_sentinel.core.interfaces import Severity
            min_severity = Severity(severity)
            severity_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            min_level = severity_order[min_severity]
            issues = [issue for issue in issues if severity_order[issue.severity] >= min_level]
        
        # Output results
        if output == 'json':
            result = {
                'file_path': str(file_path_obj),
                'total_issues': len(issues),
                'issues': [
                    {
                        'id': issue.id,
                        'severity': issue.severity.value,
                        'category': issue.category.value,
                        'line_number': issue.line_number,
                        'description': issue.description,
                        'rule_id': issue.rule_id,
                        'confidence': issue.confidence,
                        'remediation_suggestions': issue.remediation_suggestions
                    }
                    for issue in issues
                ]
            }
            console.print(json.dumps(result, indent=2))
        else:
            _display_analysis_results(file_path_obj, issues)
        
    except Exception as e:
        console.print(f"[bold red]❌ Analysis failed: {e}[/bold red]")
        logger.error(f"Analysis error: {e}", exc_info=True)
        sys.exit(1)


@main.command()
@click.option('--pattern', help='File pattern to scan (glob syntax, overrides COMPLIANCE_SENTINEL_CLI_DEFAULT_PATTERN)')
@click.option('--output', '-o', type=click.Choice(['text', 'json']), 
              help='Output format (overrides COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT)')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Minimum severity level')
@click.option('--max-files', type=int, 
              help='Maximum number of files to scan (overrides COMPLIANCE_SENTINEL_CLI_MAX_FILES)')
def scan(pattern: Optional[str], output: Optional[str], severity: Optional[str], max_files: Optional[int]):
    """Scan multiple files matching a pattern with dynamic configuration."""
    try:
        cli_config = get_cli_config()
        
        # Use configuration defaults if not provided
        if pattern is None:
            pattern = cli_config["default_pattern"]
        if output is None:
            output = cli_config["default_output_format"]
        if max_files is None:
            max_files = cli_config["max_files_default"]
        
        logger.debug(f"Scanning with pattern: {pattern}, output: {output}, max_files: {max_files}")
        
        # Find files matching pattern
        files = list(Path.cwd().glob(pattern))[:max_files]
        
        if not files:
            console.print(f"[yellow]No files found matching pattern: {pattern}[/yellow]")
            return
        
        console.print(f"[blue]Scanning {len(files)} files...[/blue]")
        
        all_issues = []
        policy_engine = PolicyEngine()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning files...", total=len(files))
            
            for file_path in files:
                try:
                    if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.java', '.go']:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        file_issues = policy_engine.apply_policies_to_content(
                            content, str(file_path), file_path.suffix
                        )
                        all_issues.extend(file_issues)
                
                except Exception as e:
                    logger.warning(f"Error scanning {file_path}: {e}")
                
                progress.advance(task)
        
        # Filter by severity if specified
        if severity:
            from compliance_sentinel.core.interfaces import Severity
            min_severity = Severity(severity)
            severity_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            min_level = severity_order[min_severity]
            all_issues = [issue for issue in all_issues if severity_order[issue.severity] >= min_level]
        
        # Output results
        if output == 'json':
            result = {
                'scan_pattern': pattern,
                'files_scanned': len(files),
                'total_issues': len(all_issues),
                'issues_by_file': {}
            }
            
            for issue in all_issues:
                file_path = issue.file_path
                if file_path not in result['issues_by_file']:
                    result['issues_by_file'][file_path] = []
                
                result['issues_by_file'][file_path].append({
                    'id': issue.id,
                    'severity': issue.severity.value,
                    'category': issue.category.value,
                    'line_number': issue.line_number,
                    'description': issue.description,
                    'rule_id': issue.rule_id,
                    'confidence': issue.confidence,
                    'remediation_suggestions': issue.remediation_suggestions
                })
            
            console.print(json.dumps(result, indent=2))
        else:
            _display_scan_results(files, all_issues)
        
    except Exception as e:
        console.print(f"[bold red]❌ Scan failed: {e}[/bold red]")
        logger.error(f"Scan error: {e}", exc_info=True)
        sys.exit(1)


@main.group()
def config():
    """Configuration management commands with dynamic configuration support."""
    pass


@config.command()
@click.option('--format', type=click.Choice(['json', 'yaml', 'table']), default='table',
              help='Output format for configuration display')
@click.option('--show-sensitive', is_flag=True, help='Show sensitive configuration values')
def show(format: str, show_sensitive: bool):
    """Show current configuration values."""
    try:
        config_manager = get_dynamic_config_manager()
        
        console.print(f"[blue]Configuration for environment: {config_manager.environment}[/blue]")
        
        # Get all configuration
        all_config = {
            "system": config_manager.get_system_config(),
            "mcp": config_manager.get_mcp_config(),
            "environment": dict(os.environ)
        }
        
        if format == 'json':
            # Redact sensitive values if not showing them
            if not show_sensitive:
                all_config = _redact_sensitive_config(all_config)
            console.print(json.dumps(all_config, indent=2, default=str))
        
        elif format == 'yaml':
            try:
                import yaml
                if not show_sensitive:
                    all_config = _redact_sensitive_config(all_config)
                console.print(yaml.dump(all_config, default_flow_style=False))
            except ImportError:
                console.print("[red]PyYAML not installed. Use 'pip install PyYAML' for YAML output.[/red]")
                sys.exit(1)
        
        else:  # table format
            for section_name, section_config in all_config.items():
                if section_name == 'environment':
                    # Only show Compliance Sentinel environment variables
                    section_config = {k: v for k, v in section_config.items() 
                                    if k.startswith('COMPLIANCE_SENTINEL_')}
                
                if section_config:
                    table = Table(title=f"{section_name.title()} Configuration")
                    table.add_column("Setting", style="cyan")
                    table.add_column("Value", style="green")
                    
                    for key, value in section_config.items():
                        if not show_sensitive and any(sensitive in key.lower() 
                                                    for sensitive in ['password', 'secret', 'key', 'token']):
                            value = "[REDACTED]"
                        table.add_row(key, str(value))
                    
                    console.print(table)
                    console.print()
    
    except Exception as e:
        console.print(f"[bold red]❌ Failed to show configuration: {e}[/bold red]")
        logger.error(f"Configuration show error: {e}", exc_info=True)
        sys.exit(1)


@config.command()
@click.argument('key')
@click.argument('value')
@click.option('--environment', type=click.Choice(['development', 'staging', 'production']),
              help='Set configuration for specific environment')
def set(key: str, value: str, environment: Optional[str]):
    """Set a configuration value."""
    try:
        if environment:
            os.environ["COMPLIANCE_SENTINEL_ENVIRONMENT"] = environment
        
        # Convert key to environment variable format
        env_key = f"COMPLIANCE_SENTINEL_{key.upper()}"
        os.environ[env_key] = value
        
        console.print(f"[green]✅ Set {env_key} = {value}[/green]")
        console.print("[dim]Note: This only affects the current session. For persistent changes, set the environment variable in your shell or deployment configuration.[/dim]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Failed to set configuration: {e}[/bold red]")
        sys.exit(1)


@config.command()
@click.argument('key')
def get(key: str):
    """Get a configuration value."""
    try:
        config_manager = get_dynamic_config_manager()
        
        # Try to get from environment variables first
        env_key = f"COMPLIANCE_SENTINEL_{key.upper()}"
        value = os.getenv(env_key)
        
        if value is not None:
            # Check if it's sensitive
            if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                console.print(f"{env_key} = [REDACTED] (use --show-sensitive to display)")
            else:
                console.print(f"{env_key} = {value}")
        else:
            console.print(f"[yellow]Configuration key '{key}' not found[/yellow]")
            console.print(f"[dim]Try setting it with: compliance-sentinel config set {key} <value>[/dim]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Failed to get configuration: {e}[/bold red]")
        sys.exit(1)


@config.command()
def reload():
    """Reload configuration from environment variables."""
    try:
        config_manager = get_dynamic_config_manager()
        config_manager.reload_configuration()
        
        console.print("[green]✅ Configuration reloaded successfully[/green]")
        console.print(f"[dim]Environment: {config_manager.environment}[/dim]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Failed to reload configuration: {e}[/bold red]")
        logger.error(f"Configuration reload error: {e}", exc_info=True)
        sys.exit(1)


def _redact_sensitive_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive configuration values."""
    redacted = {}
    
    for key, value in config.items():
        if isinstance(value, dict):
            redacted[key] = _redact_sensitive_config(value)
        elif isinstance(key, str) and any(sensitive in key.lower() 
                                        for sensitive in ['password', 'secret', 'key', 'token']):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    
    return redacted


@config.command()
@click.option('--environment', type=click.Choice(['development', 'staging', 'production']),
              help='Validate configuration for specific environment')
@click.option('--show-values', is_flag=True, help='Show configuration values (sensitive data will be redacted)')
def validate(environment: Optional[str], show_values: bool):
    """Validate all configuration files with dynamic configuration support."""
    try:
        # Set environment if provided
        if environment:
            os.environ["COMPLIANCE_SENTINEL_ENVIRONMENT"] = environment
        
        # Use dynamic config manager for validation
        config_manager = get_dynamic_config_manager()
        
        console.print(f"[blue]Validating configuration for environment: {config_manager.environment}[/blue]")
        
        # Validate configuration
        validation_results = []
        
        # Validate system configuration
        try:
            system_config = config_manager.get_system_config()
            validation_results.append(("System Configuration", True, "Valid"))
            
            if show_values:
                console.print("\n[bold]System Configuration:[/bold]")
                for key, value in system_config.items():
                    # Redact sensitive values
                    if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                        value = "[REDACTED]"
                    console.print(f"  {key}: {value}")
        except Exception as e:
            validation_results.append(("System Configuration", False, str(e)))
        
        # Validate MCP configuration
        try:
            mcp_config = config_manager.get_mcp_config()
            validation_results.append(("MCP Configuration", True, "Valid"))
            
            if show_values:
                console.print("\n[bold]MCP Configuration:[/bold]")
                for key, value in mcp_config.items():
                    if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                        value = "[REDACTED]"
                    console.print(f"  {key}: {value}")
        except Exception as e:
            validation_results.append(("MCP Configuration", False, str(e)))
        
        # Display results
        console.print("\n[bold]Validation Results:[/bold]")
        
        valid_count = 0
        for config_name, is_valid, message in validation_results:
            if is_valid:
                console.print(f"  [green]✅ {config_name}: {message}[/green]")
                valid_count += 1
            else:
                console.print(f"  [red]❌ {config_name}: {message}[/red]")
        
        if valid_count == len(validation_results):
            console.print(f"\n[bold green]✅ All {valid_count} configurations are valid![/bold green]")
        else:
            console.print(f"\n[bold red]❌ {len(validation_results) - valid_count} configuration(s) failed validation[/bold red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[bold red]❌ Validation failed: {e}[/bold red]")
        logger.error(f"Configuration validation error: {e}", exc_info=True)
        sys.exit(1)


@config.command()
def show():
    """Show current configuration."""
    try:
        config_loader = ConfigLoader()
        
        # Load all configurations
        system_config = config_loader.load_system_config()
        hook_settings = config_loader.load_hook_settings()
        mcp_config = config_loader.load_mcp_config()
        
        # Display system configuration
        table = Table(title="System Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Python Version", system_config.python_version)
        table.add_row("Analysis Tools", ", ".join(system_config.analysis_tools))
        table.add_row("MCP Server URL", system_config.mcp_server_url)
        table.add_row("Cache TTL", f"{system_config.cache_ttl}s")
        table.add_row("Max Concurrent", str(system_config.max_concurrent_analyses))
        table.add_row("Severity Threshold", system_config.severity_threshold.value)
        
        console.print(table)
        
        # Display hook settings
        hook_table = Table(title="Hook Settings")
        hook_table.add_column("Setting", style="cyan")
        hook_table.add_column("Value", style="green")
        
        hook_table.add_row("File Patterns", ", ".join(hook_settings.enabled_file_patterns))
        hook_table.add_row("Excluded Dirs", ", ".join(hook_settings.excluded_directories))
        hook_table.add_row("Timeout", f"{hook_settings.analysis_timeout}s")
        hook_table.add_row("Async Processing", str(hook_settings.async_processing))
        
        console.print(hook_table)
        
    except Exception as e:
        console.print(f"[bold red]❌ Failed to show configuration: {e}[/bold red]")
        sys.exit(1)


@main.group()
def policy():
    """Policy management commands."""
    pass


# Add hook commands
main.add_command(hooks_cli)


@policy.command()
def list():
    """List all loaded policies."""
    try:
        policy_engine = PolicyEngine()
        stats = policy_engine.get_policy_statistics()
        
        console.print(f"[bold blue]Policy Statistics[/bold blue]")
        console.print(f"Total Policies: {stats['total_policies']}")
        console.print(f"Enabled Policies: {stats['enabled_policies']}")
        
        # Display by category
        if stats['by_category']:
            category_table = Table(title="Policies by Category")
            category_table.add_column("Category", style="cyan")
            category_table.add_column("Count", style="green")
            
            for category, count in stats['by_category'].items():
                category_table.add_row(category, str(count))
            
            console.print(category_table)
        
        # Display by severity
        if stats['by_severity']:
            severity_table = Table(title="Policies by Severity")
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="green")
            
            for severity, count in stats['by_severity'].items():
                severity_table.add_row(severity, str(count))
            
            console.print(severity_table)
        
    except Exception as e:
        console.print(f"[bold red]❌ Failed to list policies: {e}[/bold red]")
        sys.exit(1)


@policy.command()
def reload():
    """Reload policies from configuration files."""
    try:
        policy_engine = PolicyEngine()
        success = policy_engine.reload_policies()
        
        if success:
            console.print("[bold green]✅ Policies reloaded successfully![/bold green]")
            stats = policy_engine.get_policy_statistics()
            console.print(f"Loaded {stats['total_policies']} policies")
        else:
            console.print("[bold red]❌ Failed to reload policies[/bold red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[bold red]❌ Policy reload failed: {e}[/bold red]")
        sys.exit(1)


def _display_analysis_results(file_path: Path, issues: List):
    """Display analysis results in a formatted table."""
    if not issues:
        console.print(f"[bold green]✅ No security issues found in {file_path.name}[/bold green]")
        return
    
    console.print(f"[bold red]🚨 Found {len(issues)} security issues in {file_path.name}[/bold red]")
    
    # Group issues by severity
    by_severity = {}
    for issue in issues:
        severity = issue.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(issue)
    
    # Display issues by severity
    severity_colors = {
        'critical': 'bold red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue'
    }
    
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in by_severity:
            console.print(f"\n[{severity_colors[severity]}]{severity.upper()} SEVERITY ({len(by_severity[severity])} issues)[/{severity_colors[severity]}]")
            
            for issue in by_severity[severity]:
                console.print(f"  Line {issue.line_number}: {issue.description}")
                console.print(f"    Rule: {issue.rule_id} (confidence: {issue.confidence:.1%})")
                
                if issue.remediation_suggestions:
                    console.print("    [dim]Remediation:[/dim]")
                    for suggestion in issue.remediation_suggestions[:2]:  # Show top 2
                        console.print(f"      • {suggestion}")
                console.print()


def _display_scan_results(files: List[Path], issues: List):
    """Display scan results summary."""
    if not issues:
        console.print(f"[bold green]✅ No security issues found in {len(files)} files[/bold green]")
        return
    
    console.print(f"[bold red]🚨 Found {len(issues)} security issues across {len(files)} files[/bold red]")
    
    # Group by file
    by_file = {}
    for issue in issues:
        file_path = issue.file_path
        if file_path not in by_file:
            by_file[file_path] = []
        by_file[file_path].append(issue)
    
    # Summary table
    table = Table(title="Scan Results Summary")
    table.add_column("File", style="cyan")
    table.add_column("Issues", style="red")
    table.add_column("Critical", style="bold red")
    table.add_column("High", style="red")
    table.add_column("Medium", style="yellow")
    table.add_column("Low", style="blue")
    
    for file_path, file_issues in by_file.items():
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in file_issues:
            severity_counts[issue.severity.value] += 1
        
        table.add_row(
            Path(file_path).name,
            str(len(file_issues)),
            str(severity_counts['critical']),
            str(severity_counts['high']),
            str(severity_counts['medium']),
            str(severity_counts['low'])
        )
    
    console.print(table)


# Analysis command group
@main.group()
def analysis():
    """Analysis commands with environment-specific configuration."""
    pass


@analysis.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--rules', help='Comma-separated list of rule IDs to apply')
@click.option('--exclude-rules', help='Comma-separated list of rule IDs to exclude')
@click.option('--output-format', type=click.Choice(['text', 'json', 'sarif']),
              help='Output format (overrides COMPLIANCE_SENTINEL_ANALYSIS_OUTPUT_FORMAT)')
@click.option('--output-file', type=click.Path(), help='Output file path')
@click.option('--severity-threshold', type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Minimum severity threshold')
@click.option('--fail-on-issues', is_flag=True, help='Exit with non-zero code if issues found')
def run(path: str, rules: Optional[str], exclude_rules: Optional[str], 
        output_format: Optional[str], output_file: Optional[str],
        severity_threshold: Optional[str], fail_on_issues: bool):
    """Run comprehensive analysis with environment-specific configuration."""
    try:
        # Get analysis configuration from environment
        analysis_config = _get_analysis_config()
        
        # Override with command line options
        if rules:
            analysis_config["rules"] = [rule.strip() for rule in rules.split(',')]
        if exclude_rules:
            analysis_config["exclude_rules"] = [rule.strip() for rule in exclude_rules.split(',')]
        if output_format:
            analysis_config["output_format"] = output_format
        if severity_threshold:
            analysis_config["severity_threshold"] = severity_threshold
        
        logger.debug(f"Running analysis with config: {analysis_config}")
        
        # Initialize policy engine
        policy_engine = PolicyEngine()
        
        path_obj = Path(path)
        all_issues = []
        
        cli_config = get_cli_config()
        if cli_config["progress_enabled"]:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                all_issues = _run_analysis_with_progress(policy_engine, path_obj, analysis_config, progress)
        else:
            all_issues = _run_analysis_simple(policy_engine, path_obj, analysis_config)
        
        # Filter issues by severity threshold
        if analysis_config.get("severity_threshold"):
            all_issues = _filter_by_severity(all_issues, analysis_config["severity_threshold"])
        
        # Output results
        output_format = analysis_config.get("output_format", "text")
        if output_file:
            _write_analysis_output(all_issues, output_format, output_file)
            console.print(f"[green]✅ Analysis results written to {output_file}[/green]")
        else:
            _display_analysis_output(all_issues, output_format)
        
        # Exit with error code if issues found and fail_on_issues is set
        if fail_on_issues and all_issues:
            console.print(f"[red]❌ Found {len(all_issues)} issues, exiting with error code[/red]")
            sys.exit(1)
        
        console.print(f"[green]✅ Analysis complete. Found {len(all_issues)} issues.[/green]")
    
    except Exception as e:
        console.print(f"[bold red]❌ Analysis failed: {e}[/bold red]")
        logger.error(f"Analysis error: {e}", exc_info=True)
        sys.exit(1)


def _get_analysis_config() -> Dict[str, Any]:
    """Get analysis configuration from environment variables."""
    return {
        "output_format": os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_OUTPUT_FORMAT", "text"),
        "severity_threshold": os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_SEVERITY_THRESHOLD", "medium"),
        "file_extensions": os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_FILE_EXTENSIONS", ".py,.js,.ts,.java,.go").split(","),
        "rules": os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_RULES", "").split(",") if os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_RULES") else None,
        "exclude_rules": os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_EXCLUDE_RULES", "").split(",") if os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_EXCLUDE_RULES") else [],
        "max_file_size_mb": int(os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_MAX_FILE_SIZE_MB", "10")),
        "timeout_seconds": int(os.getenv("COMPLIANCE_SENTINEL_ANALYSIS_TIMEOUT_SECONDS", "300"))
    }


def _run_analysis_with_progress(policy_engine: PolicyEngine, path_obj: Path, config: Dict[str, Any], progress) -> List[Any]:
    """Run analysis with progress display."""
    all_issues = []
    
    if path_obj.is_file():
        task = progress.add_task(f"Analyzing {path_obj.name}...", total=1)
        issues = _analyze_file(policy_engine, path_obj, config)
        all_issues.extend(issues)
        progress.advance(task)
    else:
        # Analyze directory
        files = list(path_obj.rglob("*"))
        supported_files = [f for f in files if f.is_file() and 
                         f.suffix in config.get("file_extensions", [".py", ".js", ".ts", ".java", ".go"])]
        
        task = progress.add_task(f"Analyzing {len(supported_files)} files...", total=len(supported_files))
        
        for file_path in supported_files:
            try:
                issues = _analyze_file(policy_engine, file_path, config)
                all_issues.extend(issues)
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
            progress.advance(task)
    
    return all_issues


def _run_analysis_simple(policy_engine: PolicyEngine, path_obj: Path, config: Dict[str, Any]) -> List[Any]:
    """Run analysis without progress display."""
    all_issues = []
    
    if path_obj.is_file():
        issues = _analyze_file(policy_engine, path_obj, config)
        all_issues.extend(issues)
    else:
        files = list(path_obj.rglob("*"))
        supported_files = [f for f in files if f.is_file() and 
                         f.suffix in config.get("file_extensions", [".py", ".js", ".ts", ".java", ".go"])]
        
        for file_path in supported_files:
            try:
                issues = _analyze_file(policy_engine, file_path, config)
                all_issues.extend(issues)
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
    
    return all_issues


def _analyze_file(policy_engine: PolicyEngine, file_path: Path, config: Dict[str, Any]) -> List[Any]:
    """Analyze a single file with configuration."""
    # Check file size limit
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    if file_size_mb > config.get("max_file_size_mb", 10):
        logger.warning(f"Skipping {file_path}: file size ({file_size_mb:.1f}MB) exceeds limit")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        issues = policy_engine.apply_policies_to_content(content, str(file_path), file_path.suffix)
        return issues
    
    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {e}")
        return []


def _filter_by_severity(issues: List[Any], min_severity: str) -> List[Any]:
    """Filter issues by minimum severity level."""
    from compliance_sentinel.core.interfaces import Severity
    
    severity_order = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4
    }
    
    min_level = severity_order[Severity(min_severity)]
    return [issue for issue in issues if severity_order[issue.severity] >= min_level]


def _write_analysis_output(issues: List[Any], format: str, output_file: str) -> None:
    """Write analysis results to file."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format == 'json':
        result = {
            'total_issues': len(issues),
            'issues': [
                {
                    'id': issue.id,
                    'severity': issue.severity.value,
                    'category': issue.category.value,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'description': issue.description,
                    'rule_id': issue.rule_id,
                    'confidence': issue.confidence,
                    'remediation_suggestions': issue.remediation_suggestions
                }
                for issue in issues
            ]
        }
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
    
    elif format == 'sarif':
        # SARIF (Static Analysis Results Interchange Format)
        sarif_result = _convert_to_sarif(issues)
        with open(output_path, 'w') as f:
            json.dump(sarif_result, f, indent=2)
    
    else:  # text format
        with open(output_path, 'w') as f:
            for issue in issues:
                f.write(f"{issue.file_path}:{issue.line_number}: {issue.severity.value.upper()}: {issue.description}\\n")


def _display_analysis_output(issues: List[Any], format: str) -> None:
    """Display analysis results to console."""
    if format == 'json':
        result = {
            'total_issues': len(issues),
            'issues': [
                {
                    'id': issue.id,
                    'severity': issue.severity.value,
                    'category': issue.category.value,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'description': issue.description,
                    'rule_id': issue.rule_id,
                    'confidence': issue.confidence,
                    'remediation_suggestions': issue.remediation_suggestions
                }
                for issue in issues
            ]
        }
        console.print(json.dumps(result, indent=2))
    else:
        # Use existing display functions if available
        try:
            _display_analysis_results(Path("analysis"), issues)
        except NameError:
            # Fallback to simple text display
            for issue in issues:
                console.print(f"{issue.file_path}:{issue.line_number}: {issue.severity.value.upper()}: {issue.description}")


def _convert_to_sarif(issues: List[Any]) -> Dict[str, Any]:
    """Convert issues to SARIF format."""
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Compliance Sentinel",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/compliance-sentinel"
                    }
                },
                "results": [
                    {
                        "ruleId": issue.rule_id,
                        "level": _severity_to_sarif_level(issue.severity),
                        "message": {"text": issue.description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": issue.file_path},
                                    "region": {"startLine": issue.line_number}
                                }
                            }
                        ]
                    }
                    for issue in issues
                ]
            }
        ]
    }


def _severity_to_sarif_level(severity) -> str:
    """Convert severity to SARIF level."""
    from compliance_sentinel.core.interfaces import Severity
    
    mapping = {
        Severity.LOW: "note",
        Severity.MEDIUM: "warning",
        Severity.HIGH: "error",
        Severity.CRITICAL: "error"
    }
    return mapping.get(severity, "warning")


if __name__ == '__main__':
    main()