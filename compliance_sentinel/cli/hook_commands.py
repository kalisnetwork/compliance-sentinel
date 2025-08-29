"""CLI commands for managing Kiro Agent Hook integration."""

import asyncio
import json
from pathlib import Path
from typing import Optional
import click
import logging

from compliance_sentinel.hooks.hook_manager import HookManager
from compliance_sentinel.hooks.kiro_integration import (
    KiroIntegration,
    install_kiro_hooks,
    uninstall_kiro_hooks,
    get_kiro_hook_status
)
from compliance_sentinel.models.config import HookSettings
from compliance_sentinel.utils.config_loader import ConfigLoader


logger = logging.getLogger(__name__)


@click.group(name='hooks')
def hooks_cli():
    """Manage Kiro Agent Hook integration."""
    pass


@hooks_cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Path to hook configuration file')
@click.option('--patterns', '-p', multiple=True,
              help='File patterns to monitor (e.g., *.py, *.js)')
@click.option('--exclude', '-e', multiple=True,
              help='Directories to exclude (e.g., node_modules, .git)')
@click.option('--timeout', '-t', type=int, default=30,
              help='Analysis timeout in seconds')
@click.option('--debounce', '-d', type=float, default=2.0,
              help='Debounce delay in seconds')
@click.option('--async/--sync', default=True,
              help='Enable asynchronous processing')
def install(config: Optional[str], patterns: tuple, exclude: tuple, 
           timeout: int, debounce: float, async_processing: bool):
    """Install Compliance Sentinel hooks into Kiro."""
    try:
        # Load or create hook settings
        if config:
            config_loader = ConfigLoader()
            hook_settings = config_loader.load_hook_settings(Path(config))
        else:
            # Create settings from CLI options
            file_patterns = list(patterns) if patterns else [
                "*.py", "*.js", "*.ts", "*.java", "*.go", "*.php", "*.rb"
            ]
            excluded_dirs = list(exclude) if exclude else [
                "node_modules", ".git", "__pycache__", ".venv", "venv"
            ]
            
            hook_settings = HookSettings(
                enabled_file_patterns=file_patterns,
                excluded_directories=excluded_dirs,
                debounce_delay=debounce,
                async_processing=async_processing,
                analysis_timeout=timeout
            )
        
        # Install hooks
        success = install_kiro_hooks(hook_settings)
        
        if success:
            click.echo("✅ Successfully installed Compliance Sentinel hooks")
            click.echo("\nInstalled hooks:")
            
            # Show installed hooks
            status = get_kiro_hook_status()
            for hook in status.get("hooks", []):
                click.echo(f"  • {hook['name']}")
                click.echo(f"    Triggers: {', '.join(hook['triggers'])}")
                click.echo(f"    Patterns: {', '.join(hook['patterns'])}")
                click.echo()
        else:
            click.echo("❌ Failed to install hooks", err=True)
            return 1
            
    except Exception as e:
        click.echo(f"❌ Error installing hooks: {e}", err=True)
        logger.error(f"Hook installation error: {e}")
        return 1


@hooks_cli.command()
def uninstall():
    """Remove Compliance Sentinel hooks from Kiro."""
    try:
        success = uninstall_kiro_hooks()
        
        if success:
            click.echo("✅ Successfully uninstalled Compliance Sentinel hooks")
        else:
            click.echo("❌ Failed to uninstall hooks", err=True)
            return 1
            
    except Exception as e:
        click.echo(f"❌ Error uninstalling hooks: {e}", err=True)
        logger.error(f"Hook uninstallation error: {e}")
        return 1


@hooks_cli.command()
def status():
    """Show status of installed hooks."""
    try:
        status = get_kiro_hook_status()
        
        if status["installed"]:
            click.echo("✅ Compliance Sentinel hooks are installed")
            click.echo()
            
            # Show hook details
            for hook in status.get("hooks", []):
                click.echo(f"📋 {hook['name']}")
                click.echo(f"   File: {hook['file']}")
                click.echo(f"   Triggers: {', '.join(hook['triggers'])}")
                click.echo(f"   Patterns: {', '.join(hook['patterns'])}")
                click.echo()
            
            # Show system status
            click.echo("System Status:")
            click.echo(f"  Kiro config exists: {'✅' if status['kiro_config_exists'] else '❌'}")
            click.echo(f"  Handler script exists: {'✅' if status['handler_exists'] else '❌'}")
            
        else:
            click.echo("❌ No Compliance Sentinel hooks installed")
            click.echo("Run 'compliance-sentinel hooks install' to install hooks")
            
    except Exception as e:
        click.echo(f"❌ Error checking hook status: {e}", err=True)
        logger.error(f"Hook status error: {e}")
        return 1


@hooks_cli.command()
def validate():
    """Validate hook installation."""
    try:
        integration = KiroIntegration()
        issues = integration.validate_installation()
        
        if not issues:
            click.echo("✅ Hook installation is valid")
        else:
            click.echo("❌ Hook installation has issues:")
            for issue in issues:
                click.echo(f"  • {issue}")
            return 1
            
    except Exception as e:
        click.echo(f"❌ Error validating hooks: {e}", err=True)
        logger.error(f"Hook validation error: {e}")
        return 1


@hooks_cli.command()
@click.argument('file_path', type=click.Path(exists=True))
def test(file_path: str):
    """Test hook processing on a specific file."""
    async def run_test():
        try:
            # Load configuration
            config_loader = ConfigLoader()
            hook_settings = config_loader.load_hook_settings()
            
            # Initialize hook manager
            hook_manager = HookManager(hook_settings)
            await hook_manager.start()
            
            try:
                # Trigger manual analysis
                result = await hook_manager.trigger_manual_analysis(file_path)
                
                # Display results
                click.echo(f"📁 File: {file_path}")
                click.echo(f"✅ Success: {result.success}")
                click.echo(f"⏱️  Duration: {result.duration_ms:.2f}ms")
                click.echo(f"🔍 Issues found: {result.issues_found}")
                click.echo(f"📝 Summary: {result.analysis_summary}")
                click.echo(f"💬 Feedback provided: {result.feedback_provided}")
                
                if result.error_message:
                    click.echo(f"❌ Error: {result.error_message}")
                
            finally:
                await hook_manager.stop()
                
        except Exception as e:
            click.echo(f"❌ Error testing hook: {e}", err=True)
            logger.error(f"Hook test error: {e}")
            return 1
    
    try:
        asyncio.run(run_test())
    except Exception as e:
        click.echo(f"❌ Error running test: {e}", err=True)
        return 1


@hooks_cli.command()
@click.option('--watch-dir', '-w', multiple=True, default=['.'],
              help='Directories to watch for file changes')
@click.option('--duration', '-d', type=int, default=60,
              help='How long to run the daemon (seconds)')
def daemon(watch_dir: tuple, duration: int):
    """Run hook manager as a daemon for testing."""
    async def run_daemon():
        try:
            # Load configuration
            config_loader = ConfigLoader()
            hook_settings = config_loader.load_hook_settings()
            
            # Initialize hook manager
            hook_manager = HookManager(hook_settings)
            
            click.echo(f"🚀 Starting hook daemon for {duration} seconds...")
            click.echo(f"📁 Watching directories: {', '.join(watch_dir)}")
            
            await hook_manager.start()
            
            try:
                # Run for specified duration
                await asyncio.sleep(duration)
                
                # Show statistics
                stats = hook_manager.get_hook_statistics()
                click.echo("\n📊 Hook Statistics:")
                click.echo(f"  Total events: {stats['total_events']}")
                click.echo(f"  Successful events: {stats['successful_events']}")
                click.echo(f"  Failed events: {stats['failed_events']}")
                click.echo(f"  Success rate: {stats['success_rate']:.1%}")
                click.echo(f"  Average duration: {stats['average_duration_ms']:.2f}ms")
                click.echo(f"  Total issues found: {stats['total_issues_found']}")
                click.echo(f"  Feedback provided: {stats['feedback_provided_count']}")
                
            finally:
                await hook_manager.stop()
                
        except Exception as e:
            click.echo(f"❌ Error running daemon: {e}", err=True)
            logger.error(f"Hook daemon error: {e}")
            return 1
    
    try:
        asyncio.run(run_daemon())
    except KeyboardInterrupt:
        click.echo("\n🛑 Daemon stopped by user")
    except Exception as e:
        click.echo(f"❌ Error running daemon: {e}", err=True)
        return 1


@hooks_cli.command()
def config():
    """Show current hook configuration."""
    try:
        config_loader = ConfigLoader()
        hook_settings = config_loader.load_hook_settings()
        
        click.echo("🔧 Current Hook Configuration:")
        click.echo()
        click.echo(f"File Patterns: {', '.join(hook_settings.enabled_file_patterns)}")
        click.echo(f"Excluded Directories: {', '.join(hook_settings.excluded_directories)}")
        click.echo(f"Debounce Delay: {hook_settings.debounce_delay}s")
        click.echo(f"Async Processing: {hook_settings.async_processing}")
        click.echo(f"Analysis Timeout: {hook_settings.analysis_timeout}s")
        
        # Show watch directories if available
        if hasattr(hook_settings, 'watch_directories'):
            watch_dirs = getattr(hook_settings, 'watch_directories', [])
            click.echo(f"Watch Directories: {', '.join(watch_dirs)}")
        
    except Exception as e:
        click.echo(f"❌ Error loading configuration: {e}", err=True)
        logger.error(f"Hook config error: {e}")
        return 1


# Hook handler entry point (called by Kiro)
@click.command(name='hook-handler')
@click.argument('event_data')
def hook_handler(event_data: str):
    """Handle hook events from Kiro (internal use)."""
    # This is handled by the Python script in kiro_integration.py
    # This command is just for CLI completeness
    click.echo("This command is handled by the hook handler script", err=True)
    return 1


if __name__ == '__main__':
    hooks_cli()