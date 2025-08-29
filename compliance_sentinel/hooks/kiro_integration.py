"""Kiro-specific integration utilities and hook configuration."""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

from compliance_sentinel.models.config import HookSettings
from compliance_sentinel.utils.config_loader import ConfigLoader


logger = logging.getLogger(__name__)


@dataclass
class KiroHookConfig:
    """Configuration for Kiro Agent Hook integration."""
    hook_name: str
    trigger_events: List[str]
    file_patterns: List[str]
    excluded_paths: List[str]
    async_execution: bool = True
    timeout_seconds: int = 60
    priority: int = 5  # 1-10, higher is more urgent
    
    def to_kiro_format(self) -> Dict[str, Any]:
        """Convert to Kiro hook configuration format."""
        return {
            "name": self.hook_name,
            "triggers": self.trigger_events,
            "patterns": self.file_patterns,
            "exclude": self.excluded_paths,
            "async": self.async_execution,
            "timeout": self.timeout_seconds,
            "priority": self.priority,
            "command": "compliance-sentinel hook-handler",
            "description": "Compliance Sentinel real-time security analysis"
        }


class KiroIntegration:
    """Handles integration with Kiro's Agent Hook system."""
    
    def __init__(self):
        """Initialize Kiro integration."""
        self.config_loader = ConfigLoader()
        self.kiro_dir = Path.cwd() / ".kiro"
        self.hooks_dir = self.kiro_dir / "hooks"
        self.steering_dir = self.kiro_dir / "steering"
        
        # Ensure directories exist
        self.hooks_dir.mkdir(parents=True, exist_ok=True)
        self.steering_dir.mkdir(parents=True, exist_ok=True)
    
    def install_hooks(self, hook_settings: Optional[HookSettings] = None) -> bool:
        """Install Compliance Sentinel hooks into Kiro."""
        try:
            if hook_settings is None:
                hook_settings = self.config_loader.load_hook_settings()
            
            # Create hook configurations
            hooks = self._create_hook_configurations(hook_settings)
            
            # Install each hook
            for hook in hooks:
                self._install_single_hook(hook)
            
            # Create hook handler script
            self._create_hook_handler()
            
            # Update Kiro configuration
            self._update_kiro_config(hooks)
            
            logger.info(f"Successfully installed {len(hooks)} Compliance Sentinel hooks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install hooks: {e}")
            return False
    
    def uninstall_hooks(self) -> bool:
        """Remove Compliance Sentinel hooks from Kiro."""
        try:
            # Remove hook files
            hook_files = list(self.hooks_dir.glob("compliance-sentinel-*.json"))
            for hook_file in hook_files:
                hook_file.unlink()
                logger.info(f"Removed hook file: {hook_file.name}")
            
            # Remove hook handler
            handler_file = self.hooks_dir / "compliance-sentinel-handler.py"
            if handler_file.exists():
                handler_file.unlink()
                logger.info("Removed hook handler script")
            
            logger.info("Successfully uninstalled Compliance Sentinel hooks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall hooks: {e}")
            return False
    
    def _create_hook_configurations(self, settings: HookSettings) -> List[KiroHookConfig]:
        """Create hook configurations based on settings."""
        hooks = []
        
        # File save hook for real-time analysis
        file_save_hook = KiroHookConfig(
            hook_name="compliance-sentinel-file-save",
            trigger_events=["file:save", "file:create"],
            file_patterns=settings.enabled_file_patterns,
            excluded_paths=settings.excluded_directories,
            async_execution=settings.async_processing,
            timeout_seconds=settings.analysis_timeout,
            priority=8  # High priority for real-time feedback
        )
        hooks.append(file_save_hook)
        
        # Pre-commit hook for comprehensive analysis
        pre_commit_hook = KiroHookConfig(
            hook_name="compliance-sentinel-pre-commit",
            trigger_events=["git:pre-commit"],
            file_patterns=settings.enabled_file_patterns,
            excluded_paths=settings.excluded_directories,
            async_execution=False,  # Synchronous for commit blocking
            timeout_seconds=settings.analysis_timeout * 2,
            priority=10  # Highest priority for commit blocking
        )
        hooks.append(pre_commit_hook)
        
        # Manual analysis hook
        manual_hook = KiroHookConfig(
            hook_name="compliance-sentinel-manual",
            trigger_events=["command:compliance-check"],
            file_patterns=settings.enabled_file_patterns,
            excluded_paths=settings.excluded_directories,
            async_execution=True,
            timeout_seconds=settings.analysis_timeout,
            priority=5  # Normal priority for manual triggers
        )
        hooks.append(manual_hook)
        
        return hooks
    
    def _install_single_hook(self, hook: KiroHookConfig) -> None:
        """Install a single hook configuration."""
        hook_file = self.hooks_dir / f"{hook.hook_name}.json"
        
        with open(hook_file, 'w') as f:
            json.dump(hook.to_kiro_format(), f, indent=2)
        
        logger.debug(f"Created hook file: {hook_file}")
    
    def _create_hook_handler(self) -> None:
        """Create the hook handler script that Kiro will execute."""
        handler_content = '''#!/usr/bin/env python3
"""Compliance Sentinel Hook Handler for Kiro Agent Hooks."""

import sys
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime

# Add compliance_sentinel to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from compliance_sentinel.hooks.hook_manager import HookManager, HookEvent
from compliance_sentinel.models.config import HookSettings
from compliance_sentinel.utils.config_loader import ConfigLoader


async def main():
    """Main hook handler entry point."""
    try:
        # Parse command line arguments
        if len(sys.argv) < 2:
            print("Usage: hook-handler <event_data>", file=sys.stderr)
            sys.exit(1)
        
        # Parse event data from Kiro
        event_data = json.loads(sys.argv[1])
        
        # Create hook event
        hook_event = HookEvent(
            event_id=event_data.get('id', 'unknown'),
            event_type=event_data.get('type', 'unknown'),
            file_path=event_data.get('file_path', ''),
            timestamp=datetime.utcnow(),
            content=event_data.get('content'),
            metadata=event_data.get('metadata', {})
        )
        
        # Load configuration
        config_loader = ConfigLoader()
        hook_settings = config_loader.load_hook_settings()
        
        # Initialize hook manager
        hook_manager = HookManager(hook_settings)
        await hook_manager.start()
        
        try:
            # Process the event
            result = await hook_manager.process_hook_event(hook_event)
            
            # Output result for Kiro
            output = {
                "success": result.success,
                "duration_ms": result.duration_ms,
                "issues_found": result.issues_found,
                "summary": result.analysis_summary,
                "feedback_provided": result.feedback_provided
            }
            
            if result.error_message:
                output["error"] = result.error_message
            
            print(json.dumps(output))
            
            # Exit with appropriate code
            sys.exit(0 if result.success else 1)
            
        finally:
            await hook_manager.stop()
    
    except Exception as e:
        error_output = {
            "success": False,
            "error": str(e),
            "summary": "Hook handler failed"
        }
        print(json.dumps(error_output), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
'''
        
        handler_file = self.hooks_dir / "compliance-sentinel-handler.py"
        with open(handler_file, 'w') as f:
            f.write(handler_content)
        
        # Make executable
        handler_file.chmod(0o755)
        
        logger.debug(f"Created hook handler: {handler_file}")
    
    def _update_kiro_config(self, hooks: List[KiroHookConfig]) -> None:
        """Update Kiro configuration with hook information."""
        kiro_config_file = self.kiro_dir / "config.json"
        
        # Load existing config or create new
        if kiro_config_file.exists():
            with open(kiro_config_file, 'r') as f:
                kiro_config = json.load(f)
        else:
            kiro_config = {}
        
        # Add hooks section
        if "hooks" not in kiro_config:
            kiro_config["hooks"] = {}
        
        # Add compliance sentinel hooks
        for hook in hooks:
            kiro_config["hooks"][hook.hook_name] = {
                "enabled": True,
                "handler": str(self.hooks_dir / "compliance-sentinel-handler.py"),
                "config": hook.to_kiro_format()
            }
        
        # Save updated config
        with open(kiro_config_file, 'w') as f:
            json.dump(kiro_config, f, indent=2)
        
        logger.debug("Updated Kiro configuration")
    
    def create_steering_rules(self) -> None:
        """Create steering rules for Compliance Sentinel integration."""
        steering_content = '''---
inclusion: always
---

# Compliance Sentinel Integration

This document provides context for Kiro about the Compliance Sentinel system integration.

## Security Analysis Context

When working with code files, Compliance Sentinel provides real-time security analysis through:

- **SAST Analysis**: Static analysis using Bandit and Semgrep
- **Dependency Scanning**: Vulnerability detection in dependencies
- **Policy Enforcement**: Custom security policy validation
- **Real-time Feedback**: IDE integration for immediate issue reporting

## Hook Integration

Compliance Sentinel integrates with Kiro through Agent Hooks:

1. **File Save Hooks**: Analyze files on save for immediate feedback
2. **Pre-commit Hooks**: Comprehensive analysis before commits
3. **Manual Triggers**: On-demand security analysis

## Security Policies

The system enforces security policies defined in security.md:

- API Security and Authentication
- Credential and Secret Management  
- Dependency Vulnerability Management
- Input Validation and Sanitization
- Cryptographic Security
- Error Handling and Information Disclosure
- Secure Communication
- Access Control and Authorization

## Usage Guidelines

When making code changes:

1. Save files to trigger automatic analysis
2. Review security feedback in IDE
3. Address critical and high-severity issues before committing
4. Use manual analysis for comprehensive security review

## Configuration

Hook settings can be configured in `.kiro/settings/compliance-sentinel.json`:

```json
{
  "hooks": {
    "enabled_file_patterns": ["*.py", "*.js", "*.ts"],
    "excluded_directories": ["node_modules", ".git", "__pycache__"],
    "debounce_delay": 2.0,
    "async_processing": true,
    "analysis_timeout": 30
  }
}
```
'''
        
        steering_file = self.steering_dir / "compliance-sentinel.md"
        with open(steering_file, 'w') as f:
            f.write(steering_content)
        
        logger.info(f"Created steering rules: {steering_file}")
    
    def get_hook_status(self) -> Dict[str, Any]:
        """Get status of installed hooks."""
        status = {
            "installed": False,
            "hooks": [],
            "kiro_config_exists": False,
            "handler_exists": False
        }
        
        # Check if hooks are installed
        hook_files = list(self.hooks_dir.glob("compliance-sentinel-*.json"))
        status["installed"] = len(hook_files) > 0
        
        # Get hook information
        for hook_file in hook_files:
            try:
                with open(hook_file, 'r') as f:
                    hook_config = json.load(f)
                    status["hooks"].append({
                        "name": hook_config.get("name", "unknown"),
                        "file": hook_file.name,
                        "triggers": hook_config.get("triggers", []),
                        "patterns": hook_config.get("patterns", [])
                    })
            except Exception as e:
                logger.warning(f"Could not read hook file {hook_file}: {e}")
        
        # Check Kiro config
        kiro_config_file = self.kiro_dir / "config.json"
        status["kiro_config_exists"] = kiro_config_file.exists()
        
        # Check handler
        handler_file = self.hooks_dir / "compliance-sentinel-handler.py"
        status["handler_exists"] = handler_file.exists()
        
        return status
    
    def validate_installation(self) -> List[str]:
        """Validate hook installation and return any issues."""
        issues = []
        
        # Check if Kiro directory exists
        if not self.kiro_dir.exists():
            issues.append("Kiro directory (.kiro) not found - not in a Kiro workspace?")
            return issues
        
        # Check hook files
        hook_files = list(self.hooks_dir.glob("compliance-sentinel-*.json"))
        if not hook_files:
            issues.append("No Compliance Sentinel hook files found")
        
        # Validate each hook file
        for hook_file in hook_files:
            try:
                with open(hook_file, 'r') as f:
                    hook_config = json.load(f)
                    
                    required_fields = ["name", "triggers", "patterns", "command"]
                    for field in required_fields:
                        if field not in hook_config:
                            issues.append(f"Hook file {hook_file.name} missing required field: {field}")
                            
            except json.JSONDecodeError as e:
                issues.append(f"Invalid JSON in hook file {hook_file.name}: {e}")
            except Exception as e:
                issues.append(f"Error reading hook file {hook_file.name}: {e}")
        
        # Check handler script
        handler_file = self.hooks_dir / "compliance-sentinel-handler.py"
        if not handler_file.exists():
            issues.append("Hook handler script not found")
        elif not os.access(handler_file, os.X_OK):
            issues.append("Hook handler script is not executable")
        
        return issues


def install_kiro_hooks(hook_settings: Optional[HookSettings] = None) -> bool:
    """Convenience function to install Kiro hooks."""
    integration = KiroIntegration()
    success = integration.install_hooks(hook_settings)
    
    if success:
        integration.create_steering_rules()
    
    return success


def uninstall_kiro_hooks() -> bool:
    """Convenience function to uninstall Kiro hooks."""
    integration = KiroIntegration()
    return integration.uninstall_hooks()


def get_kiro_hook_status() -> Dict[str, Any]:
    """Convenience function to get hook status."""
    integration = KiroIntegration()
    return integration.get_hook_status()