"""Kiro Agent Hook integration and management for real-time security analysis with environment-aware configuration."""

import asyncio
import json
import time
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import hashlib

from compliance_sentinel.models.config import HookSettings
from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
from compliance_sentinel.analyzers.coordinator import AnalysisCoordinator
from compliance_sentinel.engines.policy_engine import PolicyEngine
from compliance_sentinel.engines.feedback_engine import FeedbackEngine
from compliance_sentinel.utils.error_handler import get_global_error_handler, async_safe_execute
from compliance_sentinel.utils.cache import get_global_cache
from compliance_sentinel.utils.performance import get_performance_monitor, performance_monitor
from compliance_sentinel.utils.async_utils import get_async_task_manager, AsyncRateLimiter
from compliance_sentinel.core.validation import InputSanitizer
from compliance_sentinel.config import get_config_manager


logger = logging.getLogger(__name__)


def _get_hook_env_var(key: str, default: Any, var_type: type = str) -> Any:
    """Get hook-specific environment variable."""
    env_key = f"COMPLIANCE_SENTINEL_HOOK_{key.upper()}"
    value = os.getenv(env_key)
    
    if value is None:
        return default
    
    try:
        if var_type == bool:
            return value.lower() in ('true', '1', 'yes', 'on')
        elif var_type == int:
            return int(value)
        elif var_type == float:
            return float(value)
        elif var_type == list:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return [item.strip() for item in value.split(',') if item.strip()]
        elif var_type == dict:
            return json.loads(value)
        else:
            return value
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid value for hook config {key}: {value}. Error: {e}")


@dataclass
class EnvironmentAwareHookSettings:
    """Hook settings with environment variable support."""
    enabled_file_patterns: List[str] = field(default_factory=lambda: _get_hook_env_var("file_patterns", ["*.py", "*.js", "*.ts"], list))
    excluded_directories: List[str] = field(default_factory=lambda: _get_hook_env_var("excluded_dirs", [
        "node_modules", "__pycache__", ".git", ".venv", "venv", "build", "dist"
    ], list))
    analysis_timeout: int = field(default_factory=lambda: _get_hook_env_var("analysis_timeout", 60, int))
    async_processing: bool = field(default_factory=lambda: _get_hook_env_var("async_processing", True, bool))
    batch_size: int = field(default_factory=lambda: _get_hook_env_var("batch_size", 10, int))
    debounce_delay: float = field(default_factory=lambda: _get_hook_env_var("debounce_delay", 0.5, float))
    max_concurrent_analyses: int = field(default_factory=lambda: _get_hook_env_var("max_concurrent_analyses", 3, int))
    enable_pre_commit_hooks: bool = field(default_factory=lambda: _get_hook_env_var("enable_pre_commit_hooks", True, bool))
    enable_file_watching: bool = field(default_factory=lambda: _get_hook_env_var("enable_file_watching", True, bool))
    rate_limit_per_second: float = field(default_factory=lambda: _get_hook_env_var("rate_limit_per_second", 10.0, float))
    rate_limit_burst: int = field(default_factory=lambda: _get_hook_env_var("rate_limit_burst", 5, int))
    
    def __post_init__(self):
        """Validate hook settings."""
        errors = []
        
        if self.analysis_timeout < 10:
            errors.append("analysis_timeout must be at least 10 seconds")
        
        if self.batch_size < 1:
            errors.append("batch_size must be at least 1")
        
        if self.debounce_delay < 0:
            errors.append("debounce_delay must be non-negative")
        
        if not self.enabled_file_patterns:
            errors.append("at least one file pattern must be enabled")
        
        if self.max_concurrent_analyses < 1:
            errors.append("max_concurrent_analyses must be at least 1")
        
        if self.rate_limit_per_second <= 0:
            errors.append("rate_limit_per_second must be positive")
        
        if self.rate_limit_burst < 1:
            errors.append("rate_limit_burst must be at least 1")
        
        if errors:
            raise ValueError(f"Hook settings validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return {
            'enabled_file_patterns': self.enabled_file_patterns,
            'excluded_directories': self.excluded_directories,
            'analysis_timeout': self.analysis_timeout,
            'async_processing': self.async_processing,
            'batch_size': self.batch_size,
            'debounce_delay': self.debounce_delay,
            'max_concurrent_analyses': self.max_concurrent_analyses,
            'enable_pre_commit_hooks': self.enable_pre_commit_hooks,
            'enable_file_watching': self.enable_file_watching,
            'rate_limit_per_second': self.rate_limit_per_second,
            'rate_limit_burst': self.rate_limit_burst
        }
    
    def get_secure_defaults(self, environment: str = "development") -> Dict[str, Any]:
        """Get secure defaults based on environment."""
        if environment == "production":
            return {
                "analysis_timeout": 30,  # Shorter timeout for production
                "max_concurrent_analyses": 2,  # Fewer concurrent analyses
                "async_processing": True,  # Always async in production
                "enable_file_watching": False,  # Disable file watching in production
                "rate_limit_per_second": 5.0,  # More restrictive rate limiting
                "rate_limit_burst": 2
            }
        else:
            return {
                "analysis_timeout": 60,
                "max_concurrent_analyses": 3,
                "async_processing": True,
                "enable_file_watching": True,
                "rate_limit_per_second": 10.0,
                "rate_limit_burst": 5
            }


class HookTrigger(Enum):
    """Types of hook triggers."""
    FILE_SAVE = "file_save"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    PRE_COMMIT = "pre_commit"
    POST_COMMIT = "post_commit"
    MANUAL = "manual"


class HookStatus(Enum):
    """Status of hook execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class HookEvent:
    """Represents a hook trigger event."""
    event_id: str
    trigger: HookTrigger
    file_path: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_file_extension(self) -> str:
        """Get file extension."""
        return Path(self.file_path).suffix.lower()
    
    def get_file_size(self) -> Optional[int]:
        """Get file size in bytes."""
        try:
            return Path(self.file_path).stat().st_size
        except Exception:
            return None
    
    def is_supported_file(self, supported_extensions: Set[str]) -> bool:
        """Check if file is supported for analysis."""
        return self.get_file_extension() in supported_extensions


@dataclass
class HookExecution:
    """Represents a hook execution instance."""
    execution_id: str
    event: HookEvent
    status: HookStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    issues_found: int = 0
    
    def complete(self, result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        """Mark execution as complete."""
        self.completed_at = datetime.utcnow()
        self.duration_ms = (self.completed_at - self.started_at).total_seconds() * 1000
        
        if error:
            self.status = HookStatus.FAILED
            self.error_message = error
        else:
            self.status = HookStatus.COMPLETED
            self.result = result or {}
            self.issues_found = len(result.get("issues", [])) if result else 0


@dataclass
class HookResult:
    """Result of a hook execution."""
    execution_id: str
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    issues_found: int = 0
    duration_ms: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)


class FileWatcher:
    """Watches for file system events and triggers hooks with environment-aware configuration."""
    
    def __init__(self, hook_manager: 'HookManager'):
        """Initialize file watcher with dynamic configuration."""
        self.hook_manager = hook_manager
        self.watched_patterns: Set[str] = set()
        self.excluded_patterns: Set[str] = set()
        self.debounce_cache: Dict[str, float] = {}
        
        # Initialize rate limiter with environment-aware settings
        settings = hook_manager.settings
        self.rate_limiter = AsyncRateLimiter(
            rate=settings.rate_limit_per_second, 
            burst=settings.rate_limit_burst
        )
        
    def add_watch_pattern(self, pattern: str) -> None:
        """Add file pattern to watch."""
        self.watched_patterns.add(pattern)
        logger.debug(f"Added watch pattern: {pattern}")
    
    def add_exclude_pattern(self, pattern: str) -> None:
        """Add file pattern to exclude."""
        self.excluded_patterns.add(pattern)
        logger.debug(f"Added exclude pattern: {pattern}")
    
    def should_process_file(self, file_path: str) -> bool:
        """Check if file should be processed."""
        path = Path(file_path)
        
        # Check if file matches watched patterns
        if self.watched_patterns:
            matches_pattern = any(
                path.match(pattern) for pattern in self.watched_patterns
            )
            if not matches_pattern:
                return False
        
        # Check if file matches excluded patterns
        if self.excluded_patterns:
            matches_exclude = any(
                path.match(pattern) for pattern in self.excluded_patterns
            )
            if matches_exclude:
                return False
        
        return True
    
    async def handle_file_event(
        self, 
        trigger: HookTrigger, 
        file_path: str, 
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Handle a file system event."""
        # Rate limiting
        async with self.rate_limiter:
            # Sanitize file path
            file_path = InputSanitizer.sanitize_filename(file_path)
            
            # Check if file should be processed
            if not self.should_process_file(file_path):
                logger.debug(f"Skipping file {file_path} (doesn't match patterns)")
                return None
            
            # Debouncing - prevent rapid-fire events for same file
            debounce_key = f"{file_path}:{trigger.value}"
            current_time = time.time()
            
            if debounce_key in self.debounce_cache:
                last_event_time = self.debounce_cache[debounce_key]
                if current_time - last_event_time < self.hook_manager.settings.debounce_delay:
                    logger.debug(f"Debouncing event for {file_path}")
                    return None
            
            self.debounce_cache[debounce_key] = current_time
            
            # Create hook event
            event = HookEvent(
                event_id=self._generate_event_id(file_path, trigger),
                trigger=trigger,
                file_path=file_path,
                timestamp=datetime.utcnow(),
                metadata=metadata or {}
            )
            
            # Trigger hook execution
            execution_id = await self.hook_manager.execute_hook(event)
            
            logger.info(f"Triggered hook for {file_path} (execution: {execution_id})")
            return execution_id
    
    def _generate_event_id(self, file_path: str, trigger: HookTrigger) -> str:
        """Generate unique event ID."""
        content = f"{file_path}:{trigger.value}:{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def cleanup_debounce_cache(self) -> None:
        """Clean up old debounce cache entries."""
        current_time = time.time()
        cutoff_time = current_time - (self.hook_manager.settings.debounce_delay * 10)
        
        keys_to_remove = [
            key for key, timestamp in self.debounce_cache.items()
            if timestamp < cutoff_time
        ]
        
        for key in keys_to_remove:
            del self.debounce_cache[key]
        
        if keys_to_remove:
            logger.debug(f"Cleaned up {len(keys_to_remove)} debounce cache entries")


class HookManager:
    """Manages Kiro Agent Hook integration for real-time security analysis with environment-aware configuration."""
    
    def __init__(self, settings: Optional[EnvironmentAwareHookSettings] = None):
        """Initialize hook manager with environment-aware settings."""
        self.settings = settings or EnvironmentAwareHookSettings()
        self.config_manager = get_config_manager()
        
        # Initialize components
        self.analysis_coordinator = AnalysisCoordinator()
        self.policy_engine = PolicyEngine()
        self.feedback_engine = FeedbackEngine()
        
        # Utilities
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        self.performance_monitor = get_performance_monitor()
        self.task_manager = get_async_task_manager()
        
        # Initialize file watcher after settings are set
        self.file_watcher = FileWatcher(self)
        
        # Hook execution tracking
        self.active_executions: Dict[str, HookExecution] = {}
        self.execution_history: List[HookExecution] = []
        self.max_history = _get_hook_env_var("max_history", 1000, int)
        
        # Concurrency control
        self.analysis_semaphore = asyncio.Semaphore(self.settings.max_concurrent_analyses)
        
        # Statistics
        self.stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "total_issues_found": 0,
            "avg_execution_time_ms": 0.0,
            "config_reloads": 0,
            "rate_limited_events": 0
        }
        
        # Configure file watcher
        self._configure_file_watcher()
        
        # Set up configuration change monitoring
        self._setup_config_monitoring()
        
        logger.info(f"Hook manager initialized with settings: {self.settings.to_dict()}")
    
    def _configure_file_watcher(self) -> None:
        """Configure file watcher with patterns from settings."""
        # Add watched patterns
        for pattern in self.settings.enabled_file_patterns:
            self.file_watcher.add_watch_pattern(pattern)
        
        # Add excluded directories as patterns
        for excluded_dir in self.settings.excluded_directories:
            self.file_watcher.add_exclude_pattern(f"{excluded_dir}/**")
            self.file_watcher.add_exclude_pattern(f"**/{excluded_dir}/**")
    
    @performance_monitor("hook_execution")
    async def execute_hook(self, event: HookEvent) -> str:
        """Execute hook for a file event with concurrency control."""
        execution_id = f"exec_{event.event_id}_{int(time.time())}"
        
        # Create execution record
        execution = HookExecution(
            execution_id=execution_id,
            event=event,
            status=HookStatus.PENDING,
            started_at=datetime.utcnow()
        )
        
        self.active_executions[execution_id] = execution
        
        try:
            # Check if file exists and is readable
            if not Path(event.file_path).exists():
                raise FileNotFoundError(f"File not found: {event.file_path}")
            
            # Check if file watching is enabled
            if not self.settings.enable_file_watching and event.trigger in [
                HookTrigger.FILE_SAVE, HookTrigger.FILE_CREATE, HookTrigger.FILE_MODIFY
            ]:
                logger.debug(f"File watching disabled, skipping {event.file_path}")
                execution.complete(error="File watching disabled")
                self._finalize_execution(execution)
                return execution_id
            
            # Check if pre-commit hooks are enabled
            if not self.settings.enable_pre_commit_hooks and event.trigger == HookTrigger.PRE_COMMIT:
                logger.debug(f"Pre-commit hooks disabled, skipping {event.file_path}")
                execution.complete(error="Pre-commit hooks disabled")
                self._finalize_execution(execution)
                return execution_id
            
            # Update status to running
            execution.status = HookStatus.RUNNING
            
            # Submit analysis task with concurrency control
            if self.settings.async_processing:
                # Async execution with semaphore
                task_id = await self.task_manager.submit_task(
                    self._analyze_file_with_semaphore(event),
                    task_name=f"hook_analysis_{event.event_id}",
                    timeout=self.settings.analysis_timeout
                )
                
                # Store task ID for tracking
                execution.metadata = {"task_id": task_id}
                
                # Don't wait for completion in async mode
                logger.info(f"Started async analysis for {event.file_path} (task: {task_id})")
                
            else:
                # Synchronous execution with semaphore
                result = await self._analyze_file_with_semaphore(event)
                execution.complete(result)
                self._finalize_execution(execution)
        
        except Exception as e:
            logger.error(f"Hook execution failed for {event.file_path}: {e}")
            execution.complete(error=str(e))
            self._finalize_execution(execution)
            self.error_handler.handle_analysis_error(e, f"hook_execution:{event.file_path}")
        
        return execution_id
    
    async def _analyze_file_with_semaphore(self, event: HookEvent) -> Dict[str, Any]:
        """Analyze file with concurrency control."""
        async with self.analysis_semaphore:
            return await self._analyze_file_async(event)
    
    async def _analyze_file_async(self, event: HookEvent) -> Dict[str, Any]:
        """Perform async analysis of a file."""
        file_path = event.file_path
        
        try:
            # Create analysis request
            analysis_request = AnalysisRequest(
                file_paths=[file_path],
                analysis_type=AnalysisType.COMPREHENSIVE,
                timeout_seconds=self.settings.analysis_timeout
            )
            
            # Run comprehensive analysis
            analysis_response = await self.analysis_coordinator.run_comprehensive_scan(analysis_request)
            
            # Generate feedback if issues found
            feedback = None
            if analysis_response.issues:
                feedback = self.feedback_engine.format_ide_feedback(analysis_response.issues)
            
            # Prepare result
            result = {
                "file_path": file_path,
                "analysis_status": analysis_response.status.value,
                "issues": [
                    {
                        "id": issue.id,
                        "severity": issue.severity.value,
                        "category": issue.category.value,
                        "line": issue.line_number,
                        "description": issue.description,
                        "confidence": issue.confidence,
                        "remediation": issue.remediation_suggestions[:3]
                    }
                    for issue in analysis_response.issues
                ],
                "vulnerabilities": [
                    {
                        "cve_id": vuln.cve_id,
                        "package": vuln.package_name,
                        "severity": vuln.severity_score,
                        "description": vuln.description
                    }
                    for vuln in analysis_response.vulnerabilities
                ],
                "recommendations": analysis_response.recommendations,
                "analysis_duration_ms": analysis_response.duration_seconds * 1000 if analysis_response.duration_seconds else 0,
                "tools_used": analysis_response.tools_used,
                "ide_feedback": feedback
            }
            
            logger.info(f"Analysis completed for {file_path}: {len(analysis_response.issues)} issues found")
            return result
            
        except Exception as e:
            logger.error(f"File analysis failed for {file_path}: {e}")
            raise
    
    def _finalize_execution(self, execution: HookExecution) -> None:
        """Finalize hook execution and update statistics."""
        # Remove from active executions
        if execution.execution_id in self.active_executions:
            del self.active_executions[execution.execution_id]
        
        # Add to history
        self.execution_history.append(execution)
        
        # Trim history if needed
        if len(self.execution_history) > self.max_history:
            self.execution_history = self.execution_history[-self.max_history//2:]
        
        # Update statistics
        self.stats["total_executions"] += 1
        
        if execution.status == HookStatus.COMPLETED:
            self.stats["successful_executions"] += 1
            self.stats["total_issues_found"] += execution.issues_found
        elif execution.status == HookStatus.FAILED:
            self.stats["failed_executions"] += 1
        
        # Update average execution time
        if execution.duration_ms:
            total_time = self.stats["avg_execution_time_ms"] * (self.stats["total_executions"] - 1)
            self.stats["avg_execution_time_ms"] = (total_time + execution.duration_ms) / self.stats["total_executions"]
        
        logger.debug(f"Finalized execution {execution.execution_id}: {execution.status.value}")
    
    async def handle_file_save(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Handle file save event."""
        return await self.file_watcher.handle_file_event(HookTrigger.FILE_SAVE, file_path, metadata)
    
    async def handle_file_create(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Handle file create event."""
        return await self.file_watcher.handle_file_event(HookTrigger.FILE_CREATE, file_path, metadata)
    
    async def handle_file_modify(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Handle file modify event."""
        return await self.file_watcher.handle_file_event(HookTrigger.FILE_MODIFY, file_path, metadata)
    
    async def handle_pre_commit(self, file_paths: List[str], metadata: Optional[Dict[str, Any]] = None) -> List[str]:
        """Handle pre-commit hook for multiple files."""
        execution_ids = []
        
        for file_path in file_paths:
            execution_id = await self.file_watcher.handle_file_event(
                HookTrigger.PRE_COMMIT, file_path, metadata
            )
            if execution_id:
                execution_ids.append(execution_id)
        
        logger.info(f"Pre-commit hook triggered for {len(file_paths)} files")
        return execution_ids
    
    async def manual_analysis(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Trigger manual analysis of a file."""
        return await self.file_watcher.handle_file_event(HookTrigger.MANUAL, file_path, metadata)
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a hook execution."""
        # Check active executions
        if execution_id in self.active_executions:
            execution = self.active_executions[execution_id]
            return self._execution_to_dict(execution)
        
        # Check execution history
        for execution in reversed(self.execution_history):
            if execution.execution_id == execution_id:
                return self._execution_to_dict(execution)
        
        return None
    
    def _execution_to_dict(self, execution: HookExecution) -> Dict[str, Any]:
        """Convert execution to dictionary."""
        return {
            "execution_id": execution.execution_id,
            "status": execution.status.value,
            "trigger": execution.event.trigger.value,
            "file_path": execution.event.file_path,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "duration_ms": execution.duration_ms,
            "issues_found": execution.issues_found,
            "error_message": execution.error_message,
            "result": execution.result
        }
    
    def get_recent_executions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent hook executions."""
        recent = list(reversed(self.execution_history[-limit:]))
        return [self._execution_to_dict(execution) for execution in recent]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get hook execution statistics with environment-aware information."""
        # Calculate success rate
        success_rate = 0.0
        if self.stats["total_executions"] > 0:
            success_rate = self.stats["successful_executions"] / self.stats["total_executions"]
        
        # Get recent activity (last hour)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_executions = [
            exec for exec in self.execution_history
            if exec.started_at > one_hour_ago
        ]
        
        # Get environment info
        environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        
        return {
            "total_executions": self.stats["total_executions"],
            "successful_executions": self.stats["successful_executions"],
            "failed_executions": self.stats["failed_executions"],
            "success_rate": round(success_rate, 3),
            "total_issues_found": self.stats["total_issues_found"],
            "avg_execution_time_ms": round(self.stats["avg_execution_time_ms"], 2),
            "active_executions": len(self.active_executions),
            "recent_activity_1h": len(recent_executions),
            "config_reloads": self.stats["config_reloads"],
            "rate_limited_events": self.stats["rate_limited_events"],
            "watched_patterns": list(self.file_watcher.watched_patterns),
            "excluded_patterns": list(self.file_watcher.excluded_patterns),
            "environment": environment,
            "current_settings": self.settings.to_dict(),
            "concurrency": {
                "max_concurrent_analyses": self.settings.max_concurrent_analyses,
                "available_slots": self.analysis_semaphore._value,
                "rate_limit_per_second": self.settings.rate_limit_per_second,
                "rate_limit_burst": self.settings.rate_limit_burst
            }
        }
    
    async def wait_for_execution(self, execution_id: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Wait for a hook execution to complete."""
        start_time = time.time()
        timeout = timeout or self.settings.analysis_timeout
        
        while True:
            # Check if execution is complete
            status = self.get_execution_status(execution_id)
            if status and status["status"] in ["completed", "failed", "cancelled"]:
                return status
            
            # Check timeout
            if time.time() - start_time > timeout:
                logger.warning(f"Timeout waiting for execution {execution_id}")
                return None
            
            # Wait before checking again
            await asyncio.sleep(0.5)
    
    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running hook execution."""
        if execution_id in self.active_executions:
            execution = self.active_executions[execution_id]
            
            # Try to cancel the task if it has one
            if "task_id" in execution.metadata:
                task_id = execution.metadata["task_id"]
                cancelled = self.task_manager.cancel_task(task_id)
                
                if cancelled:
                    execution.status = HookStatus.CANCELLED
                    execution.complete(error="Execution cancelled by user")
                    self._finalize_execution(execution)
                    
                    logger.info(f"Cancelled execution {execution_id}")
                    return True
        
        return False
    
    def _setup_config_monitoring(self) -> None:
        """Set up configuration change monitoring."""
        try:
            # Register for configuration change notifications
            self.config_manager.add_reload_callback(self._on_config_reload)
            logger.debug("Configuration monitoring set up for hook manager")
        except Exception as e:
            logger.warning(f"Could not set up configuration monitoring: {e}")
    
    async def _on_config_reload(self) -> None:
        """Handle configuration reload."""
        try:
            # Reload settings from environment
            new_settings = EnvironmentAwareHookSettings()
            await self.update_settings(new_settings)
            self.stats["config_reloads"] += 1
            logger.info("Hook manager configuration reloaded from environment")
        except Exception as e:
            logger.error(f"Error reloading hook manager configuration: {e}")
    
    async def update_settings(self, new_settings: EnvironmentAwareHookSettings) -> None:
        """Update hook manager settings dynamically."""
        old_settings = self.settings
        self.settings = new_settings
        
        # Update concurrency control
        if old_settings.max_concurrent_analyses != new_settings.max_concurrent_analyses:
            self.analysis_semaphore = asyncio.Semaphore(new_settings.max_concurrent_analyses)
        
        # Update rate limiter
        if (old_settings.rate_limit_per_second != new_settings.rate_limit_per_second or
            old_settings.rate_limit_burst != new_settings.rate_limit_burst):
            self.file_watcher.rate_limiter = AsyncRateLimiter(
                rate=new_settings.rate_limit_per_second,
                burst=new_settings.rate_limit_burst
            )
        
        # Reconfigure file watcher
        self.file_watcher.watched_patterns.clear()
        self.file_watcher.excluded_patterns.clear()
        self._configure_file_watcher()
        
        logger.info(f"Hook manager settings updated: {new_settings.to_dict()}")
    
    def reload_settings_from_environment(self) -> None:
        """Reload settings from environment variables."""
        try:
            new_settings = EnvironmentAwareHookSettings()
            asyncio.create_task(self.update_settings(new_settings))
            logger.info("Hook manager settings reloaded from environment")
        except Exception as e:
            logger.error(f"Error reloading hook manager settings: {e}")
    
    def get_environment_variables_info(self) -> Dict[str, Any]:
        """Get information about environment variables used for configuration."""
        env_vars = {}
        config_fields = [
            "file_patterns", "excluded_dirs", "analysis_timeout", "async_processing",
            "batch_size", "debounce_delay", "max_concurrent_analyses", 
            "enable_pre_commit_hooks", "enable_file_watching", 
            "rate_limit_per_second", "rate_limit_burst"
        ]
        
        for field in config_fields:
            env_key = f"COMPLIANCE_SENTINEL_HOOK_{field.upper()}"
            env_value = os.getenv(env_key)
            
            # Map field names to actual attribute names
            attr_name = field
            if field == "file_patterns":
                attr_name = "enabled_file_patterns"
            elif field == "excluded_dirs":
                attr_name = "excluded_directories"
            
            current_value = getattr(self.settings, attr_name, None)
            
            env_vars[field] = {
                "env_key": env_key,
                "env_value": env_value,
                "current_value": current_value,
                "using_default": env_value is None
            }
        
        return env_vars
    
    def cleanup(self) -> None:
        """Cleanup resources and cancel active executions."""
        # Cancel all active executions
        for execution_id in list(self.active_executions.keys()):
            self.cancel_execution(execution_id)
        
        # Cleanup file watcher
        self.file_watcher.cleanup_debounce_cache()
        
        logger.info("Hook manager cleanup completed")


# Global hook manager instance
_hook_manager: Optional[HookManager] = None


def get_hook_manager() -> HookManager:
    """Get or create global hook manager instance with environment-aware settings."""
    global _hook_manager
    if _hook_manager is None:
        _hook_manager = HookManager()
    return _hook_manager


def set_hook_manager(hook_manager: HookManager) -> None:
    """Set global hook manager instance."""
    global _hook_manager
    _hook_manager = hook_manager


def create_hook_manager_with_environment_settings() -> HookManager:
    """Create hook manager with fresh environment settings."""
    settings = EnvironmentAwareHookSettings()
    return HookManager(settings)


def reload_global_hook_manager_settings() -> None:
    """Reload global hook manager settings from environment."""
    global _hook_manager
    if _hook_manager is not None:
        _hook_manager.reload_settings_from_environment()