"""File system watcher for detecting code changes and triggering security analysis with dynamic configuration."""

import asyncio
import time
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
import fnmatch
import hashlib

from compliance_sentinel.hooks.hook_manager import HookTrigger, HookEvent
from compliance_sentinel.utils.error_handler import get_global_error_handler
from compliance_sentinel.core.validation import InputSanitizer


logger = logging.getLogger(__name__)


def _get_file_watcher_env_var(key: str, default: Any, var_type: type = str) -> Any:
    """Get file watcher-specific environment variable."""
    env_key = f"COMPLIANCE_SENTINEL_FILE_WATCHER_{key.upper()}"
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
        raise ValueError(f"Invalid value for file watcher config {key}: {value}. Error: {e}")


@dataclass
class FileWatcherConfig:
    """Configuration for file watcher with environment variable support."""
    batch_size: int = field(default_factory=lambda: _get_file_watcher_env_var("batch_size", 10, int))
    batch_timeout: float = field(default_factory=lambda: _get_file_watcher_env_var("batch_timeout", 2.0, float))
    debounce_delay: float = field(default_factory=lambda: _get_file_watcher_env_var("debounce_delay", 0.5, float))
    max_file_size_mb: int = field(default_factory=lambda: _get_file_watcher_env_var("max_file_size_mb", 10, int))
    include_patterns: List[str] = field(default_factory=lambda: _get_file_watcher_env_var("include_patterns", ["*.py", "*.js", "*.ts", "*.java", "*.go"], list))
    exclude_patterns: List[str] = field(default_factory=lambda: _get_file_watcher_env_var("exclude_patterns", ["*.pyc", "*.log", "*.tmp", "__pycache__/*", ".git/*", "node_modules/*"], list))
    excluded_directories: List[str] = field(default_factory=lambda: _get_file_watcher_env_var("excluded_directories", [".git", "__pycache__", "node_modules", ".pytest_cache", "venv", ".venv"], list))
    enable_hash_calculation: bool = field(default_factory=lambda: _get_file_watcher_env_var("enable_hash_calculation", True, bool))
    hash_calculation_threshold_kb: int = field(default_factory=lambda: _get_file_watcher_env_var("hash_calculation_threshold_kb", 1024, int))
    enable_content_analysis: bool = field(default_factory=lambda: _get_file_watcher_env_var("enable_content_analysis", False, bool))
    
    def __post_init__(self):
        """Validate file watcher configuration."""
        errors = []
        
        if self.batch_size <= 0:
            errors.append("batch_size must be positive")
        
        if self.batch_timeout <= 0:
            errors.append("batch_timeout must be positive")
        
        if self.debounce_delay < 0:
            errors.append("debounce_delay must be non-negative")
        
        if self.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        if not self.include_patterns:
            errors.append("at least one include pattern must be specified")
        
        if errors:
            raise ValueError(f"File watcher configuration validation failed: {'; '.join(errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "batch_size": self.batch_size,
            "batch_timeout": self.batch_timeout,
            "debounce_delay": self.debounce_delay,
            "max_file_size_mb": self.max_file_size_mb,
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
            "excluded_directories": self.excluded_directories,
            "enable_hash_calculation": self.enable_hash_calculation,
            "hash_calculation_threshold_kb": self.hash_calculation_threshold_kb,
            "enable_content_analysis": self.enable_content_analysis
        }
    
    def get_secure_defaults(self, environment: str = "development") -> Dict[str, Any]:
        """Get secure defaults based on environment."""
        if environment == "production":
            return {
                "batch_size": 5,  # Smaller batches for production
                "batch_timeout": 1.0,  # Faster processing
                "debounce_delay": 0.2,  # Less debouncing
                "max_file_size_mb": 5,  # Smaller file limit
                "enable_hash_calculation": False,  # Disable for performance
                "enable_content_analysis": False  # Disable for security
            }
        else:
            return {
                "batch_size": 10,
                "batch_timeout": 2.0,
                "debounce_delay": 0.5,
                "max_file_size_mb": 10,
                "enable_hash_calculation": True,
                "enable_content_analysis": True
            }


@dataclass
class FileChangeEvent:
    """Represents a file system change event with configurable metadata calculation."""
    file_path: str
    event_type: str  # created, modified, deleted, moved
    timestamp: datetime
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    content_preview: Optional[str] = None
    config: Optional[FileWatcherConfig] = None
    
    def __post_init__(self):
        """Calculate file metadata based on configuration."""
        if not self.config:
            self.config = FileWatcherConfig()
        
        try:
            path = Path(self.file_path)
            if not path.exists() or not path.is_file():
                return
            
            # Always calculate file size
            self.file_size = path.stat().st_size
            
            # Check file size limit
            max_size_bytes = self.config.max_file_size_mb * 1024 * 1024
            if self.file_size > max_size_bytes:
                logger.debug(f"File too large for processing: {self.file_path} ({self.file_size} bytes)")
                return
            
            # Calculate hash if enabled and file is small enough
            if (self.config.enable_hash_calculation and 
                self.file_size < self.config.hash_calculation_threshold_kb * 1024):
                
                with open(path, 'rb') as f:
                    content = f.read()
                self.file_hash = hashlib.md5(content).hexdigest()
                
                # Generate content preview if enabled
                if self.config.enable_content_analysis:
                    try:
                        # Try to decode as text for preview
                        text_content = content.decode('utf-8', errors='ignore')
                        # Get first 200 characters as preview
                        self.content_preview = text_content[:200] if text_content else None
                    except Exception:
                        self.content_preview = None
                        
        except Exception as e:
            logger.debug(f"Could not calculate file metadata for {self.file_path}: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "file_path": self.file_path,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "has_content_preview": self.content_preview is not None,
            "content_preview_length": len(self.content_preview) if self.content_preview else 0
        }


class FilePatternMatcher:
    """Matches files against include/exclude patterns with dynamic configuration."""
    
    def __init__(self, config: Optional[FileWatcherConfig] = None):
        """Initialize pattern matcher with configuration."""
        self.config = config or FileWatcherConfig()
        self.include_patterns: Set[str] = set(self.config.include_patterns)
        self.exclude_patterns: Set[str] = set(self.config.exclude_patterns)
        self.excluded_directories: Set[str] = set(self.config.excluded_directories)
        self.compiled_patterns: Dict[str, Any] = {}
        
        # Compile initial patterns
        for pattern in self.include_patterns:
            self._compile_pattern(pattern)
        for pattern in self.exclude_patterns:
            self._compile_pattern(pattern)
    
    def add_include_pattern(self, pattern: str) -> None:
        """Add include pattern."""
        self.include_patterns.add(pattern)
        self._compile_pattern(pattern)
    
    def add_exclude_pattern(self, pattern: str) -> None:
        """Add exclude pattern."""
        self.exclude_patterns.add(pattern)
        self._compile_pattern(pattern)
    
    def _compile_pattern(self, pattern: str) -> None:
        """Compile pattern for efficient matching."""
        # Store compiled regex or glob pattern
        self.compiled_patterns[pattern] = {
            "original": pattern,
            "compiled_at": datetime.utcnow()
        }
    
    def matches_include_patterns(self, file_path: str) -> bool:
        """Check if file matches any include patterns."""
        if not self.include_patterns:
            return True  # No include patterns means include all
        
        path = Path(file_path)
        
        for pattern in self.include_patterns:
            if self._matches_pattern(path, pattern):
                return True
        
        return False
    
    def matches_exclude_patterns(self, file_path: str) -> bool:
        """Check if file matches any exclude patterns."""
        if not self.exclude_patterns:
            return False  # No exclude patterns means exclude none
        
        path = Path(file_path)
        
        for pattern in self.exclude_patterns:
            if self._matches_pattern(path, pattern):
                return True
        
        return False
    
    def _matches_pattern(self, path: Path, pattern: str) -> bool:
        """Check if path matches a specific pattern."""
        try:
            # Handle different pattern types
            if '**' in pattern:
                # Recursive glob pattern
                return path.match(pattern)
            elif '*' in pattern or '?' in pattern:
                # Simple glob pattern
                return fnmatch.fnmatch(str(path), pattern) or fnmatch.fnmatch(path.name, pattern)
            else:
                # Exact match or substring
                return pattern in str(path) or pattern == path.name
        except Exception as e:
            logger.warning(f"Pattern matching error for {pattern}: {e}")
            return False
    
    def should_process_file(self, file_path: str) -> bool:
        """Determine if file should be processed based on patterns and configuration."""
        path = Path(file_path)
        
        # Check if file is in excluded directory
        for excluded_dir in self.excluded_directories:
            if excluded_dir in path.parts:
                return False
        
        # Check file size limit
        try:
            if path.exists() and path.is_file():
                file_size = path.stat().st_size
                max_size_bytes = self.config.max_file_size_mb * 1024 * 1024
                if file_size > max_size_bytes:
                    return False
        except Exception:
            # If we can't check file size, skip it
            return False
        
        # Must match include patterns (if any)
        if not self.matches_include_patterns(file_path):
            return False
        
        # Must not match exclude patterns
        if self.matches_exclude_patterns(file_path):
            return False
        
        return True
    
    def get_pattern_stats(self) -> Dict[str, Any]:
        """Get pattern matching statistics."""
        return {
            "include_patterns": list(self.include_patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "total_patterns": len(self.include_patterns) + len(self.exclude_patterns),
            "compiled_patterns": len(self.compiled_patterns)
        }


class AdvancedFileWatcher:
    """Advanced file watcher with intelligent filtering and batching using dynamic configuration."""
    
    def __init__(self, hook_callback: Callable[[HookEvent], None], config: Optional[FileWatcherConfig] = None):
        """Initialize advanced file watcher with configuration."""
        self.config = config or FileWatcherConfig()
        self.hook_callback = hook_callback
        self.pattern_matcher = FilePatternMatcher(self.config)
        self.error_handler = get_global_error_handler()
        
        # File change tracking
        self.file_states: Dict[str, FileChangeEvent] = {}
        self.pending_events: Dict[str, FileChangeEvent] = {}
        
        # Configuration-driven settings
        self.batch_size = self.config.batch_size
        self.batch_timeout = self.config.batch_timeout
        self.debounce_delay = self.config.debounce_delay
        self.last_batch_time = time.time()
        
        # Debouncing cache
        self.debounce_cache: Dict[str, float] = {}
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "events_filtered": 0,
            "events_debounced": 0,
            "batches_processed": 0,
            "config_reloads": 0,
            "large_files_skipped": 0
        }
        
        # Start batch processing task
        self._batch_task = None
        self._start_batch_processing()
        
        logger.info(f"Advanced file watcher initialized with config: {self.config.to_dict()}")
    
    def _start_batch_processing(self) -> None:
        """Start background batch processing task."""
        async def batch_processor():
            while True:
                try:
                    await self._process_pending_events()
                    await asyncio.sleep(0.1)  # Check every 100ms
                except Exception as e:
                    logger.error(f"Batch processing error: {e}")
                    await asyncio.sleep(1.0)  # Wait longer on error
        
        self._batch_task = asyncio.create_task(batch_processor())
    
    async def on_file_changed(
        self, 
        file_path: str, 
        event_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Handle file change event."""
        try:
            # Sanitize file path
            file_path = InputSanitizer.sanitize_filename(file_path)
            
            # Check if file should be processed
            if not self.pattern_matcher.should_process_file(file_path):
                self.stats["events_filtered"] += 1
                logger.debug(f"Filtered out file change: {file_path}")
                return
            
            # Debouncing check
            debounce_key = f"{file_path}:{event_type}"
            current_time = time.time()
            
            if debounce_key in self.debounce_cache:
                last_event_time = self.debounce_cache[debounce_key]
                if current_time - last_event_time < self.debounce_delay:
                    self.stats["events_debounced"] += 1
                    logger.debug(f"Debounced file change: {file_path}")
                    return
            
            self.debounce_cache[debounce_key] = current_time
            
            # Create file change event with configuration
            change_event = FileChangeEvent(
                file_path=file_path,
                event_type=event_type,
                timestamp=datetime.utcnow(),
                config=self.config
            )
            
            # Skip if file is too large
            if (change_event.file_size and 
                change_event.file_size > self.config.max_file_size_mb * 1024 * 1024):
                self.stats["large_files_skipped"] += 1
                logger.debug(f"Skipped large file: {file_path} ({change_event.file_size} bytes)")
                return
            
            # Add to pending events for batch processing
            self.pending_events[file_path] = change_event
            self.stats["events_processed"] += 1
            
            logger.debug(f"Queued file change event: {file_path} ({event_type})")
            
        except Exception as e:
            logger.error(f"Error handling file change for {file_path}: {e}")
            self.error_handler.handle_analysis_error(e, f"file_watcher:{file_path}")
    
    async def _process_pending_events(self) -> None:
        """Process pending file change events in batches."""
        current_time = time.time()
        
        # Check if we should process a batch
        should_process = (
            len(self.pending_events) >= self.batch_size or
            (self.pending_events and current_time - self.last_batch_time > self.batch_timeout)
        )
        
        if not should_process:
            return
        
        # Get events to process
        events_to_process = list(self.pending_events.values())
        self.pending_events.clear()
        self.last_batch_time = current_time
        
        if not events_to_process:
            return
        
        logger.info(f"Processing batch of {len(events_to_process)} file change events")
        
        # Process events
        for change_event in events_to_process:
            try:
                # Map file change event to hook trigger
                trigger = self._map_event_type_to_trigger(change_event.event_type)
                
                # Create hook event
                hook_event = HookEvent(
                    event_id=self._generate_event_id(change_event),
                    trigger=trigger,
                    file_path=change_event.file_path,
                    timestamp=change_event.timestamp,
                    metadata={
                        "file_size": change_event.file_size,
                        "file_hash": change_event.file_hash,
                        "event_type": change_event.event_type
                    }
                )
                
                # Trigger hook callback
                await self.hook_callback(hook_event)
                
            except Exception as e:
                logger.error(f"Error processing file change event: {e}")
                self.error_handler.handle_analysis_error(e, "batch_event_processing")
        
        self.stats["batches_processed"] += 1
        logger.debug(f"Completed batch processing: {len(events_to_process)} events")
    
    def _map_event_type_to_trigger(self, event_type: str) -> HookTrigger:
        """Map file system event type to hook trigger."""
        mapping = {
            "created": HookTrigger.FILE_CREATE,
            "modified": HookTrigger.FILE_MODIFY,
            "deleted": HookTrigger.FILE_DELETE,
            "saved": HookTrigger.FILE_SAVE
        }
        return mapping.get(event_type, HookTrigger.FILE_MODIFY)
    
    def _generate_event_id(self, change_event: FileChangeEvent) -> str:
        """Generate unique event ID."""
        content = f"{change_event.file_path}:{change_event.event_type}:{change_event.timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def add_include_pattern(self, pattern: str) -> None:
        """Add file pattern to include."""
        self.pattern_matcher.add_include_pattern(pattern)
    
    def add_exclude_pattern(self, pattern: str) -> None:
        """Add file pattern to exclude."""
        self.pattern_matcher.add_exclude_pattern(pattern)
    
    def update_config(self, new_config: FileWatcherConfig) -> None:
        """Update file watcher configuration dynamically."""
        old_config = self.config
        self.config = new_config
        
        # Update runtime settings
        self.batch_size = new_config.batch_size
        self.batch_timeout = new_config.batch_timeout
        self.debounce_delay = new_config.debounce_delay
        
        # Update pattern matcher
        self.pattern_matcher = FilePatternMatcher(new_config)
        
        # Clear caches if significant changes
        if (old_config.debounce_delay != new_config.debounce_delay or
            old_config.include_patterns != new_config.include_patterns or
            old_config.exclude_patterns != new_config.exclude_patterns):
            self.debounce_cache.clear()
        
        self.stats["config_reloads"] += 1
        logger.info(f"File watcher configuration updated: {new_config.to_dict()}")
    
    def reload_config_from_environment(self) -> None:
        """Reload configuration from environment variables."""
        try:
            new_config = FileWatcherConfig()
            self.update_config(new_config)
            logger.info("File watcher configuration reloaded from environment")
        except Exception as e:
            logger.error(f"Error reloading file watcher configuration: {e}")
    
    def get_config(self) -> FileWatcherConfig:
        """Get current configuration."""
        return self.config
    
    def get_watcher_stats(self) -> Dict[str, Any]:
        """Get file watcher statistics."""
        return {
            "events_processed": self.stats["events_processed"],
            "events_filtered": self.stats["events_filtered"],
            "events_debounced": self.stats["events_debounced"],
            "batches_processed": self.stats["batches_processed"],
            "config_reloads": self.stats["config_reloads"],
            "large_files_skipped": self.stats["large_files_skipped"],
            "pending_events": len(self.pending_events),
            "debounce_cache_size": len(self.debounce_cache),
            "pattern_stats": self.pattern_matcher.get_pattern_stats(),
            "current_config": self.config.to_dict()
        }
    
    def get_environment_variables_info(self) -> Dict[str, Any]:
        """Get information about environment variables used for configuration."""
        env_vars = {}
        config_fields = [
            "batch_size", "batch_timeout", "debounce_delay", "max_file_size_mb",
            "include_patterns", "exclude_patterns", "excluded_directories",
            "enable_hash_calculation", "hash_calculation_threshold_kb", "enable_content_analysis"
        ]
        
        for field in config_fields:
            env_key = f"COMPLIANCE_SENTINEL_FILE_WATCHER_{field.upper()}"
            env_value = os.getenv(env_key)
            current_value = getattr(self.config, field)
            
            env_vars[field] = {
                "env_key": env_key,
                "env_value": env_value,
                "current_value": current_value,
                "using_default": env_value is None
            }
        
        return env_vars
    
    def cleanup(self) -> None:
        """Cleanup file watcher resources."""
        # Cancel batch processing task
        if self._batch_task and not self._batch_task.done():
            self._batch_task.cancel()
        
        # Clear caches
        self.pending_events.clear()
        self.debounce_cache.clear()
        self.file_states.clear()
        
        logger.info("File watcher cleanup completed")