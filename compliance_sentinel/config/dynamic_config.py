"""Dynamic configuration management system with environment variable support."""

import os
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)


@dataclass
class ConfigChangeEvent:
    """Event for configuration changes."""
    key: str
    old_value: Any
    new_value: Any
    source: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ConfigSource(ABC):
    """Abstract base class for configuration sources."""
    
    @abstractmethod
    async def load_config(self) -> Dict[str, Any]:
        """Load configuration from source."""
        pass
    
    @abstractmethod
    async def watch_changes(self, callback: Callable[[ConfigChangeEvent], None]) -> None:
        """Watch for configuration changes."""
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Get the name of this configuration source."""
        pass
    
    @abstractmethod
    async def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate configuration and return list of errors."""
        pass


class EnvironmentConfigSource(ConfigSource):
    """Environment variable configuration source."""
    
    def __init__(self, prefix: str = "COMPLIANCE_SENTINEL_"):
        """Initialize with environment variable prefix."""
        self.prefix = prefix
        self.last_config = {}
        self.watchers = []
    
    async def load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        
        for key, value in os.environ.items():
            if key.startswith(self.prefix):
                # Remove prefix and convert to lowercase
                config_key = key[len(self.prefix):].lower()
                
                # Convert nested keys (e.g., DB_HOST -> db.host)
                config_key = config_key.replace('_', '.')
                
                # Try to parse as JSON for complex values
                parsed_value = self._parse_value(value)
                
                # Set nested configuration
                self._set_nested_value(config, config_key, parsed_value)
        
        self.last_config = config.copy()
        return config
    
    def _parse_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Try JSON
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Return as string
        return value
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """Set nested configuration value using dot notation."""
        keys = key.split('.')
        current = config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    async def watch_changes(self, callback: Callable[[ConfigChangeEvent], None]) -> None:
        """Watch for environment variable changes."""
        # Note: Environment variables don't change during runtime in most cases
        # This is a placeholder for future implementation with external config services
        self.watchers.append(callback)
        logger.debug("Environment variable watching registered (no-op for now)")
    
    def get_source_name(self) -> str:
        """Get the name of this configuration source."""
        return f"environment({self.prefix})"
    
    async def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate environment configuration."""
        errors = []
        
        # Add validation rules as needed
        if 'mcp_server' in config:
            mcp_config = config['mcp_server']
            if 'port' in mcp_config:
                port = mcp_config['port']
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    errors.append(f"Invalid port number: {port}")
        
        return errors


class FileConfigSource(ConfigSource):
    """File-based configuration source with hot-reload support."""
    
    def __init__(self, file_path: Union[str, Path]):
        """Initialize with configuration file path."""
        self.file_path = Path(file_path)
        self.last_modified = None
        self.last_config = {}
        self.watchers = []
        self.observer = None
        self.file_handler = None
    
    async def load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if not self.file_path.exists():
            logger.warning(f"Configuration file not found: {self.file_path}")
            return {}
        
        try:
            with open(self.file_path, 'r') as f:
                if self.file_path.suffix.lower() == '.json':
                    config = json.load(f)
                elif self.file_path.suffix.lower() in ('.yml', '.yaml'):
                    config = yaml.safe_load(f) or {}
                else:
                    raise ValueError(f"Unsupported file format: {self.file_path.suffix}")
            
            self.last_modified = self.file_path.stat().st_mtime
            self.last_config = config.copy()
            
            logger.debug(f"Loaded configuration from {self.file_path}")
            return config
            
        except Exception as e:
            logger.error(f"Error loading configuration from {self.file_path}: {e}")
            return {}
    
    async def watch_changes(self, callback: Callable[[ConfigChangeEvent], None]) -> None:
        """Watch for file changes."""
        if self.observer is None:
            self.watchers.append(callback)
            self._start_file_watcher()
    
    def _start_file_watcher(self) -> None:
        """Start file system watcher."""
        if self.observer is not None:
            return
        
        class ConfigFileHandler(FileSystemEventHandler):
            def __init__(self, config_source):
                self.config_source = config_source
            
            def on_modified(self, event):
                if not event.is_directory and Path(event.src_path) == self.config_source.file_path:
                    asyncio.create_task(self.config_source._handle_file_change())
        
        self.file_handler = ConfigFileHandler(self)
        self.observer = Observer()
        self.observer.schedule(
            self.file_handler,
            str(self.file_path.parent),
            recursive=False
        )
        self.observer.start()
        logger.debug(f"Started file watcher for {self.file_path}")
    
    async def _handle_file_change(self) -> None:
        """Handle file change event."""
        try:
            # Check if file was actually modified
            current_modified = self.file_path.stat().st_mtime
            if current_modified <= self.last_modified:
                return
            
            # Load new configuration
            new_config = await self.load_config()
            
            # Compare with old configuration and notify watchers
            for watcher in self.watchers:
                try:
                    # For simplicity, we'll send a generic change event
                    # In a more sophisticated implementation, we'd diff the configs
                    event = ConfigChangeEvent(
                        key="file_config",
                        old_value=self.last_config,
                        new_value=new_config,
                        source=self.get_source_name()
                    )
                    watcher(event)
                except Exception as e:
                    logger.error(f"Error notifying config watcher: {e}")
            
        except Exception as e:
            logger.error(f"Error handling file change: {e}")
    
    def get_source_name(self) -> str:
        """Get the name of this configuration source."""
        return f"file({self.file_path})"
    
    async def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate file configuration."""
        errors = []
        
        # Basic structure validation
        if not isinstance(config, dict):
            errors.append("Configuration must be a dictionary")
            return errors
        
        # Add specific validation rules as needed
        return errors
    
    def stop_watching(self) -> None:
        """Stop file watching."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            logger.debug(f"Stopped file watcher for {self.file_path}")


class DynamicConfigManager:
    """Enhanced configuration manager with real-time updates."""
    
    def __init__(self, config_sources: List[ConfigSource]):
        """Initialize with list of configuration sources."""
        self.config_sources = config_sources
        self.config_cache = {}
        self.watchers = {}
        self.reload_callbacks = []
        self.last_reload = datetime.now(timezone.utc)
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize configuration manager."""
        await self._reload_all_configs()
        
        # Set up watchers for all sources
        for source in self.config_sources:
            await source.watch_changes(self._handle_config_change)
        
        logger.info(f"DynamicConfigManager initialized with {len(self.config_sources)} sources")
    
    async def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value with environment variable override."""
        async with self._lock:
            # Check cache first
            if key in self.config_cache:
                return self.config_cache[key]
            
            # If not in cache, try to find in merged config
            merged_config = await self._get_merged_config()
            value = self._get_nested_value(merged_config, key, default)
            
            # Cache the value
            self.config_cache[key] = value
            return value
    
    async def set_config(self, key: str, value: Any) -> None:
        """Set configuration value (runtime override)."""
        async with self._lock:
            self.config_cache[key] = value
            logger.debug(f"Set runtime config: {key} = {value}")
    
    async def watch_config(self, key: str, callback: Callable[[Any, Any], None]) -> None:
        """Watch for configuration changes on specific key."""
        if key not in self.watchers:
            self.watchers[key] = []
        self.watchers[key].append(callback)
        logger.debug(f"Added watcher for config key: {key}")
    
    async def reload_config(self, source: str = None) -> None:
        """Reload configuration from sources."""
        async with self._lock:
            if source:
                # Reload specific source
                for config_source in self.config_sources:
                    if config_source.get_source_name() == source:
                        await self._reload_source_config(config_source)
                        break
            else:
                # Reload all sources
                await self._reload_all_configs()
            
            # Clear cache to force re-evaluation
            self.config_cache.clear()
            self.last_reload = datetime.now(timezone.utc)
            
            # Notify reload callbacks
            for callback in self.reload_callbacks:
                try:
                    await callback()
                except Exception as e:
                    logger.error(f"Error in reload callback: {e}")
    
    def add_reload_callback(self, callback: Callable[[], None]) -> None:
        """Add callback to be called when configuration is reloaded."""
        self.reload_callbacks.append(callback)
    
    async def validate_all_configs(self) -> Dict[str, List[str]]:
        """Validate all configuration sources."""
        validation_results = {}
        
        for source in self.config_sources:
            try:
                config = await source.load_config()
                errors = await source.validate_config(config)
                validation_results[source.get_source_name()] = errors
            except Exception as e:
                validation_results[source.get_source_name()] = [f"Failed to validate: {e}"]
        
        return validation_results
    
    async def get_config_info(self) -> Dict[str, Any]:
        """Get information about configuration sources and status."""
        return {
            'sources': [source.get_source_name() for source in self.config_sources],
            'last_reload': self.last_reload.isoformat(),
            'cache_size': len(self.config_cache),
            'watchers': list(self.watchers.keys()),
            'reload_callbacks': len(self.reload_callbacks)
        }
    
    async def _reload_all_configs(self) -> None:
        """Reload configuration from all sources."""
        for source in self.config_sources:
            await self._reload_source_config(source)
    
    async def _reload_source_config(self, source: ConfigSource) -> None:
        """Reload configuration from a specific source."""
        try:
            config = await source.load_config()
            logger.debug(f"Reloaded config from {source.get_source_name()}")
        except Exception as e:
            logger.error(f"Error reloading config from {source.get_source_name()}: {e}")
    
    async def _get_merged_config(self) -> Dict[str, Any]:
        """Get merged configuration from all sources."""
        merged = {}
        
        # Merge configurations in order (later sources override earlier ones)
        for source in self.config_sources:
            try:
                config = await source.load_config()
                merged = self._deep_merge_dicts(merged, config)
            except Exception as e:
                logger.error(f"Error loading config from {source.get_source_name()}: {e}")
        
        return merged
    
    def _deep_merge_dicts(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dicts(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _get_nested_value(self, config: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Get nested configuration value using dot notation."""
        keys = key.split('.')
        current = config
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    async def _handle_config_change(self, event: ConfigChangeEvent) -> None:
        """Handle configuration change event."""
        logger.info(f"Configuration changed: {event.key} in {event.source}")
        
        # Clear cache to force re-evaluation
        async with self._lock:
            self.config_cache.clear()
        
        # Notify specific watchers
        if event.key in self.watchers:
            for watcher in self.watchers[event.key]:
                try:
                    await watcher(event.old_value, event.new_value)
                except Exception as e:
                    logger.error(f"Error in config watcher: {e}")
    
    async def shutdown(self) -> None:
        """Shutdown configuration manager and cleanup resources."""
        for source in self.config_sources:
            if hasattr(source, 'stop_watching'):
                source.stop_watching()
        
        logger.info("DynamicConfigManager shutdown complete")