"""Environment-aware logging configuration for compliance sentinel."""

import os
import sys
import json
import logging
import logging.config
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import traceback

# Try to import structured logging libraries
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

try:
    from pythonjsonlogger import jsonlogger
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False


class SecurityFilter(logging.Filter):
    """Filter to prevent logging of sensitive information."""
    
    def __init__(self):
        super().__init__()
        # Patterns that indicate sensitive data
        self.sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth',
            'credential', 'private', 'confidential', 'sensitive'
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out log records that might contain sensitive information."""
        message = record.getMessage().lower()
        
        # Check if message contains sensitive patterns
        for pattern in self.sensitive_patterns:
            if pattern in message:
                # Replace the sensitive part with [REDACTED]
                original_msg = record.getMessage()
                # Simple redaction - in production, use more sophisticated methods
                for sensitive_word in self.sensitive_patterns:
                    if sensitive_word in original_msg.lower():
                        # Find and redact the value after the sensitive word
                        import re
                        pattern = rf'({sensitive_word}["\']?\s*[=:]\s*["\']?)([^"\'\s,}}]+)'
                        redacted = re.sub(pattern, r'\1[REDACTED]', original_msg, flags=re.IGNORECASE)
                        record.msg = redacted
                        record.args = ()
                        break
        
        return True


class EnvironmentFormatter(logging.Formatter):
    """Custom formatter that includes environment information."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        self.service_name = os.getenv("COMPLIANCE_SENTINEL_SERVICE_NAME", "compliance-sentinel")
        self.version = os.getenv("COMPLIANCE_SENTINEL_VERSION", "unknown")
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with environment information."""
        # Add environment context to the record
        record.environment = self.environment
        record.service = self.service_name
        record.version = self.version
        record.timestamp = datetime.utcnow().isoformat()
        
        # Add request ID if available (from context)
        record.request_id = getattr(record, 'request_id', None)
        
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def __init__(self):
        super().__init__()
        self.environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        self.service_name = os.getenv("COMPLIANCE_SENTINEL_SERVICE_NAME", "compliance-sentinel")
        self.version = os.getenv("COMPLIANCE_SENTINEL_VERSION", "unknown")
        self.hostname = os.getenv("HOSTNAME", "unknown")
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "environment": self.environment,
            "service": self.service_name,
            "version": self.version,
            "hostname": self.hostname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "process": record.process
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields from the record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'exc_info', 'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


@dataclass
class LoggingConfig:
    """Configuration for environment-aware logging."""
    # Environment-based settings
    environment: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development"))
    
    # Log level configuration
    log_level: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_LOG_LEVEL", "INFO"))
    root_log_level: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_ROOT_LOG_LEVEL", "WARNING"))
    
    # Log format configuration
    log_format: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_LOG_FORMAT", "structured"))
    date_format: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_DATE_FORMAT", "%Y-%m-%d %H:%M:%S"))
    
    # Output configuration
    console_enabled: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_CONSOLE_LOGGING", "true").lower() == "true")
    file_enabled: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_FILE_LOGGING", "false").lower() == "true")
    log_file_path: Optional[str] = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_LOG_FILE"))
    
    # Security settings
    enable_security_filter: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_SECURITY_FILTER", "true").lower() == "true")
    
    # Structured logging settings
    enable_json_logging: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_JSON_LOGGING", "false").lower() == "true")
    enable_structured_logging: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_STRUCTURED_LOGGING", "false").lower() == "true")
    
    # External logging integration
    syslog_enabled: bool = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_SYSLOG_ENABLED", "false").lower() == "true")
    syslog_address: str = field(default_factory=lambda: os.getenv("COMPLIANCE_SENTINEL_SYSLOG_ADDRESS", "localhost:514"))
    
    # Log rotation settings
    max_log_size_mb: int = field(default_factory=lambda: int(os.getenv("COMPLIANCE_SENTINEL_MAX_LOG_SIZE_MB", "100")))
    backup_count: int = field(default_factory=lambda: int(os.getenv("COMPLIANCE_SENTINEL_LOG_BACKUP_COUNT", "5")))
    
    # Module-specific log levels
    module_log_levels: Dict[str, str] = field(default_factory=lambda: {
        "compliance_sentinel.mcp_server": os.getenv("COMPLIANCE_SENTINEL_MCP_LOG_LEVEL", "INFO"),
        "compliance_sentinel.analyzers": os.getenv("COMPLIANCE_SENTINEL_ANALYZERS_LOG_LEVEL", "INFO"),
        "compliance_sentinel.providers": os.getenv("COMPLIANCE_SENTINEL_PROVIDERS_LOG_LEVEL", "INFO"),
        "compliance_sentinel.utils": os.getenv("COMPLIANCE_SENTINEL_UTILS_LOG_LEVEL", "WARNING"),
        "httpx": os.getenv("COMPLIANCE_SENTINEL_HTTPX_LOG_LEVEL", "WARNING"),
        "urllib3": os.getenv("COMPLIANCE_SENTINEL_URLLIB3_LOG_LEVEL", "WARNING"),
        "asyncio": os.getenv("COMPLIANCE_SENTINEL_ASYNCIO_LOG_LEVEL", "WARNING")
    })
    
    def __post_init__(self):
        """Validate logging configuration."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        if self.log_level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
        
        if self.root_log_level.upper() not in valid_levels:
            raise ValueError(f"Invalid root log level: {self.root_log_level}")
        
        valid_formats = ["simple", "detailed", "json", "structured"]
        if self.log_format not in valid_formats:
            raise ValueError(f"Invalid log format: {self.log_format}")
        
        if self.max_log_size_mb < 1:
            raise ValueError("Max log size must be at least 1 MB")
        
        if self.backup_count < 0:
            raise ValueError("Backup count must be non-negative")
    
    def get_environment_defaults(self) -> Dict[str, Any]:
        """Get environment-specific default settings."""
        if self.environment.lower() in ["production", "prod", "live"]:
            return {
                "log_level": "WARNING",
                "root_log_level": "ERROR",
                "enable_json_logging": True,
                "enable_structured_logging": True,
                "file_enabled": True,
                "console_enabled": False,
                "enable_security_filter": True
            }
        elif self.environment.lower() in ["staging", "stage"]:
            return {
                "log_level": "INFO",
                "root_log_level": "WARNING",
                "enable_json_logging": True,
                "enable_structured_logging": True,
                "file_enabled": True,
                "console_enabled": True,
                "enable_security_filter": True
            }
        else:  # development, test, etc.
            return {
                "log_level": "DEBUG",
                "root_log_level": "INFO",
                "enable_json_logging": False,
                "enable_structured_logging": False,
                "file_enabled": False,
                "console_enabled": True,
                "enable_security_filter": False
            }


class EnvironmentAwareLogger:
    """Environment-aware logging system for compliance sentinel."""
    
    def __init__(self, config: Optional[LoggingConfig] = None):
        """Initialize environment-aware logger."""
        self.config = config or LoggingConfig()
        self._configured = False
        self._original_factory = None
        
        # Apply environment defaults if not explicitly configured
        env_defaults = self.config.get_environment_defaults()
        for key, value in env_defaults.items():
            if not hasattr(self.config, key) or getattr(self.config, key) is None:
                setattr(self.config, key, value)
    
    def configure_logging(self) -> None:
        """Configure logging based on environment settings."""
        if self._configured:
            return
        
        # Create logging configuration
        logging_config = self._create_logging_config()
        
        # Apply configuration
        logging.config.dictConfig(logging_config)
        
        # Set module-specific log levels
        self._configure_module_log_levels()
        
        # Configure structured logging if enabled
        if self.config.enable_structured_logging and STRUCTLOG_AVAILABLE:
            self._configure_structured_logging()
        
        self._configured = True
        
        # Log configuration summary
        logger = logging.getLogger(__name__)
        logger.info(f"Logging configured for environment: {self.config.environment}")
        logger.info(f"Log level: {self.config.log_level}, Format: {self.config.log_format}")
    
    def _create_logging_config(self) -> Dict[str, Any]:
        """Create logging configuration dictionary."""
        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {},
            "filters": {},
            "handlers": {},
            "loggers": {},
            "root": {
                "level": self.config.root_log_level,
                "handlers": []
            }
        }
        
        # Add security filter if enabled
        if self.config.enable_security_filter:
            config["filters"]["security"] = {
                "()": SecurityFilter
            }
        
        # Configure formatters
        if self.config.enable_json_logging or self.config.log_format == "json":
            config["formatters"]["json"] = {
                "()": JSONFormatter
            }
        
        if self.config.log_format == "structured":
            config["formatters"]["structured"] = {
                "()": EnvironmentFormatter,
                "format": "[{timestamp}] {environment}:{service} {levelname:8} {name:30} {message}",
                "style": "{"
            }
        
        config["formatters"]["simple"] = {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": self.config.date_format
        }
        
        config["formatters"]["detailed"] = {
            "()": EnvironmentFormatter,
            "format": "[{timestamp}] {environment}:{service}:{version} {levelname:8} {name:30} {funcName}:{lineno} {message}",
            "style": "{"
        }
        
        # Configure handlers
        handlers = []
        
        # Console handler
        if self.config.console_enabled:
            formatter = self._get_formatter_name()
            console_handler = {
                "class": "logging.StreamHandler",
                "level": self.config.log_level,
                "formatter": formatter,
                "stream": "ext://sys.stdout"
            }
            
            if self.config.enable_security_filter:
                console_handler["filters"] = ["security"]
            
            config["handlers"]["console"] = console_handler
            handlers.append("console")
        
        # File handler
        if self.config.file_enabled and self.config.log_file_path:
            # Ensure log directory exists
            log_path = Path(self.config.log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            formatter = self._get_formatter_name()
            file_handler = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": self.config.log_level,
                "formatter": formatter,
                "filename": self.config.log_file_path,
                "maxBytes": self.config.max_log_size_mb * 1024 * 1024,
                "backupCount": self.config.backup_count,
                "encoding": "utf-8"
            }
            
            if self.config.enable_security_filter:
                file_handler["filters"] = ["security"]
            
            config["handlers"]["file"] = file_handler
            handlers.append("file")
        
        # Syslog handler
        if self.config.syslog_enabled:
            syslog_handler = {
                "class": "logging.handlers.SysLogHandler",
                "level": self.config.log_level,
                "formatter": "json" if self.config.enable_json_logging else "simple",
                "address": self._parse_syslog_address()
            }
            
            if self.config.enable_security_filter:
                syslog_handler["filters"] = ["security"]
            
            config["handlers"]["syslog"] = syslog_handler
            handlers.append("syslog")
        
        # Configure root logger
        config["root"]["handlers"] = handlers
        
        # Configure compliance sentinel logger
        config["loggers"]["compliance_sentinel"] = {
            "level": self.config.log_level,
            "handlers": handlers,
            "propagate": False
        }
        
        return config
    
    def _get_formatter_name(self) -> str:
        """Get the appropriate formatter name based on configuration."""
        if self.config.enable_json_logging or self.config.log_format == "json":
            return "json"
        elif self.config.log_format == "structured":
            return "structured"
        elif self.config.log_format == "detailed":
            return "detailed"
        else:
            return "simple"
    
    def _parse_syslog_address(self) -> Union[str, tuple]:
        """Parse syslog address configuration."""
        if ":" in self.config.syslog_address:
            host, port = self.config.syslog_address.split(":", 1)
            return (host, int(port))
        else:
            return self.config.syslog_address
    
    def _configure_module_log_levels(self) -> None:
        """Configure log levels for specific modules."""
        for module_name, level in self.config.module_log_levels.items():
            logger = logging.getLogger(module_name)
            logger.setLevel(getattr(logging, level.upper()))
    
    def _configure_structured_logging(self) -> None:
        """Configure structured logging with structlog."""
        if not STRUCTLOG_AVAILABLE:
            return
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the specified name."""
        if not self._configured:
            self.configure_logging()
        
        return logging.getLogger(name)
    
    def reconfigure(self, new_config: Optional[LoggingConfig] = None) -> None:
        """Reconfigure logging with new settings."""
        if new_config:
            self.config = new_config
        
        self._configured = False
        self.configure_logging()
    
    def add_context_filter(self, filter_func: callable) -> None:
        """Add a custom context filter to all handlers."""
        if not self._configured:
            self.configure_logging()
        
        class ContextFilter(logging.Filter):
            def filter(self, record):
                return filter_func(record)
        
        # Add filter to all handlers
        for handler in logging.getLogger().handlers:
            handler.addFilter(ContextFilter())
    
    def set_request_context(self, request_id: str, user_id: Optional[str] = None) -> None:
        """Set request context for logging."""
        # This would typically be used with a context manager or middleware
        # For now, we'll store it in a thread-local or similar mechanism
        pass
    
    def get_logging_stats(self) -> Dict[str, Any]:
        """Get logging system statistics."""
        stats = {
            "configured": self._configured,
            "environment": self.config.environment,
            "log_level": self.config.log_level,
            "handlers": [],
            "loggers": {}
        }
        
        # Get handler information
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            handler_info = {
                "type": type(handler).__name__,
                "level": logging.getLevelName(handler.level),
                "formatter": type(handler.formatter).__name__ if handler.formatter else None
            }
            stats["handlers"].append(handler_info)
        
        # Get logger information
        for name in logging.Logger.manager.loggerDict:
            logger = logging.getLogger(name)
            if logger.handlers or logger.level != logging.NOTSET:
                stats["loggers"][name] = {
                    "level": logging.getLevelName(logger.level),
                    "handlers": len(logger.handlers),
                    "propagate": logger.propagate
                }
        
        return stats


# Global logger instance
_global_logger = EnvironmentAwareLogger()


def configure_logging(config: Optional[LoggingConfig] = None) -> None:
    """Configure global logging system."""
    global _global_logger
    if config:
        _global_logger = EnvironmentAwareLogger(config)
    _global_logger.configure_logging()


def get_logger(name: str) -> logging.Logger:
    """Get a logger with environment-aware configuration."""
    return _global_logger.get_logger(name)


def reconfigure_logging(config: Optional[LoggingConfig] = None) -> None:
    """Reconfigure the global logging system."""
    _global_logger.reconfigure(config)


def get_logging_stats() -> Dict[str, Any]:
    """Get logging system statistics."""
    return _global_logger.get_logging_stats()


# Context manager for request logging
class RequestLoggingContext:
    """Context manager for request-specific logging."""
    
    def __init__(self, request_id: str, user_id: Optional[str] = None):
        self.request_id = request_id
        self.user_id = user_id
        self.old_factory = None
    
    def __enter__(self):
        # Store the old factory
        self.old_factory = logging.getLogRecordFactory()
        
        # Create new factory that adds request context
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            record.request_id = self.request_id
            if self.user_id:
                record.user_id = self.user_id
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore the old factory
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)