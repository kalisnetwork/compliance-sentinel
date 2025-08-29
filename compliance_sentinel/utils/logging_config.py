"""Comprehensive logging configuration for Compliance Sentinel."""

import logging
import logging.handlers
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import json


class ComplianceSentinelFormatter(logging.Formatter):
    """Custom formatter for Compliance Sentinel logs."""
    
    def __init__(self, include_context: bool = True):
        self.include_context = include_context
        super().__init__()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with additional context."""
        # Base format
        timestamp = datetime.fromtimestamp(record.created).isoformat()
        
        # Build log entry
        log_entry = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra context if available
        if self.include_context and hasattr(record, 'context'):
            log_entry["context"] = record.context
        
        # Add request ID if available
        if hasattr(record, 'request_id'):
            log_entry["request_id"] = record.request_id
        
        # Add user ID if available
        if hasattr(record, 'user_id'):
            log_entry["user_id"] = record.user_id
        
        # Add file path if available (for analysis operations)
        if hasattr(record, 'file_path'):
            log_entry["file_path"] = record.file_path
        
        # Format as JSON for structured logging
        return json.dumps(log_entry, default=str)


class SecurityAuditHandler(logging.Handler):
    """Special handler for security-related audit logs."""
    
    def __init__(self, audit_file: str):
        super().__init__()
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler for audit logs
        self.file_handler = logging.handlers.RotatingFileHandler(
            self.audit_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        self.file_handler.setFormatter(ComplianceSentinelFormatter())
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit security audit log record."""
        # Only log security-related events
        security_keywords = [
            'security', 'vulnerability', 'credential', 'authentication',
            'authorization', 'policy', 'violation', 'threat', 'risk'
        ]
        
        message_lower = record.getMessage().lower()
        if any(keyword in message_lower for keyword in security_keywords):
            # Add audit context
            record.audit_type = "security_event"
            record.audit_timestamp = datetime.utcnow().isoformat()
            
            self.file_handler.emit(record)


class PerformanceHandler(logging.Handler):
    """Handler for performance monitoring logs."""
    
    def __init__(self, performance_file: str):
        super().__init__()
        self.performance_file = Path(performance_file)
        self.performance_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.file_handler = logging.handlers.RotatingFileHandler(
            self.performance_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3
        )
        self.file_handler.setFormatter(ComplianceSentinelFormatter())
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit performance log record."""
        # Only log performance-related events
        if hasattr(record, 'performance_metric') or 'duration' in record.getMessage().lower():
            self.file_handler.emit(record)


class LoggingConfig:
    """Centralized logging configuration for Compliance Sentinel."""
    
    def __init__(self, 
                 log_level: str = "INFO",
                 log_dir: Optional[str] = None,
                 enable_console: bool = True,
                 enable_file: bool = True,
                 enable_audit: bool = True,
                 enable_performance: bool = True,
                 structured_logging: bool = True):
        
        self.log_level = getattr(logging, log_level.upper())
        self.log_dir = Path(log_dir) if log_dir else Path.cwd() / "logs"
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.enable_audit = enable_audit
        self.enable_performance = enable_performance
        self.structured_logging = structured_logging
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        if self.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            
            if self.structured_logging:
                console_handler.setFormatter(ComplianceSentinelFormatter())
            else:
                console_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
            
            root_logger.addHandler(console_handler)
        
        # File handler for general logs
        if self.enable_file:
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "compliance_sentinel.log",
                maxBytes=20 * 1024 * 1024,  # 20MB
                backupCount=10
            )
            file_handler.setLevel(self.log_level)
            file_handler.setFormatter(ComplianceSentinelFormatter())
            root_logger.addHandler(file_handler)
        
        # Error file handler
        if self.enable_file:
            error_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "errors.log",
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(ComplianceSentinelFormatter())
            root_logger.addHandler(error_handler)
        
        # Security audit handler
        if self.enable_audit:
            audit_handler = SecurityAuditHandler(str(self.log_dir / "security_audit.log"))
            audit_handler.setLevel(logging.INFO)
            root_logger.addHandler(audit_handler)
        
        # Performance handler
        if self.enable_performance:
            perf_handler = PerformanceHandler(str(self.log_dir / "performance.log"))
            perf_handler.setLevel(logging.INFO)
            root_logger.addHandler(perf_handler)
        
        # Set specific logger levels
        self._configure_component_loggers()
    
    def _configure_component_loggers(self) -> None:
        """Configure logging levels for specific components."""
        component_levels = {
            "compliance_sentinel.analyzers": logging.INFO,
            "compliance_sentinel.engines": logging.INFO,
            "compliance_sentinel.hooks": logging.INFO,
            "compliance_sentinel.mcp_server": logging.INFO,
            "compliance_sentinel.utils.cache": logging.WARNING,
            "compliance_sentinel.utils.performance": logging.INFO,
            "httpx": logging.WARNING,
            "uvicorn": logging.INFO,
            "fastapi": logging.INFO,
        }
        
        for logger_name, level in component_levels.items():
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the specified name."""
        return logging.getLogger(name)
    
    def add_context_to_logger(self, logger: logging.Logger, context: Dict[str, Any]) -> None:
        """Add context information to a logger."""
        # Create a custom adapter that adds context
        class ContextAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return f"[{self.extra}] {msg}", kwargs
        
        return ContextAdapter(logger, context)
    
    def log_security_event(self, 
                          event_type: str,
                          description: str,
                          severity: str = "INFO",
                          user_id: Optional[str] = None,
                          file_path: Optional[str] = None,
                          additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a security event."""
        logger = logging.getLogger("compliance_sentinel.security")
        
        # Create log record with security context
        record = logger.makeRecord(
            name=logger.name,
            level=getattr(logging, severity.upper()),
            fn="",
            lno=0,
            msg=f"Security Event: {event_type} - {description}",
            args=(),
            exc_info=None
        )
        
        # Add security context
        record.security_event = True
        record.event_type = event_type
        record.user_id = user_id
        record.file_path = file_path
        record.additional_data = additional_data or {}
        
        logger.handle(record)
    
    def log_performance_metric(self,
                              operation: str,
                              duration_ms: float,
                              component: str,
                              additional_metrics: Optional[Dict[str, Any]] = None) -> None:
        """Log a performance metric."""
        logger = logging.getLogger("compliance_sentinel.performance")
        
        record = logger.makeRecord(
            name=logger.name,
            level=logging.INFO,
            fn="",
            lno=0,
            msg=f"Performance: {operation} completed in {duration_ms:.2f}ms",
            args=(),
            exc_info=None
        )
        
        # Add performance context
        record.performance_metric = True
        record.operation = operation
        record.duration_ms = duration_ms
        record.component = component
        record.additional_metrics = additional_metrics or {}
        
        logger.handle(record)
    
    def configure_debug_mode(self) -> None:
        """Enable debug mode with verbose logging."""
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Add debug file handler
        debug_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "debug.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=3
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(ComplianceSentinelFormatter())
        root_logger.addHandler(debug_handler)
        
        logging.info("Debug mode enabled - verbose logging active")
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        stats = {
            "log_level": logging.getLevelName(self.log_level),
            "log_directory": str(self.log_dir),
            "handlers_enabled": {
                "console": self.enable_console,
                "file": self.enable_file,
                "audit": self.enable_audit,
                "performance": self.enable_performance
            },
            "structured_logging": self.structured_logging
        }
        
        # Get log file sizes
        log_files = {}
        for log_file in self.log_dir.glob("*.log"):
            try:
                log_files[log_file.name] = {
                    "size_bytes": log_file.stat().st_size,
                    "modified": datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
                }
            except Exception:
                pass
        
        stats["log_files"] = log_files
        return stats


# Global logging configuration
_logging_config: Optional[LoggingConfig] = None


def setup_logging(config: Optional[Dict[str, Any]] = None) -> LoggingConfig:
    """Set up global logging configuration."""
    global _logging_config
    
    if config is None:
        config = {}
    
    _logging_config = LoggingConfig(**config)
    return _logging_config


def get_logging_config() -> LoggingConfig:
    """Get global logging configuration."""
    global _logging_config
    if _logging_config is None:
        _logging_config = setup_logging()
    return _logging_config


def get_logger(name: str) -> logging.Logger:
    """Get a logger with proper configuration."""
    # Ensure logging is configured
    get_logging_config()
    return logging.getLogger(name)


def log_security_event(event_type: str, description: str, **kwargs) -> None:
    """Convenience function to log security events."""
    config = get_logging_config()
    config.log_security_event(event_type, description, **kwargs)


def log_performance_metric(operation: str, duration_ms: float, component: str, **kwargs) -> None:
    """Convenience function to log performance metrics."""
    config = get_logging_config()
    config.log_performance_metric(operation, duration_ms, component, **kwargs)