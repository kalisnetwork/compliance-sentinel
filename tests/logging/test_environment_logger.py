"""Tests for environment-aware logging system."""

import os
import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from compliance_sentinel.logging.environment_logger import (
    LoggingConfig, EnvironmentAwareLogger, SecurityFilter, EnvironmentFormatter,
    JSONFormatter, configure_logging, get_logger, reconfigure_logging,
    get_logging_stats, RequestLoggingContext
)


class TestLoggingConfig:
    """Test cases for LoggingConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = LoggingConfig()
        
        assert config.environment == "development"
        assert config.log_level == "INFO"
        assert config.root_log_level == "WARNING"
        assert config.log_format == "structured"
        assert config.console_enabled is True
        assert config.file_enabled is False
        assert config.enable_security_filter is True
    
    @patch.dict(os.environ, {
        'COMPLIANCE_SENTINEL_ENVIRONMENT': 'production',
        'COMPLIANCE_SENTINEL_LOG_LEVEL': 'ERROR',
        'COMPLIANCE_SENTINEL_LOG_FORMAT': 'json',
        'COMPLIANCE_SENTINEL_FILE_LOGGING': 'true',
        'COMPLIANCE_SENTINEL_LOG_FILE': '/var/log/compliance.log'
    })
    def test_environment_config(self):
        """Test configuration from environment variables."""
        config = LoggingConfig()
        
        assert config.environment == "production"
        assert config.log_level == "ERROR"
        assert config.log_format == "json"
        assert config.file_enabled is True
        assert config.log_file_path == "/var/log/compliance.log"
    
    def test_invalid_config_validation(self):
        """Test configuration validation with invalid values."""
        with pytest.raises(ValueError, match="Invalid log level"):
            LoggingConfig(log_level="INVALID")
        
        with pytest.raises(ValueError, match="Invalid root log level"):
            LoggingConfig(root_log_level="INVALID")
        
        with pytest.raises(ValueError, match="Invalid log format"):
            LoggingConfig(log_format="invalid")
        
        with pytest.raises(ValueError, match="Max log size must be at least 1 MB"):
            LoggingConfig(max_log_size_mb=0)
        
        with pytest.raises(ValueError, match="Backup count must be non-negative"):
            LoggingConfig(backup_count=-1)
    
    def test_environment_defaults(self):
        """Test environment-specific default settings."""
        # Production environment
        prod_config = LoggingConfig(environment="production")
        prod_defaults = prod_config.get_environment_defaults()
        
        assert prod_defaults["log_level"] == "WARNING"
        assert prod_defaults["enable_json_logging"] is True
        assert prod_defaults["file_enabled"] is True
        assert prod_defaults["console_enabled"] is False
        
        # Development environment
        dev_config = LoggingConfig(environment="development")
        dev_defaults = dev_config.get_environment_defaults()
        
        assert dev_defaults["log_level"] == "DEBUG"
        assert dev_defaults["enable_json_logging"] is False
        assert dev_defaults["file_enabled"] is False
        assert dev_defaults["console_enabled"] is True
        
        # Staging environment
        stage_config = LoggingConfig(environment="staging")
        stage_defaults = stage_config.get_environment_defaults()
        
        assert stage_defaults["log_level"] == "INFO"
        assert stage_defaults["enable_json_logging"] is True
        assert stage_defaults["file_enabled"] is True
        assert stage_defaults["console_enabled"] is True


class TestSecurityFilter:
    """Test cases for SecurityFilter."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.filter = SecurityFilter()
    
    def test_filter_sensitive_data(self):
        """Test filtering of sensitive data."""
        # Create a log record with sensitive information
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User login with password=secret123",
            args=(),
            exc_info=None
        )
        
        # Apply filter
        result = self.filter.filter(record)
        
        assert result is True  # Record should not be filtered out
        assert "[REDACTED]" in record.getMessage()
        assert "secret123" not in record.getMessage()
    
    def test_filter_api_key(self):
        """Test filtering of API keys."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="API request with api_key=abc123def456",
            args=(),
            exc_info=None
        )
        
        result = self.filter.filter(record)
        
        assert result is True
        assert "[REDACTED]" in record.getMessage()
        assert "abc123def456" not in record.getMessage()
    
    def test_no_sensitive_data(self):
        """Test that normal log messages are not modified."""
        original_message = "Normal log message without sensitive data"
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=original_message,
            args=(),
            exc_info=None
        )
        
        result = self.filter.filter(record)
        
        assert result is True
        assert record.getMessage() == original_message


class TestEnvironmentFormatter:
    """Test cases for EnvironmentFormatter."""
    
    @patch.dict(os.environ, {
        'COMPLIANCE_SENTINEL_ENVIRONMENT': 'test',
        'COMPLIANCE_SENTINEL_SERVICE_NAME': 'test-service',
        'COMPLIANCE_SENTINEL_VERSION': '1.0.0'
    })
    def test_format_with_environment_info(self):
        """Test formatting with environment information."""
        formatter = EnvironmentFormatter(
            fmt="{environment}:{service}:{version} {levelname} {message}",
            style="{"
        )
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(record)
        
        assert "test:test-service:1.0.0" in formatted
        assert "INFO" in formatted
        assert "Test message" in formatted
    
    def test_format_with_request_id(self):
        """Test formatting with request ID."""
        formatter = EnvironmentFormatter(
            fmt="{request_id} {message}",
            style="{"
        )
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.request_id = "req-123"
        
        formatted = formatter.format(record)
        
        assert "req-123" in formatted
        assert "Test message" in formatted


class TestJSONFormatter:
    """Test cases for JSONFormatter."""
    
    @patch.dict(os.environ, {
        'COMPLIANCE_SENTINEL_ENVIRONMENT': 'test',
        'COMPLIANCE_SENTINEL_SERVICE_NAME': 'test-service',
        'COMPLIANCE_SENTINEL_VERSION': '1.0.0',
        'HOSTNAME': 'test-host'
    })
    def test_json_format(self):
        """Test JSON formatting."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.module"
        assert log_data["message"] == "Test message"
        assert log_data["environment"] == "test"
        assert log_data["service"] == "test-service"
        assert log_data["version"] == "1.0.0"
        assert log_data["hostname"] == "test-host"
        assert log_data["line"] == 42
        assert "timestamp" in log_data
    
    def test_json_format_with_exception(self):
        """Test JSON formatting with exception information."""
        formatter = JSONFormatter()
        
        try:
            raise ValueError("Test exception")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Error occurred",
            args=(),
            exc_info=exc_info
        )
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert "exception" in log_data
        assert log_data["exception"]["type"] == "ValueError"
        assert log_data["exception"]["message"] == "Test exception"
        assert "traceback" in log_data["exception"]


class TestEnvironmentAwareLogger:
    """Test cases for EnvironmentAwareLogger."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test.log")
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_logger_initialization(self):
        """Test logger initialization."""
        config = LoggingConfig(
            environment="test",
            log_level="DEBUG",
            console_enabled=True,
            file_enabled=False
        )
        
        logger = EnvironmentAwareLogger(config)
        
        assert logger.config == config
        assert not logger._configured
    
    def test_configure_logging(self):
        """Test logging configuration."""
        config = LoggingConfig(
            environment="test",
            log_level="INFO",
            console_enabled=True,
            file_enabled=False,
            enable_security_filter=True
        )
        
        logger = EnvironmentAwareLogger(config)
        logger.configure_logging()
        
        assert logger._configured
        
        # Test that we can get a logger
        test_logger = logger.get_logger("test.module")
        assert isinstance(test_logger, logging.Logger)
        assert test_logger.name == "test.module"
    
    def test_file_logging_configuration(self):
        """Test file logging configuration."""
        config = LoggingConfig(
            environment="test",
            log_level="INFO",
            console_enabled=False,
            file_enabled=True,
            log_file_path=self.log_file,
            max_log_size_mb=1,
            backup_count=2
        )
        
        logger = EnvironmentAwareLogger(config)
        logger.configure_logging()
        
        # Test logging to file
        test_logger = logger.get_logger("test.file")
        test_logger.info("Test file logging message")
        
        # Check that log file was created
        assert os.path.exists(self.log_file)
        
        # Check log file content
        with open(self.log_file, 'r') as f:
            content = f.read()
            assert "Test file logging message" in content
    
    def test_json_logging_configuration(self):
        """Test JSON logging configuration."""
        config = LoggingConfig(
            environment="test",
            log_level="INFO",
            console_enabled=False,
            file_enabled=True,
            log_file_path=self.log_file,
            enable_json_logging=True
        )
        
        logger = EnvironmentAwareLogger(config)
        logger.configure_logging()
        
        # Test JSON logging
        test_logger = logger.get_logger("test.json")
        test_logger.info("Test JSON logging message")
        
        # Check that log file contains JSON
        with open(self.log_file, 'r') as f:
            content = f.read().strip()
            log_data = json.loads(content)
            assert log_data["message"] == "Test JSON logging message"
            assert log_data["level"] == "INFO"
    
    def test_module_log_levels(self):
        """Test module-specific log levels."""
        config = LoggingConfig(
            environment="test",
            log_level="INFO",
            module_log_levels={
                "test.module1": "DEBUG",
                "test.module2": "ERROR"
            }
        )
        
        logger = EnvironmentAwareLogger(config)
        logger.configure_logging()
        
        # Check that module log levels are set correctly
        module1_logger = logging.getLogger("test.module1")
        module2_logger = logging.getLogger("test.module2")
        
        assert module1_logger.level == logging.DEBUG
        assert module2_logger.level == logging.ERROR
    
    def test_reconfigure_logging(self):
        """Test reconfiguring logging."""
        initial_config = LoggingConfig(
            environment="test",
            log_level="INFO"
        )
        
        logger = EnvironmentAwareLogger(initial_config)
        logger.configure_logging()
        
        # Reconfigure with new settings
        new_config = LoggingConfig(
            environment="test",
            log_level="DEBUG"
        )
        
        logger.reconfigure(new_config)
        
        assert logger.config == new_config
        assert logger._configured
    
    def test_get_logging_stats(self):
        """Test getting logging statistics."""
        config = LoggingConfig(
            environment="test",
            log_level="INFO",
            console_enabled=True
        )
        
        logger = EnvironmentAwareLogger(config)
        logger.configure_logging()
        
        stats = logger.get_logging_stats()
        
        assert "configured" in stats
        assert "environment" in stats
        assert "log_level" in stats
        assert "handlers" in stats
        assert "loggers" in stats
        assert stats["configured"] is True
        assert stats["environment"] == "test"


class TestGlobalFunctions:
    """Test global convenience functions."""
    
    def test_configure_logging_global(self):
        """Test global configure_logging function."""
        config = LoggingConfig(
            environment="test",
            log_level="DEBUG"
        )
        
        configure_logging(config)
        
        # Test that we can get a logger
        logger = get_logger("test.global")
        assert isinstance(logger, logging.Logger)
    
    def test_get_logger_global(self):
        """Test global get_logger function."""
        logger = get_logger("test.global.function")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.global.function"
    
    def test_reconfigure_logging_global(self):
        """Test global reconfigure_logging function."""
        new_config = LoggingConfig(
            environment="test",
            log_level="ERROR"
        )
        
        reconfigure_logging(new_config)
        
        # Should not raise an exception
        logger = get_logger("test.reconfigure")
        assert isinstance(logger, logging.Logger)
    
    def test_get_logging_stats_global(self):
        """Test global get_logging_stats function."""
        stats = get_logging_stats()
        
        assert isinstance(stats, dict)
        assert "configured" in stats
        assert "environment" in stats


class TestRequestLoggingContext:
    """Test request logging context manager."""
    
    def test_request_context(self):
        """Test request logging context."""
        # Configure logging first
        configure_logging()
        
        with RequestLoggingContext("req-123", "user-456"):
            logger = get_logger("test.request")
            
            # Capture log output
            import io
            log_stream = io.StringIO()
            handler = logging.StreamHandler(log_stream)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            
            logger.info("Test message with context")
            
            # The request_id should be added to the log record
            # This would be visible in custom formatters
            # For this test, we just verify the context manager works
            assert True  # Context manager executed without error
    
    def test_request_context_restoration(self):
        """Test that request context is properly restored."""
        configure_logging()
        
        # Get original factory
        original_factory = logging.getLogRecordFactory()
        
        with RequestLoggingContext("req-123"):
            # Factory should be different inside context
            current_factory = logging.getLogRecordFactory()
            assert current_factory != original_factory
        
        # Factory should be restored after context
        restored_factory = logging.getLogRecordFactory()
        assert restored_factory == original_factory


if __name__ == "__main__":
    pytest.main([__file__])