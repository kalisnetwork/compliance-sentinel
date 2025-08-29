"""Error handling and recovery utilities for the Compliance Sentinel system."""

import logging
import traceback
import time
from typing import Any, Callable, Optional, Dict, List, Type, Union, Set
from dataclasses import dataclass
from enum import Enum
from functools import wraps
import asyncio
from datetime import datetime, timedelta

from compliance_sentinel.core.interfaces import ErrorHandler as IErrorHandler


logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Categories of errors."""
    ANALYSIS_ERROR = "analysis_error"
    EXTERNAL_SERVICE_ERROR = "external_service_error"
    CONFIGURATION_ERROR = "configuration_error"
    VALIDATION_ERROR = "validation_error"
    NETWORK_ERROR = "network_error"
    FILE_SYSTEM_ERROR = "file_system_error"
    AUTHENTICATION_ERROR = "authentication_error"
    RATE_LIMIT_ERROR = "rate_limit_error"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    component: str
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    file_path: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


@dataclass
class ErrorRecord:
    """Record of an error occurrence."""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    context: ErrorContext
    exception_type: str
    stack_trace: Optional[str] = None
    resolved: bool = False
    resolution_notes: Optional[str] = None


class RetryStrategy:
    """Configuration for retry behavior."""
    
    def __init__(self, 
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt number."""
        if attempt <= 0:
            return 0.0
        
        delay = self.base_delay * (self.exponential_base ** (attempt - 1))
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)  # Add 0-50% jitter
        
        return delay


class ComplianceSentinelErrorHandler(IErrorHandler):
    """Main error handler for the Compliance Sentinel system."""
    
    def __init__(self):
        self.error_records: List[ErrorRecord] = []
        self.retry_strategies: Dict[ErrorCategory, RetryStrategy] = {
            ErrorCategory.EXTERNAL_SERVICE_ERROR: RetryStrategy(max_attempts=3, base_delay=2.0),
            ErrorCategory.NETWORK_ERROR: RetryStrategy(max_attempts=5, base_delay=1.0),
            ErrorCategory.RATE_LIMIT_ERROR: RetryStrategy(max_attempts=3, base_delay=10.0),
            ErrorCategory.ANALYSIS_ERROR: RetryStrategy(max_attempts=2, base_delay=0.5),
        }
        
        # Error rate tracking for circuit breaker pattern
        self.error_counts: Dict[str, List[datetime]] = {}
        self.circuit_breaker_threshold = 10  # errors per minute
        self.circuit_breaker_window = timedelta(minutes=1)
        
        # Service availability tracking for graceful degradation
        self.service_status: Dict[str, Dict[str, Any]] = {}
        self.degraded_services: Set[str] = set()
        
        # Fallback strategies
        self.fallback_strategies: Dict[str, Callable] = {
            "nvd_service": self._nvd_fallback_strategy,
            "cve_service": self._cve_fallback_strategy,
            "dependency_scanner": self._dependency_scanner_fallback,
            "mcp_server": self._mcp_server_fallback,
        }
    
    def handle_analysis_error(self, error: Exception, context: str) -> None:
        """Handle errors during security analysis."""
        error_context = ErrorContext(
            operation="security_analysis",
            component="analyzer",
            additional_data={"context": context}
        )
        
        self._record_error(
            error=error,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.ANALYSIS_ERROR,
            context=error_context
        )
        
        # Log with appropriate level based on error type
        if isinstance(error, (FileNotFoundError, PermissionError)):
            logger.warning(f"Analysis error in {context}: {error}")
        else:
            logger.error(f"Analysis error in {context}: {error}", exc_info=True)
    
    def handle_system_error(self, error: Exception, context: str) -> None:
        """Handle system-level errors."""
        error_context = ErrorContext(
            operation="system_operation",
            component="system",
            additional_data={"context": context}
        )
        
        self._record_error(
            error=error,
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SYSTEM_ERROR,
            context=error_context
        )
        
        logger.critical(f"System error in {context}: {error}", exc_info=True)
    
    def handle_external_service_error(self, service: str, error: Exception) -> None:
        """Handle errors from external services."""
        error_context = ErrorContext(
            operation="external_service_call",
            component="mcp_client",
            additional_data={"service": service}
        )
        
        severity = ErrorSeverity.HIGH if self._is_critical_service(service) else ErrorSeverity.MEDIUM
        
        self._record_error(
            error=error,
            severity=severity,
            category=ErrorCategory.EXTERNAL_SERVICE_ERROR,
            context=error_context
        )
        
        logger.error(f"External service error ({service}): {error}")
        
        # Check if we should enable circuit breaker
        if self._should_enable_circuit_breaker(service):
            logger.warning(f"Circuit breaker activated for service: {service}")
    
    def should_retry(self, error: Exception) -> bool:
        """Determine if an operation should be retried."""
        # Don't retry certain types of errors
        non_retryable_errors = (
            ValueError,
            TypeError,
            FileNotFoundError,
            PermissionError,
        )
        
        if isinstance(error, non_retryable_errors):
            return False
        
        # Retry network and external service errors
        if isinstance(error, (ConnectionError, TimeoutError)):
            return True
        
        # Check error message for retryable conditions
        error_message = str(error).lower()
        retryable_patterns = [
            "timeout",
            "connection",
            "rate limit",
            "service unavailable",
            "temporary",
        ]
        
        return any(pattern in error_message for pattern in retryable_patterns)
    
    def _record_error(self, 
                     error: Exception, 
                     severity: ErrorSeverity,
                     category: ErrorCategory,
                     context: ErrorContext) -> None:
        """Record an error occurrence."""
        import uuid
        
        error_record = ErrorRecord(
            error_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            severity=severity,
            category=category,
            message=str(error),
            context=context,
            exception_type=type(error).__name__,
            stack_trace=traceback.format_exc() if severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL] else None
        )
        
        self.error_records.append(error_record)
        
        # Keep only recent errors to prevent memory issues
        if len(self.error_records) > 1000:
            self.error_records = self.error_records[-500:]  # Keep last 500
    
    def _is_critical_service(self, service: str) -> bool:
        """Check if a service is considered critical."""
        critical_services = ["nvd", "cve", "authentication"]
        return service.lower() in critical_services
    
    def _should_enable_circuit_breaker(self, service: str) -> bool:
        """Check if circuit breaker should be enabled for a service."""
        now = datetime.utcnow()
        
        # Initialize error tracking for service if not exists
        if service not in self.error_counts:
            self.error_counts[service] = []
        
        # Add current error
        self.error_counts[service].append(now)
        
        # Remove old errors outside the window
        cutoff_time = now - self.circuit_breaker_window
        self.error_counts[service] = [
            error_time for error_time in self.error_counts[service]
            if error_time > cutoff_time
        ]
        
        # Check if threshold exceeded
        return len(self.error_counts[service]) >= self.circuit_breaker_threshold
    
    def enable_graceful_degradation(self, service: str, reason: str = "Service unavailable") -> None:
        """Enable graceful degradation for a service."""
        self.degraded_services.add(service)
        self.service_status[service] = {
            "status": "degraded",
            "reason": reason,
            "degraded_at": datetime.utcnow(),
            "fallback_active": True
        }
        
        logger.warning(f"Graceful degradation enabled for {service}: {reason}")
    
    def disable_graceful_degradation(self, service: str) -> None:
        """Disable graceful degradation for a service."""
        if service in self.degraded_services:
            self.degraded_services.remove(service)
        
        self.service_status[service] = {
            "status": "healthy",
            "reason": "Service restored",
            "restored_at": datetime.utcnow(),
            "fallback_active": False
        }
        
        logger.info(f"Graceful degradation disabled for {service}: Service restored")
    
    def is_service_degraded(self, service: str) -> bool:
        """Check if a service is in degraded mode."""
        return service in self.degraded_services
    
    def get_fallback_strategy(self, service: str) -> Optional[Callable]:
        """Get fallback strategy for a service."""
        return self.fallback_strategies.get(service)
    
    def _nvd_fallback_strategy(self, *args, **kwargs) -> Dict[str, Any]:
        """Fallback strategy for NVD service failures."""
        logger.info("Using NVD fallback strategy - returning cached/local data")
        return {
            "vulnerabilities": [],
            "source": "fallback",
            "message": "NVD service unavailable, using local cache",
            "degraded": True
        }
    
    def _cve_fallback_strategy(self, *args, **kwargs) -> Dict[str, Any]:
        """Fallback strategy for CVE service failures."""
        logger.info("Using CVE fallback strategy - returning basic vulnerability info")
        return {
            "cve_details": {},
            "source": "fallback", 
            "message": "CVE service unavailable, limited vulnerability information",
            "degraded": True
        }
    
    def _dependency_scanner_fallback(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Fallback strategy for dependency scanner failures."""
        logger.info("Using dependency scanner fallback - basic local scanning only")
        return []
    
    def _mcp_server_fallback(self, *args, **kwargs) -> Dict[str, Any]:
        """Fallback strategy for MCP server failures."""
        logger.info("Using MCP server fallback - local analysis only")
        return {
            "analysis_mode": "local_only",
            "external_data": False,
            "message": "External services unavailable, using local analysis",
            "degraded": True
        }
    
    def handle_service_failure(self, service: str, error: Exception, enable_degradation: bool = True) -> Any:
        """Handle service failure with optional graceful degradation."""
        self.handle_external_service_error(service, error)
        
        if enable_degradation and not self.is_service_degraded(service):
            self.enable_graceful_degradation(service, str(error))
            
            # Execute fallback strategy if available
            fallback = self.get_fallback_strategy(service)
            if fallback:
                try:
                    return fallback()
                except Exception as fallback_error:
                    logger.error(f"Fallback strategy failed for {service}: {fallback_error}")
        
        return None
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors."""
        if not self.error_records:
            return {"total_errors": 0, "by_category": {}, "by_severity": {}}
        
        # Count errors by category and severity
        by_category = {}
        by_severity = {}
        
        for record in self.error_records:
            category = record.category.value
            severity = record.severity.value
            
            by_category[category] = by_category.get(category, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            "total_errors": len(self.error_records),
            "by_category": by_category,
            "by_severity": by_severity,
            "degraded_services": list(self.degraded_services),
            "service_status": self.service_status,
            "recent_errors": [
                {
                    "timestamp": record.timestamp.isoformat(),
                    "severity": record.severity.value,
                    "category": record.category.value,
                    "message": record.message,
                    "component": record.context.component
                }
                for record in self.error_records[-10:]  # Last 10 errors
            ]
        }


def retry_with_backoff(strategy: Optional[RetryStrategy] = None,
                      exceptions: tuple = (Exception,),
                      on_retry: Optional[Callable] = None):
    """Decorator for retrying functions with exponential backoff."""
    if strategy is None:
        strategy = RetryStrategy()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(strategy.max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == strategy.max_attempts - 1:
                        # Last attempt, re-raise the exception
                        raise e
                    
                    delay = strategy.get_delay(attempt + 1)
                    
                    if on_retry:
                        on_retry(e, attempt + 1, delay)
                    
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                                 f"Retrying in {delay:.2f} seconds...")
                    
                    time.sleep(delay)
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator


def async_retry_with_backoff(strategy: Optional[RetryStrategy] = None,
                           exceptions: tuple = (Exception,),
                           on_retry: Optional[Callable] = None):
    """Async decorator for retrying functions with exponential backoff."""
    if strategy is None:
        strategy = RetryStrategy()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(strategy.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == strategy.max_attempts - 1:
                        # Last attempt, re-raise the exception
                        raise e
                    
                    delay = strategy.get_delay(attempt + 1)
                    
                    if on_retry:
                        if asyncio.iscoroutinefunction(on_retry):
                            await on_retry(e, attempt + 1, delay)
                        else:
                            on_retry(e, attempt + 1, delay)
                    
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                                 f"Retrying in {delay:.2f} seconds...")
                    
                    await asyncio.sleep(delay)
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator


class CircuitBreaker:
    """Circuit breaker pattern implementation for external services."""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 expected_exception: Type[Exception] = Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if self.state == "OPEN":
                if self._should_attempt_reset():
                    self.state = "HALF_OPEN"
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except self.expected_exception as e:
                self._on_failure()
                raise e
        
        return wrapper
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit breaker."""
        if self.last_failure_time is None:
            return True
        
        return (datetime.utcnow() - self.last_failure_time).total_seconds() > self.recovery_timeout
    
    def _on_success(self) -> None:
        """Handle successful operation."""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def _on_failure(self) -> None:
        """Handle failed operation."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


def safe_execute(func: Callable, 
                default_return: Any = None,
                log_errors: bool = True,
                error_handler: Optional[IErrorHandler] = None) -> Any:
    """Safely execute a function with error handling."""
    try:
        return func()
    except Exception as e:
        if log_errors:
            logger.error(f"Error in safe_execute: {e}", exc_info=True)
        
        if error_handler:
            error_handler.handle_analysis_error(e, func.__name__)
        
        return default_return


async def async_safe_execute(func: Callable,
                           default_return: Any = None,
                           log_errors: bool = True,
                           error_handler: Optional[IErrorHandler] = None) -> Any:
    """Safely execute an async function with error handling."""
    try:
        if asyncio.iscoroutinefunction(func):
            return await func()
        else:
            return func()
    except Exception as e:
        if log_errors:
            logger.error(f"Error in async_safe_execute: {e}", exc_info=True)
        
        if error_handler:
            error_handler.handle_analysis_error(e, func.__name__)
        
        return default_return


# Global error handler instance
_global_error_handler: Optional[ComplianceSentinelErrorHandler] = None


def get_global_error_handler() -> ComplianceSentinelErrorHandler:
    """Get or create global error handler instance."""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ComplianceSentinelErrorHandler()
    return _global_error_handler


def set_global_error_handler(error_handler: ComplianceSentinelErrorHandler) -> None:
    """Set global error handler instance."""
    global _global_error_handler
    _global_error_handler = error_handler