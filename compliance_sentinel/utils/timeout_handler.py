"""Timeout handling utilities for long-running operations."""

import asyncio
import signal
import time
from typing import Any, Callable, Optional, Union, TypeVar, Awaitable
from functools import wraps
from contextlib import contextmanager
import logging
from dataclasses import dataclass
from enum import Enum

from compliance_sentinel.utils.error_handler import get_global_error_handler


logger = logging.getLogger(__name__)

T = TypeVar('T')


class TimeoutStrategy(Enum):
    """Strategies for handling timeouts."""
    RAISE_EXCEPTION = "raise_exception"
    RETURN_DEFAULT = "return_default"
    RETURN_PARTIAL = "return_partial"
    CANCEL_GRACEFULLY = "cancel_gracefully"


@dataclass
class TimeoutConfig:
    """Configuration for timeout handling."""
    timeout_seconds: float
    strategy: TimeoutStrategy = TimeoutStrategy.RAISE_EXCEPTION
    default_return: Any = None
    warning_threshold: float = 0.8  # Warn when 80% of timeout is reached
    enable_progress_tracking: bool = False


class TimeoutError(Exception):
    """Custom timeout exception."""
    
    def __init__(self, operation: str, timeout_seconds: float, elapsed_seconds: float):
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds
        super().__init__(
            f"Operation '{operation}' timed out after {elapsed_seconds:.2f}s "
            f"(limit: {timeout_seconds}s)"
        )


class ProgressTracker:
    """Tracks progress of long-running operations."""
    
    def __init__(self, operation_name: str, total_steps: Optional[int] = None):
        self.operation_name = operation_name
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.step_times = []
    
    def update(self, step: int, description: Optional[str] = None) -> None:
        """Update progress."""
        current_time = time.time()
        self.current_step = step
        
        # Track step duration
        step_duration = current_time - self.last_update
        self.step_times.append(step_duration)
        self.last_update = current_time
        
        # Log progress
        if self.total_steps:
            progress_pct = (step / self.total_steps) * 100
            logger.debug(f"{self.operation_name}: Step {step}/{self.total_steps} "
                        f"({progress_pct:.1f}%) - {description or 'Processing'}")
        else:
            logger.debug(f"{self.operation_name}: Step {step} - {description or 'Processing'}")
    
    def get_estimated_remaining_time(self) -> Optional[float]:
        """Estimate remaining time based on current progress."""
        if not self.total_steps or self.current_step == 0:
            return None
        
        elapsed = time.time() - self.start_time
        progress_ratio = self.current_step / self.total_steps
        
        if progress_ratio > 0:
            estimated_total = elapsed / progress_ratio
            return max(0, estimated_total - elapsed)
        
        return None
    
    def get_stats(self) -> dict:
        """Get progress statistics."""
        elapsed = time.time() - self.start_time
        avg_step_time = sum(self.step_times) / len(self.step_times) if self.step_times else 0
        
        return {
            "operation": self.operation_name,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "elapsed_seconds": elapsed,
            "average_step_time": avg_step_time,
            "estimated_remaining": self.get_estimated_remaining_time()
        }


class TimeoutHandler:
    """Handles timeouts for various operations."""
    
    def __init__(self):
        self.error_handler = get_global_error_handler()
        self.active_operations: dict = {}
    
    def with_timeout(self, 
                    timeout_config: TimeoutConfig,
                    operation_name: Optional[str] = None):
        """Decorator for adding timeout to functions."""
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                op_name = operation_name or func.__name__
                return self._execute_with_timeout(func, timeout_config, op_name, *args, **kwargs)
            return wrapper
        return decorator
    
    def with_async_timeout(self,
                          timeout_config: TimeoutConfig,
                          operation_name: Optional[str] = None):
        """Decorator for adding timeout to async functions."""
        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @wraps(func)
            async def wrapper(*args, **kwargs) -> T:
                op_name = operation_name or func.__name__
                return await self._execute_async_with_timeout(func, timeout_config, op_name, *args, **kwargs)
            return wrapper
        return decorator
    
    def _execute_with_timeout(self,
                             func: Callable,
                             config: TimeoutConfig,
                             operation_name: str,
                             *args, **kwargs) -> Any:
        """Execute function with timeout (synchronous)."""
        start_time = time.time()
        
        # Set up signal handler for timeout
        def timeout_handler(signum, frame):
            elapsed = time.time() - start_time
            raise TimeoutError(operation_name, config.timeout_seconds, elapsed)
        
        # Store original handler
        original_handler = signal.signal(signal.SIGALRM, timeout_handler)
        
        try:
            # Set alarm
            signal.alarm(int(config.timeout_seconds))
            
            # Track operation
            self.active_operations[operation_name] = {
                "start_time": start_time,
                "timeout": config.timeout_seconds,
                "type": "sync"
            }
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Clear alarm
            signal.alarm(0)
            
            elapsed = time.time() - start_time
            logger.debug(f"Operation '{operation_name}' completed in {elapsed:.2f}s")
            
            return result
            
        except TimeoutError as e:
            logger.error(f"Timeout in operation '{operation_name}': {e}")
            self.error_handler.handle_analysis_error(e, f"timeout:{operation_name}")
            
            return self._handle_timeout_strategy(config, operation_name, e)
            
        except Exception as e:
            signal.alarm(0)  # Clear alarm on any exception
            raise
            
        finally:
            # Restore original handler
            signal.signal(signal.SIGALRM, original_handler)
            
            # Remove from active operations
            self.active_operations.pop(operation_name, None)
    
    async def _execute_async_with_timeout(self,
                                         func: Callable,
                                         config: TimeoutConfig,
                                         operation_name: str,
                                         *args, **kwargs) -> Any:
        """Execute async function with timeout."""
        start_time = time.time()
        
        # Track operation
        self.active_operations[operation_name] = {
            "start_time": start_time,
            "timeout": config.timeout_seconds,
            "type": "async"
        }
        
        try:
            # Create progress tracker if enabled
            progress_tracker = None
            if config.enable_progress_tracking:
                progress_tracker = ProgressTracker(operation_name)
                kwargs['progress_tracker'] = progress_tracker
            
            # Execute with asyncio timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=config.timeout_seconds
            )
            
            elapsed = time.time() - start_time
            logger.debug(f"Async operation '{operation_name}' completed in {elapsed:.2f}s")
            
            return result
            
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            timeout_error = TimeoutError(operation_name, config.timeout_seconds, elapsed)
            
            logger.error(f"Async timeout in operation '{operation_name}': {timeout_error}")
            self.error_handler.handle_analysis_error(timeout_error, f"async_timeout:{operation_name}")
            
            return self._handle_timeout_strategy(config, operation_name, timeout_error)
            
        finally:
            # Remove from active operations
            self.active_operations.pop(operation_name, None)
    
    def _handle_timeout_strategy(self,
                                config: TimeoutConfig,
                                operation_name: str,
                                timeout_error: TimeoutError) -> Any:
        """Handle timeout based on configured strategy."""
        if config.strategy == TimeoutStrategy.RAISE_EXCEPTION:
            raise timeout_error
        
        elif config.strategy == TimeoutStrategy.RETURN_DEFAULT:
            logger.warning(f"Returning default value for timed out operation '{operation_name}'")
            return config.default_return
        
        elif config.strategy == TimeoutStrategy.RETURN_PARTIAL:
            logger.warning(f"Returning partial results for timed out operation '{operation_name}'")
            # This would need to be implemented per operation
            return config.default_return
        
        elif config.strategy == TimeoutStrategy.CANCEL_GRACEFULLY:
            logger.warning(f"Gracefully cancelling timed out operation '{operation_name}'")
            return None
        
        else:
            raise timeout_error
    
    @contextmanager
    def timeout_context(self, timeout_seconds: float, operation_name: str):
        """Context manager for timeout handling."""
        config = TimeoutConfig(timeout_seconds=timeout_seconds)
        start_time = time.time()
        
        # Set up signal handler
        def timeout_handler(signum, frame):
            elapsed = time.time() - start_time
            raise TimeoutError(operation_name, timeout_seconds, elapsed)
        
        original_handler = signal.signal(signal.SIGALRM, timeout_handler)
        
        try:
            signal.alarm(int(timeout_seconds))
            yield
            signal.alarm(0)
            
        except TimeoutError:
            logger.error(f"Context timeout in operation '{operation_name}'")
            raise
            
        finally:
            signal.signal(signal.SIGALRM, original_handler)
    
    def get_active_operations(self) -> dict:
        """Get information about currently active operations."""
        current_time = time.time()
        
        active_ops = {}
        for op_name, op_info in self.active_operations.items():
            elapsed = current_time - op_info["start_time"]
            remaining = max(0, op_info["timeout"] - elapsed)
            
            active_ops[op_name] = {
                "elapsed_seconds": elapsed,
                "remaining_seconds": remaining,
                "timeout_seconds": op_info["timeout"],
                "type": op_info["type"],
                "progress_percent": min(100, (elapsed / op_info["timeout"]) * 100)
            }
        
        return active_ops
    
    def cancel_operation(self, operation_name: str) -> bool:
        """Cancel an active operation."""
        if operation_name in self.active_operations:
            logger.info(f"Cancelling operation '{operation_name}'")
            # For sync operations, we can't easily cancel, but we can mark it
            # For async operations, this would need integration with asyncio tasks
            return True
        return False


# Convenience functions and decorators

def timeout(seconds: float, 
           strategy: TimeoutStrategy = TimeoutStrategy.RAISE_EXCEPTION,
           default_return: Any = None,
           operation_name: Optional[str] = None):
    """Simple timeout decorator."""
    config = TimeoutConfig(
        timeout_seconds=seconds,
        strategy=strategy,
        default_return=default_return
    )
    
    handler = TimeoutHandler()
    return handler.with_timeout(config, operation_name)


def async_timeout(seconds: float,
                 strategy: TimeoutStrategy = TimeoutStrategy.RAISE_EXCEPTION,
                 default_return: Any = None,
                 operation_name: Optional[str] = None,
                 enable_progress: bool = False):
    """Simple async timeout decorator."""
    config = TimeoutConfig(
        timeout_seconds=seconds,
        strategy=strategy,
        default_return=default_return,
        enable_progress_tracking=enable_progress
    )
    
    handler = TimeoutHandler()
    return handler.with_async_timeout(config, operation_name)


# Global timeout handler instance
_global_timeout_handler: Optional[TimeoutHandler] = None


def get_timeout_handler() -> TimeoutHandler:
    """Get global timeout handler instance."""
    global _global_timeout_handler
    if _global_timeout_handler is None:
        _global_timeout_handler = TimeoutHandler()
    return _global_timeout_handler


def set_timeout_handler(handler: TimeoutHandler) -> None:
    """Set global timeout handler instance."""
    global _global_timeout_handler
    _global_timeout_handler = handler