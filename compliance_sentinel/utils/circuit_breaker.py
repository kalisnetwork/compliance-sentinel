"""Circuit breaker pattern implementation for resilient external service calls."""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, calls are blocked
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5  # Number of failures before opening
    recovery_timeout: int = 60  # Seconds to wait before trying half-open
    success_threshold: int = 3  # Successful calls needed to close from half-open
    timeout: float = 30.0  # Timeout for individual calls
    expected_exception_types: List[type] = field(default_factory=lambda: [Exception])
    
    def __post_init__(self):
        """Validate configuration."""
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.recovery_timeout < 1:
            raise ValueError("recovery_timeout must be at least 1")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be at least 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    state_changes: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    current_consecutive_failures: int = 0
    current_consecutive_successes: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_calls == 0:
            return 1.0
        return self.successful_calls / self.total_calls
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        return 1.0 - self.success_rate
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "rejected_calls": self.rejected_calls,
            "state_changes": self.state_changes,
            "success_rate": self.success_rate,
            "failure_rate": self.failure_rate,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "current_consecutive_failures": self.current_consecutive_failures,
            "current_consecutive_successes": self.current_consecutive_successes
        }


class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open."""
    
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class CircuitBreaker:
    """Circuit breaker implementation for resilient service calls."""
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        """Initialize circuit breaker."""
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_failure_time = 0.0
        self.state_change_listeners: List[Callable] = []
        self._lock = asyncio.Lock()
        
        logger.info(f"Circuit breaker '{name}' initialized with config: {self.config}")
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            # Check if we should attempt the call
            if not self._should_attempt_call():
                self.stats.rejected_calls += 1
                retry_after = self._get_retry_after_seconds()
                raise CircuitBreakerOpenException(
                    f"Circuit breaker '{self.name}' is open",
                    retry_after=retry_after
                )
            
            self.stats.total_calls += 1
        
        # Execute the call with timeout
        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.config.timeout
                )
            else:
                # Run sync function in executor with timeout
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, func, *args, **kwargs),
                    timeout=self.config.timeout
                )
            
            await self._on_success()
            return result
            
        except asyncio.TimeoutError as e:
            await self._on_failure(e)
            raise
        except Exception as e:
            # Only count as failure if it's an expected exception type
            if any(isinstance(e, exc_type) for exc_type in self.config.expected_exception_types):
                await self._on_failure(e)
            raise
    
    def _should_attempt_call(self) -> bool:
        """Check if we should attempt the call based on current state."""
        current_time = time.time()
        
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if current_time - self.last_failure_time >= self.config.recovery_timeout:
                self._change_state(CircuitState.HALF_OPEN)
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    async def _on_success(self) -> None:
        """Handle successful call."""
        async with self._lock:
            self.stats.successful_calls += 1
            self.stats.last_success_time = datetime.now(timezone.utc)
            self.stats.current_consecutive_failures = 0
            self.stats.current_consecutive_successes += 1
            
            if self.state == CircuitState.HALF_OPEN:
                if self.stats.current_consecutive_successes >= self.config.success_threshold:
                    self._change_state(CircuitState.CLOSED)
                    self.stats.current_consecutive_successes = 0
    
    async def _on_failure(self, exception: Exception) -> None:
        """Handle failed call."""
        async with self._lock:
            self.stats.failed_calls += 1
            self.stats.last_failure_time = datetime.now(timezone.utc)
            self.stats.current_consecutive_successes = 0
            self.stats.current_consecutive_failures += 1
            self.last_failure_time = time.time()
            
            logger.warning(f"Circuit breaker '{self.name}' recorded failure: {exception}")
            
            if self.state == CircuitState.CLOSED:
                if self.stats.current_consecutive_failures >= self.config.failure_threshold:
                    self._change_state(CircuitState.OPEN)
            elif self.state == CircuitState.HALF_OPEN:
                # Any failure in half-open state goes back to open
                self._change_state(CircuitState.OPEN)
    
    def _change_state(self, new_state: CircuitState) -> None:
        """Change circuit breaker state."""
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            self.stats.state_changes += 1
            
            logger.info(f"Circuit breaker '{self.name}' state changed: {old_state.value} -> {new_state.value}")
            
            # Notify listeners
            for listener in self.state_change_listeners:
                try:
                    listener(self.name, old_state, new_state)
                except Exception as e:
                    logger.error(f"Error in circuit breaker state change listener: {e}")
    
    def _get_retry_after_seconds(self) -> float:
        """Get seconds until next retry attempt."""
        if self.state == CircuitState.OPEN:
            elapsed = time.time() - self.last_failure_time
            return max(0, self.config.recovery_timeout - elapsed)
        return 0
    
    def add_state_change_listener(self, listener: Callable[[str, CircuitState, CircuitState], None]) -> None:
        """Add listener for state changes."""
        self.state_change_listeners.append(listener)
    
    def remove_state_change_listener(self, listener: Callable) -> None:
        """Remove state change listener."""
        if listener in self.state_change_listeners:
            self.state_change_listeners.remove(listener)
    
    def get_state(self) -> CircuitState:
        """Get current circuit breaker state."""
        return self.state
    
    def get_stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        return self.stats
    
    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        logger.info(f"Resetting circuit breaker '{self.name}'")
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_failure_time = 0.0
    
    def force_open(self) -> None:
        """Force circuit breaker to open state."""
        logger.warning(f"Forcing circuit breaker '{self.name}' to open state")
        self._change_state(CircuitState.OPEN)
        self.last_failure_time = time.time()
    
    def force_close(self) -> None:
        """Force circuit breaker to closed state."""
        logger.info(f"Forcing circuit breaker '{self.name}' to closed state")
        self._change_state(CircuitState.CLOSED)
        self.stats.current_consecutive_failures = 0
    
    def is_call_permitted(self) -> bool:
        """Check if calls are currently permitted."""
        return self._should_attempt_call()
    
    def get_info(self) -> Dict[str, Any]:
        """Get comprehensive circuit breaker information."""
        return {
            "name": self.name,
            "state": self.state.value,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout
            },
            "stats": self.stats.to_dict(),
            "call_permitted": self.is_call_permitted(),
            "retry_after_seconds": self._get_retry_after_seconds()
        }


class CircuitBreakerManager:
    """Manages multiple circuit breakers."""
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.global_listeners: List[Callable] = []
    
    def get_circuit_breaker(
        self, 
        name: str, 
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if name not in self.circuit_breakers:
            circuit_breaker = CircuitBreaker(name, config)
            
            # Add global listeners to new circuit breaker
            for listener in self.global_listeners:
                circuit_breaker.add_state_change_listener(listener)
            
            self.circuit_breakers[name] = circuit_breaker
            logger.info(f"Created new circuit breaker: {name}")
        
        return self.circuit_breakers[name]
    
    def remove_circuit_breaker(self, name: str) -> bool:
        """Remove a circuit breaker."""
        if name in self.circuit_breakers:
            del self.circuit_breakers[name]
            logger.info(f"Removed circuit breaker: {name}")
            return True
        return False
    
    def get_all_circuit_breakers(self) -> Dict[str, CircuitBreaker]:
        """Get all circuit breakers."""
        return self.circuit_breakers.copy()
    
    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for circuit_breaker in self.circuit_breakers.values():
            circuit_breaker.reset()
        logger.info("Reset all circuit breakers")
    
    def add_global_state_change_listener(
        self, 
        listener: Callable[[str, CircuitState, CircuitState], None]
    ) -> None:
        """Add global state change listener for all circuit breakers."""
        self.global_listeners.append(listener)
        
        # Add to existing circuit breakers
        for circuit_breaker in self.circuit_breakers.values():
            circuit_breaker.add_state_change_listener(listener)
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system-wide circuit breaker statistics."""
        total_breakers = len(self.circuit_breakers)
        open_breakers = sum(1 for cb in self.circuit_breakers.values() if cb.get_state() == CircuitState.OPEN)
        half_open_breakers = sum(1 for cb in self.circuit_breakers.values() if cb.get_state() == CircuitState.HALF_OPEN)
        closed_breakers = total_breakers - open_breakers - half_open_breakers
        
        total_calls = sum(cb.get_stats().total_calls for cb in self.circuit_breakers.values())
        total_failures = sum(cb.get_stats().failed_calls for cb in self.circuit_breakers.values())
        total_rejections = sum(cb.get_stats().rejected_calls for cb in self.circuit_breakers.values())
        
        return {
            "total_circuit_breakers": total_breakers,
            "closed_breakers": closed_breakers,
            "open_breakers": open_breakers,
            "half_open_breakers": half_open_breakers,
            "system_health_percentage": (closed_breakers / total_breakers * 100) if total_breakers > 0 else 100,
            "total_calls": total_calls,
            "total_failures": total_failures,
            "total_rejections": total_rejections,
            "overall_success_rate": ((total_calls - total_failures) / total_calls * 100) if total_calls > 0 else 100,
            "circuit_breakers": {name: cb.get_info() for name, cb in self.circuit_breakers.items()}
        }


# Global circuit breaker manager instance
_global_circuit_breaker_manager = CircuitBreakerManager()


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get a circuit breaker from the global manager."""
    return _global_circuit_breaker_manager.get_circuit_breaker(name, config)


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Get the global circuit breaker manager."""
    return _global_circuit_breaker_manager


async def with_circuit_breaker(
    name: str, 
    func: Callable, 
    *args, 
    config: Optional[CircuitBreakerConfig] = None,
    **kwargs
) -> Any:
    """Convenience function to execute a function with circuit breaker protection."""
    circuit_breaker = get_circuit_breaker(name, config)
    return await circuit_breaker.call(func, *args, **kwargs)


class CircuitBreakerDecorator:
    """Decorator for circuit breaker protection."""
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        """Initialize decorator."""
        self.name = name
        self.config = config
    
    def __call__(self, func: Callable) -> Callable:
        """Apply circuit breaker to function."""
        async def wrapper(*args, **kwargs):
            return await with_circuit_breaker(self.name, func, *args, config=self.config, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper


def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Decorator for circuit breaker protection."""
    return CircuitBreakerDecorator(name, config)