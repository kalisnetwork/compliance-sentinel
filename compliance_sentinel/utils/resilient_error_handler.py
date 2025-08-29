"""Resilient error handling with fallback strategies."""

import logging
import asyncio
from typing import Any, Dict, Optional, Callable, Union, List
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from .circuit_breaker import CircuitBreakerManager
from .intelligent_cache import IntelligentCache
from ..monitoring.real_time_metrics import get_metrics


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FallbackStrategy(Enum):
    """Fallback strategy types."""
    CACHED_DATA = "cached_data"
    DEFAULT_VALUE = "default_value"
    ALTERNATIVE_SERVICE = "alternative_service"
    DEGRADED_FUNCTIONALITY = "degraded_functionality"
    FAIL_FAST = "fail_fast"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    service: str
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    timestamp: datetime = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
        if self.metadata is None:
            self.metadata = {}


@dataclass
class FallbackResult:
    """Result of fallback operation."""
    success: bool
    data: Any = None
    strategy_used: Optional[FallbackStrategy] = None
    error: Optional[str] = None
    is_degraded: bool = False
    cache_hit: bool = False


class ResilientErrorHandler:
    """Enhanced error handler with fallback strategies."""
    
    def __init__(self, 
                 cache_manager: Optional[IntelligentCache] = None,
                 circuit_breaker_manager: Optional[CircuitBreakerManager] = None):
        self.logger = logging.getLogger(__name__)
        self.cache_manager = cache_manager or IntelligentCache()
        self.circuit_breaker_manager = circuit_breaker_manager or CircuitBreakerManager()
        self.metrics = get_metrics()
        
        # Fallback strategies registry
        self.fallback_strategies: Dict[str, List[Callable]] = {}
        
        # Error patterns and their handling
        self.error_patterns = {
            "connection_error": [FallbackStrategy.CACHED_DATA, FallbackStrategy.ALTERNATIVE_SERVICE],
            "timeout_error": [FallbackStrategy.CACHED_DATA, FallbackStrategy.DEGRADED_FUNCTIONALITY],
            "rate_limit_error": [FallbackStrategy.CACHED_DATA, FallbackStrategy.DEGRADED_FUNCTIONALITY],
            "authentication_error": [FallbackStrategy.ALTERNATIVE_SERVICE, FallbackStrategy.FAIL_FAST],
            "service_unavailable": [FallbackStrategy.CACHED_DATA, FallbackStrategy.ALTERNATIVE_SERVICE],
            "data_validation_error": [FallbackStrategy.DEFAULT_VALUE, FallbackStrategy.DEGRADED_FUNCTIONALITY]
        }
    
    async def handle_external_service_error(self,
                                          service_name: str,
                                          error: Exception,
                                          context: ErrorContext,
                                          fallback_data: Any = None) -> FallbackResult:
        """Handle external service errors with fallback strategies."""
        try:
            # Record error metrics
            self.metrics.increment_counter(
                "external_service_errors_total",
                1.0,
                {"service": service_name, "error_type": type(error).__name__}
            )
            
            # Log error with context
            self.logger.error(
                f"External service error in {service_name}: {error}",
                extra={
                    "service": service_name,
                    "operation": context.operation,
                    "request_id": context.request_id,
                    "error_type": type(error).__name__
                }
            )
            
            # Determine error pattern
            error_pattern = self._classify_error(error)
            
            # Get fallback strategies for this error pattern
            strategies = self.error_patterns.get(error_pattern, [FallbackStrategy.CACHED_DATA])
            
            # Try fallback strategies in order
            for strategy in strategies:
                try:
                    result = await self._execute_fallback_strategy(
                        strategy, service_name, context, fallback_data, error
                    )
                    
                    if result.success:
                        self.metrics.increment_counter(
                            "fallback_activations_total",
                            1.0,
                            {"service": service_name, "strategy": strategy.value}
                        )
                        return result
                        
                except Exception as fallback_error:
                    self.logger.warning(
                        f"Fallback strategy {strategy.value} failed: {fallback_error}",
                        extra={"service": service_name, "strategy": strategy.value}
                    )
                    continue
            
            # All fallback strategies failed
            return FallbackResult(
                success=False,
                error=f"All fallback strategies failed for {service_name}: {error}",
                strategy_used=None
            )
            
        except Exception as handler_error:
            self.logger.error(f"Error handler itself failed: {handler_error}")
            return FallbackResult(
                success=False,
                error=f"Error handler failed: {handler_error}",
                strategy_used=None
            )
    
    async def handle_configuration_error(self,
                                       config_key: str,
                                       error: Exception,
                                       secure_default: Any = None) -> Any:
        """Handle configuration errors with secure defaults."""
        try:
            self.logger.error(
                f"Configuration error for {config_key}: {error}",
                extra={"config_key": config_key, "error_type": type(error).__name__}
            )
            
            # Record configuration error
            self.metrics.increment_counter(
                "configuration_errors_total",
                1.0,
                {"config_key": config_key}
            )
            
            # Return secure default if provided
            if secure_default is not None:
                self.logger.info(f"Using secure default for {config_key}")
                return secure_default
            
            # Try to get cached configuration
            cached_config = await self.cache_manager.get(f"config_backup_{config_key}")
            if cached_config is not None:
                self.logger.info(f"Using cached configuration for {config_key}")
                return cached_config
            
            # No fallback available
            raise ValueError(f"No fallback available for configuration key: {config_key}")
            
        except Exception as handler_error:
            self.logger.error(f"Configuration error handler failed: {handler_error}")
            raise
    
    def register_fallback_strategy(self,
                                 service_name: str,
                                 strategy_func: Callable) -> None:
        """Register a custom fallback strategy for a service."""
        if service_name not in self.fallback_strategies:
            self.fallback_strategies[service_name] = []
        
        self.fallback_strategies[service_name].append(strategy_func)
        self.logger.info(f"Registered fallback strategy for {service_name}")
    
    async def _execute_fallback_strategy(self,
                                       strategy: FallbackStrategy,
                                       service_name: str,
                                       context: ErrorContext,
                                       fallback_data: Any,
                                       original_error: Exception) -> FallbackResult:
        """Execute a specific fallback strategy."""
        if strategy == FallbackStrategy.CACHED_DATA:
            return await self._fallback_to_cached_data(service_name, context)
        
        elif strategy == FallbackStrategy.DEFAULT_VALUE:
            return await self._fallback_to_default_value(fallback_data)
        
        elif strategy == FallbackStrategy.ALTERNATIVE_SERVICE:
            return await self._fallback_to_alternative_service(service_name, context)
        
        elif strategy == FallbackStrategy.DEGRADED_FUNCTIONALITY:
            return await self._fallback_to_degraded_functionality(service_name, context)
        
        elif strategy == FallbackStrategy.FAIL_FAST:
            return FallbackResult(
                success=False,
                error=f"Fail-fast strategy: {original_error}",
                strategy_used=strategy
            )
        
        else:
            raise ValueError(f"Unknown fallback strategy: {strategy}")
    
    async def _fallback_to_cached_data(self,
                                     service_name: str,
                                     context: ErrorContext) -> FallbackResult:
        """Fallback to cached data."""
        cache_key = f"fallback_{context.operation}_{service_name}"
        cached_data = await self.cache_manager.get(cache_key)
        
        if cached_data is not None:
            self.logger.info(f"Using cached data for {service_name}")
            return FallbackResult(
                success=True,
                data=cached_data,
                strategy_used=FallbackStrategy.CACHED_DATA,
                cache_hit=True,
                is_degraded=True
            )
        
        return FallbackResult(
            success=False,
            error="No cached data available",
            strategy_used=FallbackStrategy.CACHED_DATA
        )
    
    async def _fallback_to_default_value(self, default_value: Any) -> FallbackResult:
        """Fallback to default value."""
        if default_value is not None:
            return FallbackResult(
                success=True,
                data=default_value,
                strategy_used=FallbackStrategy.DEFAULT_VALUE,
                is_degraded=True
            )
        
        return FallbackResult(
            success=False,
            error="No default value provided",
            strategy_used=FallbackStrategy.DEFAULT_VALUE
        )
    
    async def _fallback_to_alternative_service(self,
                                             service_name: str,
                                             context: ErrorContext) -> FallbackResult:
        """Fallback to alternative service."""
        # Check if alternative service is available
        alternative_services = {
            "nvd-api": ["cve-circl", "osv-api"],
            "cve-circl": ["nvd-api", "osv-api"],
            "osv-api": ["nvd-api", "cve-circl"]
        }
        
        alternatives = alternative_services.get(service_name, [])
        
        for alt_service in alternatives:
            # Check if alternative service circuit breaker is closed
            if not self.circuit_breaker_manager.is_circuit_open(alt_service):
                self.logger.info(f"Attempting fallback to {alt_service}")
                
                # Execute custom fallback strategies if registered
                if alt_service in self.fallback_strategies:
                    for strategy_func in self.fallback_strategies[alt_service]:
                        try:
                            result = await strategy_func(context)
                            if result:
                                return FallbackResult(
                                    success=True,
                                    data=result,
                                    strategy_used=FallbackStrategy.ALTERNATIVE_SERVICE,
                                    is_degraded=True
                                )
                        except Exception as e:
                            self.logger.warning(f"Alternative service {alt_service} failed: {e}")
                            continue
        
        return FallbackResult(
            success=False,
            error="No alternative services available",
            strategy_used=FallbackStrategy.ALTERNATIVE_SERVICE
        )
    
    async def _fallback_to_degraded_functionality(self,
                                                service_name: str,
                                                context: ErrorContext) -> FallbackResult:
        """Fallback to degraded functionality."""
        # Provide minimal functionality based on service type
        degraded_data = self._get_degraded_data(service_name, context)
        
        if degraded_data is not None:
            return FallbackResult(
                success=True,
                data=degraded_data,
                strategy_used=FallbackStrategy.DEGRADED_FUNCTIONALITY,
                is_degraded=True
            )
        
        return FallbackResult(
            success=False,
            error="No degraded functionality available",
            strategy_used=FallbackStrategy.DEGRADED_FUNCTIONALITY
        )
    
    def _classify_error(self, error: Exception) -> str:
        """Classify error type for appropriate handling."""
        error_type = type(error).__name__.lower()
        error_message = str(error).lower()
        
        if "connection" in error_type or "connection" in error_message:
            return "connection_error"
        elif "timeout" in error_type or "timeout" in error_message:
            return "timeout_error"
        elif "rate" in error_message or "limit" in error_message:
            return "rate_limit_error"
        elif "auth" in error_type or "auth" in error_message:
            return "authentication_error"
        elif "unavailable" in error_message or "503" in error_message:
            return "service_unavailable"
        elif "validation" in error_type or "validation" in error_message:
            return "data_validation_error"
        else:
            return "unknown_error"
    
    def _get_degraded_data(self, service_name: str, context: ErrorContext) -> Any:
        """Get degraded data for service when full functionality is unavailable."""
        if "vulnerability" in service_name.lower():
            return {
                "vulnerabilities": [],
                "message": "Vulnerability data temporarily unavailable",
                "degraded": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        elif "compliance" in service_name.lower():
            return {
                "requirements": [],
                "message": "Compliance data temporarily unavailable",
                "degraded": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        else:
            return {
                "data": [],
                "message": f"{service_name} temporarily unavailable",
                "degraded": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    async def cache_successful_response(self,
                                      service_name: str,
                                      operation: str,
                                      data: Any,
                                      ttl: int = 3600) -> None:
        """Cache successful response for future fallback use."""
        cache_key = f"fallback_{operation}_{service_name}"
        await self.cache_manager.set(cache_key, data, ttl=ttl)
        
        self.logger.debug(f"Cached successful response for {service_name}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error handling statistics."""
        return {
            "total_errors_handled": self.metrics.get_metric_value("external_service_errors_total") or 0,
            "fallback_activations": self.metrics.get_metric_value("fallback_activations_total") or 0,
            "configuration_errors": self.metrics.get_metric_value("configuration_errors_total") or 0,
            "circuit_breaker_trips": self.metrics.get_metric_value("circuit_breaker_trips_total") or 0
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of error handling components."""
        health_status = {
            "cache_manager": "healthy",
            "circuit_breaker_manager": "healthy",
            "metrics": "healthy",
            "overall": "healthy"
        }
        
        try:
            # Test cache manager
            await self.cache_manager.set("health_check", "test", ttl=60)
            test_value = await self.cache_manager.get("health_check")
            if test_value != "test":
                health_status["cache_manager"] = "unhealthy"
                health_status["overall"] = "degraded"
        except Exception as e:
            health_status["cache_manager"] = f"unhealthy: {e}"
            health_status["overall"] = "degraded"
        
        try:
            # Test circuit breaker manager
            cb_stats = self.circuit_breaker_manager.get_all_circuit_states()
            if not isinstance(cb_stats, dict):
                health_status["circuit_breaker_manager"] = "unhealthy"
                health_status["overall"] = "degraded"
        except Exception as e:
            health_status["circuit_breaker_manager"] = f"unhealthy: {e}"
            health_status["overall"] = "degraded"
        
        try:
            # Test metrics
            self.metrics.increment_counter("health_check_test", 1.0)
        except Exception as e:
            health_status["metrics"] = f"unhealthy: {e}"
            health_status["overall"] = "degraded"
        
        return health_status


# Global instance for easy access
_global_error_handler: Optional[ResilientErrorHandler] = None


def get_resilient_error_handler() -> ResilientErrorHandler:
    """Get the global resilient error handler instance."""
    global _global_error_handler
    
    if _global_error_handler is None:
        _global_error_handler = ResilientErrorHandler()
    
    return _global_error_handler


def set_resilient_error_handler(handler: ResilientErrorHandler) -> None:
    """Set the global resilient error handler instance."""
    global _global_error_handler
    _global_error_handler = handler


async def handle_service_error(service_name: str,
                             error: Exception,
                             context: ErrorContext,
                             fallback_data: Any = None) -> FallbackResult:
    """Convenience function to handle service errors using the global handler."""
    handler = get_resilient_error_handler()
    return await handler.handle_external_service_error(
        service_name, error, context, fallback_data
    )