"""Fallback management for data providers when services are unavailable."""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .data_provider import DataRequest, DataResponse, HealthStatus
from ..utils.circuit_breaker import CircuitBreakerOpenException

logger = logging.getLogger(__name__)


class FallbackStrategy(Enum):
    """Fallback strategies when primary services fail."""
    CACHED_DATA = "cached_data"
    STATIC_DATA = "static_data"
    DEGRADED_SERVICE = "degraded_service"
    ALTERNATIVE_PROVIDER = "alternative_provider"
    FAIL_GRACEFULLY = "fail_gracefully"


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""
    strategy: FallbackStrategy
    max_cache_age_hours: int = 24
    enable_stale_data: bool = True
    fallback_timeout: int = 10
    retry_after_minutes: int = 5
    degraded_response_limit: int = 10
    
    def __post_init__(self):
        """Validate fallback configuration."""
        if self.max_cache_age_hours < 0:
            raise ValueError("max_cache_age_hours must be non-negative")
        if self.fallback_timeout <= 0:
            raise ValueError("fallback_timeout must be positive")


@dataclass
class FallbackResult:
    """Result from fallback mechanism."""
    success: bool
    data: Any = None
    strategy_used: Optional[FallbackStrategy] = None
    data_age_hours: Optional[float] = None
    warning_message: Optional[str] = None
    degraded: bool = False
    
    def to_data_response(self, provider_name: str) -> DataResponse:
        """Convert to DataResponse."""
        metadata = {
            "fallback_used": True,
            "strategy": self.strategy_used.value if self.strategy_used else None,
            "data_age_hours": self.data_age_hours,
            "degraded": self.degraded
        }
        
        return DataResponse(
            success=self.success,
            data=self.data,
            error_message=None if self.success else self.warning_message,
            metadata=metadata,
            cached=True,
            provider_name=f"{provider_name}-fallback"
        )


class FallbackDataManager:
    """Manages fallback data and strategies."""
    
    def __init__(self, cache_manager=None):
        """Initialize fallback data manager."""
        self.cache_manager = cache_manager
        self.static_data_cache: Dict[str, Any] = {}
        self.fallback_configs: Dict[str, FallbackConfig] = {}
        self.degraded_responses: Dict[str, List[Any]] = {}
        
    def register_fallback_config(self, provider_name: str, config: FallbackConfig) -> None:
        """Register fallback configuration for a provider."""
        self.fallback_configs[provider_name] = config
        logger.info(f"Registered fallback config for {provider_name}: {config.strategy.value}")
    
    def set_static_fallback_data(self, key: str, data: Any) -> None:
        """Set static fallback data."""
        self.static_data_cache[key] = {
            "data": data,
            "timestamp": datetime.utcnow()
        }
        logger.debug(f"Set static fallback data for key: {key}")
    
    async def handle_fallback(
        self, 
        provider_name: str, 
        request: DataRequest, 
        original_error: Exception
    ) -> FallbackResult:
        """Handle fallback when primary provider fails."""
        config = self.fallback_configs.get(provider_name, FallbackConfig(FallbackStrategy.FAIL_GRACEFULLY))
        
        logger.warning(f"Handling fallback for {provider_name} using strategy: {config.strategy.value}")
        
        try:
            if config.strategy == FallbackStrategy.CACHED_DATA:
                return await self._try_cached_data_fallback(request, config)
            elif config.strategy == FallbackStrategy.STATIC_DATA:
                return await self._try_static_data_fallback(request, config)
            elif config.strategy == FallbackStrategy.DEGRADED_SERVICE:
                return await self._try_degraded_service_fallback(provider_name, request, config)
            elif config.strategy == FallbackStrategy.ALTERNATIVE_PROVIDER:
                return await self._try_alternative_provider_fallback(request, config)
            else:  # FAIL_GRACEFULLY
                return await self._fail_gracefully(original_error, config)
                
        except Exception as e:
            logger.error(f"Fallback mechanism failed for {provider_name}: {e}")
            return FallbackResult(
                success=False,
                warning_message=f"Fallback failed: {e}",
                strategy_used=config.strategy
            )
    
    async def _try_cached_data_fallback(self, request: DataRequest, config: FallbackConfig) -> FallbackResult:
        """Try to use cached data as fallback."""
        if not self.cache_manager or not request.cache_key:
            return FallbackResult(
                success=False,
                warning_message="No cache available for fallback",
                strategy_used=FallbackStrategy.CACHED_DATA
            )
        
        try:
            cached_data = await self.cache_manager.get(request.cache_key)
            if cached_data:
                # Check data age
                data_age = (datetime.utcnow() - cached_data.timestamp).total_seconds() / 3600
                
                if data_age <= config.max_cache_age_hours or config.enable_stale_data:
                    warning = None
                    if data_age > config.max_cache_age_hours:
                        warning = f"Using stale cached data (age: {data_age:.1f} hours)"
                    
                    return FallbackResult(
                        success=True,
                        data=cached_data.data,
                        strategy_used=FallbackStrategy.CACHED_DATA,
                        data_age_hours=data_age,
                        warning_message=warning,
                        degraded=data_age > config.max_cache_age_hours
                    )
            
            return FallbackResult(
                success=False,
                warning_message="No suitable cached data found",
                strategy_used=FallbackStrategy.CACHED_DATA
            )
            
        except Exception as e:
            return FallbackResult(
                success=False,
                warning_message=f"Cache access failed: {e}",
                strategy_used=FallbackStrategy.CACHED_DATA
            )
    
    async def _try_static_data_fallback(self, request: DataRequest, config: FallbackConfig) -> FallbackResult:
        """Try to use static fallback data."""
        cache_key = request.cache_key or f"{request.request_type}_static"
        
        if cache_key in self.static_data_cache:
            static_entry = self.static_data_cache[cache_key]
            data_age = (datetime.utcnow() - static_entry["timestamp"]).total_seconds() / 3600
            
            return FallbackResult(
                success=True,
                data=static_entry["data"],
                strategy_used=FallbackStrategy.STATIC_DATA,
                data_age_hours=data_age,
                warning_message=f"Using static fallback data (age: {data_age:.1f} hours)",
                degraded=True
            )
        
        # Generate basic static data based on request type
        static_data = self._generate_basic_static_data(request)
        if static_data:
            return FallbackResult(
                success=True,
                data=static_data,
                strategy_used=FallbackStrategy.STATIC_DATA,
                warning_message="Using generated static fallback data",
                degraded=True
            )
        
        return FallbackResult(
            success=False,
            warning_message="No static fallback data available",
            strategy_used=FallbackStrategy.STATIC_DATA
        )
    
    async def _try_degraded_service_fallback(
        self, 
        provider_name: str, 
        request: DataRequest, 
        config: FallbackConfig
    ) -> FallbackResult:
        """Try to provide degraded service with limited data."""
        if provider_name not in self.degraded_responses:
            self.degraded_responses[provider_name] = []
        
        degraded_data = self.degraded_responses[provider_name]
        
        # Limit the amount of data returned in degraded mode
        limited_data = degraded_data[:config.degraded_response_limit]
        
        return FallbackResult(
            success=True,
            data=limited_data,
            strategy_used=FallbackStrategy.DEGRADED_SERVICE,
            warning_message=f"Service degraded - returning limited data ({len(limited_data)} items)",
            degraded=True
        )
    
    async def _try_alternative_provider_fallback(self, request: DataRequest, config: FallbackConfig) -> FallbackResult:
        """Try to use alternative provider (placeholder for future implementation)."""
        # This would integrate with the DataProviderManager to try alternative providers
        return FallbackResult(
            success=False,
            warning_message="Alternative provider fallback not implemented",
            strategy_used=FallbackStrategy.ALTERNATIVE_PROVIDER
        )
    
    async def _fail_gracefully(self, original_error: Exception, config: FallbackConfig) -> FallbackResult:
        """Fail gracefully with informative error."""
        if isinstance(original_error, CircuitBreakerOpenException):
            message = f"Service temporarily unavailable (circuit breaker open). Retry after {original_error.retry_after} seconds"
        else:
            message = f"Service unavailable: {original_error}"
        
        return FallbackResult(
            success=False,
            warning_message=message,
            strategy_used=FallbackStrategy.FAIL_GRACEFULLY
        )
    
    def _generate_basic_static_data(self, request: DataRequest) -> Optional[Any]:
        """Generate basic static data based on request type."""
        if request.request_type == "get_vulnerabilities_by_package":
            return []  # Empty vulnerability list
        elif request.request_type == "search_vulnerabilities":
            return []  # Empty search results
        elif request.request_type == "get_framework_requirements":
            return []  # Empty requirements list
        elif request.request_type == "check_compliance":
            # Basic compliance result
            return {
                "framework": request.parameters.get("framework", "unknown"),
                "overall_score": 0.0,
                "passed_requirements": 0,
                "failed_requirements": 0,
                "total_requirements": 0,
                "compliance_percentage": 0.0,
                "requirement_results": [],
                "recommendations": ["Service unavailable - compliance check incomplete"],
                "timestamp": datetime.utcnow().isoformat()
            }
        
        return None
    
    def update_degraded_responses(self, provider_name: str, data: List[Any]) -> None:
        """Update degraded response data for a provider."""
        self.degraded_responses[provider_name] = data
        logger.debug(f"Updated degraded responses for {provider_name}: {len(data)} items")
    
    def get_fallback_stats(self) -> Dict[str, Any]:
        """Get fallback mechanism statistics."""
        return {
            "registered_providers": len(self.fallback_configs),
            "static_data_entries": len(self.static_data_cache),
            "degraded_response_providers": len(self.degraded_responses),
            "fallback_configs": {
                name: config.strategy.value 
                for name, config in self.fallback_configs.items()
            }
        }


class FallbackAwareProvider:
    """Mixin class for providers that support fallback mechanisms."""
    
    def __init__(self, *args, fallback_manager: Optional[FallbackDataManager] = None, **kwargs):
        """Initialize with fallback manager."""
        super().__init__(*args, **kwargs)
        self.fallback_manager = fallback_manager
        
        if self.fallback_manager and hasattr(self, 'name'):
            # Register default fallback config
            default_config = FallbackConfig(
                strategy=FallbackStrategy.CACHED_DATA,
                max_cache_age_hours=24,
                enable_stale_data=True
            )
            self.fallback_manager.register_fallback_config(self.name, default_config)
    
    async def get_data_with_fallback(self, request: DataRequest) -> DataResponse:
        """Get data with fallback support."""
        try:
            # Try primary data source
            return await self.get_data(request)
            
        except Exception as e:
            if self.fallback_manager:
                # Try fallback mechanism
                fallback_result = await self.fallback_manager.handle_fallback(
                    self.name, request, e
                )
                
                if fallback_result.success:
                    logger.info(f"Fallback successful for {self.name} using {fallback_result.strategy_used.value}")
                    response = fallback_result.to_data_response(self.name)
                    
                    # Add warning to metadata if data is degraded
                    if fallback_result.warning_message:
                        response.metadata["warning"] = fallback_result.warning_message
                    
                    return response
                else:
                    logger.error(f"Fallback failed for {self.name}: {fallback_result.warning_message}")
            
            # Re-raise original exception if no fallback or fallback failed
            raise


# Global fallback manager instance
_global_fallback_manager = FallbackDataManager()


def get_fallback_manager() -> FallbackDataManager:
    """Get the global fallback manager."""
    return _global_fallback_manager


def configure_provider_fallback(
    provider_name: str, 
    strategy: FallbackStrategy,
    **config_kwargs
) -> None:
    """Configure fallback for a provider."""
    config = FallbackConfig(strategy=strategy, **config_kwargs)
    _global_fallback_manager.register_fallback_config(provider_name, config)