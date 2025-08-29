"""Data provider system for real-time data integration."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status for data providers."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class DataRequest:
    """Request for data from a provider."""
    request_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: Optional[int] = None
    cache_key: Optional[str] = None
    priority: str = "normal"  # low, normal, high
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate data request."""
        if not self.request_type:
            raise ValueError("request_type is required")
        
        if self.priority not in ["low", "normal", "high"]:
            raise ValueError("priority must be one of: low, normal, high")


@dataclass
class DataResponse:
    """Response from a data provider."""
    success: bool
    data: Any = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)
    provider_name: str = ""
    request_duration_ms: float = 0.0
    
    @property
    def is_success(self) -> bool:
        """Check if response is successful."""
        return self.success and self.error_message is None
    
    @property
    def age_seconds(self) -> float:
        """Get age of response in seconds."""
        return (datetime.utcnow() - self.timestamp).total_seconds()


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    status: HealthStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    response_time_ms: float = 0.0
    
    @property
    def is_healthy(self) -> bool:
        """Check if provider is healthy."""
        return self.status == HealthStatus.HEALTHY


class DataProvider(ABC):
    """Abstract base class for data providers."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize data provider."""
        self.name = name
        self.config = config
        self.initialized = False
        self.last_health_check: Optional[HealthCheckResult] = None
        self._initialization_lock = asyncio.Lock()
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize provider with configuration."""
        pass
    
    @abstractmethod
    async def get_data(self, request: DataRequest) -> DataResponse:
        """Fetch data based on request."""
        pass
    
    @abstractmethod
    async def health_check(self) -> HealthCheckResult:
        """Check provider health."""
        pass
    
    @abstractmethod
    def get_supported_request_types(self) -> List[str]:
        """Get list of supported request types."""
        pass
    
    async def ensure_initialized(self) -> None:
        """Ensure provider is initialized."""
        if not self.initialized:
            async with self._initialization_lock:
                if not self.initialized:
                    await self.initialize(self.config)
                    self.initialized = True
                    logger.info(f"Data provider '{self.name}' initialized")
    
    def supports_request_type(self, request_type: str) -> bool:
        """Check if provider supports a request type."""
        return request_type in self.get_supported_request_types()
    
    async def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the provider."""
        return {
            "name": self.name,
            "initialized": self.initialized,
            "supported_request_types": self.get_supported_request_types(),
            "last_health_check": {
                "status": self.last_health_check.status.value if self.last_health_check else "unknown",
                "timestamp": self.last_health_check.timestamp.isoformat() if self.last_health_check else None,
                "response_time_ms": self.last_health_check.response_time_ms if self.last_health_check else 0
            },
            "config": {k: v for k, v in self.config.items() if not k.lower().endswith(('key', 'secret', 'token', 'password'))}
        }
    
    async def shutdown(self) -> None:
        """Shutdown provider and cleanup resources."""
        logger.info(f"Data provider '{self.name}' shutting down")


class CachingDataProvider(DataProvider):
    """Base class for data providers with caching support."""
    
    def __init__(self, name: str, config: Dict[str, Any], cache_manager=None):
        """Initialize caching data provider."""
        super().__init__(name, config)
        self.cache_manager = cache_manager
        self.cache_enabled = config.get("cache_enabled", True)
        self.default_cache_ttl = config.get("default_cache_ttl", 3600)
    
    async def get_data(self, request: DataRequest) -> DataResponse:
        """Get data with caching support."""
        # Check cache first if enabled and cache key provided
        if self.cache_enabled and self.cache_manager and request.cache_key:
            cached_response = await self._get_cached_data(request.cache_key)
            if cached_response:
                cached_response.cached = True
                logger.debug(f"Cache hit for {request.cache_key}")
                return cached_response
        
        # Fetch fresh data
        response = await self._fetch_data(request)
        
        # Cache the response if successful
        if (response.is_success and self.cache_enabled and 
            self.cache_manager and request.cache_key):
            await self._cache_data(request.cache_key, response)
        
        return response
    
    @abstractmethod
    async def _fetch_data(self, request: DataRequest) -> DataResponse:
        """Fetch data from the actual source (to be implemented by subclasses)."""
        pass
    
    async def _get_cached_data(self, cache_key: str) -> Optional[DataResponse]:
        """Get data from cache."""
        try:
            if self.cache_manager:
                cached_data = await self.cache_manager.get(cache_key)
                if cached_data:
                    return cached_data
        except Exception as e:
            logger.warning(f"Error getting cached data for {cache_key}: {e}")
        return None
    
    async def _cache_data(self, cache_key: str, response: DataResponse) -> None:
        """Cache data response."""
        try:
            if self.cache_manager:
                ttl = self.config.get("cache_ttl", self.default_cache_ttl)
                await self.cache_manager.set(cache_key, response, ttl)
                logger.debug(f"Cached data for {cache_key} with TTL {ttl}")
        except Exception as e:
            logger.warning(f"Error caching data for {cache_key}: {e}")


class DataProviderManager:
    """Manages multiple data providers."""
    
    def __init__(self):
        """Initialize data provider manager."""
        self.providers: Dict[str, DataProvider] = {}
        self.provider_health: Dict[str, HealthCheckResult] = {}
        self.health_check_interval = 300  # 5 minutes
        self._health_check_task: Optional[asyncio.Task] = None
    
    def register_provider(self, provider: DataProvider) -> None:
        """Register a data provider."""
        self.providers[provider.name] = provider
        logger.info(f"Registered data provider: {provider.name}")
    
    def unregister_provider(self, provider_name: str) -> bool:
        """Unregister a data provider."""
        if provider_name in self.providers:
            del self.providers[provider_name]
            self.provider_health.pop(provider_name, None)
            logger.info(f"Unregistered data provider: {provider_name}")
            return True
        return False
    
    def get_provider(self, provider_name: str) -> Optional[DataProvider]:
        """Get a provider by name."""
        return self.providers.get(provider_name)
    
    def get_providers_for_request_type(self, request_type: str) -> List[DataProvider]:
        """Get all providers that support a request type."""
        return [
            provider for provider in self.providers.values()
            if provider.supports_request_type(request_type)
        ]
    
    async def get_data(
        self, 
        request: DataRequest, 
        provider_name: Optional[str] = None,
        fallback_providers: Optional[List[str]] = None
    ) -> DataResponse:
        """
        Get data from providers with fallback support.
        
        Args:
            request: Data request
            provider_name: Specific provider to use (optional)
            fallback_providers: List of fallback provider names (optional)
        
        Returns:
            DataResponse from the first successful provider
        """
        providers_to_try = []
        
        if provider_name:
            # Use specific provider
            provider = self.get_provider(provider_name)
            if provider:
                providers_to_try.append(provider)
        else:
            # Use all providers that support the request type
            providers_to_try = self.get_providers_for_request_type(request.request_type)
        
        # Add fallback providers
        if fallback_providers:
            for fallback_name in fallback_providers:
                fallback_provider = self.get_provider(fallback_name)
                if fallback_provider and fallback_provider not in providers_to_try:
                    providers_to_try.append(fallback_provider)
        
        if not providers_to_try:
            return DataResponse(
                success=False,
                error_message=f"No providers available for request type: {request.request_type}"
            )
        
        # Try providers in order
        last_error = None
        for provider in providers_to_try:
            try:
                await provider.ensure_initialized()
                
                # Check provider health
                if provider.name in self.provider_health:
                    health = self.provider_health[provider.name]
                    if health.status == HealthStatus.UNHEALTHY:
                        logger.warning(f"Skipping unhealthy provider: {provider.name}")
                        continue
                
                response = await provider.get_data(request)
                if response.is_success:
                    response.provider_name = provider.name
                    return response
                else:
                    last_error = response.error_message
                    logger.warning(f"Provider {provider.name} failed: {response.error_message}")
                    
            except Exception as e:
                last_error = str(e)
                logger.error(f"Error getting data from provider {provider.name}: {e}")
        
        # All providers failed
        return DataResponse(
            success=False,
            error_message=f"All providers failed. Last error: {last_error}"
        )
    
    async def health_check_all(self) -> Dict[str, HealthCheckResult]:
        """Run health checks on all providers."""
        results = {}
        
        for provider_name, provider in self.providers.items():
            try:
                if provider.initialized:
                    result = await provider.health_check()
                    results[provider_name] = result
                    self.provider_health[provider_name] = result
                else:
                    results[provider_name] = HealthCheckResult(
                        status=HealthStatus.UNKNOWN,
                        message="Provider not initialized"
                    )
            except Exception as e:
                result = HealthCheckResult(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check failed: {e}"
                )
                results[provider_name] = result
                self.provider_health[provider_name] = result
                logger.error(f"Health check failed for provider {provider_name}: {e}")
        
        return results
    
    async def start_health_monitoring(self) -> None:
        """Start periodic health monitoring."""
        if self._health_check_task is None:
            self._health_check_task = asyncio.create_task(self._periodic_health_check())
            logger.info("Started health monitoring for data providers")
    
    async def stop_health_monitoring(self) -> None:
        """Stop periodic health monitoring."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
            logger.info("Stopped health monitoring for data providers")
    
    async def _periodic_health_check(self) -> None:
        """Periodic health check task."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self.health_check_all()
                logger.debug("Completed periodic health check for all providers")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic health check: {e}")
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        provider_statuses = {}
        healthy_count = 0
        total_count = len(self.providers)
        
        for provider_name, provider in self.providers.items():
            health = self.provider_health.get(provider_name)
            status_info = {
                "initialized": provider.initialized,
                "supported_request_types": provider.get_supported_request_types(),
                "health_status": health.status.value if health else "unknown",
                "last_health_check": health.timestamp.isoformat() if health else None
            }
            
            if health and health.is_healthy:
                healthy_count += 1
            
            provider_statuses[provider_name] = status_info
        
        return {
            "total_providers": total_count,
            "healthy_providers": healthy_count,
            "health_percentage": (healthy_count / total_count * 100) if total_count > 0 else 0,
            "providers": provider_statuses,
            "health_monitoring_active": self._health_check_task is not None
        }
    
    async def shutdown_all(self) -> None:
        """Shutdown all providers."""
        await self.stop_health_monitoring()
        
        for provider in self.providers.values():
            try:
                await provider.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down provider {provider.name}: {e}")
        
        self.providers.clear()
        self.provider_health.clear()
        logger.info("All data providers shut down")