"""Data synchronization system for real-time updates."""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from ..providers.data_provider import DataProvider, DataRequest
from ..utils.intelligent_cache import IntelligentCache
from ..monitoring.real_time_metrics import get_metrics

logger = logging.getLogger(__name__)


class SyncStatus(Enum):
    """Synchronization status."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


@dataclass
class SyncResult:
    """Result of a synchronization operation."""
    provider_name: str
    status: SyncStatus
    records_synced: int
    sync_duration: float
    last_sync_time: datetime = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.last_sync_time is None:
            self.last_sync_time = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "provider_name": self.provider_name,
            "status": self.status.value,
            "records_synced": self.records_synced,
            "sync_duration": self.sync_duration,
            "last_sync_time": self.last_sync_time.isoformat(),
            "error": self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SyncResult':
        """Create from dictionary."""
        return cls(
            provider_name=data["provider_name"],
            status=SyncStatus(data["status"]),
            records_synced=data["records_synced"],
            sync_duration=data["sync_duration"],
            last_sync_time=datetime.fromisoformat(data["last_sync_time"]),
            error=data.get("error")
        )


class DataSynchronizer:
    """Manages data synchronization across multiple providers."""
    
    def __init__(self,
                 providers: List[DataProvider],
                 cache_manager: IntelligentCache,
                 sync_interval: int = 300,
                 max_concurrent_syncs: int = 3,
                 sync_timeout: int = 60,
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 data_transformer: Optional[Callable] = None,
                 data_validator: Optional[Callable] = None):
        self.providers = providers
        self.cache_manager = cache_manager
        self.sync_interval = sync_interval
        self.max_concurrent_syncs = max_concurrent_syncs
        self.sync_timeout = sync_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.data_transformer = data_transformer
        self.data_validator = data_validator
        
        self.metrics = get_metrics()
        self._running = False
        self._sync_task = None
        self._progress_callback = None
        
        # Semaphore to limit concurrent syncs
        self._sync_semaphore = asyncio.Semaphore(max_concurrent_syncs)
    
    async def sync_provider(self, provider: DataProvider) -> SyncResult:
        """Synchronize a single provider."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with self._sync_semaphore:
                # Create a generic data request for sync
                request = DataRequest(
                    request_type="sync_all",
                    parameters={}
                )
                
                # Try sync with retries
                for attempt in range(self.max_retries):
                    try:
                        # Execute with timeout
                        response = await asyncio.wait_for(
                            provider.get_data(request),
                            timeout=self.sync_timeout
                        )
                        
                        if response.success:
                            data = response.data
                            
                            # Apply data transformation if configured
                            if self.data_transformer:
                                data = self.data_transformer(data)
                            
                            # Apply data validation if configured
                            if self.data_validator:
                                data = self.data_validator(data)
                            
                            # Cache the synchronized data
                            cache_key = f"sync_data_{provider.name}"
                            await self.cache_manager.set(cache_key, data, ttl=self.sync_interval * 2)
                            
                            # Record success metrics
                            sync_duration = asyncio.get_event_loop().time() - start_time
                            self.metrics.increment_counter(
                                "sync_operations_total",
                                1.0,
                                {"provider": provider.name, "status": "success"}
                            )
                            self.metrics.record_timer("sync_duration_seconds", sync_duration)
                            
                            return SyncResult(
                                provider_name=provider.name,
                                status=SyncStatus.SUCCESS,
                                records_synced=len(data) if isinstance(data, list) else 1,
                                sync_duration=sync_duration
                            )
                        else:
                            if attempt < self.max_retries - 1:
                                await asyncio.sleep(self.retry_delay * (attempt + 1))
                                continue
                            else:
                                raise Exception(response.error or "Sync failed")
                    
                    except asyncio.TimeoutError:
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        else:
                            raise Exception("Sync timeout")
                    
                    except Exception as e:
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        else:
                            raise e
        
        except Exception as e:
            # Record failure metrics
            sync_duration = asyncio.get_event_loop().time() - start_time
            self.metrics.increment_counter(
                "sync_operations_total",
                1.0,
                {"provider": provider.name, "status": "failed"}
            )
            
            # Check if circuit breaker is involved
            error_msg = str(e)
            if "circuit breaker" in error_msg.lower():
                return SyncResult(
                    provider_name=provider.name,
                    status=SyncStatus.FAILED,
                    records_synced=0,
                    sync_duration=sync_duration,
                    error=f"Circuit breaker open: {error_msg}"
                )
            
            return SyncResult(
                provider_name=provider.name,
                status=SyncStatus.FAILED,
                records_synced=0,
                sync_duration=sync_duration,
                error=str(e)
            )
    
    async def sync_all_providers(self, incremental: bool = False, force: bool = False) -> List[SyncResult]:
        """Synchronize all providers."""
        results = []
        
        # Check if we should skip sync based on cache
        if not force and not incremental:
            last_sync_key = "last_full_sync"
            last_sync_data = await self.cache_manager.get(last_sync_key)
            if last_sync_data:
                last_sync_time = datetime.fromisoformat(last_sync_data["timestamp"])
                if (datetime.utcnow() - last_sync_time).total_seconds() < self.sync_interval:
                    logger.info("Skipping sync - too recent")
                    return []
        
        # Create sync tasks for all providers
        tasks = []
        for provider in self.providers:
            if self._progress_callback:
                self._progress_callback(provider.name, "starting", 0.0)
            
            task = asyncio.create_task(self.sync_provider(provider))
            tasks.append(task)
        
        # Execute all sync tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            provider = self.providers[i]
            
            if isinstance(result, Exception):
                processed_results.append(SyncResult(
                    provider_name=provider.name,
                    status=SyncStatus.FAILED,
                    records_synced=0,
                    sync_duration=0.0,
                    error=str(result)
                ))
            else:
                processed_results.append(result)
            
            if self._progress_callback:
                status = "completed" if not isinstance(result, Exception) else "failed"
                self._progress_callback(provider.name, status, 1.0)
        
        # Cache sync metadata
        sync_metadata = {
            "timestamp": datetime.utcnow().isoformat(),
            "results": [r.to_dict() for r in processed_results]
        }
        await self.cache_manager.set("last_full_sync", sync_metadata, ttl=self.sync_interval * 4)
        
        return processed_results
    
    async def sync_providers(self, provider_names: List[str]) -> List[SyncResult]:
        """Synchronize specific providers by name."""
        selected_providers = [p for p in self.providers if p.name in provider_names]
        
        if not selected_providers:
            logger.warning(f"No providers found with names: {provider_names}")
            return []
        
        results = []
        for provider in selected_providers:
            result = await self.sync_provider(provider)
            results.append(result)
        
        return results
    
    def set_progress_callback(self, callback: Callable[[str, str, float], None]):
        """Set progress callback for sync operations."""
        self._progress_callback = callback
    
    def start_background_sync(self):
        """Start background synchronization."""
        if self._running:
            return
        
        self._running = True
        self._sync_task = asyncio.create_task(self._background_sync_loop())
        logger.info("Started background synchronization")
    
    def stop_background_sync(self):
        """Stop background synchronization."""
        self._running = False
        if self._sync_task:
            self._sync_task.cancel()
        logger.info("Stopped background synchronization")
    
    def is_background_sync_running(self) -> bool:
        """Check if background sync is running."""
        return self._running
    
    async def _background_sync_loop(self):
        """Background sync loop."""
        while self._running:
            try:
                await self.sync_all_providers()
                await asyncio.sleep(self.sync_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Background sync error: {e}")
                await asyncio.sleep(self.sync_interval)
    
    async def cleanup(self):
        """Cleanup resources."""
        self.stop_background_sync()
        if self._sync_task:
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass