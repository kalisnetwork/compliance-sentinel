"""Intelligent multi-level caching system with configurable TTL and eviction policies."""

import asyncio
import time
import json
import pickle
import logging
import os
from typing import Any, Dict, Optional, List, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import OrderedDict
import hashlib

logger = logging.getLogger(__name__)


class EvictionPolicy(Enum):
    """Cache eviction policies."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL = "ttl"  # Time To Live based


# Aliases for backward compatibility with tests
CacheEvictionPolicy = EvictionPolicy


class CacheBackend(Enum):
    """Cache backend types."""
    MEMORY = "memory"
    REDIS = "redis"
    FILE = "file"


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def record_hit(self):
        """Record cache hit."""
        self.hits += 1
    
    def record_miss(self):
        """Record cache miss."""
        self.misses += 1
    
    def record_eviction(self):
        """Record cache eviction."""
        self.evictions += 1
    
    def reset(self):
        """Reset all statistics."""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.size = 0


class CompressionType(Enum):
    """Compression types for cached data."""
    NONE = "none"
    GZIP = "gzip"
    PICKLE = "pickle"
    JSON = "json"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    last_accessed: datetime
    access_count: int = 0
    size_bytes: int = 0
    compressed: bool = False
    compression_type: CompressionType = CompressionType.NONE
    
    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def record_access(self):
        """Record access to this entry."""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_accessed": self.last_accessed.isoformat(),
            "access_count": self.access_count,
            "size_bytes": self.size_bytes,
            "compressed": self.compressed,
            "compression_type": self.compression_type.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        """Create from dictionary."""
        return cls(
            key=data["key"],
            value=data["value"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            last_accessed=datetime.fromisoformat(data["last_accessed"]),
            access_count=data.get("access_count", 0),
            size_bytes=data.get("size_bytes", 0),
            compressed=data.get("compressed", False),
            compression_type=CompressionType(data.get("compression_type", "none"))
        )
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def age_seconds(self) -> float:
        """Get age of entry in seconds."""
        return (datetime.utcnow() - self.created_at).total_seconds()
    
    @property
    def time_since_access_seconds(self) -> float:
        """Get time since last access in seconds."""
        return (datetime.utcnow() - self.last_accessed).total_seconds()
    
    def touch(self) -> None:
        """Update access time and count."""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization."""
        return {
            "key": self.key,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_accessed": self.last_accessed.isoformat(),
            "access_count": self.access_count,
            "size_bytes": self.size_bytes,
            "compressed": self.compressed,
            "compression_type": self.compression_type.value,
            "age_seconds": self.age_seconds,
            "time_since_access_seconds": self.time_since_access_seconds
        }


@dataclass
class CacheConfig:
    """Configuration for intelligent cache."""
    max_memory_mb: int = 100
    default_ttl: int = 3600  # 1 hour
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    compression_enabled: bool = True
    compression_threshold_bytes: int = 1024  # Compress items larger than 1KB
    compression_type: CompressionType = CompressionType.GZIP
    cleanup_interval: int = 300  # 5 minutes
    max_entries: int = 10000
    enable_persistence: bool = False
    persistence_file: Optional[str] = None
    
    def __post_init__(self):
        """Validate cache configuration."""
        if self.max_memory_mb <= 0:
            raise ValueError("max_memory_mb must be positive")
        if self.default_ttl < 0:
            raise ValueError("default_ttl must be non-negative")
        if self.cleanup_interval <= 0:
            raise ValueError("cleanup_interval must be positive")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")


@dataclass
class CacheMetrics:
    """Cache performance metrics."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    evictions: int = 0
    expired_entries: int = 0
    total_size_bytes: int = 0
    entry_count: int = 0
    compression_ratio: float = 0.0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        if self.total_requests == 0:
            return 0.0
        return self.cache_hits / self.total_requests
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate
    
    @property
    def average_entry_size_bytes(self) -> float:
        """Calculate average entry size."""
        if self.entry_count == 0:
            return 0.0
        return self.total_size_bytes / self.entry_count
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": self.hit_rate,
            "miss_rate": self.miss_rate,
            "evictions": self.evictions,
            "expired_entries": self.expired_entries,
            "total_size_bytes": self.total_size_bytes,
            "entry_count": self.entry_count,
            "average_entry_size_bytes": self.average_entry_size_bytes,
            "compression_ratio": self.compression_ratio
        }


class IntelligentCache:
    """Multi-level cache with TTL, eviction policies, and compression."""
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize intelligent cache."""
        self.config = config or CacheConfig()
        self.l1_cache: Dict[str, CacheEntry] = {}
        self.l2_cache: Optional[Any] = None  # External cache (Redis, etc.)
        self.metrics = CacheMetrics()
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._compression_stats = {"original_size": 0, "compressed_size": 0}
        
        # Initialize eviction policy handler
        if self.config.eviction_policy == EvictionPolicy.LRU:
            self.l1_cache = OrderedDict()
        
        logger.info(f"Intelligent cache initialized with config: {self.config}")
    
    async def start(self) -> None:
        """Start cache background tasks."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            logger.info("Cache cleanup task started")
        
        # Load persisted data if enabled
        if self.config.enable_persistence and self.config.persistence_file:
            await self._load_from_persistence()
    
    async def stop(self) -> None:
        """Stop cache and cleanup resources."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        # Save to persistence if enabled
        if self.config.enable_persistence and self.config.persistence_file:
            await self._save_to_persistence()
        
        logger.info("Cache stopped")
    
    async def get(self, key: str, fetch_func: Optional[Callable] = None) -> Any:
        """Get value with cache-aside pattern."""
        async with self._lock:
            self.metrics.total_requests += 1
            
            # Check L1 cache first
            if key in self.l1_cache:
                entry = self.l1_cache[key]
                
                if entry.is_expired:
                    # Remove expired entry
                    await self._remove_entry(key)
                    self.metrics.expired_entries += 1
                else:
                    # Cache hit
                    entry.touch()
                    self._update_access_order(key)
                    self.metrics.cache_hits += 1
                    
                    value = await self._decompress_value(entry)
                    logger.debug(f"Cache hit for key: {key}")
                    return value
            
            # Cache miss
            self.metrics.cache_misses += 1
            logger.debug(f"Cache miss for key: {key}")
            
            # Try to fetch data if fetch function provided
            if fetch_func:
                try:
                    if asyncio.iscoroutinefunction(fetch_func):
                        value = await fetch_func()
                    else:
                        value = fetch_func()
                    
                    # Store in cache
                    await self.set(key, value)
                    return value
                    
                except Exception as e:
                    logger.error(f"Error in fetch function for key {key}: {e}")
                    raise
            
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL."""
        async with self._lock:
            # Calculate expiration time
            expires_at = None
            if ttl is not None:
                expires_at = datetime.utcnow() + timedelta(seconds=ttl)
            elif self.config.default_ttl > 0:
                expires_at = datetime.utcnow() + timedelta(seconds=self.config.default_ttl)
            
            # Compress value if needed
            compressed_value, compressed, compression_type, original_size, compressed_size = await self._compress_value(value)
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=compressed_value,
                created_at=datetime.utcnow(),
                expires_at=expires_at,
                last_accessed=datetime.utcnow(),
                access_count=1,
                size_bytes=compressed_size,
                compressed=compressed,
                compression_type=compression_type
            )
            
            # Check if we need to evict entries
            await self._ensure_capacity(entry.size_bytes)
            
            # Store entry
            self.l1_cache[key] = entry
            self._update_access_order(key)
            
            # Update metrics
            self.metrics.entry_count += 1
            self.metrics.total_size_bytes += entry.size_bytes
            
            # Update compression stats
            if compressed:
                self._compression_stats["original_size"] += original_size
                self._compression_stats["compressed_size"] += compressed_size
                self._update_compression_ratio()
            
            logger.debug(f"Cached key: {key}, size: {entry.size_bytes} bytes, compressed: {compressed}")
    
    async def delete(self, key: str) -> bool:
        """Delete entry from cache."""
        async with self._lock:
            if key in self.l1_cache:
                await self._remove_entry(key)
                return True
            return False
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self.l1_cache.clear()
            self.metrics = CacheMetrics()
            self._compression_stats = {"original_size": 0, "compressed_size": 0}
            logger.info("Cache cleared")
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate cache entries matching pattern."""
        async with self._lock:
            keys_to_remove = []
            
            for key in self.l1_cache.keys():
                if self._matches_pattern(key, pattern):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                await self._remove_entry(key)
            
            logger.info(f"Invalidated {len(keys_to_remove)} entries matching pattern: {pattern}")
            return len(keys_to_remove)
    
    def get_metrics(self) -> CacheMetrics:
        """Get cache performance metrics."""
        return self.metrics
    
    async def get_entry_info(self, key: str) -> Optional[Dict[str, Any]]:
        """Get information about a cache entry."""
        async with self._lock:
            if key in self.l1_cache:
                return self.l1_cache[key].to_dict()
            return None
    
    async def get_all_keys(self) -> List[str]:
        """Get all cache keys."""
        async with self._lock:
            return list(self.l1_cache.keys())
    
    async def get_cache_info(self) -> Dict[str, Any]:
        """Get comprehensive cache information."""
        async with self._lock:
            return {
                "config": {
                    "max_memory_mb": self.config.max_memory_mb,
                    "default_ttl": self.config.default_ttl,
                    "eviction_policy": self.config.eviction_policy.value,
                    "compression_enabled": self.config.compression_enabled,
                    "max_entries": self.config.max_entries
                },
                "metrics": self.metrics.to_dict(),
                "memory_usage_mb": self.metrics.total_size_bytes / (1024 * 1024),
                "memory_usage_percentage": (self.metrics.total_size_bytes / (self.config.max_memory_mb * 1024 * 1024)) * 100,
                "entry_count": len(self.l1_cache),
                "cleanup_task_running": self._cleanup_task is not None and not self._cleanup_task.done()
            }
    
    async def _compress_value(self, value: Any) -> tuple:
        """Compress value if beneficial."""
        if not self.config.compression_enabled:
            serialized = pickle.dumps(value)
            return value, False, CompressionType.NONE, len(serialized), len(serialized)
        
        # Serialize value
        if self.config.compression_type == CompressionType.JSON:
            try:
                serialized = json.dumps(value, default=str).encode('utf-8')
                compression_type = CompressionType.JSON
            except (TypeError, ValueError):
                serialized = pickle.dumps(value)
                compression_type = CompressionType.PICKLE
        else:
            serialized = pickle.dumps(value)
            compression_type = CompressionType.PICKLE
        
        original_size = len(serialized)
        
        # Check if compression is beneficial
        if original_size < self.config.compression_threshold_bytes:
            return value, False, CompressionType.NONE, original_size, original_size
        
        # Compress data
        if self.config.compression_type == CompressionType.GZIP:
            import gzip
            compressed = gzip.compress(serialized)
            compressed_size = len(compressed)
            
            # Only use compression if it reduces size significantly
            if compressed_size < original_size * 0.9:
                return compressed, True, CompressionType.GZIP, original_size, compressed_size
        
        return value, False, compression_type, original_size, original_size
    
    async def _decompress_value(self, entry: CacheEntry) -> Any:
        """Decompress cached value."""
        if not entry.compressed:
            return entry.value
        
        if entry.compression_type == CompressionType.GZIP:
            import gzip
            decompressed = gzip.decompress(entry.value)
            
            # Deserialize based on original type
            try:
                return pickle.loads(decompressed)
            except:
                return json.loads(decompressed.decode('utf-8'))
        
        return entry.value
    
    async def _ensure_capacity(self, new_entry_size: int) -> None:
        """Ensure cache has capacity for new entry."""
        max_size_bytes = self.config.max_memory_mb * 1024 * 1024
        
        # Check memory limit
        while (self.metrics.total_size_bytes + new_entry_size > max_size_bytes or 
               len(self.l1_cache) >= self.config.max_entries):
            
            if not self.l1_cache:
                break
            
            # Evict entry based on policy
            key_to_evict = self._select_eviction_candidate()
            if key_to_evict:
                await self._remove_entry(key_to_evict)
                self.metrics.evictions += 1
            else:
                break
    
    def _select_eviction_candidate(self) -> Optional[str]:
        """Select entry for eviction based on policy."""
        if not self.l1_cache:
            return None
        
        if self.config.eviction_policy == EvictionPolicy.LRU:
            # OrderedDict maintains insertion/access order
            return next(iter(self.l1_cache))
        
        elif self.config.eviction_policy == EvictionPolicy.LFU:
            # Find least frequently used
            min_access_count = float('inf')
            candidate = None
            for key, entry in self.l1_cache.items():
                if entry.access_count < min_access_count:
                    min_access_count = entry.access_count
                    candidate = key
            return candidate
        
        elif self.config.eviction_policy == EvictionPolicy.FIFO:
            # Find oldest entry
            oldest_time = datetime.max
            candidate = None
            for key, entry in self.l1_cache.items():
                if entry.created_at < oldest_time:
                    oldest_time = entry.created_at
                    candidate = key
            return candidate
        
        elif self.config.eviction_policy == EvictionPolicy.TTL:
            # Find entry closest to expiration
            closest_expiry = datetime.max
            candidate = None
            for key, entry in self.l1_cache.items():
                if entry.expires_at and entry.expires_at < closest_expiry:
                    closest_expiry = entry.expires_at
                    candidate = key
            return candidate
        
        # Default to first entry
        return next(iter(self.l1_cache))
    
    def _update_access_order(self, key: str) -> None:
        """Update access order for LRU policy."""
        if self.config.eviction_policy == EvictionPolicy.LRU and isinstance(self.l1_cache, OrderedDict):
            # Move to end (most recently used)
            self.l1_cache.move_to_end(key)
    
    async def _remove_entry(self, key: str) -> None:
        """Remove entry and update metrics."""
        if key in self.l1_cache:
            entry = self.l1_cache[key]
            del self.l1_cache[key]
            
            self.metrics.entry_count -= 1
            self.metrics.total_size_bytes -= entry.size_bytes
    
    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Check if key matches pattern (supports wildcards)."""
        import fnmatch
        return fnmatch.fnmatch(key, pattern)
    
    def _update_compression_ratio(self) -> None:
        """Update compression ratio metric."""
        if self._compression_stats["original_size"] > 0:
            self.metrics.compression_ratio = (
                1.0 - (self._compression_stats["compressed_size"] / 
                       self._compression_stats["original_size"])
            )
    
    async def _periodic_cleanup(self) -> None:
        """Periodic cleanup of expired entries."""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                await self._cleanup_expired_entries()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
    
    async def _cleanup_expired_entries(self) -> None:
        """Remove expired entries."""
        async with self._lock:
            expired_keys = []
            
            for key, entry in self.l1_cache.items():
                if entry.is_expired:
                    expired_keys.append(key)
            
            for key in expired_keys:
                await self._remove_entry(key)
                self.metrics.expired_entries += 1
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    async def _save_to_persistence(self) -> None:
        """Save cache to persistent storage."""
        if not self.config.persistence_file:
            return
        
        try:
            cache_data = {}
            for key, entry in self.l1_cache.items():
                if not entry.is_expired:
                    cache_data[key] = {
                        "value": entry.value,
                        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
                        "compressed": entry.compressed,
                        "compression_type": entry.compression_type.value
                    }
            
            with open(self.config.persistence_file, 'wb') as f:
                pickle.dump(cache_data, f)
            
            logger.info(f"Saved {len(cache_data)} cache entries to persistence")
            
        except Exception as e:
            logger.error(f"Error saving cache to persistence: {e}")
    
    async def _load_from_persistence(self) -> None:
        """Load cache from persistent storage."""
        if not self.config.persistence_file or not os.path.exists(self.config.persistence_file):
            return
        
        try:
            with open(self.config.persistence_file, 'rb') as f:
                cache_data = pickle.load(f)
            
            loaded_count = 0
            for key, data in cache_data.items():
                expires_at = None
                if data.get("expires_at"):
                    expires_at = datetime.fromisoformat(data["expires_at"])
                    if expires_at <= datetime.utcnow():
                        continue  # Skip expired entries
                
                entry = CacheEntry(
                    key=key,
                    value=data["value"],
                    created_at=datetime.utcnow(),
                    expires_at=expires_at,
                    last_accessed=datetime.utcnow(),
                    compressed=data.get("compressed", False),
                    compression_type=CompressionType(data.get("compression_type", "none"))
                )
                
                # Calculate size
                if entry.compressed:
                    entry.size_bytes = len(entry.value) if isinstance(entry.value, bytes) else len(pickle.dumps(entry.value))
                else:
                    entry.size_bytes = len(pickle.dumps(entry.value))
                
                self.l1_cache[key] = entry
                self.metrics.entry_count += 1
                self.metrics.total_size_bytes += entry.size_bytes
                loaded_count += 1
            
            logger.info(f"Loaded {loaded_count} cache entries from persistence")
            
        except Exception as e:
            logger.error(f"Error loading cache from persistence: {e}")


# Global cache instance
_global_cache = IntelligentCache()


def get_global_cache() -> IntelligentCache:
    """Get the global cache instance."""
    return _global_cache


async def cached(
    key: str, 
    fetch_func: Callable, 
    ttl: Optional[int] = None,
    cache_instance: Optional[IntelligentCache] = None
) -> Any:
    """Decorator function for caching with fetch function."""
    cache = cache_instance or get_global_cache()
    return await cache.get(key, fetch_func)