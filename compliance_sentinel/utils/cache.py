"""Caching utilities for the Compliance Sentinel system."""

import json
import hashlib
import time
from typing import Any, Optional, Dict, List, Union
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from threading import Lock
import pickle
import logging

from cachetools import TTLCache, LRUCache
from compliance_sentinel.core.interfaces import CacheManager


logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached entry with metadata."""
    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def touch(self) -> None:
        """Update access statistics."""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()


class MemoryCacheManager(CacheManager):
    """In-memory cache manager with TTL and LRU eviction."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        """Initialize memory cache manager.
        
        Args:
            max_size: Maximum number of entries to cache
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache = TTLCache(maxsize=max_size, ttl=default_ttl)
        self._metadata: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        
        logger.info(f"Initialized memory cache with max_size={max_size}, default_ttl={default_ttl}")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached data by key."""
        with self._lock:
            try:
                value = self._cache.get(key)
                if value is not None and key in self._metadata:
                    self._metadata[key].touch()
                    logger.debug(f"Cache hit for key: {key}")
                    return value
                else:
                    logger.debug(f"Cache miss for key: {key}")
                    return None
            except Exception as e:
                logger.error(f"Error retrieving from cache: {e}")
                return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Store data in cache with optional TTL."""
        if ttl is None:
            ttl = self.default_ttl
        
        with self._lock:
            try:
                # Calculate size estimate
                size_bytes = self._estimate_size(value)
                
                # Store in cache
                self._cache[key] = value
                
                # Update metadata
                expires_at = datetime.utcnow() + timedelta(seconds=ttl) if ttl > 0 else None
                self._metadata[key] = CacheEntry(
                    key=key,
                    value=value,
                    created_at=datetime.utcnow(),
                    expires_at=expires_at,
                    size_bytes=size_bytes
                )
                
                logger.debug(f"Cached key: {key}, size: {size_bytes} bytes, ttl: {ttl}s")
                
            except Exception as e:
                logger.error(f"Error storing in cache: {e}")
    
    def invalidate(self, pattern: str) -> None:
        """Invalidate cached data matching pattern."""
        with self._lock:
            try:
                keys_to_remove = []
                
                # Simple pattern matching (supports * wildcard)
                if '*' in pattern:
                    pattern_regex = pattern.replace('*', '.*')
                    import re
                    regex = re.compile(pattern_regex)
                    
                    for key in self._cache.keys():
                        if regex.match(key):
                            keys_to_remove.append(key)
                else:
                    # Exact match
                    if pattern in self._cache:
                        keys_to_remove.append(pattern)
                
                # Remove matched keys
                for key in keys_to_remove:
                    del self._cache[key]
                    if key in self._metadata:
                        del self._metadata[key]
                
                logger.info(f"Invalidated {len(keys_to_remove)} cache entries matching pattern: {pattern}")
                
            except Exception as e:
                logger.error(f"Error invalidating cache: {e}")
    
    def clear(self) -> None:
        """Clear all cached data."""
        with self._lock:
            self._cache.clear()
            self._metadata.clear()
            logger.info("Cleared all cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_size = sum(entry.size_bytes for entry in self._metadata.values())
            total_accesses = sum(entry.access_count for entry in self._metadata.values())
            
            return {
                'entries': len(self._cache),
                'max_size': self.max_size,
                'total_size_bytes': total_size,
                'total_accesses': total_accesses,
                'hit_rate': self._calculate_hit_rate(),
                'oldest_entry': self._get_oldest_entry_age(),
                'memory_usage_mb': total_size / (1024 * 1024)
            }
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate the size of a cached value in bytes."""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (int, float, bool)):
                return 8  # Approximate
            elif isinstance(value, (list, tuple, dict)):
                return len(pickle.dumps(value))
            else:
                return len(str(value))
        except Exception:
            return 100  # Default estimate
    
    def _calculate_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        # This is a simplified calculation
        # In a real implementation, you'd track hits/misses separately
        total_accesses = sum(entry.access_count for entry in self._metadata.values())
        if total_accesses == 0:
            return 0.0
        return min(1.0, total_accesses / len(self._metadata)) if self._metadata else 0.0
    
    def _get_oldest_entry_age(self) -> Optional[float]:
        """Get age of oldest entry in seconds."""
        if not self._metadata:
            return None
        
        oldest = min(self._metadata.values(), key=lambda e: e.created_at)
        return (datetime.utcnow() - oldest.created_at).total_seconds()


class FileCacheManager(CacheManager):
    """File-based cache manager for persistent caching."""
    
    def __init__(self, cache_dir: str = ".cache", max_size_mb: int = 100):
        """Initialize file cache manager.
        
        Args:
            cache_dir: Directory to store cache files
            max_size_mb: Maximum cache size in megabytes
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = Lock()
        
        logger.info(f"Initialized file cache at {self.cache_dir}, max_size={max_size_mb}MB")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve cached data from file."""
        cache_file = self._get_cache_file(key)
        
        try:
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'rb') as f:
                cache_data = pickle.load(f)
            
            # Check expiration
            if 'expires_at' in cache_data and cache_data['expires_at']:
                if datetime.fromisoformat(cache_data['expires_at']) < datetime.utcnow():
                    cache_file.unlink()  # Remove expired file
                    return None
            
            logger.debug(f"File cache hit for key: {key}")
            return cache_data['value']
            
        except Exception as e:
            logger.error(f"Error reading from file cache: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Store data in file cache."""
        cache_file = self._get_cache_file(key)
        
        try:
            expires_at = None
            if ttl > 0:
                expires_at = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
            
            cache_data = {
                'key': key,
                'value': value,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': expires_at
            }
            
            with self._lock:
                with open(cache_file, 'wb') as f:
                    pickle.dump(cache_data, f)
                
                # Clean up if cache is too large
                self._cleanup_if_needed()
            
            logger.debug(f"Stored in file cache: {key}")
            
        except Exception as e:
            logger.error(f"Error storing in file cache: {e}")
    
    def invalidate(self, pattern: str) -> None:
        """Invalidate cached files matching pattern."""
        try:
            removed_count = 0
            
            if '*' in pattern:
                # Glob pattern matching
                pattern_path = self.cache_dir / pattern.replace('*', '*')
                for cache_file in self.cache_dir.glob(pattern_path.name):
                    cache_file.unlink()
                    removed_count += 1
            else:
                # Exact match
                cache_file = self._get_cache_file(pattern)
                if cache_file.exists():
                    cache_file.unlink()
                    removed_count += 1
            
            logger.info(f"Invalidated {removed_count} file cache entries matching: {pattern}")
            
        except Exception as e:
            logger.error(f"Error invalidating file cache: {e}")
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for a key."""
        # Hash the key to create a safe filename
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def _cleanup_if_needed(self) -> None:
        """Clean up old cache files if size limit exceeded."""
        try:
            total_size = sum(f.stat().st_size for f in self.cache_dir.glob('*.cache'))
            
            if total_size > self.max_size_bytes:
                # Remove oldest files first
                cache_files = list(self.cache_dir.glob('*.cache'))
                cache_files.sort(key=lambda f: f.stat().st_mtime)
                
                removed_size = 0
                for cache_file in cache_files:
                    if total_size - removed_size <= self.max_size_bytes * 0.8:  # Leave 20% buffer
                        break
                    
                    file_size = cache_file.stat().st_size
                    cache_file.unlink()
                    removed_size += file_size
                
                logger.info(f"Cleaned up {removed_size} bytes from file cache")
                
        except Exception as e:
            logger.error(f"Error during cache cleanup: {e}")


class HybridCacheManager(CacheManager):
    """Hybrid cache manager combining memory and file caching."""
    
    def __init__(self, 
                 memory_max_size: int = 500,
                 file_cache_dir: str = ".cache",
                 file_max_size_mb: int = 100,
                 default_ttl: int = 3600):
        """Initialize hybrid cache manager."""
        self.memory_cache = MemoryCacheManager(memory_max_size, default_ttl)
        self.file_cache = FileCacheManager(file_cache_dir, file_max_size_mb)
        self.default_ttl = default_ttl
        
        logger.info("Initialized hybrid cache manager")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve from memory cache first, then file cache."""
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # Try file cache
        value = self.file_cache.get(key)
        if value is not None:
            # Promote to memory cache
            self.memory_cache.set(key, value, self.default_ttl)
            return value
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Store in both memory and file cache."""
        if ttl is None:
            ttl = self.default_ttl
        
        # Store in memory cache
        self.memory_cache.set(key, value, ttl)
        
        # Store in file cache for persistence
        self.file_cache.set(key, value, ttl)
    
    def invalidate(self, pattern: str) -> None:
        """Invalidate from both caches."""
        self.memory_cache.invalidate(pattern)
        self.file_cache.invalidate(pattern)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get combined cache statistics."""
        memory_stats = self.memory_cache.get_stats()
        
        return {
            'memory_cache': memory_stats,
            'file_cache': {
                'cache_dir': str(self.file_cache.cache_dir),
                'max_size_mb': self.file_cache.max_size_bytes / (1024 * 1024)
            },
            'type': 'hybrid'
        }


class VulnerabilityCacheManager:
    """Specialized cache manager for vulnerability data."""
    
    def __init__(self, cache_manager: CacheManager):
        """Initialize with a base cache manager."""
        self.cache = cache_manager
        self.vulnerability_ttl = 3600  # 1 hour for vulnerability data
        self.cve_ttl = 86400  # 24 hours for CVE data
    
    def cache_vulnerability_scan(self, package_name: str, version: str, 
                               scan_result: Any) -> None:
        """Cache vulnerability scan result for a package."""
        key = f"vuln_scan:{package_name}:{version}"
        self.cache.set(key, scan_result, self.vulnerability_ttl)
    
    def get_vulnerability_scan(self, package_name: str, version: str) -> Optional[Any]:
        """Get cached vulnerability scan result."""
        key = f"vuln_scan:{package_name}:{version}"
        return self.cache.get(key)
    
    def cache_cve_data(self, cve_id: str, cve_data: Any) -> None:
        """Cache CVE data."""
        key = f"cve:{cve_id}"
        self.cache.set(key, cve_data, self.cve_ttl)
    
    def get_cve_data(self, cve_id: str) -> Optional[Any]:
        """Get cached CVE data."""
        key = f"cve:{cve_id}"
        return self.cache.get(key)
    
    def cache_package_metadata(self, package_name: str, metadata: Any) -> None:
        """Cache package metadata."""
        key = f"pkg_meta:{package_name}"
        self.cache.set(key, metadata, self.cve_ttl)
    
    def get_package_metadata(self, package_name: str) -> Optional[Any]:
        """Get cached package metadata."""
        key = f"pkg_meta:{package_name}"
        return self.cache.get(key)
    
    def invalidate_package_cache(self, package_name: str) -> None:
        """Invalidate all cache entries for a package."""
        self.cache.invalidate(f"vuln_scan:{package_name}:*")
        self.cache.invalidate(f"pkg_meta:{package_name}")


def create_cache_manager(cache_type: str = "hybrid", **kwargs) -> CacheManager:
    """Factory function to create cache managers.
    
    Args:
        cache_type: Type of cache manager ('memory', 'file', 'hybrid')
        **kwargs: Additional arguments for cache manager
    
    Returns:
        Configured cache manager instance
    """
    if cache_type == "memory":
        return MemoryCacheManager(**kwargs)
    elif cache_type == "file":
        return FileCacheManager(**kwargs)
    elif cache_type == "hybrid":
        return HybridCacheManager(**kwargs)
    else:
        raise ValueError(f"Unknown cache type: {cache_type}")


# Global cache instance (can be configured)
_global_cache: Optional[CacheManager] = None


def get_global_cache() -> CacheManager:
    """Get or create global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = create_cache_manager("hybrid")
    return _global_cache


def set_global_cache(cache_manager: CacheManager) -> None:
    """Set global cache instance."""
    global _global_cache
    _global_cache = cache_manager