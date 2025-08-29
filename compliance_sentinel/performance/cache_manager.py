"""Intelligent caching system with multi-level cache hierarchy."""

import asyncio
import hashlib
import json
import logging
import pickle
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import weakref
import threading
from collections import OrderedDict
import os
import sqlite3
import redis
import memcache

from compliance_sentinel.core.interfaces import SecurityIssue, AnalysisResult


logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """Cache level enumeration."""
    MEMORY = "memory"
    DISK = "disk"
    REDIS = "redis"
    MEMCACHED = "memcached"


class CachePolicy(Enum):
    """Cache eviction policies."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL = "ttl"  # Time To Live
    ADAPTIVE = "adaptive"  # Adaptive based on access patterns


@dataclass
class CacheEntry:
    """Represents a cache entry with metadata."""
    
    key: str
    value: Any
    size_bytes: int
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    ttl_seconds: Optional[int] = None
    tags: Set[str] = field(default_factory=set)
    
    @property
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.ttl_seconds is None:
            return False
        
        age = (datetime.now() - self.created_at).total_seconds()
        return age > self.ttl_seconds
    
    @property
    def age_seconds(self) -> float:
        """Get age of entry in seconds."""
        return (datetime.now() - self.created_at).total_seconds()
    
    @property
    def idle_seconds(self) -> float:
        """Get idle time since last access in seconds."""
        return (datetime.now() - self.last_accessed).total_seconds()
    
    def access(self):
        """Record access to this entry."""
        self.last_accessed = datetime.now()
        self.access_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            'key': self.key,
            'size_bytes': self.size_bytes,
            'created_at': self.created_at.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'access_count': self.access_count,
            'ttl_seconds': self.ttl_seconds,
            'tags': list(self.tags),
            'age_seconds': self.age_seconds,
            'idle_seconds': self.idle_seconds,
            'is_expired': self.is_expired
        }


@dataclass
class CacheStats:
    """Cache statistics."""
    
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size_bytes: int = 0
    entry_count: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'evictions': self.evictions,
            'size_bytes': self.size_bytes,
            'entry_count': self.entry_count,
            'hit_rate': self.hit_rate,
            'miss_rate': self.miss_rate
        }


class MemoryCache:
    """In-memory cache with configurable eviction policies."""
    
    def __init__(self, 
                 max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
                 max_entries: int = 10000,
                 policy: CachePolicy = CachePolicy.LRU,
                 default_ttl: Optional[int] = None):
        """Initialize memory cache."""
        self.max_size_bytes = max_size_bytes
        self.max_entries = max_entries
        self.policy = policy
        self.default_ttl = default_ttl
        
        self.entries = OrderedDict()  # For LRU ordering
        self.access_counts = {}  # For LFU policy
        self.stats = CacheStats()
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.entries:
                self.stats.misses += 1
                return None
            
            entry = self.entries[key]
            
            # Check expiration
            if entry.is_expired:
                del self.entries[key]
                if key in self.access_counts:
                    del self.access_counts[key]
                self.stats.misses += 1
                self.stats.evictions += 1
                return None
            
            # Update access information
            entry.access()
            self.access_counts[key] = self.access_counts.get(key, 0) + 1
            
            # Move to end for LRU
            if self.policy == CachePolicy.LRU:
                self.entries.move_to_end(key)
            
            self.stats.hits += 1
            return entry.value
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None, tags: Set[str] = None) -> bool:
        """Put value in cache."""
        with self.lock:
            # Calculate size
            size_bytes = self._calculate_size(value)
            
            # Check if we need to evict
            if key not in self.entries:
                while (len(self.entries) >= self.max_entries or 
                       self.stats.size_bytes + size_bytes > self.max_size_bytes):
                    if not self._evict_one():
                        return False  # Cannot evict
            
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                size_bytes=size_bytes,
                ttl_seconds=ttl or self.default_ttl,
                tags=tags or set()
            )
            
            # Update stats if replacing
            if key in self.entries:
                old_entry = self.entries[key]
                self.stats.size_bytes -= old_entry.size_bytes
                self.stats.entry_count -= 1
            
            # Store entry
            self.entries[key] = entry
            self.access_counts[key] = 1
            
            # Update stats
            self.stats.size_bytes += size_bytes
            self.stats.entry_count += 1
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache."""
        with self.lock:
            if key in self.entries:
                entry = self.entries[key]
                del self.entries[key]
                
                if key in self.access_counts:
                    del self.access_counts[key]
                
                self.stats.size_bytes -= entry.size_bytes
                self.stats.entry_count -= 1
                return True
            
            return False
    
    def clear(self):
        """Clear all entries from cache."""
        with self.lock:
            self.entries.clear()
            self.access_counts.clear()
            self.stats = CacheStats()
    
    def _evict_one(self) -> bool:
        """Evict one entry based on policy."""
        if not self.entries:
            return False
        
        if self.policy == CachePolicy.LRU:
            # Remove least recently used (first in OrderedDict)
            key = next(iter(self.entries))
        elif self.policy == CachePolicy.LFU:
            # Remove least frequently used
            key = min(self.access_counts.keys(), key=lambda k: self.access_counts[k])
        elif self.policy == CachePolicy.FIFO:
            # Remove first inserted
            key = next(iter(self.entries))
        elif self.policy == CachePolicy.TTL:
            # Remove expired entries first, then oldest
            expired_keys = [k for k, e in self.entries.items() if e.is_expired]
            if expired_keys:
                key = expired_keys[0]
            else:
                key = min(self.entries.keys(), key=lambda k: self.entries[k].created_at)
        else:  # ADAPTIVE
            key = self._adaptive_eviction()
        
        # Remove entry
        entry = self.entries[key]
        del self.entries[key]
        
        if key in self.access_counts:
            del self.access_counts[key]
        
        self.stats.size_bytes -= entry.size_bytes
        self.stats.entry_count -= 1
        self.stats.evictions += 1
        
        return True
    
    def _adaptive_eviction(self) -> str:
        """Adaptive eviction based on access patterns."""
        # Score entries based on multiple factors
        scores = {}
        
        for key, entry in self.entries.items():
            access_count = self.access_counts.get(key, 1)
            
            # Factors: recency, frequency, size, age
            recency_score = 1.0 / (entry.idle_seconds + 1)
            frequency_score = access_count / (entry.age_seconds + 1)
            size_penalty = entry.size_bytes / (1024 * 1024)  # MB
            age_penalty = entry.age_seconds / 3600  # Hours
            
            # Combined score (lower is better for eviction)
            score = (recency_score + frequency_score) / (1 + size_penalty + age_penalty)
            scores[key] = score
        
        # Return key with lowest score
        return min(scores.keys(), key=lambda k: scores[k])
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of value in bytes."""
        try:
            return len(pickle.dumps(value))
        except:
            # Fallback estimation
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (int, float)):
                return 8
            elif isinstance(value, (list, tuple)):
                return sum(self._calculate_size(item) for item in value)
            elif isinstance(value, dict):
                return sum(self._calculate_size(k) + self._calculate_size(v) for k, v in value.items())
            else:
                return 1024  # Default estimate
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return self.stats.to_dict()
    
    def get_entries_info(self) -> List[Dict[str, Any]]:
        """Get information about all entries."""
        with self.lock:
            return [entry.to_dict() for entry in self.entries.values()]


class DiskCache:
    """Disk-based cache using SQLite."""
    
    def __init__(self, 
                 cache_dir: str = "/tmp/compliance_cache",
                 max_size_bytes: int = 1024 * 1024 * 1024,  # 1GB
                 default_ttl: Optional[int] = None):
        """Initialize disk cache."""
        self.cache_dir = cache_dir
        self.max_size_bytes = max_size_bytes
        self.default_ttl = default_ttl
        
        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize SQLite database
        self.db_path = os.path.join(cache_dir, "cache.db")
        self._init_database()
        
        self.stats = CacheStats()
        self.lock = threading.RLock()
    
    def _init_database(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value_path TEXT,
                    size_bytes INTEGER,
                    created_at TIMESTAMP,
                    last_accessed TIMESTAMP,
                    access_count INTEGER DEFAULT 0,
                    ttl_seconds INTEGER,
                    tags TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache_entries(last_accessed)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON cache_entries(created_at)")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from disk cache."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        SELECT * FROM cache_entries WHERE key = ?
                    """, (key,))
                    
                    row = cursor.fetchone()
                    if not row:
                        self.stats.misses += 1
                        return None
                    
                    # Check expiration
                    if row['ttl_seconds']:
                        created_at = datetime.fromisoformat(row['created_at'])
                        age = (datetime.now() - created_at).total_seconds()
                        if age > row['ttl_seconds']:
                            self.delete(key)
                            self.stats.misses += 1
                            return None
                    
                    # Load value from file
                    value_path = row['value_path']
                    if not os.path.exists(value_path):
                        self.delete(key)
                        self.stats.misses += 1
                        return None
                    
                    with open(value_path, 'rb') as f:
                        value = pickle.load(f)
                    
                    # Update access information
                    cursor.execute("""
                        UPDATE cache_entries 
                        SET last_accessed = ?, access_count = access_count + 1
                        WHERE key = ?
                    """, (datetime.now().isoformat(), key))
                    
                    self.stats.hits += 1
                    return value
                    
            except Exception as e:
                logger.error(f"Error getting from disk cache: {e}")
                self.stats.misses += 1
                return None
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None, tags: Set[str] = None) -> bool:
        """Put value in disk cache."""
        with self.lock:
            try:
                # Create value file
                value_filename = hashlib.md5(key.encode()).hexdigest() + ".pkl"
                value_path = os.path.join(self.cache_dir, value_filename)
                
                with open(value_path, 'wb') as f:
                    pickle.dump(value, f)
                
                size_bytes = os.path.getsize(value_path)
                
                # Check size limits and evict if necessary
                while self._get_total_size() + size_bytes > self.max_size_bytes:
                    if not self._evict_one():
                        os.remove(value_path)
                        return False
                
                # Store in database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Check if key exists
                    cursor.execute("SELECT value_path FROM cache_entries WHERE key = ?", (key,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Remove old file
                        old_path = existing[0]
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    
                    # Insert/update entry
                    cursor.execute("""
                        INSERT OR REPLACE INTO cache_entries 
                        (key, value_path, size_bytes, created_at, last_accessed, access_count, ttl_seconds, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        key,
                        value_path,
                        size_bytes,
                        datetime.now().isoformat(),
                        datetime.now().isoformat(),
                        1,
                        ttl or self.default_ttl,
                        json.dumps(list(tags)) if tags else None
                    ))
                
                return True
                
            except Exception as e:
                logger.error(f"Error putting to disk cache: {e}")
                return False
    
    def delete(self, key: str) -> bool:
        """Delete entry from disk cache."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Get value path
                    cursor.execute("SELECT value_path FROM cache_entries WHERE key = ?", (key,))
                    row = cursor.fetchone()
                    
                    if row:
                        value_path = row[0]
                        
                        # Remove file
                        if os.path.exists(value_path):
                            os.remove(value_path)
                        
                        # Remove from database
                        cursor.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                        
                        return True
                
                return False
                
            except Exception as e:
                logger.error(f"Error deleting from disk cache: {e}")
                return False
    
    def clear(self):
        """Clear all entries from disk cache."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Get all value paths
                    cursor.execute("SELECT value_path FROM cache_entries")
                    paths = cursor.fetchall()
                    
                    # Remove all files
                    for (path,) in paths:
                        if os.path.exists(path):
                            os.remove(path)
                    
                    # Clear database
                    cursor.execute("DELETE FROM cache_entries")
                
                self.stats = CacheStats()
                
            except Exception as e:
                logger.error(f"Error clearing disk cache: {e}")
    
    def _get_total_size(self) -> int:
        """Get total size of cache in bytes."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT SUM(size_bytes) FROM cache_entries")
                result = cursor.fetchone()
                return result[0] or 0
        except:
            return 0
    
    def _evict_one(self) -> bool:
        """Evict one entry (LRU policy)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find least recently used entry
                cursor.execute("""
                    SELECT key FROM cache_entries 
                    ORDER BY last_accessed ASC 
                    LIMIT 1
                """)
                
                row = cursor.fetchone()
                if row:
                    key = row[0]
                    self.delete(key)
                    self.stats.evictions += 1
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error evicting from disk cache: {e}")
            return False


class RedisCache:
    """Redis-based distributed cache."""
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 6379,
                 db: int = 0,
                 password: Optional[str] = None,
                 default_ttl: Optional[int] = None,
                 key_prefix: str = "compliance:"):
        """Initialize Redis cache."""
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix
        
        try:
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=False
            )
            # Test connection
            self.redis_client.ping()
            self.available = True
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
            self.available = False
        
        self.stats = CacheStats()
    
    def _make_key(self, key: str) -> str:
        """Create prefixed key."""
        return f"{self.key_prefix}{key}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache."""
        if not self.available:
            self.stats.misses += 1
            return None
        
        try:
            redis_key = self._make_key(key)
            data = self.redis_client.get(redis_key)
            
            if data is None:
                self.stats.misses += 1
                return None
            
            value = pickle.loads(data)
            self.stats.hits += 1
            return value
            
        except Exception as e:
            logger.error(f"Error getting from Redis cache: {e}")
            self.stats.misses += 1
            return None
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None, tags: Set[str] = None) -> bool:
        """Put value in Redis cache."""
        if not self.available:
            return False
        
        try:
            redis_key = self._make_key(key)
            data = pickle.dumps(value)
            
            ttl_to_use = ttl or self.default_ttl
            
            if ttl_to_use:
                self.redis_client.setex(redis_key, ttl_to_use, data)
            else:
                self.redis_client.set(redis_key, data)
            
            # Store tags if provided
            if tags:
                tag_key = f"{redis_key}:tags"
                self.redis_client.sadd(tag_key, *tags)
                if ttl_to_use:
                    self.redis_client.expire(tag_key, ttl_to_use)
            
            return True
            
        except Exception as e:
            logger.error(f"Error putting to Redis cache: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete entry from Redis cache."""
        if not self.available:
            return False
        
        try:
            redis_key = self._make_key(key)
            tag_key = f"{redis_key}:tags"
            
            # Delete both data and tags
            deleted = self.redis_client.delete(redis_key, tag_key)
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Error deleting from Redis cache: {e}")
            return False
    
    def clear(self):
        """Clear all entries with our prefix."""
        if not self.available:
            return
        
        try:
            pattern = f"{self.key_prefix}*"
            keys = self.redis_client.keys(pattern)
            
            if keys:
                self.redis_client.delete(*keys)
            
            self.stats = CacheStats()
            
        except Exception as e:
            logger.error(f"Error clearing Redis cache: {e}")


class CacheManager:
    """Multi-level cache manager with intelligent routing."""
    
    def __init__(self, 
                 memory_cache_config: Dict[str, Any] = None,
                 disk_cache_config: Dict[str, Any] = None,
                 redis_cache_config: Dict[str, Any] = None):
        """Initialize cache manager."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize cache levels
        self.caches = {}
        
        # Memory cache (L1)
        if memory_cache_config is not False:
            config = memory_cache_config or {}
            self.caches[CacheLevel.MEMORY] = MemoryCache(**config)
        
        # Disk cache (L2)
        if disk_cache_config is not False:
            config = disk_cache_config or {}
            self.caches[CacheLevel.DISK] = DiskCache(**config)
        
        # Redis cache (L3)
        if redis_cache_config is not False:
            config = redis_cache_config or {}
            redis_cache = RedisCache(**config)
            if redis_cache.available:
                self.caches[CacheLevel.REDIS] = redis_cache
        
        # Cache hierarchy (order matters)
        self.cache_hierarchy = [
            CacheLevel.MEMORY,
            CacheLevel.DISK,
            CacheLevel.REDIS
        ]
        
        # Filter available caches
        self.cache_hierarchy = [level for level in self.cache_hierarchy if level in self.caches]
        
        # Global stats
        self.global_stats = CacheStats()
        
        self.logger.info(f"Cache manager initialized with levels: {[level.value for level in self.cache_hierarchy]}")
    
    def get(self, key: str, promote: bool = True) -> Optional[Any]:
        """Get value from cache hierarchy."""
        for level in self.cache_hierarchy:
            cache = self.caches[level]
            value = cache.get(key)
            
            if value is not None:
                self.global_stats.hits += 1
                
                # Promote to higher levels if requested
                if promote:
                    self._promote_value(key, value, level)
                
                return value
        
        self.global_stats.misses += 1
        return None
    
    def put(self, key: str, value: Any, 
            ttl: Optional[int] = None, 
            tags: Set[str] = None,
            levels: Optional[List[CacheLevel]] = None) -> bool:
        """Put value in specified cache levels."""
        if levels is None:
            levels = self.cache_hierarchy
        
        success = False
        
        for level in levels:
            if level in self.caches:
                cache = self.caches[level]
                if cache.put(key, value, ttl, tags):
                    success = True
        
        return success
    
    def delete(self, key: str, levels: Optional[List[CacheLevel]] = None) -> bool:
        """Delete from specified cache levels."""
        if levels is None:
            levels = self.cache_hierarchy
        
        success = False
        
        for level in levels:
            if level in self.caches:
                cache = self.caches[level]
                if cache.delete(key):
                    success = True
        
        return success
    
    def clear(self, levels: Optional[List[CacheLevel]] = None):
        """Clear specified cache levels."""
        if levels is None:
            levels = self.cache_hierarchy
        
        for level in levels:
            if level in self.caches:
                cache = self.caches[level]
                cache.clear()
        
        self.global_stats = CacheStats()
    
    def _promote_value(self, key: str, value: Any, current_level: CacheLevel):
        """Promote value to higher cache levels."""
        current_index = self.cache_hierarchy.index(current_level)
        
        # Promote to all higher levels
        for i in range(current_index):
            higher_level = self.cache_hierarchy[i]
            cache = self.caches[higher_level]
            cache.put(key, value)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        stats = {
            'global': self.global_stats.to_dict(),
            'levels': {}
        }
        
        for level, cache in self.caches.items():
            if hasattr(cache, 'get_stats'):
                stats['levels'][level.value] = cache.get_stats()
        
        return stats
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache configuration and status information."""
        info = {
            'hierarchy': [level.value for level in self.cache_hierarchy],
            'available_levels': list(self.caches.keys()),
            'level_info': {}
        }
        
        for level, cache in self.caches.items():
            level_info = {
                'type': type(cache).__name__,
                'available': True
            }
            
            if hasattr(cache, 'max_size_bytes'):
                level_info['max_size_bytes'] = cache.max_size_bytes
            
            if hasattr(cache, 'max_entries'):
                level_info['max_entries'] = cache.max_entries
            
            if hasattr(cache, 'policy'):
                level_info['policy'] = cache.policy.value
            
            info['level_info'][level.value] = level_info
        
        return info


# Utility functions for common caching patterns

def cache_key_for_file_analysis(file_path: str, analyzer_type: str, config_hash: str = "") -> str:
    """Generate cache key for file analysis results."""
    key_data = f"file_analysis:{file_path}:{analyzer_type}:{config_hash}"
    return hashlib.md5(key_data.encode()).hexdigest()


def cache_key_for_ml_inference(model_name: str, input_hash: str, model_version: str = "latest") -> str:
    """Generate cache key for ML inference results."""
    key_data = f"ml_inference:{model_name}:{model_version}:{input_hash}"
    return hashlib.md5(key_data.encode()).hexdigest()


def cache_key_for_dependency_scan(package_file_path: str, package_file_hash: str) -> str:
    """Generate cache key for dependency scan results."""
    key_data = f"dependency_scan:{package_file_path}:{package_file_hash}"
    return hashlib.md5(key_data.encode()).hexdigest()


class CacheDecorator:
    """Decorator for automatic caching of function results."""
    
    def __init__(self, 
                 cache_manager: CacheManager,
                 ttl: Optional[int] = None,
                 key_func: Optional[Callable] = None,
                 tags: Optional[Set[str]] = None):
        """Initialize cache decorator."""
        self.cache_manager = cache_manager
        self.ttl = ttl
        self.key_func = key_func
        self.tags = tags or set()
    
    def __call__(self, func):
        """Decorate function with caching."""
        def wrapper(*args, **kwargs):
            # Generate cache key
            if self.key_func:
                cache_key = self.key_func(*args, **kwargs)
            else:
                key_data = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
                cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Try to get from cache
            cached_result = self.cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            self.cache_manager.put(cache_key, result, self.ttl, self.tags)
            
            return result
        
        return wrapper


def cached(cache_manager: CacheManager, 
          ttl: Optional[int] = None,
          key_func: Optional[Callable] = None,
          tags: Optional[Set[str]] = None):
    """Decorator factory for caching function results."""
    return CacheDecorator(cache_manager, ttl, key_func, tags)