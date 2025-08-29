"""Tests for intelligent cache functionality."""

import pytest
import asyncio
import time
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timedelta

from compliance_sentinel.utils.intelligent_cache import (
    IntelligentCache,
    CacheEntry,
    CacheStats,
    CacheEvictionPolicy,
    CacheBackend
)


class TestCacheEntry:
    """Test cache entry functionality."""
    
    def test_cache_entry_creation(self):
        """Test creating a cache entry."""
        data = {"key": "value", "number": 42}
        entry = CacheEntry(
            key="test_key",
            value=data,
            ttl=3600,
            created_at=datetime.utcnow()
        )
        
        assert entry.key == "test_key"
        assert entry.value == data
        assert entry.ttl == 3600
        assert entry.created_at is not None
    
    def test_cache_entry_expiration(self):
        """Test cache entry expiration logic."""
        # Create expired entry
        past_time = datetime.utcnow() - timedelta(hours=2)
        expired_entry = CacheEntry(
            key="expired_key",
            value="expired_value",
            ttl=3600,  # 1 hour TTL
            created_at=past_time
        )
        
        assert expired_entry.is_expired() is True
        
        # Create non-expired entry
        recent_time = datetime.utcnow() - timedelta(minutes=30)
        valid_entry = CacheEntry(
            key="valid_key",
            value="valid_value",
            ttl=3600,  # 1 hour TTL
            created_at=recent_time
        )
        
        assert valid_entry.is_expired() is False
    
    def test_cache_entry_serialization(self):
        """Test cache entry serialization."""
        data = {"test": "data", "number": 123}
        entry = CacheEntry(
            key="serialize_test",
            value=data,
            ttl=1800
        )
        
        serialized = entry.to_dict()
        
        assert serialized["key"] == "serialize_test"
        assert serialized["value"] == data
        assert serialized["ttl"] == 1800
        assert "created_at" in serialized
        assert "access_count" in serialized
        assert "last_accessed" in serialized
    
    def test_cache_entry_deserialization(self):
        """Test cache entry deserialization."""
        entry_dict = {
            "key": "deserialize_test",
            "value": {"data": "test"},
            "ttl": 2400,
            "created_at": "2023-12-01T10:00:00Z",
            "access_count": 5,
            "last_accessed": "2023-12-01T11:00:00Z"
        }
        
        entry = CacheEntry.from_dict(entry_dict)
        
        assert entry.key == "deserialize_test"
        assert entry.value == {"data": "test"}
        assert entry.ttl == 2400
        assert entry.access_count == 5
    
    def test_cache_entry_access_tracking(self):
        """Test cache entry access tracking."""
        entry = CacheEntry(
            key="access_test",
            value="test_value",
            ttl=3600
        )
        
        initial_count = entry.access_count
        initial_time = entry.last_accessed
        
        # Simulate access
        time.sleep(0.01)  # Small delay to ensure time difference
        entry.record_access()
        
        assert entry.access_count == initial_count + 1
        assert entry.last_accessed > initial_time


class TestCacheStats:
    """Test cache statistics functionality."""
    
    def test_cache_stats_creation(self):
        """Test creating cache statistics."""
        stats = CacheStats()
        
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0
        assert stats.size == 0
        assert stats.hit_rate == 0.0
    
    def test_cache_stats_calculations(self):
        """Test cache statistics calculations."""
        stats = CacheStats()
        
        # Record some hits and misses
        stats.record_hit()
        stats.record_hit()
        stats.record_miss()
        
        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.hit_rate == 2.0 / 3.0  # 66.67%
    
    def test_cache_stats_reset(self):
        """Test resetting cache statistics."""
        stats = CacheStats()
        
        stats.record_hit()
        stats.record_miss()
        stats.record_eviction()
        
        assert stats.hits > 0
        assert stats.misses > 0
        assert stats.evictions > 0
        
        stats.reset()
        
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0


class TestIntelligentCache:
    """Test intelligent cache functionality."""
    
    @pytest.fixture
    def cache(self):
        """Create cache instance for testing."""
        return IntelligentCache(
            max_size=100,
            default_ttl=3600,
            eviction_policy=CacheEvictionPolicy.LRU
        )
    
    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, cache):
        """Test basic cache set and get operations."""
        key = "test_key"
        value = {"data": "test_value", "number": 42}
        
        # Set value
        await cache.set(key, value, ttl=1800)
        
        # Get value
        retrieved_value = await cache.get(key)
        
        assert retrieved_value == value
    
    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        """Test cache miss behavior."""
        result = await cache.get("nonexistent_key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache):
        """Test cache entry expiration."""
        key = "expiring_key"
        value = "expiring_value"
        
        # Set with very short TTL
        await cache.set(key, value, ttl=0.1)  # 0.1 seconds
        
        # Should be available immediately
        result = await cache.get(key)
        assert result == value
        
        # Wait for expiration
        await asyncio.sleep(0.2)
        
        # Should be expired now
        result = await cache.get(key)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_delete(self, cache):
        """Test cache deletion."""
        key = "delete_test"
        value = "delete_value"
        
        # Set and verify
        await cache.set(key, value)
        assert await cache.get(key) == value
        
        # Delete and verify
        await cache.delete(key)
        assert await cache.get(key) is None
    
    @pytest.mark.asyncio
    async def test_cache_clear(self, cache):
        """Test cache clearing."""
        # Set multiple values
        for i in range(5):
            await cache.set(f"key_{i}", f"value_{i}")
        
        # Verify values exist
        for i in range(5):
            assert await cache.get(f"key_{i}") == f"value_{i}"
        
        # Clear cache
        await cache.clear()
        
        # Verify all values are gone
        for i in range(5):
            assert await cache.get(f"key_{i}") is None
    
    @pytest.mark.asyncio
    async def test_cache_size_limit(self):
        """Test cache size limit enforcement."""
        small_cache = IntelligentCache(max_size=3)
        
        # Fill cache to capacity
        for i in range(3):
            await small_cache.set(f"key_{i}", f"value_{i}")
        
        # Add one more item (should trigger eviction)
        await small_cache.set("key_3", "value_3")
        
        # Cache should still have 3 items
        assert small_cache.size() <= 3
        
        # At least one of the original items should be evicted
        original_items = [await small_cache.get(f"key_{i}") for i in range(3)]
        assert None in original_items
    
    @pytest.mark.asyncio
    async def test_lru_eviction_policy(self):
        """Test LRU (Least Recently Used) eviction policy."""
        cache = IntelligentCache(max_size=3, eviction_policy=CacheEvictionPolicy.LRU)
        
        # Fill cache
        await cache.set("key_1", "value_1")
        await cache.set("key_2", "value_2")
        await cache.set("key_3", "value_3")
        
        # Access key_1 to make it recently used
        await cache.get("key_1")
        
        # Add new item (should evict key_2 as it's least recently used)
        await cache.set("key_4", "value_4")
        
        # key_1 should still exist (recently accessed)
        assert await cache.get("key_1") == "value_1"
        
        # key_2 should be evicted
        assert await cache.get("key_2") is None
        
        # key_3 and key_4 should exist
        assert await cache.get("key_3") == "value_3"
        assert await cache.get("key_4") == "value_4"
    
    @pytest.mark.asyncio
    async def test_lfu_eviction_policy(self):
        """Test LFU (Least Frequently Used) eviction policy."""
        cache = IntelligentCache(max_size=3, eviction_policy=CacheEvictionPolicy.LFU)
        
        # Fill cache
        await cache.set("key_1", "value_1")
        await cache.set("key_2", "value_2")
        await cache.set("key_3", "value_3")
        
        # Access key_1 multiple times to make it frequently used
        for _ in range(5):
            await cache.get("key_1")
        
        # Access key_3 once
        await cache.get("key_3")
        
        # Add new item (should evict key_2 as it's least frequently used)
        await cache.set("key_4", "value_4")
        
        # key_1 should still exist (most frequently used)
        assert await cache.get("key_1") == "value_1"
        
        # key_2 should be evicted (never accessed)
        assert await cache.get("key_2") is None
        
        # key_3 and key_4 should exist
        assert await cache.get("key_3") == "value_3"
        assert await cache.get("key_4") == "value_4"
    
    @pytest.mark.asyncio
    async def test_cache_statistics(self, cache):
        """Test cache statistics tracking."""
        # Generate some hits and misses
        await cache.set("hit_key", "hit_value")
        
        # Record hits
        await cache.get("hit_key")  # Hit
        await cache.get("hit_key")  # Hit
        
        # Record misses
        await cache.get("miss_key_1")  # Miss
        await cache.get("miss_key_2")  # Miss
        await cache.get("miss_key_3")  # Miss
        
        stats = cache.get_stats()
        
        assert stats.hits == 2
        assert stats.misses == 3
        assert stats.hit_rate == 2.0 / 5.0  # 40%
    
    @pytest.mark.asyncio
    async def test_cache_with_fetch_function(self, cache):
        """Test cache with automatic fetch function."""
        fetch_count = 0
        
        async def fetch_function(key):
            nonlocal fetch_count
            fetch_count += 1
            return f"fetched_value_for_{key}"
        
        key = "fetch_test"
        
        # First call should fetch and cache
        value1 = await cache.get_or_fetch(key, fetch_function, ttl=3600)
        assert value1 == "fetched_value_for_fetch_test"
        assert fetch_count == 1
        
        # Second call should use cache
        value2 = await cache.get_or_fetch(key, fetch_function, ttl=3600)
        assert value2 == "fetched_value_for_fetch_test"
        assert fetch_count == 1  # Should not have fetched again
    
    @pytest.mark.asyncio
    async def test_cache_pattern_operations(self, cache):
        """Test cache operations with patterns."""
        # Set multiple keys with pattern
        for i in range(5):
            await cache.set(f"pattern_test_{i}", f"value_{i}")
            await cache.set(f"other_key_{i}", f"other_value_{i}")
        
        # Get keys matching pattern
        pattern_keys = await cache.get_keys_by_pattern("pattern_test_*")
        assert len(pattern_keys) == 5
        assert all(key.startswith("pattern_test_") for key in pattern_keys)
        
        # Delete keys matching pattern
        deleted_count = await cache.delete_by_pattern("pattern_test_*")
        assert deleted_count == 5
        
        # Verify pattern keys are deleted
        for i in range(5):
            assert await cache.get(f"pattern_test_{i}") is None
        
        # Verify other keys still exist
        for i in range(5):
            assert await cache.get(f"other_key_{i}") == f"other_value_{i}"
    
    @pytest.mark.asyncio
    async def test_cache_batch_operations(self, cache):
        """Test cache batch operations."""
        # Batch set
        batch_data = {
            f"batch_key_{i}": f"batch_value_{i}"
            for i in range(10)
        }
        
        await cache.set_batch(batch_data, ttl=3600)
        
        # Batch get
        keys = list(batch_data.keys())
        values = await cache.get_batch(keys)
        
        assert len(values) == 10
        for key, value in zip(keys, values):
            assert value == batch_data[key]
        
        # Batch delete
        deleted_count = await cache.delete_batch(keys[:5])
        assert deleted_count == 5
        
        # Verify partial deletion
        remaining_values = await cache.get_batch(keys)
        assert remaining_values[:5] == [None] * 5  # First 5 should be None
        assert remaining_values[5:] == [batch_data[key] for key in keys[5:]]  # Last 5 should exist
    
    @pytest.mark.asyncio
    async def test_cache_warming(self, cache):
        """Test cache warming functionality."""
        warm_data = {
            f"warm_key_{i}": f"warm_value_{i}"
            for i in range(20)
        }
        
        # Warm cache
        await cache.warm_cache(warm_data, ttl=3600)
        
        # Verify all data was cached
        for key, expected_value in warm_data.items():
            cached_value = await cache.get(key)
            assert cached_value == expected_value
    
    @pytest.mark.asyncio
    async def test_cache_invalidation_by_tags(self, cache):
        """Test cache invalidation by tags."""
        # Set entries with tags
        await cache.set("user_1_profile", {"name": "John"}, tags=["user_1", "profile"])
        await cache.set("user_1_settings", {"theme": "dark"}, tags=["user_1", "settings"])
        await cache.set("user_2_profile", {"name": "Jane"}, tags=["user_2", "profile"])
        
        # Verify entries exist
        assert await cache.get("user_1_profile") is not None
        assert await cache.get("user_1_settings") is not None
        assert await cache.get("user_2_profile") is not None
        
        # Invalidate by tag
        invalidated_count = await cache.invalidate_by_tag("user_1")
        assert invalidated_count == 2
        
        # Verify user_1 entries are gone
        assert await cache.get("user_1_profile") is None
        assert await cache.get("user_1_settings") is None
        
        # Verify user_2 entry still exists
        assert await cache.get("user_2_profile") is not None
    
    @pytest.mark.asyncio
    async def test_cache_compression(self):
        """Test cache compression for large values."""
        cache = IntelligentCache(compression_enabled=True, compression_threshold=100)
        
        # Small value (should not be compressed)
        small_value = "small_value"
        await cache.set("small_key", small_value)
        assert await cache.get("small_key") == small_value
        
        # Large value (should be compressed)
        large_value = "x" * 1000  # 1000 characters
        await cache.set("large_key", large_value)
        assert await cache.get("large_key") == large_value
    
    @pytest.mark.asyncio
    async def test_cache_serialization_formats(self, cache):
        """Test different serialization formats."""
        test_data = {
            "string": "test_string",
            "number": 42,
            "list": [1, 2, 3],
            "dict": {"nested": "value"},
            "boolean": True,
            "null": None
        }
        
        for key, value in test_data.items():
            await cache.set(f"serialize_{key}", value)
            retrieved_value = await cache.get(f"serialize_{key}")
            assert retrieved_value == value
    
    @pytest.mark.asyncio
    async def test_cache_concurrent_access(self, cache):
        """Test cache behavior under concurrent access."""
        async def concurrent_operation(operation_id):
            key = f"concurrent_key_{operation_id}"
            value = f"concurrent_value_{operation_id}"
            
            # Set value
            await cache.set(key, value)
            
            # Get value multiple times
            for _ in range(10):
                retrieved_value = await cache.get(key)
                assert retrieved_value == value
            
            return operation_id
        
        # Run multiple concurrent operations
        tasks = [concurrent_operation(i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        # All operations should complete successfully
        assert len(results) == 20
        assert results == list(range(20))
    
    @pytest.mark.asyncio
    async def test_cache_memory_usage_monitoring(self, cache):
        """Test cache memory usage monitoring."""
        # Add some data
        for i in range(50):
            await cache.set(f"memory_test_{i}", {"data": "x" * 100})
        
        # Get memory usage stats
        memory_stats = cache.get_memory_stats()
        
        assert memory_stats["total_entries"] == 50
        assert memory_stats["estimated_size_bytes"] > 0
        assert memory_stats["average_entry_size"] > 0
    
    @pytest.mark.asyncio
    async def test_cache_cleanup_expired_entries(self, cache):
        """Test cleanup of expired entries."""
        # Add entries with different TTLs
        await cache.set("short_ttl", "value1", ttl=0.1)  # 0.1 seconds
        await cache.set("long_ttl", "value2", ttl=3600)  # 1 hour
        
        # Wait for short TTL to expire
        await asyncio.sleep(0.2)
        
        # Trigger cleanup
        cleaned_count = await cache.cleanup_expired()
        
        assert cleaned_count >= 1  # At least the short TTL entry should be cleaned
        assert await cache.get("short_ttl") is None
        assert await cache.get("long_ttl") == "value2"


class TestCacheBackends:
    """Test different cache backends."""
    
    @pytest.mark.asyncio
    async def test_memory_backend(self):
        """Test in-memory cache backend."""
        cache = IntelligentCache(backend=CacheBackend.MEMORY)
        
        await cache.set("memory_test", "memory_value")
        assert await cache.get("memory_test") == "memory_value"
    
    @pytest.mark.asyncio
    async def test_redis_backend_mock(self):
        """Test Redis cache backend with mocking."""
        with patch('redis.asyncio.Redis') as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            
            # Mock Redis operations
            mock_redis_instance.get.return_value = b'{"value": "redis_value"}'
            mock_redis_instance.set.return_value = True
            mock_redis_instance.delete.return_value = 1
            
            cache = IntelligentCache(backend=CacheBackend.REDIS, redis_url="redis://localhost:6379")
            
            await cache.set("redis_test", "redis_value")
            value = await cache.get("redis_test")
            
            # Verify Redis operations were called
            mock_redis_instance.set.assert_called()
            mock_redis_instance.get.assert_called()
    
    @pytest.mark.asyncio
    async def test_file_backend(self):
        """Test file-based cache backend."""
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            cache = IntelligentCache(
                backend=CacheBackend.FILE,
                file_cache_dir=temp_dir
            )
            
            await cache.set("file_test", "file_value")
            assert await cache.get("file_test") == "file_value"
            
            # Verify file was created
            import os
            cache_files = os.listdir(temp_dir)
            assert len(cache_files) > 0
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestCacheEvictionPolicies:
    """Test different cache eviction policies."""
    
    @pytest.mark.asyncio
    async def test_fifo_eviction(self):
        """Test FIFO (First In, First Out) eviction policy."""
        cache = IntelligentCache(max_size=3, eviction_policy=CacheEvictionPolicy.FIFO)
        
        # Fill cache in order
        await cache.set("first", "value1")
        await cache.set("second", "value2")
        await cache.set("third", "value3")
        
        # Add fourth item (should evict first)
        await cache.set("fourth", "value4")
        
        # First should be evicted
        assert await cache.get("first") is None
        
        # Others should remain
        assert await cache.get("second") == "value2"
        assert await cache.get("third") == "value3"
        assert await cache.get("fourth") == "value4"
    
    @pytest.mark.asyncio
    async def test_random_eviction(self):
        """Test random eviction policy."""
        cache = IntelligentCache(max_size=3, eviction_policy=CacheEvictionPolicy.RANDOM)
        
        # Fill cache
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        # Add fourth item (should evict one randomly)
        await cache.set("key4", "value4")
        
        # Cache should still have 3 items
        assert cache.size() == 3
        
        # key4 should exist
        assert await cache.get("key4") == "value4"
        
        # One of the original keys should be evicted
        original_values = [
            await cache.get("key1"),
            await cache.get("key2"),
            await cache.get("key3")
        ]
        assert None in original_values


class TestCachePerformance:
    """Test cache performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_cache_performance_under_load(self):
        """Test cache performance under high load."""
        cache = IntelligentCache(max_size=1000)
        
        import time
        
        # Measure set performance
        start_time = time.time()
        for i in range(1000):
            await cache.set(f"perf_key_{i}", f"perf_value_{i}")
        set_time = time.time() - start_time
        
        # Measure get performance
        start_time = time.time()
        for i in range(1000):
            await cache.get(f"perf_key_{i}")
        get_time = time.time() - start_time
        
        # Performance should be reasonable
        assert set_time < 5.0  # Should set 1000 items in under 5 seconds
        assert get_time < 2.0  # Should get 1000 items in under 2 seconds
        
        # Hit rate should be 100%
        stats = cache.get_stats()
        assert stats.hit_rate == 1.0
    
    @pytest.mark.asyncio
    async def test_cache_memory_efficiency(self):
        """Test cache memory efficiency."""
        cache = IntelligentCache(max_size=100)
        
        # Add data and monitor memory usage
        for i in range(100):
            await cache.set(f"mem_key_{i}", {"data": "x" * 100, "id": i})
        
        memory_stats = cache.get_memory_stats()
        
        # Memory usage should be reasonable
        assert memory_stats["total_entries"] == 100
        assert memory_stats["estimated_size_bytes"] > 0
        
        # Average entry size should be reasonable
        avg_size = memory_stats["average_entry_size"]
        assert 100 < avg_size < 1000  # Should be between 100 and 1000 bytes per entry


if __name__ == "__main__":
    pytest.main([__file__])