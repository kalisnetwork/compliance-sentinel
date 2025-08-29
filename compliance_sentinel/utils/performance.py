"""Performance optimization utilities and monitoring for the Compliance Sentinel system."""

import asyncio
import time
import psutil
import threading
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
from functools import wraps
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import weakref

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for operations."""
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    cache_hits: int = 0
    cache_misses: int = 0
    error_count: int = 0
    success_count: int = 0
    
    def complete(self) -> None:
        """Mark the operation as complete and calculate duration."""
        self.end_time = datetime.utcnow()
        if self.start_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
    
    def add_cache_hit(self) -> None:
        """Record a cache hit."""
        self.cache_hits += 1
    
    def add_cache_miss(self) -> None:
        """Record a cache miss."""
        self.cache_misses += 1
    
    def add_success(self) -> None:
        """Record a successful operation."""
        self.success_count += 1
    
    def add_error(self) -> None:
        """Record an error."""
        self.error_count += 1
    
    def get_cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = self.cache_hits + self.cache_misses
        if total_requests == 0:
            return 0.0
        return self.cache_hits / total_requests
    
    def get_success_rate(self) -> float:
        """Calculate success rate."""
        total_operations = self.success_count + self.error_count
        if total_operations == 0:
            return 0.0
        return self.success_count / total_operations


class PerformanceMonitor:
    """Monitors and tracks performance metrics across the system."""
    
    def __init__(self, max_history: int = 1000):
        """Initialize performance monitor."""
        self.max_history = max_history
        self.metrics_history: deque = deque(maxlen=max_history)
        self.operation_metrics: Dict[str, List[PerformanceMetrics]] = defaultdict(list)
        self.system_metrics: deque = deque(maxlen=100)  # Last 100 system snapshots
        self._lock = threading.Lock()
        
        # Start system monitoring thread
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_system_metrics, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Performance monitor initialized")
    
    def start_operation(self, operation_name: str) -> PerformanceMetrics:
        """Start tracking a new operation."""
        metrics = PerformanceMetrics(
            operation_name=operation_name,
            start_time=datetime.utcnow()
        )
        
        # Record initial system state
        try:
            process = psutil.Process()
            metrics.memory_usage_mb = process.memory_info().rss / 1024 / 1024
            metrics.cpu_usage_percent = process.cpu_percent()
        except Exception as e:
            logger.warning(f"Failed to capture initial system metrics: {e}")
        
        return metrics
    
    def complete_operation(self, metrics: PerformanceMetrics) -> None:
        """Complete an operation and store its metrics."""
        metrics.complete()
        
        with self._lock:
            self.metrics_history.append(metrics)
            self.operation_metrics[metrics.operation_name].append(metrics)
            
            # Keep only recent metrics per operation
            if len(self.operation_metrics[metrics.operation_name]) > 100:
                self.operation_metrics[metrics.operation_name] = \
                    self.operation_metrics[metrics.operation_name][-50:]
        
        logger.debug(f"Operation '{metrics.operation_name}' completed in {metrics.duration_ms:.2f}ms")
    
    def get_operation_stats(self, operation_name: str) -> Dict[str, Any]:
        """Get statistics for a specific operation."""
        with self._lock:
            operation_metrics = self.operation_metrics.get(operation_name, [])
        
        if not operation_metrics:
            return {"operation": operation_name, "total_operations": 0}
        
        durations = [m.duration_ms for m in operation_metrics if m.duration_ms is not None]
        cache_hit_rates = [m.get_cache_hit_rate() for m in operation_metrics]
        success_rates = [m.get_success_rate() for m in operation_metrics]
        
        return {
            "operation": operation_name,
            "total_operations": len(operation_metrics),
            "avg_duration_ms": sum(durations) / len(durations) if durations else 0,
            "min_duration_ms": min(durations) if durations else 0,
            "max_duration_ms": max(durations) if durations else 0,
            "avg_cache_hit_rate": sum(cache_hit_rates) / len(cache_hit_rates) if cache_hit_rates else 0,
            "avg_success_rate": sum(success_rates) / len(success_rates) if success_rates else 0,
            "total_cache_hits": sum(m.cache_hits for m in operation_metrics),
            "total_cache_misses": sum(m.cache_misses for m in operation_metrics),
            "total_errors": sum(m.error_count for m in operation_metrics),
            "total_successes": sum(m.success_count for m in operation_metrics)
        }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get current system performance statistics."""
        try:
            # Current system metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Process-specific metrics
            process = psutil.Process()
            process_memory = process.memory_info()
            process_cpu = process.cpu_percent()
            
            # Network I/O
            net_io = psutil.net_io_counters()
            
            return {
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_available_gb": memory.available / 1024 / 1024 / 1024,
                    "disk_percent": (disk.used / disk.total) * 100,
                    "disk_free_gb": disk.free / 1024 / 1024 / 1024
                },
                "process": {
                    "cpu_percent": process_cpu,
                    "memory_mb": process_memory.rss / 1024 / 1024,
                    "memory_percent": process.memory_percent(),
                    "threads": process.num_threads(),
                    "open_files": len(process.open_files()),
                    "connections": len(process.connections())
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                }
            }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {"error": str(e)}
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get overall performance summary."""
        with self._lock:
            total_operations = len(self.metrics_history)
            
            if total_operations == 0:
                return {"total_operations": 0}
            
            # Calculate aggregate statistics
            recent_metrics = list(self.metrics_history)[-100:]  # Last 100 operations
            
            durations = [m.duration_ms for m in recent_metrics if m.duration_ms is not None]
            cache_hits = sum(m.cache_hits for m in recent_metrics)
            cache_misses = sum(m.cache_misses for m in recent_metrics)
            errors = sum(m.error_count for m in recent_metrics)
            successes = sum(m.success_count for m in recent_metrics)
            
            # Operation breakdown
            operation_counts = defaultdict(int)
            for metrics in recent_metrics:
                operation_counts[metrics.operation_name] += 1
        
        return {
            "total_operations": total_operations,
            "recent_operations": len(recent_metrics),
            "avg_duration_ms": sum(durations) / len(durations) if durations else 0,
            "cache_hit_rate": cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0,
            "success_rate": successes / (successes + errors) if (successes + errors) > 0 else 0,
            "operations_per_minute": len([m for m in recent_metrics 
                                        if m.start_time > datetime.utcnow() - timedelta(minutes=1)]),
            "operation_breakdown": dict(operation_counts),
            "system_stats": self.get_system_stats()
        }
    
    def _monitor_system_metrics(self) -> None:
        """Background thread to monitor system metrics."""
        while self._monitoring_active:
            try:
                system_stats = self.get_system_stats()
                system_stats["timestamp"] = datetime.utcnow()
                
                with self._lock:
                    self.system_metrics.append(system_stats)
                
                time.sleep(30)  # Monitor every 30 seconds
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def stop_monitoring(self) -> None:
        """Stop the performance monitoring."""
        self._monitoring_active = False
        if self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        logger.info("Performance monitoring stopped")


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get or create global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def performance_monitor(operation_name: Optional[str] = None):
    """Decorator to monitor function performance."""
    def decorator(func: Callable) -> Callable:
        op_name = operation_name or f"{func.__module__}.{func.__name__}"
        
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                monitor = get_performance_monitor()
                metrics = monitor.start_operation(op_name)
                
                try:
                    result = await func(*args, **kwargs)
                    metrics.add_success()
                    return result
                except Exception as e:
                    metrics.add_error()
                    raise
                finally:
                    monitor.complete_operation(metrics)
            
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                monitor = get_performance_monitor()
                metrics = monitor.start_operation(op_name)
                
                try:
                    result = func(*args, **kwargs)
                    metrics.add_success()
                    return result
                except Exception as e:
                    metrics.add_error()
                    raise
                finally:
                    monitor.complete_operation(metrics)
            
            return sync_wrapper
    
    return decorator


class BatchProcessor:
    """Optimized batch processing for multiple operations."""
    
    def __init__(self, max_workers: int = 5, batch_size: int = 10):
        """Initialize batch processor."""
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
    async def process_batch_async(
        self, 
        items: List[Any], 
        processor_func: Callable,
        progress_callback: Optional[Callable] = None
    ) -> List[Any]:
        """Process items in batches asynchronously."""
        results = []
        total_items = len(items)
        
        # Split items into batches
        batches = [items[i:i + self.batch_size] for i in range(0, len(items), self.batch_size)]
        
        monitor = get_performance_monitor()
        metrics = monitor.start_operation("batch_processing")
        
        try:
            # Process batches in parallel
            loop = asyncio.get_event_loop()
            
            for batch_idx, batch in enumerate(batches):
                # Submit batch to thread pool
                futures = []
                for item in batch:
                    future = loop.run_in_executor(self.executor, processor_func, item)
                    futures.append(future)
                
                # Wait for batch completion
                batch_results = await asyncio.gather(*futures, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error(f"Batch processing error: {result}")
                        metrics.add_error()
                        results.append(None)
                    else:
                        metrics.add_success()
                        results.append(result)
                
                # Progress callback
                if progress_callback:
                    progress = ((batch_idx + 1) * self.batch_size) / total_items
                    progress_callback(min(progress, 1.0))
            
            logger.info(f"Batch processing completed: {len(results)} items processed")
            return results
            
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            metrics.add_error()
            raise
        finally:
            monitor.complete_operation(metrics)
    
    def process_batch_sync(
        self, 
        items: List[Any], 
        processor_func: Callable,
        progress_callback: Optional[Callable] = None
    ) -> List[Any]:
        """Process items in batches synchronously."""
        results = []
        total_items = len(items)
        
        monitor = get_performance_monitor()
        metrics = monitor.start_operation("sync_batch_processing")
        
        try:
            # Submit all items to thread pool
            futures = []
            for item in items:
                future = self.executor.submit(processor_func, item)
                futures.append(future)
            
            # Collect results as they complete
            completed_count = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    metrics.add_success()
                except Exception as e:
                    logger.error(f"Batch item processing error: {e}")
                    results.append(None)
                    metrics.add_error()
                
                completed_count += 1
                
                # Progress callback
                if progress_callback:
                    progress = completed_count / total_items
                    progress_callback(progress)
            
            logger.info(f"Sync batch processing completed: {len(results)} items processed")
            return results
            
        except Exception as e:
            logger.error(f"Sync batch processing failed: {e}")
            metrics.add_error()
            raise
        finally:
            monitor.complete_operation(metrics)
    
    def __del__(self):
        """Cleanup thread pool."""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)


class MemoryOptimizer:
    """Memory optimization utilities."""
    
    def __init__(self):
        """Initialize memory optimizer."""
        self.weak_references: Dict[str, weakref.WeakSet] = defaultdict(weakref.WeakSet)
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
    
    def register_object(self, obj: Any, category: str = "default") -> None:
        """Register an object for memory tracking."""
        self.weak_references[category].add(obj)
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage statistics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            # Count tracked objects
            tracked_objects = {}
            for category, weak_set in self.weak_references.items():
                tracked_objects[category] = len(weak_set)
            
            return {
                "rss_mb": memory_info.rss / 1024 / 1024,
                "vms_mb": memory_info.vms / 1024 / 1024,
                "percent": process.memory_percent(),
                "tracked_objects": tracked_objects,
                "total_tracked": sum(tracked_objects.values())
            }
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return {"error": str(e)}
    
    def cleanup_weak_references(self) -> int:
        """Clean up dead weak references."""
        current_time = time.time()
        
        if current_time - self._last_cleanup < self._cleanup_interval:
            return 0
        
        cleaned_count = 0
        for category in list(self.weak_references.keys()):
            weak_set = self.weak_references[category]
            initial_size = len(weak_set)
            
            # WeakSet automatically removes dead references, but we can force cleanup
            # by creating a new set with only live references
            live_objects = list(weak_set)
            weak_set.clear()
            for obj in live_objects:
                weak_set.add(obj)
            
            cleaned = initial_size - len(weak_set)
            cleaned_count += cleaned
            
            if len(weak_set) == 0:
                del self.weak_references[category]
        
        self._last_cleanup = current_time
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} dead weak references")
        
        return cleaned_count
    
    def suggest_optimizations(self) -> List[str]:
        """Suggest memory optimizations based on current usage."""
        suggestions = []
        
        try:
            memory_usage = self.get_memory_usage()
            
            if "percent" in memory_usage:
                memory_percent = memory_usage["percent"]
                
                if memory_percent > 80:
                    suggestions.append("High memory usage detected. Consider reducing cache sizes.")
                
                if memory_percent > 90:
                    suggestions.append("Critical memory usage. Immediate cleanup recommended.")
                
                # Check tracked objects
                tracked = memory_usage.get("tracked_objects", {})
                for category, count in tracked.items():
                    if count > 1000:
                        suggestions.append(f"High object count in category '{category}': {count} objects")
                
                if memory_usage.get("rss_mb", 0) > 500:
                    suggestions.append("Process using over 500MB RAM. Consider memory profiling.")
        
        except Exception as e:
            suggestions.append(f"Unable to analyze memory usage: {e}")
        
        return suggestions


class ConnectionPool:
    """Optimized connection pool for external services."""
    
    def __init__(self, max_connections: int = 20, max_keepalive: int = 10):
        """Initialize connection pool."""
        self.max_connections = max_connections
        self.max_keepalive = max_keepalive
        self._connections: Dict[str, Any] = {}
        self._connection_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            "created": 0,
            "reused": 0,
            "closed": 0,
            "errors": 0
        })
        self._lock = threading.Lock()
    
    async def get_connection(self, service_name: str, **connection_kwargs) -> Any:
        """Get a connection from the pool."""
        with self._lock:
            connection_key = f"{service_name}:{hash(frozenset(connection_kwargs.items()))}"
            
            if connection_key in self._connections:
                connection = self._connections[connection_key]
                if self._is_connection_healthy(connection):
                    self._connection_stats[service_name]["reused"] += 1
                    return connection
                else:
                    # Remove unhealthy connection
                    del self._connections[connection_key]
                    self._connection_stats[service_name]["closed"] += 1
            
            # Create new connection
            try:
                connection = await self._create_connection(service_name, **connection_kwargs)
                self._connections[connection_key] = connection
                self._connection_stats[service_name]["created"] += 1
                return connection
            except Exception as e:
                self._connection_stats[service_name]["errors"] += 1
                raise
    
    async def _create_connection(self, service_name: str, **kwargs) -> Any:
        """Create a new connection (to be implemented by subclasses)."""
        # This is a placeholder - actual implementation would depend on the service
        import httpx
        return httpx.AsyncClient(**kwargs)
    
    def _is_connection_healthy(self, connection: Any) -> bool:
        """Check if a connection is healthy."""
        # Basic health check - can be extended
        return hasattr(connection, 'is_closed') and not connection.is_closed
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        with self._lock:
            return {
                "active_connections": len(self._connections),
                "max_connections": self.max_connections,
                "connection_stats": dict(self._connection_stats),
                "pool_utilization": len(self._connections) / self.max_connections
            }
    
    async def cleanup_connections(self) -> int:
        """Clean up unused or unhealthy connections."""
        cleaned_count = 0
        
        with self._lock:
            connections_to_remove = []
            
            for key, connection in self._connections.items():
                if not self._is_connection_healthy(connection):
                    connections_to_remove.append(key)
            
            for key in connections_to_remove:
                connection = self._connections[key]
                try:
                    if hasattr(connection, 'aclose'):
                        await connection.aclose()
                except Exception as e:
                    logger.warning(f"Error closing connection: {e}")
                
                del self._connections[key]
                cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} connections")
        
        return cleaned_count


# Global instances
_memory_optimizer: Optional[MemoryOptimizer] = None
_connection_pool: Optional[ConnectionPool] = None


def get_memory_optimizer() -> MemoryOptimizer:
    """Get or create global memory optimizer instance."""
    global _memory_optimizer
    if _memory_optimizer is None:
        _memory_optimizer = MemoryOptimizer()
    return _memory_optimizer


def get_connection_pool() -> ConnectionPool:
    """Get or create global connection pool instance."""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = ConnectionPool()
    return _connection_pool