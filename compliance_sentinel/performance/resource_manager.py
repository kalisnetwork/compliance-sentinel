"""Resource management and dynamic scaling system."""

import asyncio
import logging
import psutil
import threading
import time
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import weakref
import gc
import os
import signal

from compliance_sentinel.performance.parallel_processor import ProcessingTask, TaskPriority


logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of system resources."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    GPU = "gpu"
    CUSTOM = "custom"


class ResourceStatus(Enum):
    """Resource pool status."""
    AVAILABLE = "available"
    BUSY = "busy"
    OVERLOADED = "overloaded"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class ScalingAction(Enum):
    """Scaling actions."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"
    THROTTLE = "throttle"


@dataclass
class ResourceMetrics:
    """System resource metrics."""
    
    # CPU metrics
    cpu_percent: float = 0.0
    cpu_count: int = 0
    cpu_freq_current: float = 0.0
    cpu_freq_max: float = 0.0
    load_average: List[float] = field(default_factory=list)
    
    # Memory metrics
    memory_total: int = 0
    memory_available: int = 0
    memory_used: int = 0
    memory_percent: float = 0.0
    swap_total: int = 0
    swap_used: int = 0
    swap_percent: float = 0.0
    
    # Disk metrics
    disk_total: int = 0
    disk_used: int = 0
    disk_free: int = 0
    disk_percent: float = 0.0
    disk_io_read_bytes: int = 0
    disk_io_write_bytes: int = 0
    disk_io_read_count: int = 0
    disk_io_write_count: int = 0
    
    # Network metrics
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    network_packets_sent: int = 0
    network_packets_recv: int = 0
    
    # Process metrics
    process_count: int = 0
    thread_count: int = 0
    
    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'cpu_percent': self.cpu_percent,
            'cpu_count': self.cpu_count,
            'cpu_freq_current': self.cpu_freq_current,
            'cpu_freq_max': self.cpu_freq_max,
            'load_average': self.load_average,
            'memory_total': self.memory_total,
            'memory_available': self.memory_available,
            'memory_used': self.memory_used,
            'memory_percent': self.memory_percent,
            'swap_total': self.swap_total,
            'swap_used': self.swap_used,
            'swap_percent': self.swap_percent,
            'disk_total': self.disk_total,
            'disk_used': self.disk_used,
            'disk_free': self.disk_free,
            'disk_percent': self.disk_percent,
            'disk_io_read_bytes': self.disk_io_read_bytes,
            'disk_io_write_bytes': self.disk_io_write_bytes,
            'disk_io_read_count': self.disk_io_read_count,
            'disk_io_write_count': self.disk_io_write_count,
            'network_bytes_sent': self.network_bytes_sent,
            'network_bytes_recv': self.network_bytes_recv,
            'network_packets_sent': self.network_packets_sent,
            'network_packets_recv': self.network_packets_recv,
            'process_count': self.process_count,
            'thread_count': self.thread_count,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ResourceLimits:
    """Resource usage limits and thresholds."""
    
    # CPU limits
    cpu_percent_warning: float = 70.0
    cpu_percent_critical: float = 90.0
    cpu_percent_max: float = 95.0
    
    # Memory limits
    memory_percent_warning: float = 70.0
    memory_percent_critical: float = 85.0
    memory_percent_max: float = 95.0
    
    # Disk limits
    disk_percent_warning: float = 80.0
    disk_percent_critical: float = 90.0
    disk_percent_max: float = 95.0
    
    # Process limits
    max_processes: int = 1000
    max_threads: int = 5000
    
    # Custom limits
    custom_limits: Dict[str, float] = field(default_factory=dict)
    
    def is_cpu_overloaded(self, cpu_percent: float) -> bool:
        """Check if CPU is overloaded."""
        return cpu_percent >= self.cpu_percent_critical
    
    def is_memory_overloaded(self, memory_percent: float) -> bool:
        """Check if memory is overloaded."""
        return memory_percent >= self.memory_percent_critical
    
    def is_disk_overloaded(self, disk_percent: float) -> bool:
        """Check if disk is overloaded."""
        return disk_percent >= self.disk_percent_critical
    
    def get_resource_status(self, metrics: ResourceMetrics) -> ResourceStatus:
        """Get overall resource status based on metrics."""
        if (self.is_cpu_overloaded(metrics.cpu_percent) or
            self.is_memory_overloaded(metrics.memory_percent) or
            self.is_disk_overloaded(metrics.disk_percent)):
            return ResourceStatus.OVERLOADED
        
        if (metrics.cpu_percent >= self.cpu_percent_warning or
            metrics.memory_percent >= self.memory_percent_warning or
            metrics.disk_percent >= self.disk_percent_warning):
            return ResourceStatus.BUSY
        
        return ResourceStatus.AVAILABLE


@dataclass
class ResourcePool:
    """Represents a pool of resources."""
    
    pool_id: str
    resource_type: ResourceType
    capacity: int
    allocated: int = 0
    reserved: int = 0
    status: ResourceStatus = ResourceStatus.AVAILABLE
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    # Usage tracking
    total_allocations: int = 0
    total_deallocations: int = 0
    peak_usage: int = 0
    
    @property
    def available(self) -> int:
        """Get available resources."""
        return self.capacity - self.allocated - self.reserved
    
    @property
    def utilization_percent(self) -> float:
        """Get utilization percentage."""
        if self.capacity == 0:
            return 0.0
        return (self.allocated / self.capacity) * 100.0
    
    def allocate(self, amount: int) -> bool:
        """Allocate resources from pool."""
        if self.available >= amount:
            self.allocated += amount
            self.total_allocations += amount
            self.peak_usage = max(self.peak_usage, self.allocated)
            self.last_updated = datetime.now()
            return True
        return False
    
    def deallocate(self, amount: int) -> bool:
        """Deallocate resources back to pool."""
        if self.allocated >= amount:
            self.allocated -= amount
            self.total_deallocations += amount
            self.last_updated = datetime.now()
            return True
        return False
    
    def reserve(self, amount: int) -> bool:
        """Reserve resources for future allocation."""
        if self.available >= amount:
            self.reserved += amount
            self.last_updated = datetime.now()
            return True
        return False
    
    def unreserve(self, amount: int) -> bool:
        """Unreserve resources."""
        if self.reserved >= amount:
            self.reserved -= amount
            self.last_updated = datetime.now()
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pool to dictionary."""
        return {
            'pool_id': self.pool_id,
            'resource_type': self.resource_type.value,
            'capacity': self.capacity,
            'allocated': self.allocated,
            'reserved': self.reserved,
            'available': self.available,
            'status': self.status.value,
            'utilization_percent': self.utilization_percent,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'total_allocations': self.total_allocations,
            'total_deallocations': self.total_deallocations,
            'peak_usage': self.peak_usage
        }


class ResourceMonitor:
    """Monitors system resource usage."""
    
    def __init__(self, 
                 monitoring_interval: float = 5.0,
                 history_size: int = 1000):
        """Initialize resource monitor."""
        self.monitoring_interval = monitoring_interval
        self.history_size = history_size
        
        self.metrics_history = []
        self.current_metrics = ResourceMetrics()
        
        self.monitoring_active = False
        self.monitor_task = None
        
        # Baseline metrics for comparison
        self.baseline_metrics = None
        self.baseline_samples = 10
        
        # Callbacks for resource events
        self.callbacks = {
            'high_cpu': [],
            'high_memory': [],
            'high_disk': [],
            'low_resources': [],
            'resource_recovered': []
        }
    
    async def start_monitoring(self):
        """Start resource monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Resource monitoring started")
    
    async def stop_monitoring(self):
        """Stop resource monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Resource monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        baseline_count = 0
        
        while self.monitoring_active:
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                
                # Store current metrics
                self.current_metrics = metrics
                
                # Add to history
                self.metrics_history.append(metrics)
                if len(self.metrics_history) > self.history_size:
                    self.metrics_history.pop(0)
                
                # Establish baseline
                if self.baseline_metrics is None and baseline_count < self.baseline_samples:
                    baseline_count += 1
                    if baseline_count == self.baseline_samples:
                        self._establish_baseline()
                
                # Check for resource events
                await self._check_resource_events(metrics)
                
                await asyncio.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(10)
    
    def _collect_metrics(self) -> ResourceMetrics:
        """Collect current system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network metrics
            network_io = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            
            # Thread count (approximate)
            thread_count = 0
            try:
                for proc in psutil.process_iter(['num_threads']):
                    thread_count += proc.info['num_threads'] or 0
            except:
                thread_count = 0
            
            return ResourceMetrics(
                cpu_percent=cpu_percent,
                cpu_count=cpu_count,
                cpu_freq_current=cpu_freq.current if cpu_freq else 0,
                cpu_freq_max=cpu_freq.max if cpu_freq else 0,
                load_average=list(load_avg),
                memory_total=memory.total,
                memory_available=memory.available,
                memory_used=memory.used,
                memory_percent=memory.percent,
                swap_total=swap.total,
                swap_used=swap.used,
                swap_percent=swap.percent,
                disk_total=disk.total,
                disk_used=disk.used,
                disk_free=disk.free,
                disk_percent=(disk.used / disk.total * 100) if disk.total > 0 else 0,
                disk_io_read_bytes=disk_io.read_bytes if disk_io else 0,
                disk_io_write_bytes=disk_io.write_bytes if disk_io else 0,
                disk_io_read_count=disk_io.read_count if disk_io else 0,
                disk_io_write_count=disk_io.write_count if disk_io else 0,
                network_bytes_sent=network_io.bytes_sent if network_io else 0,
                network_bytes_recv=network_io.bytes_recv if network_io else 0,
                network_packets_sent=network_io.packets_sent if network_io else 0,
                network_packets_recv=network_io.packets_recv if network_io else 0,
                process_count=process_count,
                thread_count=thread_count
            )
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return ResourceMetrics()
    
    def _establish_baseline(self):
        """Establish baseline metrics from initial samples."""
        if len(self.metrics_history) < self.baseline_samples:
            return
        
        recent_metrics = self.metrics_history[-self.baseline_samples:]
        
        # Calculate averages for baseline
        self.baseline_metrics = ResourceMetrics(
            cpu_percent=sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
            memory_percent=sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
            disk_percent=sum(m.disk_percent for m in recent_metrics) / len(recent_metrics),
            process_count=sum(m.process_count for m in recent_metrics) / len(recent_metrics),
            thread_count=sum(m.thread_count for m in recent_metrics) / len(recent_metrics)
        )
        
        logger.info(f"Established resource baseline: CPU={self.baseline_metrics.cpu_percent:.1f}%, "
                   f"Memory={self.baseline_metrics.memory_percent:.1f}%, "
                   f"Disk={self.baseline_metrics.disk_percent:.1f}%")
    
    async def _check_resource_events(self, metrics: ResourceMetrics):
        """Check for resource events and trigger callbacks."""
        # High CPU usage
        if metrics.cpu_percent > 80:
            await self._trigger_callbacks('high_cpu', metrics)
        
        # High memory usage
        if metrics.memory_percent > 80:
            await self._trigger_callbacks('high_memory', metrics)
        
        # High disk usage
        if metrics.disk_percent > 80:
            await self._trigger_callbacks('high_disk', metrics)
        
        # Low available resources
        if (metrics.cpu_percent > 90 or 
            metrics.memory_percent > 90 or 
            metrics.disk_percent > 95):
            await self._trigger_callbacks('low_resources', metrics)
    
    async def _trigger_callbacks(self, event_type: str, metrics: ResourceMetrics):
        """Trigger callbacks for resource events."""
        callbacks = self.callbacks.get(event_type, [])
        
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event_type, metrics)
                else:
                    callback(event_type, metrics)
            except Exception as e:
                logger.error(f"Error in resource callback: {e}")
    
    def add_callback(self, event_type: str, callback: Callable):
        """Add callback for resource events."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def get_current_metrics(self) -> ResourceMetrics:
        """Get current resource metrics."""
        return self.current_metrics
    
    def get_metrics_history(self, limit: int = 100) -> List[ResourceMetrics]:
        """Get recent metrics history."""
        return self.metrics_history[-limit:]
    
    def get_resource_trends(self, window_minutes: int = 30) -> Dict[str, float]:
        """Get resource usage trends over time window."""
        if not self.metrics_history:
            return {}
        
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        recent_metrics = [
            m for m in self.metrics_history 
            if m.timestamp >= cutoff_time
        ]
        
        if len(recent_metrics) < 2:
            return {}
        
        # Calculate trends (positive = increasing, negative = decreasing)
        first = recent_metrics[0]
        last = recent_metrics[-1]
        
        return {
            'cpu_trend': last.cpu_percent - first.cpu_percent,
            'memory_trend': last.memory_percent - first.memory_percent,
            'disk_trend': last.disk_percent - first.disk_percent,
            'process_trend': last.process_count - first.process_count
        }


class ResourceManager:
    """Manages system resources and dynamic scaling."""
    
    def __init__(self, 
                 limits: ResourceLimits = None,
                 monitoring_interval: float = 5.0,
                 scaling_cooldown: int = 60):
        """Initialize resource manager."""
        self.limits = limits or ResourceLimits()
        self.monitoring_interval = monitoring_interval
        self.scaling_cooldown = scaling_cooldown
        
        # Resource monitoring
        self.monitor = ResourceMonitor(monitoring_interval)
        
        # Resource pools
        self.pools = {}
        
        # Scaling state
        self.last_scaling_action = None
        self.last_scaling_time = None
        self.scaling_history = []
        
        # Task management
        self.active_tasks = weakref.WeakSet()
        self.task_queue = asyncio.Queue()
        
        # Callbacks
        self.scaling_callbacks = []
        
        # Initialize default pools
        self._initialize_default_pools()
        
        # Setup monitoring callbacks
        self.monitor.add_callback('high_cpu', self._handle_high_cpu)
        self.monitor.add_callback('high_memory', self._handle_high_memory)
        self.monitor.add_callback('low_resources', self._handle_low_resources)
    
    def _initialize_default_pools(self):
        """Initialize default resource pools."""
        # CPU pool
        cpu_count = psutil.cpu_count()
        self.pools['cpu'] = ResourcePool(
            pool_id='cpu',
            resource_type=ResourceType.CPU,
            capacity=cpu_count * 100  # 100 units per CPU core
        )
        
        # Memory pool (in MB)
        memory_total = psutil.virtual_memory().total // (1024 * 1024)
        self.pools['memory'] = ResourcePool(
            pool_id='memory',
            resource_type=ResourceType.MEMORY,
            capacity=int(memory_total * 0.8)  # Reserve 20% for system
        )
        
        # Disk pool (in MB)
        disk_total = psutil.disk_usage('/').total // (1024 * 1024)
        self.pools['disk'] = ResourcePool(
            pool_id='disk',
            resource_type=ResourceType.DISK,
            capacity=int(disk_total * 0.1)  # Only 10% for cache/temp
        )
    
    async def start(self):
        """Start resource management."""
        await self.monitor.start_monitoring()
        logger.info("Resource manager started")
    
    async def stop(self):
        """Stop resource management."""
        await self.monitor.stop_monitoring()
        logger.info("Resource manager stopped")
    
    def allocate_resources(self, 
                          task: ProcessingTask,
                          cpu_units: int = 100,
                          memory_mb: int = 100,
                          disk_mb: int = 0) -> bool:
        """Allocate resources for a task."""
        # Check if resources are available
        cpu_pool = self.pools.get('cpu')
        memory_pool = self.pools.get('memory')
        disk_pool = self.pools.get('disk')
        
        if not cpu_pool or not memory_pool:
            return False
        
        # Try to allocate
        allocations = []
        
        if cpu_pool.allocate(cpu_units):
            allocations.append(('cpu', cpu_units))
        else:
            return False
        
        if memory_pool.allocate(memory_mb):
            allocations.append(('memory', memory_mb))
        else:
            # Rollback CPU allocation
            cpu_pool.deallocate(cpu_units)
            return False
        
        if disk_mb > 0 and disk_pool:
            if disk_pool.allocate(disk_mb):
                allocations.append(('disk', disk_mb))
            else:
                # Rollback previous allocations
                cpu_pool.deallocate(cpu_units)
                memory_pool.deallocate(memory_mb)
                return False
        
        # Store allocation info with task
        task.resource_allocations = allocations
        self.active_tasks.add(task)
        
        return True
    
    def deallocate_resources(self, task: ProcessingTask) -> bool:
        """Deallocate resources from a completed task."""
        if not hasattr(task, 'resource_allocations'):
            return False
        
        success = True
        
        for pool_id, amount in task.resource_allocations:
            pool = self.pools.get(pool_id)
            if pool:
                if not pool.deallocate(amount):
                    success = False
                    logger.warning(f"Failed to deallocate {amount} units from {pool_id} pool")
        
        # Remove from active tasks
        if task in self.active_tasks:
            self.active_tasks.discard(task)
        
        return success
    
    def get_resource_availability(self) -> Dict[str, Dict[str, Any]]:
        """Get current resource availability."""
        availability = {}
        
        for pool_id, pool in self.pools.items():
            availability[pool_id] = {
                'total': pool.capacity,
                'allocated': pool.allocated,
                'available': pool.available,
                'utilization_percent': pool.utilization_percent,
                'status': pool.status.value
            }
        
        return availability
    
    def can_handle_task(self, 
                       cpu_units: int = 100,
                       memory_mb: int = 100,
                       disk_mb: int = 0) -> bool:
        """Check if system can handle a task with given resource requirements."""
        cpu_pool = self.pools.get('cpu')
        memory_pool = self.pools.get('memory')
        disk_pool = self.pools.get('disk')
        
        if not cpu_pool or not memory_pool:
            return False
        
        # Check availability
        if cpu_pool.available < cpu_units:
            return False
        
        if memory_pool.available < memory_mb:
            return False
        
        if disk_mb > 0 and disk_pool and disk_pool.available < disk_mb:
            return False
        
        return True
    
    def get_optimal_concurrency(self) -> int:
        """Calculate optimal concurrency based on current resources."""
        metrics = self.monitor.get_current_metrics()
        
        # Base concurrency on CPU cores
        base_concurrency = psutil.cpu_count()
        
        # Adjust based on current utilization
        cpu_factor = max(0.1, (100 - metrics.cpu_percent) / 100)
        memory_factor = max(0.1, (100 - metrics.memory_percent) / 100)
        
        # Use the most constraining factor
        limiting_factor = min(cpu_factor, memory_factor)
        
        optimal = int(base_concurrency * limiting_factor)
        return max(1, optimal)
    
    async def _handle_high_cpu(self, event_type: str, metrics: ResourceMetrics):
        """Handle high CPU usage event."""
        logger.warning(f"High CPU usage detected: {metrics.cpu_percent:.1f}%")
        
        # Trigger scaling decision
        action = await self._decide_scaling_action(metrics)
        if action != ScalingAction.MAINTAIN:
            await self._execute_scaling_action(action, metrics)
    
    async def _handle_high_memory(self, event_type: str, metrics: ResourceMetrics):
        """Handle high memory usage event."""
        logger.warning(f"High memory usage detected: {metrics.memory_percent:.1f}%")
        
        # Trigger garbage collection
        gc.collect()
        
        # Trigger scaling decision
        action = await self._decide_scaling_action(metrics)
        if action != ScalingAction.MAINTAIN:
            await self._execute_scaling_action(action, metrics)
    
    async def _handle_low_resources(self, event_type: str, metrics: ResourceMetrics):
        """Handle critically low resources."""
        logger.critical(f"Critically low resources: CPU={metrics.cpu_percent:.1f}%, "
                       f"Memory={metrics.memory_percent:.1f}%, Disk={metrics.disk_percent:.1f}%")
        
        # Immediate throttling
        await self._execute_scaling_action(ScalingAction.THROTTLE, metrics)
    
    async def _decide_scaling_action(self, metrics: ResourceMetrics) -> ScalingAction:
        """Decide what scaling action to take based on metrics."""
        # Check cooldown period
        if (self.last_scaling_time and 
            (datetime.now() - self.last_scaling_time).total_seconds() < self.scaling_cooldown):
            return ScalingAction.MAINTAIN
        
        # Determine action based on resource usage
        if (metrics.cpu_percent > self.limits.cpu_percent_critical or
            metrics.memory_percent > self.limits.memory_percent_critical):
            return ScalingAction.THROTTLE
        
        elif (metrics.cpu_percent > self.limits.cpu_percent_warning or
              metrics.memory_percent > self.limits.memory_percent_warning):
            return ScalingAction.SCALE_DOWN
        
        elif (metrics.cpu_percent < 30 and metrics.memory_percent < 30):
            return ScalingAction.SCALE_UP
        
        return ScalingAction.MAINTAIN
    
    async def _execute_scaling_action(self, action: ScalingAction, metrics: ResourceMetrics):
        """Execute a scaling action."""
        logger.info(f"Executing scaling action: {action.value}")
        
        if action == ScalingAction.SCALE_UP:
            await self._scale_up(metrics)
        elif action == ScalingAction.SCALE_DOWN:
            await self._scale_down(metrics)
        elif action == ScalingAction.THROTTLE:
            await self._throttle_resources(metrics)
        
        # Record scaling action
        self.last_scaling_action = action
        self.last_scaling_time = datetime.now()
        
        self.scaling_history.append({
            'action': action.value,
            'timestamp': self.last_scaling_time,
            'metrics': metrics.to_dict()
        })
        
        # Keep only recent history
        if len(self.scaling_history) > 100:
            self.scaling_history = self.scaling_history[-50:]
        
        # Notify callbacks
        await self._notify_scaling_callbacks(action, metrics)
    
    async def _scale_up(self, metrics: ResourceMetrics):
        """Scale up resources (increase concurrency)."""
        # Increase pool capacities if possible
        for pool in self.pools.values():
            if pool.utilization_percent < 50:
                # Increase capacity by 20%
                additional_capacity = int(pool.capacity * 0.2)
                pool.capacity += additional_capacity
                logger.info(f"Increased {pool.pool_id} pool capacity by {additional_capacity}")
    
    async def _scale_down(self, metrics: ResourceMetrics):
        """Scale down resources (decrease concurrency)."""
        # Reduce pool capacities
        for pool in self.pools.values():
            if pool.utilization_percent > 70:
                # Decrease capacity by 10%
                reduction = int(pool.capacity * 0.1)
                new_capacity = max(pool.allocated + pool.reserved, pool.capacity - reduction)
                pool.capacity = new_capacity
                logger.info(f"Reduced {pool.pool_id} pool capacity to {new_capacity}")
    
    async def _throttle_resources(self, metrics: ResourceMetrics):
        """Throttle resource usage during overload."""
        # Reduce all pool capacities significantly
        for pool in self.pools.values():
            # Reduce to current allocation + small buffer
            buffer = max(10, int(pool.capacity * 0.05))
            new_capacity = pool.allocated + buffer
            pool.capacity = new_capacity
            pool.status = ResourceStatus.OVERLOADED
            logger.warning(f"Throttled {pool.pool_id} pool capacity to {new_capacity}")
        
        # Force garbage collection
        gc.collect()
    
    async def _notify_scaling_callbacks(self, action: ScalingAction, metrics: ResourceMetrics):
        """Notify registered scaling callbacks."""
        for callback in self.scaling_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(action, metrics)
                else:
                    callback(action, metrics)
            except Exception as e:
                logger.error(f"Error in scaling callback: {e}")
    
    def add_scaling_callback(self, callback: Callable):
        """Add callback for scaling events."""
        self.scaling_callbacks.append(callback)
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get comprehensive resource statistics."""
        current_metrics = self.monitor.get_current_metrics()
        
        return {
            'current_metrics': current_metrics.to_dict(),
            'resource_pools': {pool_id: pool.to_dict() for pool_id, pool in self.pools.items()},
            'limits': {
                'cpu_warning': self.limits.cpu_percent_warning,
                'cpu_critical': self.limits.cpu_percent_critical,
                'memory_warning': self.limits.memory_percent_warning,
                'memory_critical': self.limits.memory_percent_critical,
                'disk_warning': self.limits.disk_percent_warning,
                'disk_critical': self.limits.disk_percent_critical
            },
            'scaling_history': self.scaling_history[-10:],  # Last 10 actions
            'active_tasks': len(self.active_tasks),
            'optimal_concurrency': self.get_optimal_concurrency()
        }
    
    def create_custom_pool(self, 
                          pool_id: str,
                          resource_type: ResourceType,
                          capacity: int) -> bool:
        """Create a custom resource pool."""
        if pool_id in self.pools:
            return False
        
        self.pools[pool_id] = ResourcePool(
            pool_id=pool_id,
            resource_type=resource_type,
            capacity=capacity
        )
        
        logger.info(f"Created custom resource pool: {pool_id} with capacity {capacity}")
        return True
    
    def remove_pool(self, pool_id: str) -> bool:
        """Remove a resource pool."""
        if pool_id in self.pools and pool_id not in ['cpu', 'memory', 'disk']:
            pool = self.pools[pool_id]
            if pool.allocated == 0:
                del self.pools[pool_id]
                logger.info(f"Removed resource pool: {pool_id}")
                return True
        
        return False


# Utility functions for resource management

def estimate_task_resources(task: ProcessingTask) -> Dict[str, int]:
    """Estimate resource requirements for a task."""
    # Base requirements
    cpu_units = 100
    memory_mb = 100
    disk_mb = 0
    
    # Adjust based on task type
    if task.task_type == 'ml_inference':
        cpu_units = 200
        memory_mb = 500
    elif task.task_type == 'large_file_analysis':
        cpu_units = 150
        memory_mb = 300
        disk_mb = 50
    elif task.task_type == 'batch_analysis':
        cpu_units = 300
        memory_mb = 200
    
    # Adjust based on priority
    if task.priority >= TaskPriority.HIGH.value:
        cpu_units = int(cpu_units * 1.5)
        memory_mb = int(memory_mb * 1.2)
    
    return {
        'cpu_units': cpu_units,
        'memory_mb': memory_mb,
        'disk_mb': disk_mb
    }


def get_system_resource_info() -> Dict[str, Any]:
    """Get comprehensive system resource information."""
    try:
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
            'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0
        }
        
        memory_info = {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available,
            'percent': psutil.virtual_memory().percent
        }
        
        disk_info = {
            'total': psutil.disk_usage('/').total,
            'used': psutil.disk_usage('/').used,
            'free': psutil.disk_usage('/').free,
            'percent': psutil.disk_usage('/').used / psutil.disk_usage('/').total * 100
        }
        
        return {
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_info,
            'platform': psutil.LINUX or psutil.WINDOWS or psutil.MACOS
        }
        
    except Exception as e:
        logger.error(f"Error getting system resource info: {e}")
        return {}