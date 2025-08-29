"""Advanced queue management with priority-based scheduling."""

import asyncio
import heapq
import logging
import time
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import uuid
from collections import defaultdict, deque

from compliance_sentinel.performance.parallel_processor import ProcessingTask, TaskPriority


logger = logging.getLogger(__name__)


class QueueType(Enum):
    """Types of task queues."""
    PRIORITY = "priority"
    FIFO = "fifo"
    LIFO = "lifo"
    ROUND_ROBIN = "round_robin"
    WEIGHTED_FAIR = "weighted_fair"
    DEADLINE = "deadline"


class QueueStatus(Enum):
    """Queue status."""
    ACTIVE = "active"
    PAUSED = "paused"
    DRAINING = "draining"
    STOPPED = "stopped"


@dataclass
class QueueMetrics:
    """Queue performance metrics."""
    
    # Basic metrics
    total_enqueued: int = 0
    total_dequeued: int = 0
    total_completed: int = 0
    total_failed: int = 0
    
    # Timing metrics
    average_wait_time: float = 0.0
    average_processing_time: float = 0.0
    total_wait_time: float = 0.0
    total_processing_time: float = 0.0
    
    # Queue state
    current_size: int = 0
    peak_size: int = 0
    
    # Throughput
    throughput_per_second: float = 0.0
    
    # Priority distribution
    priority_distribution: Dict[int, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'total_enqueued': self.total_enqueued,
            'total_dequeued': self.total_dequeued,
            'total_completed': self.total_completed,
            'total_failed': self.total_failed,
            'average_wait_time': self.average_wait_time,
            'average_processing_time': self.average_processing_time,
            'total_wait_time': self.total_wait_time,
            'total_processing_time': self.total_processing_time,
            'current_size': self.current_size,
            'peak_size': self.peak_size,
            'throughput_per_second': self.throughput_per_second,
            'priority_distribution': self.priority_distribution
        }


@dataclass
class QueuedTask:
    """Wrapper for tasks in queue with metadata."""
    
    task: ProcessingTask
    queue_id: str
    enqueued_at: datetime = field(default_factory=datetime.now)
    deadline: Optional[datetime] = None
    weight: float = 1.0
    
    # For priority queue ordering
    def __lt__(self, other):
        """Compare tasks for priority ordering (higher priority first)."""
        # Primary: priority (higher first)
        if self.task.priority != other.task.priority:
            return self.task.priority > other.task.priority
        
        # Secondary: deadline (earlier first)
        if self.deadline and other.deadline:
            return self.deadline < other.deadline
        elif self.deadline:
            return True
        elif other.deadline:
            return False
        
        # Tertiary: enqueue time (earlier first)
        return self.enqueued_at < other.enqueued_at


class PriorityQueue:
    """Priority-based task queue with advanced scheduling."""
    
    def __init__(self, 
                 queue_id: str,
                 max_size: Optional[int] = None,
                 default_priority: int = TaskPriority.NORMAL.value):
        """Initialize priority queue."""
        self.queue_id = queue_id
        self.max_size = max_size
        self.default_priority = default_priority
        
        # Queue storage
        self._heap = []
        self._task_map = {}  # task_id -> QueuedTask
        
        # Metrics
        self.metrics = QueueMetrics()
        
        # Status
        self.status = QueueStatus.ACTIVE
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Callbacks
        self.callbacks = {
            'task_enqueued': [],
            'task_dequeued': [],
            'queue_full': [],
            'queue_empty': []
        }
    
    def enqueue(self, task: ProcessingTask, 
                deadline: Optional[datetime] = None,
                weight: float = 1.0) -> bool:
        """Add task to queue."""
        with self._lock:
            # Check if queue is accepting tasks
            if self.status not in [QueueStatus.ACTIVE]:
                return False
            
            # Check size limit
            if self.max_size and len(self._heap) >= self.max_size:
                self._trigger_callbacks('queue_full', task)
                return False
            
            # Create queued task
            queued_task = QueuedTask(
                task=task,
                queue_id=self.queue_id,
                deadline=deadline,
                weight=weight
            )
            
            # Add to heap and map
            heapq.heappush(self._heap, queued_task)
            self._task_map[task.task_id] = queued_task
            
            # Update metrics
            self.metrics.total_enqueued += 1
            self.metrics.current_size = len(self._heap)
            self.metrics.peak_size = max(self.metrics.peak_size, self.metrics.current_size)
            
            # Update priority distribution
            priority = task.priority
            self.metrics.priority_distribution[priority] = (
                self.metrics.priority_distribution.get(priority, 0) + 1
            )
            
            self._trigger_callbacks('task_enqueued', task)
            
            return True
    
    def dequeue(self) -> Optional[ProcessingTask]:
        """Remove and return highest priority task."""
        with self._lock:
            if not self._heap:
                return None
            
            # Get highest priority task
            queued_task = heapq.heappop(self._heap)
            
            # Remove from map
            if queued_task.task.task_id in self._task_map:
                del self._task_map[queued_task.task.task_id]
            
            # Update metrics
            self.metrics.total_dequeued += 1
            self.metrics.current_size = len(self._heap)
            
            # Calculate wait time
            wait_time = (datetime.now() - queued_task.enqueued_at).total_seconds()
            self.metrics.total_wait_time += wait_time
            
            if self.metrics.total_dequeued > 0:
                self.metrics.average_wait_time = (
                    self.metrics.total_wait_time / self.metrics.total_dequeued
                )
            
            # Update priority distribution
            priority = queued_task.task.priority
            if priority in self.metrics.priority_distribution:
                self.metrics.priority_distribution[priority] -= 1
                if self.metrics.priority_distribution[priority] == 0:
                    del self.metrics.priority_distribution[priority]
            
            self._trigger_callbacks('task_dequeued', queued_task.task)
            
            if len(self._heap) == 0:
                self._trigger_callbacks('queue_empty', None)
            
            return queued_task.task
    
    def peek(self) -> Optional[ProcessingTask]:
        """Look at highest priority task without removing it."""
        with self._lock:
            if self._heap:
                return self._heap[0].task
            return None
    
    def remove_task(self, task_id: str) -> bool:
        """Remove specific task from queue."""
        with self._lock:
            if task_id not in self._task_map:
                return False
            
            queued_task = self._task_map[task_id]
            
            # Remove from heap (mark as removed)
            queued_task.task = None  # Mark as removed
            
            # Remove from map
            del self._task_map[task_id]
            
            # Update metrics
            self.metrics.current_size = len([qt for qt in self._heap if qt.task is not None])
            
            return True
    
    def update_priority(self, task_id: str, new_priority: int) -> bool:
        """Update priority of task in queue."""
        with self._lock:
            if task_id not in self._task_map:
                return False
            
            queued_task = self._task_map[task_id]
            old_priority = queued_task.task.priority
            
            # Update priority
            queued_task.task.priority = new_priority
            
            # Rebuild heap to maintain order
            valid_tasks = [qt for qt in self._heap if qt.task is not None]
            self._heap = valid_tasks
            heapq.heapify(self._heap)
            
            # Update priority distribution
            if old_priority in self.metrics.priority_distribution:
                self.metrics.priority_distribution[old_priority] -= 1
                if self.metrics.priority_distribution[old_priority] == 0:
                    del self.metrics.priority_distribution[old_priority]
            
            self.metrics.priority_distribution[new_priority] = (
                self.metrics.priority_distribution.get(new_priority, 0) + 1
            )
            
            return True
    
    def size(self) -> int:
        """Get current queue size."""
        with self._lock:
            return len([qt for qt in self._heap if qt.task is not None])
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self.size() == 0
    
    def is_full(self) -> bool:
        """Check if queue is full."""
        if self.max_size is None:
            return False
        return self.size() >= self.max_size
    
    def clear(self):
        """Clear all tasks from queue."""
        with self._lock:
            self._heap.clear()
            self._task_map.clear()
            self.metrics.current_size = 0
    
    def pause(self):
        """Pause queue (stop accepting new tasks)."""
        self.status = QueueStatus.PAUSED
    
    def resume(self):
        """Resume queue operations."""
        self.status = QueueStatus.ACTIVE
    
    def drain(self) -> List[ProcessingTask]:
        """Drain all tasks from queue."""
        with self._lock:
            self.status = QueueStatus.DRAINING
            
            tasks = []
            while not self.is_empty():
                task = self.dequeue()
                if task:
                    tasks.append(task)
            
            self.status = QueueStatus.STOPPED
            return tasks
    
    def get_tasks_by_priority(self, priority: int) -> List[ProcessingTask]:
        """Get all tasks with specific priority."""
        with self._lock:
            return [
                qt.task for qt in self._heap 
                if qt.task and qt.task.priority == priority
            ]
    
    def get_expired_tasks(self) -> List[ProcessingTask]:
        """Get tasks that have passed their deadline."""
        with self._lock:
            current_time = datetime.now()
            return [
                qt.task for qt in self._heap
                if qt.task and qt.deadline and qt.deadline < current_time
            ]
    
    def add_callback(self, event_type: str, callback: Callable):
        """Add callback for queue events."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def _trigger_callbacks(self, event_type: str, task: Optional[ProcessingTask]):
        """Trigger callbacks for queue events."""
        callbacks = self.callbacks.get(event_type, [])
        
        for callback in callbacks:
            try:
                callback(self.queue_id, event_type, task)
            except Exception as e:
                logger.error(f"Error in queue callback: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get queue metrics."""
        with self._lock:
            # Update current size
            self.metrics.current_size = self.size()
            
            # Calculate throughput
            if self.metrics.total_wait_time > 0:
                self.metrics.throughput_per_second = (
                    self.metrics.total_dequeued / self.metrics.total_wait_time
                )
            
            return self.metrics.to_dict()


class WeightedFairQueue:
    """Weighted fair queuing for multiple priority classes."""
    
    def __init__(self, 
                 queue_id: str,
                 priority_weights: Dict[int, float] = None):
        """Initialize weighted fair queue."""
        self.queue_id = queue_id
        self.priority_weights = priority_weights or {
            TaskPriority.CRITICAL.value: 4.0,
            TaskPriority.HIGH.value: 2.0,
            TaskPriority.NORMAL.value: 1.0,
            TaskPriority.LOW.value: 0.5,
            TaskPriority.BACKGROUND.value: 0.1
        }
        
        # Separate queues for each priority
        self.priority_queues = {}
        for priority in self.priority_weights:
            self.priority_queues[priority] = deque()
        
        # Virtual time tracking for fair scheduling
        self.virtual_times = {priority: 0.0 for priority in self.priority_weights}
        self.last_service_time = time.time()
        
        # Metrics
        self.metrics = QueueMetrics()
        
        # Thread safety
        self._lock = threading.RLock()
    
    def enqueue(self, task: ProcessingTask) -> bool:
        """Add task to appropriate priority queue."""
        with self._lock:
            priority = task.priority
            
            # Create priority queue if it doesn't exist
            if priority not in self.priority_queues:
                self.priority_queues[priority] = deque()
                self.priority_weights[priority] = 1.0
                self.virtual_times[priority] = 0.0
            
            # Add to priority queue
            queued_task = QueuedTask(task=task, queue_id=self.queue_id)
            self.priority_queues[priority].append(queued_task)
            
            # Update metrics
            self.metrics.total_enqueued += 1
            self.metrics.current_size += 1
            self.metrics.peak_size = max(self.metrics.peak_size, self.metrics.current_size)
            
            return True
    
    def dequeue(self) -> Optional[ProcessingTask]:
        """Dequeue task using weighted fair scheduling."""
        with self._lock:
            if self.metrics.current_size == 0:
                return None
            
            # Find priority queue with minimum virtual time
            min_virtual_time = float('inf')
            selected_priority = None
            
            for priority, queue in self.priority_queues.items():
                if queue and self.virtual_times[priority] < min_virtual_time:
                    min_virtual_time = self.virtual_times[priority]
                    selected_priority = priority
            
            if selected_priority is None:
                return None
            
            # Dequeue from selected priority
            queued_task = self.priority_queues[selected_priority].popleft()
            
            # Update virtual time
            weight = self.priority_weights[selected_priority]
            service_time = 1.0 / weight  # Inverse of weight
            self.virtual_times[selected_priority] += service_time
            
            # Update metrics
            self.metrics.total_dequeued += 1
            self.metrics.current_size -= 1
            
            return queued_task.task
    
    def size(self) -> int:
        """Get total queue size."""
        with self._lock:
            return sum(len(queue) for queue in self.priority_queues.values())
    
    def get_priority_sizes(self) -> Dict[int, int]:
        """Get size of each priority queue."""
        with self._lock:
            return {priority: len(queue) for priority, queue in self.priority_queues.items()}


class DeadlineQueue:
    """Queue that prioritizes tasks by deadline."""
    
    def __init__(self, queue_id: str):
        """Initialize deadline queue."""
        self.queue_id = queue_id
        self._heap = []  # Min-heap by deadline
        self._task_map = {}
        self.metrics = QueueMetrics()
        self._lock = threading.RLock()
    
    def enqueue(self, task: ProcessingTask, deadline: datetime) -> bool:
        """Add task with deadline."""
        with self._lock:
            queued_task = QueuedTask(
                task=task,
                queue_id=self.queue_id,
                deadline=deadline
            )
            
            # Use deadline as priority (earlier deadline = higher priority)
            heap_item = (deadline.timestamp(), queued_task)
            heapq.heappush(self._heap, heap_item)
            self._task_map[task.task_id] = queued_task
            
            self.metrics.total_enqueued += 1
            self.metrics.current_size += 1
            
            return True
    
    def dequeue(self) -> Optional[ProcessingTask]:
        """Dequeue task with earliest deadline."""
        with self._lock:
            if not self._heap:
                return None
            
            _, queued_task = heapq.heappop(self._heap)
            
            if queued_task.task.task_id in self._task_map:
                del self._task_map[queued_task.task.task_id]
            
            self.metrics.total_dequeued += 1
            self.metrics.current_size -= 1
            
            return queued_task.task
    
    def get_overdue_tasks(self) -> List[ProcessingTask]:
        """Get tasks that are past their deadline."""
        with self._lock:
            current_time = datetime.now()
            overdue = []
            
            for _, queued_task in self._heap:
                if queued_task.deadline < current_time:
                    overdue.append(queued_task.task)
            
            return overdue


class QueueManager:
    """Manages multiple task queues with different scheduling policies."""
    
    def __init__(self):
        """Initialize queue manager."""
        self.queues = {}
        self.default_queue_id = "default"
        
        # Create default priority queue
        self.queues[self.default_queue_id] = PriorityQueue(self.default_queue_id)
        
        # Queue routing rules
        self.routing_rules = []
        
        # Global metrics
        self.global_metrics = {
            'total_queues': 0,
            'total_tasks': 0,
            'total_processed': 0,
            'average_queue_size': 0.0
        }
        
        # Monitoring
        self.monitoring_active = False
        self.monitor_task = None
        
        # Callbacks
        self.callbacks = {
            'queue_created': [],
            'queue_removed': [],
            'task_routed': []
        }
    
    def create_queue(self, 
                    queue_id: str,
                    queue_type: QueueType = QueueType.PRIORITY,
                    **kwargs) -> bool:
        """Create a new queue."""
        if queue_id in self.queues:
            return False
        
        if queue_type == QueueType.PRIORITY:
            queue = PriorityQueue(queue_id, **kwargs)
        elif queue_type == QueueType.WEIGHTED_FAIR:
            queue = WeightedFairQueue(queue_id, **kwargs)
        elif queue_type == QueueType.DEADLINE:
            queue = DeadlineQueue(queue_id)
        else:
            # Default to priority queue
            queue = PriorityQueue(queue_id, **kwargs)
        
        self.queues[queue_id] = queue
        self.global_metrics['total_queues'] = len(self.queues)
        
        self._trigger_callbacks('queue_created', queue_id)
        logger.info(f"Created queue: {queue_id} (type: {queue_type.value})")
        
        return True
    
    def remove_queue(self, queue_id: str) -> bool:
        """Remove a queue."""
        if queue_id == self.default_queue_id:
            return False  # Cannot remove default queue
        
        if queue_id in self.queues:
            # Drain queue first
            queue = self.queues[queue_id]
            if hasattr(queue, 'drain'):
                remaining_tasks = queue.drain()
                
                # Move remaining tasks to default queue
                for task in remaining_tasks:
                    self.enqueue_task(task, self.default_queue_id)
            
            del self.queues[queue_id]
            self.global_metrics['total_queues'] = len(self.queues)
            
            self._trigger_callbacks('queue_removed', queue_id)
            logger.info(f"Removed queue: {queue_id}")
            
            return True
        
        return False
    
    def enqueue_task(self, 
                    task: ProcessingTask,
                    queue_id: Optional[str] = None,
                    **kwargs) -> bool:
        """Enqueue task to specified or routed queue."""
        # Determine target queue
        if queue_id is None:
            queue_id = self._route_task(task)
        
        if queue_id not in self.queues:
            queue_id = self.default_queue_id
        
        queue = self.queues[queue_id]
        
        # Enqueue task
        success = queue.enqueue(task, **kwargs)
        
        if success:
            self.global_metrics['total_tasks'] += 1
            self._trigger_callbacks('task_routed', (task, queue_id))
        
        return success
    
    def dequeue_task(self, queue_id: Optional[str] = None) -> Optional[ProcessingTask]:
        """Dequeue task from specified queue or using round-robin."""
        if queue_id:
            if queue_id in self.queues:
                return self.queues[queue_id].dequeue()
            return None
        
        # Round-robin dequeue from all active queues
        for queue in self.queues.values():
            if hasattr(queue, 'status') and queue.status == QueueStatus.ACTIVE:
                if not queue.is_empty():
                    task = queue.dequeue()
                    if task:
                        self.global_metrics['total_processed'] += 1
                        return task
        
        return None
    
    def dequeue_batch(self, 
                     batch_size: int,
                     queue_id: Optional[str] = None) -> List[ProcessingTask]:
        """Dequeue multiple tasks."""
        tasks = []
        
        for _ in range(batch_size):
            task = self.dequeue_task(queue_id)
            if task:
                tasks.append(task)
            else:
                break
        
        return tasks
    
    def add_routing_rule(self, 
                        condition: Callable[[ProcessingTask], bool],
                        target_queue: str,
                        priority: int = 0):
        """Add task routing rule."""
        rule = {
            'condition': condition,
            'target_queue': target_queue,
            'priority': priority
        }
        
        self.routing_rules.append(rule)
        
        # Sort by priority (higher priority first)
        self.routing_rules.sort(key=lambda r: r['priority'], reverse=True)
    
    def _route_task(self, task: ProcessingTask) -> str:
        """Route task to appropriate queue based on rules."""
        for rule in self.routing_rules:
            try:
                if rule['condition'](task):
                    target_queue = rule['target_queue']
                    if target_queue in self.queues:
                        return target_queue
            except Exception as e:
                logger.error(f"Error in routing rule: {e}")
        
        return self.default_queue_id
    
    def get_queue_status(self, queue_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of specific queue or all queues."""
        if queue_id:
            if queue_id in self.queues:
                queue = self.queues[queue_id]
                return {
                    'queue_id': queue_id,
                    'size': queue.size(),
                    'is_empty': queue.is_empty(),
                    'status': queue.status.value if hasattr(queue, 'status') else 'active',
                    'metrics': queue.get_metrics() if hasattr(queue, 'get_metrics') else {}
                }
            return {}
        
        # Return status of all queues
        status = {}
        for qid, queue in self.queues.items():
            status[qid] = {
                'size': queue.size(),
                'is_empty': queue.is_empty(),
                'status': queue.status.value if hasattr(queue, 'status') else 'active',
                'metrics': queue.get_metrics() if hasattr(queue, 'get_metrics') else {}
            }
        
        return status
    
    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global queue manager metrics."""
        # Update average queue size
        if self.queues:
            total_size = sum(queue.size() for queue in self.queues.values())
            self.global_metrics['average_queue_size'] = total_size / len(self.queues)
        
        return self.global_metrics.copy()
    
    def pause_queue(self, queue_id: str) -> bool:
        """Pause a specific queue."""
        if queue_id in self.queues:
            queue = self.queues[queue_id]
            if hasattr(queue, 'pause'):
                queue.pause()
                return True
        return False
    
    def resume_queue(self, queue_id: str) -> bool:
        """Resume a specific queue."""
        if queue_id in self.queues:
            queue = self.queues[queue_id]
            if hasattr(queue, 'resume'):
                queue.resume()
                return True
        return False
    
    def clear_queue(self, queue_id: str) -> bool:
        """Clear all tasks from a queue."""
        if queue_id in self.queues:
            queue = self.queues[queue_id]
            if hasattr(queue, 'clear'):
                queue.clear()
                return True
        return False
    
    def add_callback(self, event_type: str, callback: Callable):
        """Add callback for queue manager events."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def _trigger_callbacks(self, event_type: str, data: Any):
        """Trigger callbacks for queue manager events."""
        callbacks = self.callbacks.get(event_type, [])
        
        for callback in callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                logger.error(f"Error in queue manager callback: {e}")
    
    async def start_monitoring(self, interval: float = 30.0):
        """Start queue monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop(interval))
        logger.info("Queue monitoring started")
    
    async def stop_monitoring(self):
        """Stop queue monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Queue monitoring stopped")
    
    async def _monitoring_loop(self, interval: float):
        """Queue monitoring loop."""
        while self.monitoring_active:
            try:
                # Log queue status
                status = self.get_queue_status()
                total_tasks = sum(q['size'] for q in status.values())
                
                if total_tasks > 0:
                    logger.info(f"Queue status: {len(status)} queues, {total_tasks} total tasks")
                
                # Check for overloaded queues
                for queue_id, queue_status in status.items():
                    if queue_status['size'] > 1000:  # Threshold for overload
                        logger.warning(f"Queue {queue_id} is overloaded: {queue_status['size']} tasks")
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in queue monitoring: {e}")
                await asyncio.sleep(10)


# Utility functions for common queue operations

def create_task_routing_rules(queue_manager: QueueManager):
    """Create common task routing rules."""
    
    # High priority tasks to dedicated queue
    queue_manager.add_routing_rule(
        condition=lambda task: task.priority >= TaskPriority.HIGH.value,
        target_queue="high_priority",
        priority=10
    )
    
    # ML inference tasks to ML queue
    queue_manager.add_routing_rule(
        condition=lambda task: task.task_type == "ml_inference",
        target_queue="ml_processing",
        priority=8
    )
    
    # Large file analysis to dedicated queue
    queue_manager.add_routing_rule(
        condition=lambda task: task.task_type == "large_file_analysis",
        target_queue="large_files",
        priority=6
    )
    
    # Background tasks to low priority queue
    queue_manager.add_routing_rule(
        condition=lambda task: task.priority <= TaskPriority.BACKGROUND.value,
        target_queue="background",
        priority=1
    )


def setup_default_queues(queue_manager: QueueManager):
    """Setup default queue configuration."""
    
    # High priority queue
    queue_manager.create_queue(
        "high_priority",
        QueueType.PRIORITY,
        max_size=500
    )
    
    # ML processing queue
    queue_manager.create_queue(
        "ml_processing",
        QueueType.WEIGHTED_FAIR,
        priority_weights={
            TaskPriority.CRITICAL.value: 3.0,
            TaskPriority.HIGH.value: 2.0,
            TaskPriority.NORMAL.value: 1.0
        }
    )
    
    # Large files queue
    queue_manager.create_queue(
        "large_files",
        QueueType.PRIORITY,
        max_size=100
    )
    
    # Background processing queue
    queue_manager.create_queue(
        "background",
        QueueType.FIFO,
        max_size=1000
    )
    
    # Setup routing rules
    create_task_routing_rules(queue_manager)