"""Async utilities for the Compliance Sentinel system."""

import asyncio
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class TaskInfo:
    """Information about an async task."""
    task_id: str
    task_name: str
    created_at: datetime
    timeout: Optional[float] = None
    task: Optional[asyncio.Task] = None


class AsyncRateLimiter:
    """Async rate limiter with token bucket algorithm."""
    
    def __init__(self, rate: float, burst: int = 1):
        """
        Initialize rate limiter.
        
        Args:
            rate: Requests per second allowed
            burst: Maximum burst size (tokens in bucket)
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass
    
    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.time()
            
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            # If no tokens available, wait
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class AsyncTaskManager:
    """Manages async tasks with timeout and cancellation support."""
    
    def __init__(self):
        """Initialize task manager."""
        self.tasks: Dict[str, TaskInfo] = {}
        self.completed_tasks: Dict[str, TaskInfo] = {}
        self.max_completed_history = 1000
        
    async def submit_task(
        self, 
        coro, 
        task_name: str = "unnamed_task",
        timeout: Optional[float] = None
    ) -> str:
        """
        Submit a coroutine as a managed task.
        
        Args:
            coro: Coroutine to execute
            task_name: Human-readable task name
            timeout: Optional timeout in seconds
            
        Returns:
            Task ID for tracking
        """
        import uuid
        task_id = str(uuid.uuid4())[:8]
        
        # Create task info
        task_info = TaskInfo(
            task_id=task_id,
            task_name=task_name,
            created_at=datetime.utcnow(),
            timeout=timeout
        )
        
        # Create and start the task
        task = asyncio.create_task(self._run_with_timeout(coro, timeout))
        task_info.task = task
        
        # Store task info
        self.tasks[task_id] = task_info
        
        # Set up completion callback
        task.add_done_callback(lambda t: self._on_task_complete(task_id))
        
        logger.debug(f"Submitted task {task_id}: {task_name}")
        return task_id
    
    async def _run_with_timeout(self, coro, timeout: Optional[float]):
        """Run coroutine with optional timeout."""
        if timeout:
            return await asyncio.wait_for(coro, timeout=timeout)
        else:
            return await coro
    
    def _on_task_complete(self, task_id: str) -> None:
        """Handle task completion."""
        if task_id in self.tasks:
            task_info = self.tasks.pop(task_id)
            
            # Move to completed tasks
            self.completed_tasks[task_id] = task_info
            
            # Trim completed tasks history
            if len(self.completed_tasks) > self.max_completed_history:
                # Remove oldest completed tasks
                oldest_tasks = sorted(
                    self.completed_tasks.items(),
                    key=lambda x: x[1].created_at
                )
                for old_task_id, _ in oldest_tasks[:len(oldest_tasks) - self.max_completed_history//2]:
                    del self.completed_tasks[old_task_id]
            
            logger.debug(f"Task {task_id} completed")
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task.
        
        Args:
            task_id: ID of task to cancel
            
        Returns:
            True if task was cancelled, False if not found or already complete
        """
        if task_id in self.tasks:
            task_info = self.tasks[task_id]
            if task_info.task and not task_info.task.done():
                task_info.task.cancel()
                logger.info(f"Cancelled task {task_id}: {task_info.task_name}")
                return True
        return False
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a task."""
        # Check active tasks
        if task_id in self.tasks:
            task_info = self.tasks[task_id]
            task = task_info.task
            
            if task is None:
                status = "pending"
            elif task.done():
                if task.cancelled():
                    status = "cancelled"
                elif task.exception():
                    status = "failed"
                else:
                    status = "completed"
            else:
                status = "running"
            
            return {
                "task_id": task_id,
                "name": task_info.task_name,
                "status": status,
                "created_at": task_info.created_at.isoformat(),
                "timeout": task_info.timeout
            }
        
        # Check completed tasks
        if task_id in self.completed_tasks:
            task_info = self.completed_tasks[task_id]
            return {
                "task_id": task_id,
                "name": task_info.task_name,
                "status": "completed",
                "created_at": task_info.created_at.isoformat(),
                "timeout": task_info.timeout
            }
        
        return None
    
    def get_active_tasks(self) -> Dict[str, Dict[str, Any]]:
        """Get all active tasks."""
        active = {}
        for task_id, task_info in self.tasks.items():
            status = self.get_task_status(task_id)
            if status:
                active[task_id] = status
        return active
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get task manager statistics."""
        active_count = len(self.tasks)
        completed_count = len(self.completed_tasks)
        
        # Count by status
        status_counts = {"running": 0, "pending": 0, "cancelled": 0, "failed": 0}
        for task_info in self.tasks.values():
            if task_info.task is None:
                status_counts["pending"] += 1
            elif task_info.task.done():
                if task_info.task.cancelled():
                    status_counts["cancelled"] += 1
                elif task_info.task.exception():
                    status_counts["failed"] += 1
            else:
                status_counts["running"] += 1
        
        return {
            "active_tasks": active_count,
            "completed_tasks": completed_count,
            "total_tasks": active_count + completed_count,
            "status_breakdown": status_counts
        }


# Global instances
_global_task_manager: Optional[AsyncTaskManager] = None


def get_async_task_manager() -> AsyncTaskManager:
    """Get global async task manager instance."""
    global _global_task_manager
    if _global_task_manager is None:
        _global_task_manager = AsyncTaskManager()
    return _global_task_manager


def reset_async_task_manager() -> None:
    """Reset global task manager (for testing)."""
    global _global_task_manager
    _global_task_manager = None