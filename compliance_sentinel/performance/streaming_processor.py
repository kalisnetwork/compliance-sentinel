"""Real-time streaming processor for continuous analysis."""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any, Callable, AsyncGenerator, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
from collections import deque
import weakref

from compliance_sentinel.core.interfaces import SecurityIssue, AnalysisResult
from compliance_sentinel.performance.parallel_processor import ProcessingTask


logger = logging.getLogger(__name__)


class StreamType(Enum):
    """Types of data streams."""
    FILE_CHANGES = "file_changes"
    SECURITY_EVENTS = "security_events"
    LOG_ENTRIES = "log_entries"
    METRICS = "metrics"
    CUSTOM = "custom"


class StreamStatus(Enum):
    """Stream processing status."""
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class StreamConfig:
    """Configuration for stream processing."""
    
    stream_id: str
    stream_type: StreamType
    
    # Processing configuration
    batch_size: int = 100
    batch_timeout_seconds: float = 5.0
    max_queue_size: int = 10000
    
    # Backpressure handling
    enable_backpressure: bool = True
    backpressure_threshold: float = 0.8  # Queue utilization threshold
    
    # Error handling
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Performance tuning
    enable_batching: bool = True
    enable_compression: bool = False
    
    # Custom configuration
    custom_config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'stream_id': self.stream_id,
            'stream_type': self.stream_type.value,
            'batch_size': self.batch_size,
            'batch_timeout_seconds': self.batch_timeout_seconds,
            'max_queue_size': self.max_queue_size,
            'enable_backpressure': self.enable_backpressure,
            'backpressure_threshold': self.backpressure_threshold,
            'max_retries': self.max_retries,
            'retry_delay_seconds': self.retry_delay_seconds,
            'enable_batching': self.enable_batching,
            'enable_compression': self.enable_compression,
            'custom_config': self.custom_config
        }


@dataclass
class StreamingResult:
    """Result from stream processing."""
    
    stream_id: str
    batch_id: str
    processed_count: int
    
    # Results
    results: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Timing
    processing_time: float = 0.0
    queue_time: float = 0.0
    
    # Metadata
    processed_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'stream_id': self.stream_id,
            'batch_id': self.batch_id,
            'processed_count': self.processed_count,
            'results_count': len(self.results),
            'errors_count': len(self.errors),
            'errors': self.errors,
            'processing_time': self.processing_time,
            'queue_time': self.queue_time,
            'processed_at': self.processed_at.isoformat()
        }


@dataclass
class StreamMetrics:
    """Metrics for stream processing."""
    
    # Throughput metrics
    total_items_processed: int = 0
    total_batches_processed: int = 0
    items_per_second: float = 0.0
    batches_per_second: float = 0.0
    
    # Timing metrics
    average_processing_time: float = 0.0
    average_queue_time: float = 0.0
    total_processing_time: float = 0.0
    
    # Queue metrics
    current_queue_size: int = 0
    peak_queue_size: int = 0
    queue_utilization: float = 0.0
    
    # Error metrics
    total_errors: int = 0
    error_rate: float = 0.0
    
    # Backpressure metrics
    backpressure_events: int = 0
    dropped_items: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'total_items_processed': self.total_items_processed,
            'total_batches_processed': self.total_batches_processed,
            'items_per_second': self.items_per_second,
            'batches_per_second': self.batches_per_second,
            'average_processing_time': self.average_processing_time,
            'average_queue_time': self.average_queue_time,
            'total_processing_time': self.total_processing_time,
            'current_queue_size': self.current_queue_size,
            'peak_queue_size': self.peak_queue_size,
            'queue_utilization': self.queue_utilization,
            'total_errors': self.total_errors,
            'error_rate': self.error_rate,
            'backpressure_events': self.backpressure_events,
            'dropped_items': self.dropped_items
        }


class StreamBuffer:
    """Thread-safe buffer for streaming data."""
    
    def __init__(self, max_size: int = 10000):
        """Initialize stream buffer."""
        self.max_size = max_size
        self.buffer = deque()
        self.lock = threading.RLock()
        self.not_empty = threading.Condition(self.lock)
        self.not_full = threading.Condition(self.lock)
        
        # Metrics
        self.total_added = 0
        self.total_removed = 0
        self.total_dropped = 0
    
    def put(self, item: Any, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Add item to buffer."""
        with self.not_full:
            # Check if buffer is full
            if len(self.buffer) >= self.max_size:
                if not block:
                    self.total_dropped += 1
                    return False
                
                # Wait for space
                if not self.not_full.wait(timeout):
                    self.total_dropped += 1
                    return False
            
            # Add item
            self.buffer.append(item)
            self.total_added += 1
            
            # Notify waiting consumers
            self.not_empty.notify()
            
            return True
    
    def get(self, block: bool = True, timeout: Optional[float] = None) -> Optional[Any]:
        """Get item from buffer."""
        with self.not_empty:
            # Check if buffer is empty
            if not self.buffer:
                if not block:
                    return None
                
                # Wait for item
                if not self.not_empty.wait(timeout):
                    return None
            
            # Get item
            item = self.buffer.popleft()
            self.total_removed += 1
            
            # Notify waiting producers
            self.not_full.notify()
            
            return item
    
    def get_batch(self, batch_size: int, timeout: Optional[float] = None) -> List[Any]:
        """Get batch of items from buffer."""
        batch = []
        end_time = time.time() + (timeout or 0)
        
        while len(batch) < batch_size:
            remaining_timeout = max(0, end_time - time.time()) if timeout else None
            
            item = self.get(block=True, timeout=remaining_timeout)
            if item is None:
                break
            
            batch.append(item)
        
        return batch
    
    def size(self) -> int:
        """Get current buffer size."""
        with self.lock:
            return len(self.buffer)
    
    def is_empty(self) -> bool:
        """Check if buffer is empty."""
        with self.lock:
            return len(self.buffer) == 0
    
    def is_full(self) -> bool:
        """Check if buffer is full."""
        with self.lock:
            return len(self.buffer) >= self.max_size
    
    def clear(self):
        """Clear all items from buffer."""
        with self.lock:
            self.buffer.clear()


class StreamProcessor:
    """Processes a single data stream."""
    
    def __init__(self, 
                 config: StreamConfig,
                 processor_func: Callable):
        """Initialize stream processor."""
        self.config = config
        self.processor_func = processor_func
        
        # Stream state
        self.status = StreamStatus.STOPPED
        self.buffer = StreamBuffer(config.max_queue_size)
        
        # Processing tasks
        self.processor_task = None
        self.batch_timer_task = None
        
        # Metrics
        self.metrics = StreamMetrics()
        self.start_time = None
        
        # Callbacks
        self.callbacks = {
            'batch_processed': [],
            'error_occurred': [],
            'backpressure_triggered': []
        }
        
        # Batch management
        self.current_batch = []
        self.last_batch_time = time.time()
    
    async def start(self):
        """Start stream processing."""
        if self.status == StreamStatus.ACTIVE:
            return
        
        self.status = StreamStatus.ACTIVE
        self.start_time = time.time()
        
        # Start processing task
        self.processor_task = asyncio.create_task(self._processing_loop())
        
        # Start batch timer if batching is enabled
        if self.config.enable_batching:
            self.batch_timer_task = asyncio.create_task(self._batch_timer_loop())
        
        logger.info(f"Started stream processor: {self.config.stream_id}")
    
    async def stop(self):
        """Stop stream processing."""
        if self.status == StreamStatus.STOPPED:
            return
        
        self.status = StreamStatus.STOPPED
        
        # Cancel tasks
        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError:
                pass
        
        if self.batch_timer_task:
            self.batch_timer_task.cancel()
            try:
                await self.batch_timer_task
            except asyncio.CancelledError:
                pass
        
        # Process remaining items
        await self._flush_remaining_items()
        
        logger.info(f"Stopped stream processor: {self.config.stream_id}")
    
    async def pause(self):
        """Pause stream processing."""
        self.status = StreamStatus.PAUSED
    
    async def resume(self):
        """Resume stream processing."""
        if self.status == StreamStatus.PAUSED:
            self.status = StreamStatus.ACTIVE
    
    def add_item(self, item: Any) -> bool:
        """Add item to stream for processing."""
        if self.status != StreamStatus.ACTIVE:
            return False
        
        # Check backpressure
        if self.config.enable_backpressure:
            utilization = self.buffer.size() / self.config.max_queue_size
            if utilization >= self.config.backpressure_threshold:
                self.metrics.backpressure_events += 1
                self._trigger_callbacks('backpressure_triggered', utilization)
                return False
        
        # Add to buffer
        success = self.buffer.put(item, block=False)
        
        if not success:
            self.metrics.dropped_items += 1
        
        return success
    
    async def _processing_loop(self):
        """Main processing loop."""
        while self.status in [StreamStatus.ACTIVE, StreamStatus.PAUSED]:
            try:
                if self.status == StreamStatus.PAUSED:
                    await asyncio.sleep(0.1)
                    continue
                
                # Get batch of items
                if self.config.enable_batching:
                    batch = await self._get_batch()
                else:
                    # Process single items
                    item = await self._get_single_item()
                    batch = [item] if item is not None else []
                
                if batch:
                    await self._process_batch(batch)
                else:
                    await asyncio.sleep(0.01)  # Small delay when no items
                
            except Exception as e:
                logger.error(f"Error in processing loop for {self.config.stream_id}: {e}")
                self.status = StreamStatus.ERROR
                self.metrics.total_errors += 1
                self._trigger_callbacks('error_occurred', str(e))
                await asyncio.sleep(1)  # Error recovery delay
    
    async def _batch_timer_loop(self):
        """Timer loop for batch timeout."""
        while self.status in [StreamStatus.ACTIVE, StreamStatus.PAUSED]:
            try:
                await asyncio.sleep(self.config.batch_timeout_seconds)
                
                # Check if we have items waiting
                if self.current_batch and self.status == StreamStatus.ACTIVE:
                    time_since_last_batch = time.time() - self.last_batch_time
                    
                    if time_since_last_batch >= self.config.batch_timeout_seconds:
                        # Process current batch due to timeout
                        batch = self.current_batch.copy()
                        self.current_batch.clear()
                        
                        if batch:
                            await self._process_batch(batch)
                
            except Exception as e:
                logger.error(f"Error in batch timer for {self.config.stream_id}: {e}")
    
    async def _get_batch(self) -> List[Any]:
        """Get batch of items for processing."""
        # Check if we have a partial batch that timed out
        if self.current_batch:
            time_since_last_batch = time.time() - self.last_batch_time
            
            if time_since_last_batch >= self.config.batch_timeout_seconds:
                batch = self.current_batch.copy()
                self.current_batch.clear()
                return batch
        
        # Try to fill batch
        while len(self.current_batch) < self.config.batch_size:
            # Get item with short timeout
            item = await asyncio.get_event_loop().run_in_executor(
                None, 
                self.buffer.get, 
                True, 
                0.1
            )
            
            if item is None:
                break
            
            self.current_batch.append(item)
            
            # Update batch time
            if len(self.current_batch) == 1:
                self.last_batch_time = time.time()
        
        # Return batch if it's full or timed out
        if (len(self.current_batch) >= self.config.batch_size or
            (self.current_batch and 
             time.time() - self.last_batch_time >= self.config.batch_timeout_seconds)):
            
            batch = self.current_batch.copy()
            self.current_batch.clear()
            return batch
        
        return []
    
    async def _get_single_item(self) -> Optional[Any]:
        """Get single item for processing."""
        return await asyncio.get_event_loop().run_in_executor(
            None,
            self.buffer.get,
            True,
            1.0  # 1 second timeout
        )
    
    async def _process_batch(self, batch: List[Any]):
        """Process a batch of items."""
        if not batch:
            return
        
        batch_id = f"{self.config.stream_id}_{int(time.time())}_{len(batch)}"
        start_time = time.time()
        
        try:
            # Calculate queue time (approximate)
            queue_time = time.time() - self.last_batch_time
            
            # Process batch
            if asyncio.iscoroutinefunction(self.processor_func):
                results = await self.processor_func(batch)
            else:
                results = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.processor_func,
                    batch
                )
            
            processing_time = time.time() - start_time
            
            # Create result
            result = StreamingResult(
                stream_id=self.config.stream_id,
                batch_id=batch_id,
                processed_count=len(batch),
                results=results if isinstance(results, list) else [results],
                processing_time=processing_time,
                queue_time=queue_time
            )
            
            # Update metrics
            self._update_metrics(len(batch), processing_time, queue_time)
            
            # Trigger callbacks
            self._trigger_callbacks('batch_processed', result)
            
        except Exception as e:
            logger.error(f"Error processing batch {batch_id}: {e}")
            
            # Create error result
            result = StreamingResult(
                stream_id=self.config.stream_id,
                batch_id=batch_id,
                processed_count=0,
                errors=[str(e)],
                processing_time=time.time() - start_time
            )
            
            self.metrics.total_errors += 1
            self._trigger_callbacks('error_occurred', result)
    
    def _update_metrics(self, item_count: int, processing_time: float, queue_time: float):
        """Update processing metrics."""
        self.metrics.total_items_processed += item_count
        self.metrics.total_batches_processed += 1
        self.metrics.total_processing_time += processing_time
        
        # Update averages
        if self.metrics.total_batches_processed > 0:
            self.metrics.average_processing_time = (
                self.metrics.total_processing_time / self.metrics.total_batches_processed
            )
            
            total_queue_time = self.metrics.average_queue_time * (self.metrics.total_batches_processed - 1) + queue_time
            self.metrics.average_queue_time = total_queue_time / self.metrics.total_batches_processed
        
        # Update throughput
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            if elapsed_time > 0:
                self.metrics.items_per_second = self.metrics.total_items_processed / elapsed_time
                self.metrics.batches_per_second = self.metrics.total_batches_processed / elapsed_time
        
        # Update queue metrics
        self.metrics.current_queue_size = self.buffer.size()
        self.metrics.peak_queue_size = max(self.metrics.peak_queue_size, self.metrics.current_queue_size)
        
        if self.config.max_queue_size > 0:
            self.metrics.queue_utilization = self.metrics.current_queue_size / self.config.max_queue_size
        
        # Update error rate
        total_operations = self.metrics.total_batches_processed + self.metrics.total_errors
        if total_operations > 0:
            self.metrics.error_rate = self.metrics.total_errors / total_operations
    
    async def _flush_remaining_items(self):
        """Process any remaining items in buffer."""
        remaining_items = []
        
        # Drain buffer
        while not self.buffer.is_empty():
            item = self.buffer.get(block=False)
            if item is not None:
                remaining_items.append(item)
        
        # Add current batch
        if self.current_batch:
            remaining_items.extend(self.current_batch)
            self.current_batch.clear()
        
        # Process remaining items
        if remaining_items:
            await self._process_batch(remaining_items)
    
    def add_callback(self, event_type: str, callback: Callable):
        """Add callback for stream events."""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def _trigger_callbacks(self, event_type: str, data: Any):
        """Trigger callbacks for stream events."""
        callbacks = self.callbacks.get(event_type, [])
        
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(callback(self.config.stream_id, event_type, data))
                else:
                    callback(self.config.stream_id, event_type, data)
            except Exception as e:
                logger.error(f"Error in stream callback: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current stream metrics."""
        return self.metrics.to_dict()


class StreamingProcessor:
    """Manages multiple streaming processors."""
    
    def __init__(self):
        """Initialize streaming processor manager."""
        self.streams = {}
        self.global_metrics = {
            'total_streams': 0,
            'active_streams': 0,
            'total_items_processed': 0,
            'total_processing_time': 0.0
        }
        
        # Monitoring
        self.monitoring_active = False
        self.monitor_task = None
    
    def create_stream(self, 
                     config: StreamConfig,
                     processor_func: Callable) -> bool:
        """Create a new stream processor."""
        if config.stream_id in self.streams:
            return False
        
        stream = StreamProcessor(config, processor_func)
        self.streams[config.stream_id] = stream
        
        self.global_metrics['total_streams'] = len(self.streams)
        
        logger.info(f"Created stream: {config.stream_id}")
        return True
    
    async def start_stream(self, stream_id: str) -> bool:
        """Start a specific stream."""
        if stream_id in self.streams:
            await self.streams[stream_id].start()
            self._update_global_metrics()
            return True
        return False
    
    async def stop_stream(self, stream_id: str) -> bool:
        """Stop a specific stream."""
        if stream_id in self.streams:
            await self.streams[stream_id].stop()
            self._update_global_metrics()
            return True
        return False
    
    async def start_all_streams(self):
        """Start all streams."""
        for stream in self.streams.values():
            await stream.start()
        
        self._update_global_metrics()
        logger.info(f"Started {len(self.streams)} streams")
    
    async def stop_all_streams(self):
        """Stop all streams."""
        for stream in self.streams.values():
            await stream.stop()
        
        self._update_global_metrics()
        logger.info("Stopped all streams")
    
    def add_item_to_stream(self, stream_id: str, item: Any) -> bool:
        """Add item to specific stream."""
        if stream_id in self.streams:
            return self.streams[stream_id].add_item(item)
        return False
    
    def broadcast_item(self, item: Any, stream_type: Optional[StreamType] = None) -> int:
        """Broadcast item to all streams or streams of specific type."""
        success_count = 0
        
        for stream in self.streams.values():
            if stream_type is None or stream.config.stream_type == stream_type:
                if stream.add_item(item):
                    success_count += 1
        
        return success_count
    
    def remove_stream(self, stream_id: str) -> bool:
        """Remove a stream processor."""
        if stream_id in self.streams:
            stream = self.streams[stream_id]
            
            # Stop stream if running
            if stream.status == StreamStatus.ACTIVE:
                asyncio.create_task(stream.stop())
            
            del self.streams[stream_id]
            self.global_metrics['total_streams'] = len(self.streams)
            
            logger.info(f"Removed stream: {stream_id}")
            return True
        
        return False
    
    def get_stream_status(self, stream_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of specific stream or all streams."""
        if stream_id:
            if stream_id in self.streams:
                stream = self.streams[stream_id]
                return {
                    'stream_id': stream_id,
                    'status': stream.status.value,
                    'config': stream.config.to_dict(),
                    'metrics': stream.get_metrics(),
                    'buffer_size': stream.buffer.size()
                }
            return {}
        
        # Return status of all streams
        status = {}
        for sid, stream in self.streams.items():
            status[sid] = {
                'status': stream.status.value,
                'buffer_size': stream.buffer.size(),
                'metrics': stream.get_metrics()
            }
        
        return status
    
    def _update_global_metrics(self):
        """Update global metrics."""
        self.global_metrics['active_streams'] = len([
            s for s in self.streams.values() 
            if s.status == StreamStatus.ACTIVE
        ])
        
        self.global_metrics['total_items_processed'] = sum(
            s.metrics.total_items_processed for s in self.streams.values()
        )
        
        self.global_metrics['total_processing_time'] = sum(
            s.metrics.total_processing_time for s in self.streams.values()
        )
    
    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global streaming metrics."""
        self._update_global_metrics()
        return self.global_metrics.copy()
    
    async def start_monitoring(self, interval: float = 30.0):
        """Start stream monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop(interval))
        logger.info("Stream monitoring started")
    
    async def stop_monitoring(self):
        """Stop stream monitoring."""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stream monitoring stopped")
    
    async def _monitoring_loop(self, interval: float):
        """Stream monitoring loop."""
        while self.monitoring_active:
            try:
                # Log stream status
                status = self.get_stream_status()
                active_count = len([s for s in status.values() if s['status'] == 'active'])
                
                if active_count > 0:
                    total_items = sum(s['metrics']['total_items_processed'] for s in status.values())
                    logger.info(f"Streaming status: {active_count}/{len(status)} active streams, "
                               f"{total_items} total items processed")
                
                # Check for issues
                for stream_id, stream_status in status.items():
                    if stream_status['status'] == 'error':
                        logger.error(f"Stream {stream_id} is in error state")
                    
                    buffer_size = stream_status['buffer_size']
                    if buffer_size > 5000:  # Threshold for high buffer usage
                        logger.warning(f"Stream {stream_id} has high buffer usage: {buffer_size}")
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in stream monitoring: {e}")
                await asyncio.sleep(10)


# Utility functions for streaming

async def create_file_change_stream(processor_func: Callable,
                                  batch_size: int = 50,
                                  batch_timeout: float = 2.0) -> StreamProcessor:
    """Create a stream processor for file changes."""
    
    config = StreamConfig(
        stream_id="file_changes",
        stream_type=StreamType.FILE_CHANGES,
        batch_size=batch_size,
        batch_timeout_seconds=batch_timeout,
        enable_batching=True
    )
    
    return StreamProcessor(config, processor_func)


async def create_security_event_stream(processor_func: Callable,
                                     max_queue_size: int = 5000) -> StreamProcessor:
    """Create a stream processor for security events."""
    
    config = StreamConfig(
        stream_id="security_events",
        stream_type=StreamType.SECURITY_EVENTS,
        batch_size=100,
        batch_timeout_seconds=1.0,
        max_queue_size=max_queue_size,
        enable_backpressure=True
    )
    
    return StreamProcessor(config, processor_func)


def setup_default_streams(streaming_processor: StreamingProcessor):
    """Setup default streaming configuration."""
    
    # File change stream
    def process_file_changes(batch):
        # Process file change events
        results = []
        for change_event in batch:
            # Analyze changed file
            result = f"Processed file change: {change_event.get('file_path', 'unknown')}"
            results.append(result)
        return results
    
    file_config = StreamConfig(
        stream_id="file_changes",
        stream_type=StreamType.FILE_CHANGES,
        batch_size=20,
        batch_timeout_seconds=5.0
    )
    
    streaming_processor.create_stream(file_config, process_file_changes)
    
    # Security event stream
    def process_security_events(batch):
        # Process security events
        results = []
        for event in batch:
            result = f"Processed security event: {event.get('event_type', 'unknown')}"
            results.append(result)
        return results
    
    security_config = StreamConfig(
        stream_id="security_events",
        stream_type=StreamType.SECURITY_EVENTS,
        batch_size=100,
        batch_timeout_seconds=2.0,
        enable_backpressure=True
    )
    
    streaming_processor.create_stream(security_config, process_security_events)