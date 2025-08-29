"""Data change notification system with observer pattern and event filtering."""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import fnmatch
from collections import defaultdict

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of data changes."""
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    BATCH_UPDATE = "batch_update"
    SCHEMA_CHANGE = "schema_change"


# Alias for backward compatibility with tests
class EventType(Enum):
    """Types of data update events."""
    DATA_UPDATED = "DATA_UPDATED"
    DATA_DELETED = "DATA_DELETED"
    PROVIDER_ADDED = "PROVIDER_ADDED"
    PROVIDER_REMOVED = "PROVIDER_REMOVED"
    SYNC_STARTED = "SYNC_STARTED"
    SYNC_COMPLETED = "SYNC_COMPLETED"
    ERROR_OCCURRED = "ERROR_OCCURRED"


@dataclass
class DataUpdateEvent:
    """Data update event with metadata."""
    event_type: EventType
    provider_name: str
    data_type: str
    timestamp: datetime = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "provider_name": self.provider_name,
            "data_type": self.data_type,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DataUpdateEvent':
        """Create from dictionary."""
        return cls(
            event_type=EventType(data["event_type"]),
            provider_name=data["provider_name"],
            data_type=data["data_type"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            metadata=data.get("metadata", {})
        )
    
    def __str__(self) -> str:
        """String representation."""
        return f"DataUpdateEvent({self.event_type.value}, {self.provider_name}, {self.data_type})"


class EventFilter:
    """Event filtering utilities."""
    
    @staticmethod
    def by_event_type(event_type: EventType) -> Callable[[DataUpdateEvent], bool]:
        """Filter by event type."""
        def filter_func(event: DataUpdateEvent) -> bool:
            return event.event_type == event_type
        return filter_func
    
    @staticmethod
    def by_provider(provider_name: str) -> Callable[[DataUpdateEvent], bool]:
        """Filter by provider name."""
        def filter_func(event: DataUpdateEvent) -> bool:
            return event.provider_name == provider_name
        return filter_func
    
    @staticmethod
    def by_data_type(data_type: str) -> Callable[[DataUpdateEvent], bool]:
        """Filter by data type."""
        def filter_func(event: DataUpdateEvent) -> bool:
            return event.data_type == data_type
        return filter_func
    
    @staticmethod
    def combine(filters: List[Callable[[DataUpdateEvent], bool]]) -> Callable[[DataUpdateEvent], bool]:
        """Combine multiple filters with AND logic."""
        def combined_filter(event: DataUpdateEvent) -> bool:
            return all(f(event) for f in filters)
        return combined_filter


# Type alias for callback functions
NotificationCallback = Callable[[DataUpdateEvent], None]


class NotificationPriority(Enum):
    """Notification priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ChangeNotification:
    """Notification about a data change."""
    id: str
    change_type: ChangeType
    data_type: str
    item_id: Optional[str] = None
    old_data: Optional[Any] = None
    new_data: Optional[Any] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = ""
    priority: NotificationPriority = NotificationPriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary."""
        return {
            "id": self.id,
            "change_type": self.change_type.value,
            "data_type": self.data_type,
            "item_id": self.item_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "priority": self.priority.value,
            "metadata": self.metadata,
            "tags": list(self.tags),
            "has_old_data": self.old_data is not None,
            "has_new_data": self.new_data is not None
        }
    
    def matches_filter(self, filter_config: 'NotificationFilter') -> bool:
        """Check if notification matches filter criteria."""
        return filter_config.matches(self)


@dataclass
class NotificationFilter:
    """Filter for change notifications."""
    data_types: Optional[Set[str]] = None
    change_types: Optional[Set[ChangeType]] = None
    sources: Optional[Set[str]] = None
    priorities: Optional[Set[NotificationPriority]] = None
    tags: Optional[Set[str]] = None
    item_id_patterns: Optional[List[str]] = None
    metadata_filters: Optional[Dict[str, Any]] = None
    min_priority: Optional[NotificationPriority] = None
    
    def matches(self, notification: ChangeNotification) -> bool:
        """Check if notification matches this filter."""
        # Check data types
        if self.data_types and notification.data_type not in self.data_types:
            return False
        
        # Check change types
        if self.change_types and notification.change_type not in self.change_types:
            return False
        
        # Check sources
        if self.sources and notification.source not in self.sources:
            return False
        
        # Check priorities
        if self.priorities and notification.priority not in self.priorities:
            return False
        
        # Check minimum priority
        if self.min_priority:
            priority_order = {
                NotificationPriority.LOW: 0,
                NotificationPriority.NORMAL: 1,
                NotificationPriority.HIGH: 2,
                NotificationPriority.CRITICAL: 3
            }
            if priority_order[notification.priority] < priority_order[self.min_priority]:
                return False
        
        # Check tags (notification must have at least one matching tag)
        if self.tags and not (notification.tags & self.tags):
            return False
        
        # Check item ID patterns
        if self.item_id_patterns and notification.item_id:
            pattern_match = False
            for pattern in self.item_id_patterns:
                if fnmatch.fnmatch(notification.item_id, pattern):
                    pattern_match = True
                    break
            if not pattern_match:
                return False
        
        # Check metadata filters
        if self.metadata_filters:
            for key, expected_value in self.metadata_filters.items():
                if key not in notification.metadata:
                    return False
                if notification.metadata[key] != expected_value:
                    return False
        
        return True


@dataclass
class SubscriptionConfig:
    """Configuration for notification subscription."""
    subscriber_id: str
    callback: Callable[[ChangeNotification], None]
    filter_config: Optional[NotificationFilter] = None
    batch_size: int = 1  # Number of notifications to batch together
    batch_timeout_ms: int = 1000  # Max time to wait for batch
    retry_count: int = 3
    retry_delay_ms: int = 1000
    enabled: bool = True
    
    def __post_init__(self):
        """Validate subscription configuration."""
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.batch_timeout_ms <= 0:
            raise ValueError("batch_timeout_ms must be positive")
        if self.retry_count < 0:
            raise ValueError("retry_count must be non-negative")


@dataclass
class NotificationStats:
    """Statistics for notification system."""
    total_notifications: int = 0
    notifications_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    notifications_by_priority: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_subscribers: int = 0
    active_subscribers: int = 0
    failed_deliveries: int = 0
    successful_deliveries: int = 0
    average_delivery_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_notifications": self.total_notifications,
            "notifications_by_type": dict(self.notifications_by_type),
            "notifications_by_priority": dict(self.notifications_by_priority),
            "total_subscribers": self.total_subscribers,
            "active_subscribers": self.active_subscribers,
            "failed_deliveries": self.failed_deliveries,
            "successful_deliveries": self.successful_deliveries,
            "delivery_success_rate": (
                self.successful_deliveries / (self.successful_deliveries + self.failed_deliveries)
                if (self.successful_deliveries + self.failed_deliveries) > 0 else 1.0
            ),
            "average_delivery_time_ms": self.average_delivery_time_ms
        }


class ChangeNotificationManager:
    """Manages data change notifications with observer pattern."""
    
    def __init__(self):
        """Initialize change notification manager."""
        self.subscriptions: Dict[str, SubscriptionConfig] = {}
        self.notification_queue: asyncio.Queue = asyncio.Queue()
        self.batch_queues: Dict[str, List[ChangeNotification]] = {}
        self.batch_timers: Dict[str, asyncio.Task] = {}
        self.stats = NotificationStats()
        self.notification_history: List[ChangeNotification] = []
        self.max_history_size = 1000
        
        # Processing state
        self._processing_task: Optional[asyncio.Task] = None
        self._running = False
        self._lock = asyncio.Lock()
        
        logger.info("Change notification manager initialized")
    
    async def start(self) -> None:
        """Start notification processing."""
        if self._running:
            return
        
        self._running = True
        self._processing_task = asyncio.create_task(self._process_notifications())
        logger.info("Change notification processing started")
    
    async def stop(self) -> None:
        """Stop notification processing."""
        if not self._running:
            return
        
        self._running = False
        
        if self._processing_task:
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
        
        # Cancel batch timers
        for timer in self.batch_timers.values():
            timer.cancel()
        self.batch_timers.clear()
        
        logger.info("Change notification processing stopped")
    
    def subscribe(
        self, 
        subscriber_id: str,
        callback: Callable[[Union[ChangeNotification, List[ChangeNotification]]], None],
        filter_config: Optional[NotificationFilter] = None,
        **config_kwargs
    ) -> str:
        """Subscribe to change notifications."""
        config = SubscriptionConfig(
            subscriber_id=subscriber_id,
            callback=callback,
            filter_config=filter_config,
            **config_kwargs
        )
        
        self.subscriptions[subscriber_id] = config
        self.stats.total_subscribers = len(self.subscriptions)
        self.stats.active_subscribers = len([s for s in self.subscriptions.values() if s.enabled])
        
        logger.info(f"Added subscription: {subscriber_id}")
        return subscriber_id
    
    def unsubscribe(self, subscriber_id: str) -> bool:
        """Unsubscribe from change notifications."""
        if subscriber_id in self.subscriptions:
            del self.subscriptions[subscriber_id]
            
            # Clean up batch queue
            if subscriber_id in self.batch_queues:
                del self.batch_queues[subscriber_id]
            
            # Cancel batch timer
            if subscriber_id in self.batch_timers:
                self.batch_timers[subscriber_id].cancel()
                del self.batch_timers[subscriber_id]
            
            self.stats.total_subscribers = len(self.subscriptions)
            self.stats.active_subscribers = len([s for s in self.subscriptions.values() if s.enabled])
            
            logger.info(f"Removed subscription: {subscriber_id}")
            return True
        
        return False
    
    async def notify(self, notification: ChangeNotification) -> None:
        """Send change notification to subscribers."""
        if not self._running:
            await self.start()
        
        # Add to history
        self.notification_history.append(notification)
        if len(self.notification_history) > self.max_history_size:
            self.notification_history = self.notification_history[-self.max_history_size:]
        
        # Update stats
        self.stats.total_notifications += 1
        self.stats.notifications_by_type[notification.change_type.value] += 1
        self.stats.notifications_by_priority[notification.priority.value] += 1
        
        # Queue for processing
        await self.notification_queue.put(notification)
        
        logger.debug(f"Queued notification: {notification.id} ({notification.change_type.value})")
    
    async def notify_batch(self, notifications: List[ChangeNotification]) -> None:
        """Send batch of change notifications."""
        for notification in notifications:
            await self.notify(notification)
    
    async def _process_notifications(self) -> None:
        """Process notification queue."""
        while self._running:
            try:
                # Get notification from queue
                notification = await asyncio.wait_for(
                    self.notification_queue.get(),
                    timeout=1.0
                )
                
                # Process notification for all subscribers
                await self._deliver_notification(notification)
                
            except asyncio.TimeoutError:
                # Check for batch timeouts
                await self._check_batch_timeouts()
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing notification: {e}")
    
    async def _deliver_notification(self, notification: ChangeNotification) -> None:
        """Deliver notification to matching subscribers."""
        delivery_tasks = []
        
        for subscriber_id, config in self.subscriptions.items():
            if not config.enabled:
                continue
            
            # Check if notification matches filter
            if config.filter_config and not notification.matches_filter(config.filter_config):
                continue
            
            # Handle batching
            if config.batch_size > 1:
                task = asyncio.create_task(
                    self._handle_batched_delivery(subscriber_id, config, notification)
                )
            else:
                task = asyncio.create_task(
                    self._deliver_to_subscriber(config, [notification])
                )
            
            delivery_tasks.append(task)
        
        # Wait for all deliveries to complete
        if delivery_tasks:
            await asyncio.gather(*delivery_tasks, return_exceptions=True)
    
    async def _handle_batched_delivery(
        self, 
        subscriber_id: str, 
        config: SubscriptionConfig, 
        notification: ChangeNotification
    ) -> None:
        """Handle batched notification delivery."""
        async with self._lock:
            # Add to batch queue
            if subscriber_id not in self.batch_queues:
                self.batch_queues[subscriber_id] = []
            
            self.batch_queues[subscriber_id].append(notification)
            
            # Check if batch is full
            if len(self.batch_queues[subscriber_id]) >= config.batch_size:
                # Deliver immediately
                batch = self.batch_queues[subscriber_id]
                self.batch_queues[subscriber_id] = []
                
                # Cancel timer if exists
                if subscriber_id in self.batch_timers:
                    self.batch_timers[subscriber_id].cancel()
                    del self.batch_timers[subscriber_id]
                
                await self._deliver_to_subscriber(config, batch)
            
            elif subscriber_id not in self.batch_timers:
                # Start batch timer
                timer = asyncio.create_task(
                    self._batch_timeout(subscriber_id, config)
                )
                self.batch_timers[subscriber_id] = timer
    
    async def _batch_timeout(self, subscriber_id: str, config: SubscriptionConfig) -> None:
        """Handle batch timeout."""
        await asyncio.sleep(config.batch_timeout_ms / 1000.0)
        
        async with self._lock:
            if subscriber_id in self.batch_queues and self.batch_queues[subscriber_id]:
                # Deliver partial batch
                batch = self.batch_queues[subscriber_id]
                self.batch_queues[subscriber_id] = []
                
                await self._deliver_to_subscriber(config, batch)
            
            # Clean up timer
            if subscriber_id in self.batch_timers:
                del self.batch_timers[subscriber_id]
    
    async def _deliver_to_subscriber(
        self, 
        config: SubscriptionConfig, 
        notifications: List[ChangeNotification]
    ) -> None:
        """Deliver notifications to a specific subscriber."""
        import time
        start_time = time.time()
        
        for attempt in range(config.retry_count + 1):
            try:
                # Call subscriber callback
                if config.batch_size > 1 or len(notifications) > 1:
                    # Deliver as batch
                    if asyncio.iscoroutinefunction(config.callback):
                        await config.callback(notifications)
                    else:
                        config.callback(notifications)
                else:
                    # Deliver single notification
                    if asyncio.iscoroutinefunction(config.callback):
                        await config.callback(notifications[0])
                    else:
                        config.callback(notifications[0])
                
                # Success
                self.stats.successful_deliveries += 1
                delivery_time = (time.time() - start_time) * 1000
                
                # Update average delivery time
                total_deliveries = self.stats.successful_deliveries + self.stats.failed_deliveries
                self.stats.average_delivery_time_ms = (
                    (self.stats.average_delivery_time_ms * (total_deliveries - 1) + delivery_time) 
                    / total_deliveries
                )
                
                break
                
            except Exception as e:
                logger.error(f"Error delivering to subscriber {config.subscriber_id}: {e}")
                
                if attempt < config.retry_count:
                    await asyncio.sleep(config.retry_delay_ms / 1000.0)
                else:
                    self.stats.failed_deliveries += 1
    
    async def _check_batch_timeouts(self) -> None:
        """Check for expired batch timers."""
        # This is handled by individual batch timers
        pass
    
    def get_subscribers(self) -> List[Dict[str, Any]]:
        """Get list of subscribers."""
        subscribers = []
        for subscriber_id, config in self.subscriptions.items():
            subscribers.append({
                "subscriber_id": subscriber_id,
                "enabled": config.enabled,
                "batch_size": config.batch_size,
                "batch_timeout_ms": config.batch_timeout_ms,
                "has_filter": config.filter_config is not None,
                "pending_notifications": len(self.batch_queues.get(subscriber_id, []))
            })
        return subscribers
    
    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics."""
        return self.stats.to_dict()
    
    def get_recent_notifications(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent notifications."""
        return [n.to_dict() for n in self.notification_history[-limit:]]
    
    def enable_subscriber(self, subscriber_id: str) -> bool:
        """Enable a subscriber."""
        if subscriber_id in self.subscriptions:
            self.subscriptions[subscriber_id].enabled = True
            self.stats.active_subscribers = len([s for s in self.subscriptions.values() if s.enabled])
            return True
        return False
    
    def disable_subscriber(self, subscriber_id: str) -> bool:
        """Disable a subscriber."""
        if subscriber_id in self.subscriptions:
            self.subscriptions[subscriber_id].enabled = False
            self.stats.active_subscribers = len([s for s in self.subscriptions.values() if s.enabled])
            return True
        return False
    
    async def test_subscriber(self, subscriber_id: str) -> bool:
        """Test a subscriber with a dummy notification."""
        if subscriber_id not in self.subscriptions:
            return False
        
        test_notification = ChangeNotification(
            id="test_notification",
            change_type=ChangeType.UPDATED,
            data_type="test",
            item_id="test_item",
            source="notification_manager",
            metadata={"test": True}
        )
        
        try:
            config = self.subscriptions[subscriber_id]
            await self._deliver_to_subscriber(config, [test_notification])
            return True
        except Exception as e:
            logger.error(f"Test notification failed for {subscriber_id}: {e}")
            return False


# Global notification manager
_global_notification_manager = ChangeNotificationManager()


def get_notification_manager() -> ChangeNotificationManager:
    """Get the global change notification manager."""
    return _global_notification_manager


# Convenience functions
async def notify_data_change(
    change_type: ChangeType,
    data_type: str,
    item_id: Optional[str] = None,
    old_data: Optional[Any] = None,
    new_data: Optional[Any] = None,
    source: str = "",
    priority: NotificationPriority = NotificationPriority.NORMAL,
    **metadata
) -> None:
    """Send a data change notification."""
    import uuid
    
    notification = ChangeNotification(
        id=str(uuid.uuid4()),
        change_type=change_type,
        data_type=data_type,
        item_id=item_id,
        old_data=old_data,
        new_data=new_data,
        source=source,
        priority=priority,
        metadata=metadata
    )
    
    await _global_notification_manager.notify(notification)


def subscribe_to_changes(
    subscriber_id: str,
    callback: Callable,
    data_types: Optional[List[str]] = None,
    change_types: Optional[List[ChangeType]] = None,
    **config_kwargs
) -> str:
    """Subscribe to data changes with optional filtering."""
    filter_config = None
    
    if data_types or change_types:
        filter_config = NotificationFilter(
            data_types=set(data_types) if data_types else None,
            change_types=set(change_types) if change_types else None
        )
    
    return _global_notification_manager.subscribe(
        subscriber_id=subscriber_id,
        callback=callback,
        filter_config=filter_config,
        **config_kwargs
    )


class ChangeNotificationManager:
    """Manages change notifications with callback system."""
    
    def __init__(self, cache_manager: Optional[Any] = None):
        self.cache_manager = cache_manager
        self._callbacks = {}
        self._batch_callbacks = {}
        self._callback_counter = 0
        self._event_history = []
        self._event_history_enabled = False
        self._max_history_events = 100
        self._callback_stats = defaultdict(lambda: {"call_count": 0, "total_execution_time": 0.0})
        self.subscriptions = {}
        
        logger.info("ChangeNotificationManager initialized")
    
    def add_callback(self, 
                    callback: Callable[[DataUpdateEvent], None],
                    event_filter: Optional[Callable[[DataUpdateEvent], bool]] = None,
                    priority: int = 1,
                    rate_limit: Optional[int] = None,
                    rate_window: int = 60,
                    condition: Optional[Callable[[DataUpdateEvent], bool]] = None) -> str:
        """Add a callback for change notifications."""
        callback_id = f"callback_{self._callback_counter}"
        self._callback_counter += 1
        
        self._callbacks[callback_id] = {
            "callback": callback,
            "filter": event_filter,
            "priority": priority,
            "rate_limit": rate_limit,
            "rate_window": rate_window,
            "condition": condition,
            "last_calls": []
        }
        
        logger.debug(f"Added callback {callback_id} with priority {priority}")
        return callback_id
    
    def remove_callback(self, callback_id: str) -> bool:
        """Remove a callback."""
        if callback_id in self._callbacks:
            del self._callbacks[callback_id]
            logger.debug(f"Removed callback {callback_id}")
            return True
        return False
    
    def add_batch_callback(self, 
                          callback: Callable[[List[DataUpdateEvent]], None],
                          batch_size: int = 10,
                          batch_timeout: float = 5.0) -> str:
        """Add a batch callback for multiple events."""
        callback_id = f"batch_callback_{self._callback_counter}"
        self._callback_counter += 1
        
        self._batch_callbacks[callback_id] = {
            "callback": callback,
            "batch_size": batch_size,
            "batch_timeout": batch_timeout,
            "pending_events": [],
            "last_batch_time": datetime.utcnow()
        }
        
        return callback_id
    
    async def notify_change(self, event: DataUpdateEvent):
        """Notify all callbacks about a change event."""
        # Add to event history if enabled
        if self._event_history_enabled:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history_events:
                self._event_history.pop(0)
        
        # Sort callbacks by priority (higher priority first)
        sorted_callbacks = sorted(
            self._callbacks.items(),
            key=lambda x: x[1]["priority"],
            reverse=True
        )
        
        # Process callbacks
        for callback_id, callback_info in sorted_callbacks:
            try:
                # Check filter
                if callback_info["filter"] and not callback_info["filter"](event):
                    continue
                
                # Check condition
                if callback_info["condition"] and not callback_info["condition"](event):
                    continue
                
                # Check rate limit
                if callback_info["rate_limit"]:
                    now = datetime.utcnow()
                    callback_info["last_calls"] = [
                        call_time for call_time in callback_info["last_calls"]
                        if (now - call_time).total_seconds() < callback_info["rate_window"]
                    ]
                    
                    if len(callback_info["last_calls"]) >= callback_info["rate_limit"]:
                        continue
                    
                    callback_info["last_calls"].append(now)
                
                # Execute callback
                start_time = asyncio.get_event_loop().time()
                
                if asyncio.iscoroutinefunction(callback_info["callback"]):
                    await callback_info["callback"](event)
                else:
                    callback_info["callback"](event)
                
                # Update statistics
                execution_time = asyncio.get_event_loop().time() - start_time
                self._callback_stats[callback_id]["call_count"] += 1
                self._callback_stats[callback_id]["total_execution_time"] += execution_time
                
            except Exception as e:
                logger.error(f"Error in callback {callback_id}: {e}")
                continue
        
        # Process batch callbacks
        await self._process_batch_callbacks(event)
    
    async def _process_batch_callbacks(self, event: DataUpdateEvent):
        """Process batch callbacks."""
        for callback_id, batch_info in self._batch_callbacks.items():
            batch_info["pending_events"].append(event)
            
            # Check if batch is ready
            should_process = (
                len(batch_info["pending_events"]) >= batch_info["batch_size"] or
                (datetime.utcnow() - batch_info["last_batch_time"]).total_seconds() >= batch_info["batch_timeout"]
            )
            
            if should_process and batch_info["pending_events"]:
                try:
                    await batch_info["callback"](batch_info["pending_events"])
                    batch_info["pending_events"] = []
                    batch_info["last_batch_time"] = datetime.utcnow()
                except Exception as e:
                    logger.error(f"Error in batch callback {callback_id}: {e}")
    
    def enable_event_history(self, max_events: int = 100):
        """Enable event history tracking."""
        self._event_history_enabled = True
        self._max_history_events = max_events
        logger.info(f"Event history enabled with max {max_events} events")
    
    def get_event_history(self) -> List[DataUpdateEvent]:
        """Get event history."""
        return self._event_history.copy()
    
    def enable_event_persistence(self, cache_manager: Any):
        """Enable event persistence to cache."""
        self.cache_manager = cache_manager
        logger.info("Event persistence enabled")
    
    def subscribe(self, data_type: str, callback: Callable[[DataUpdateEvent], None]) -> str:
        """Subscribe to events for a specific data type."""
        subscription_id = f"sub_{self._callback_counter}"
        self._callback_counter += 1
        
        # Create filter for data type
        event_filter = EventFilter.by_data_type(data_type)
        
        # Add callback with filter
        callback_id = self.add_callback(callback, event_filter=event_filter)
        
        # Track subscription
        self.subscriptions[subscription_id] = {
            "data_type": data_type,
            "callback_id": callback_id
        }
        
        return subscription_id
    
    def unsubscribe(self, subscription_id: str) -> bool:
        """Unsubscribe from events."""
        if subscription_id in self.subscriptions:
            callback_id = self.subscriptions[subscription_id]["callback_id"]
            self.remove_callback(callback_id)
            del self.subscriptions[subscription_id]
            return True
        return False
    
    def get_subscriptions(self) -> Dict[str, Any]:
        """Get all active subscriptions."""
        return self.subscriptions.copy()
    
    def get_callback_statistics(self, callback_id: str) -> Dict[str, Any]:
        """Get statistics for a specific callback."""
        return dict(self._callback_stats[callback_id])
    
    def add_alert_callback(self, callback: Callable[[Any, float], None]):
        """Add alert callback (for compatibility)."""
        # This is for compatibility with metrics system
        pass