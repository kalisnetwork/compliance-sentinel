"""Tests for change notification system."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime
from typing import Dict, Any

from compliance_sentinel.sync.change_notification import (
    ChangeNotificationManager,
    DataUpdateEvent,
    EventType,
    NotificationCallback,
    EventFilter
)


class TestDataUpdateEvent:
    """Test data update event functionality."""
    
    def test_event_creation(self):
        """Test creating a data update event."""
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities",
            timestamp=datetime.utcnow(),
            metadata={"count": 10, "source": "nvd"}
        )
        
        assert event.event_type == EventType.DATA_UPDATED
        assert event.provider_name == "test_provider"
        assert event.data_type == "vulnerabilities"
        assert event.metadata["count"] == 10
        assert event.metadata["source"] == "nvd"
    
    def test_event_serialization(self):
        """Test event serialization to dictionary."""
        event = DataUpdateEvent(
            event_type=EventType.PROVIDER_ADDED,
            provider_name="new_provider",
            data_type="compliance",
            metadata={"version": "1.0"}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["event_type"] == "PROVIDER_ADDED"
        assert event_dict["provider_name"] == "new_provider"
        assert event_dict["data_type"] == "compliance"
        assert event_dict["metadata"]["version"] == "1.0"
        assert "timestamp" in event_dict
    
    def test_event_deserialization(self):
        """Test event deserialization from dictionary."""
        event_dict = {
            "event_type": "DATA_UPDATED",
            "provider_name": "test_provider",
            "data_type": "vulnerabilities",
            "timestamp": "2023-12-01T10:00:00Z",
            "metadata": {"count": 5}
        }
        
        event = DataUpdateEvent.from_dict(event_dict)
        
        assert event.event_type == EventType.DATA_UPDATED
        assert event.provider_name == "test_provider"
        assert event.data_type == "vulnerabilities"
        assert event.metadata["count"] == 5
    
    def test_event_string_representation(self):
        """Test event string representation."""
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities"
        )
        
        event_str = str(event)
        assert "DATA_UPDATED" in event_str
        assert "test_provider" in event_str
        assert "vulnerabilities" in event_str


class TestEventFilter:
    """Test event filtering functionality."""
    
    def test_filter_by_event_type(self):
        """Test filtering events by event type."""
        filter_func = EventFilter.by_event_type(EventType.DATA_UPDATED)
        
        # Should match
        matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test"
        )
        assert filter_func(matching_event) is True
        
        # Should not match
        non_matching_event = DataUpdateEvent(
            event_type=EventType.PROVIDER_ADDED,
            provider_name="test",
            data_type="test"
        )
        assert filter_func(non_matching_event) is False
    
    def test_filter_by_provider(self):
        """Test filtering events by provider name."""
        filter_func = EventFilter.by_provider("target_provider")
        
        # Should match
        matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="target_provider",
            data_type="test"
        )
        assert filter_func(matching_event) is True
        
        # Should not match
        non_matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="other_provider",
            data_type="test"
        )
        assert filter_func(non_matching_event) is False
    
    def test_filter_by_data_type(self):
        """Test filtering events by data type."""
        filter_func = EventFilter.by_data_type("vulnerabilities")
        
        # Should match
        matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="vulnerabilities"
        )
        assert filter_func(matching_event) is True
        
        # Should not match
        non_matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="compliance"
        )
        assert filter_func(non_matching_event) is False
    
    def test_combined_filter(self):
        """Test combining multiple filters."""
        filter_func = EventFilter.combine([
            EventFilter.by_event_type(EventType.DATA_UPDATED),
            EventFilter.by_provider("test_provider")
        ])
        
        # Should match (meets both criteria)
        matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="test"
        )
        assert filter_func(matching_event) is True
        
        # Should not match (wrong event type)
        non_matching_event1 = DataUpdateEvent(
            event_type=EventType.PROVIDER_ADDED,
            provider_name="test_provider",
            data_type="test"
        )
        assert filter_func(non_matching_event1) is False
        
        # Should not match (wrong provider)
        non_matching_event2 = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="other_provider",
            data_type="test"
        )
        assert filter_func(non_matching_event2) is False
    
    def test_custom_filter(self):
        """Test custom filter function."""
        def custom_filter(event: DataUpdateEvent) -> bool:
            return event.metadata.get("priority") == "high"
        
        # Should match
        matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test",
            metadata={"priority": "high"}
        )
        assert custom_filter(matching_event) is True
        
        # Should not match
        non_matching_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test",
            metadata={"priority": "low"}
        )
        assert custom_filter(non_matching_event) is False


class TestChangeNotificationManager:
    """Test change notification manager functionality."""
    
    @pytest.fixture
    def notification_manager(self):
        """Create notification manager for testing."""
        return ChangeNotificationManager()
    
    def test_add_callback(self, notification_manager):
        """Test adding notification callbacks."""
        callback_calls = []
        
        def test_callback(event: DataUpdateEvent):
            callback_calls.append(event)
        
        # Add callback
        callback_id = notification_manager.add_callback(test_callback)
        
        assert callback_id is not None
        assert len(notification_manager._callbacks) == 1
    
    def test_remove_callback(self, notification_manager):
        """Test removing notification callbacks."""
        def test_callback(event: DataUpdateEvent):
            pass
        
        # Add and remove callback
        callback_id = notification_manager.add_callback(test_callback)
        assert len(notification_manager._callbacks) == 1
        
        notification_manager.remove_callback(callback_id)
        assert len(notification_manager._callbacks) == 0
    
    @pytest.mark.asyncio
    async def test_notify_change(self, notification_manager):
        """Test notifying change to callbacks."""
        callback_calls = []
        
        def test_callback(event: DataUpdateEvent):
            callback_calls.append(event)
        
        notification_manager.add_callback(test_callback)
        
        # Notify change
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities"
        )
        
        await notification_manager.notify_change(event)
        
        assert len(callback_calls) == 1
        assert callback_calls[0].provider_name == "test_provider"
    
    @pytest.mark.asyncio
    async def test_notify_multiple_callbacks(self, notification_manager):
        """Test notifying multiple callbacks."""
        callback1_calls = []
        callback2_calls = []
        
        def callback1(event: DataUpdateEvent):
            callback1_calls.append(event)
        
        def callback2(event: DataUpdateEvent):
            callback2_calls.append(event)
        
        notification_manager.add_callback(callback1)
        notification_manager.add_callback(callback2)
        
        # Notify change
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities"
        )
        
        await notification_manager.notify_change(event)
        
        assert len(callback1_calls) == 1
        assert len(callback2_calls) == 1
    
    @pytest.mark.asyncio
    async def test_filtered_callbacks(self, notification_manager):
        """Test callbacks with event filters."""
        vuln_callback_calls = []
        compliance_callback_calls = []
        
        def vuln_callback(event: DataUpdateEvent):
            vuln_callback_calls.append(event)
        
        def compliance_callback(event: DataUpdateEvent):
            compliance_callback_calls.append(event)
        
        # Add callbacks with filters
        notification_manager.add_callback(
            vuln_callback,
            event_filter=EventFilter.by_data_type("vulnerabilities")
        )
        notification_manager.add_callback(
            compliance_callback,
            event_filter=EventFilter.by_data_type("compliance")
        )
        
        # Notify vulnerability change
        vuln_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="vulnerabilities"
        )
        await notification_manager.notify_change(vuln_event)
        
        # Notify compliance change
        compliance_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="compliance"
        )
        await notification_manager.notify_change(compliance_event)
        
        # Check that callbacks received only relevant events
        assert len(vuln_callback_calls) == 1
        assert len(compliance_callback_calls) == 1
        assert vuln_callback_calls[0].data_type == "vulnerabilities"
        assert compliance_callback_calls[0].data_type == "compliance"
    
    @pytest.mark.asyncio
    async def test_async_callback(self, notification_manager):
        """Test asynchronous callbacks."""
        callback_calls = []
        
        async def async_callback(event: DataUpdateEvent):
            await asyncio.sleep(0.01)  # Simulate async work
            callback_calls.append(event)
        
        notification_manager.add_callback(async_callback)
        
        # Notify change
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities"
        )
        
        await notification_manager.notify_change(event)
        
        assert len(callback_calls) == 1
    
    @pytest.mark.asyncio
    async def test_callback_error_handling(self, notification_manager):
        """Test error handling in callbacks."""
        successful_calls = []
        
        def failing_callback(event: DataUpdateEvent):
            raise Exception("Callback error")
        
        def successful_callback(event: DataUpdateEvent):
            successful_calls.append(event)
        
        notification_manager.add_callback(failing_callback)
        notification_manager.add_callback(successful_callback)
        
        # Notify change - should not fail despite callback error
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test_provider",
            data_type="vulnerabilities"
        )
        
        await notification_manager.notify_change(event)
        
        # Successful callback should still be called
        assert len(successful_calls) == 1
    
    @pytest.mark.asyncio
    async def test_batch_notifications(self, notification_manager):
        """Test batch notification functionality."""
        callback_calls = []
        
        def batch_callback(events: list):
            callback_calls.extend(events)
        
        notification_manager.add_batch_callback(batch_callback, batch_size=3)
        
        # Send multiple events
        events = [
            DataUpdateEvent(
                event_type=EventType.DATA_UPDATED,
                provider_name=f"provider_{i}",
                data_type="test"
            )
            for i in range(5)
        ]
        
        for event in events:
            await notification_manager.notify_change(event)
        
        # Should have received events in batches
        assert len(callback_calls) >= 3  # At least one batch should be processed
    
    def test_callback_priority(self, notification_manager):
        """Test callback priority ordering."""
        call_order = []
        
        def high_priority_callback(event: DataUpdateEvent):
            call_order.append("high")
        
        def low_priority_callback(event: DataUpdateEvent):
            call_order.append("low")
        
        def medium_priority_callback(event: DataUpdateEvent):
            call_order.append("medium")
        
        # Add callbacks with different priorities
        notification_manager.add_callback(low_priority_callback, priority=1)
        notification_manager.add_callback(high_priority_callback, priority=10)
        notification_manager.add_callback(medium_priority_callback, priority=5)
        
        # Notify change
        event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test"
        )
        
        asyncio.run(notification_manager.notify_change(event))
        
        # Should be called in priority order (high to low)
        assert call_order == ["high", "medium", "low"]
    
    @pytest.mark.asyncio
    async def test_event_history(self, notification_manager):
        """Test event history tracking."""
        # Enable event history
        notification_manager.enable_event_history(max_events=5)
        
        # Send events
        events = [
            DataUpdateEvent(
                event_type=EventType.DATA_UPDATED,
                provider_name=f"provider_{i}",
                data_type="test"
            )
            for i in range(3)
        ]
        
        for event in events:
            await notification_manager.notify_change(event)
        
        # Check event history
        history = notification_manager.get_event_history()
        assert len(history) == 3
        assert all(isinstance(event, DataUpdateEvent) for event in history)
    
    @pytest.mark.asyncio
    async def test_event_persistence(self, notification_manager):
        """Test event persistence functionality."""
        with patch('compliance_sentinel.utils.intelligent_cache.IntelligentCache') as mock_cache:
            mock_cache_instance = MagicMock()
            mock_cache.return_value = mock_cache_instance
            
            # Enable event persistence
            notification_manager.enable_event_persistence(mock_cache_instance)
            
            # Send event
            event = DataUpdateEvent(
                event_type=EventType.DATA_UPDATED,
                provider_name="test_provider",
                data_type="vulnerabilities"
            )
            
            await notification_manager.notify_change(event)
            
            # Verify event was persisted
            assert mock_cache_instance.set.called
    
    def test_subscription_management(self, notification_manager):
        """Test subscription management functionality."""
        def callback1(event: DataUpdateEvent):
            pass
        
        def callback2(event: DataUpdateEvent):
            pass
        
        # Add subscriptions
        sub1_id = notification_manager.subscribe("vulnerabilities", callback1)
        sub2_id = notification_manager.subscribe("compliance", callback2)
        
        # Check subscriptions
        subscriptions = notification_manager.get_subscriptions()
        assert len(subscriptions) == 2
        
        # Unsubscribe
        notification_manager.unsubscribe(sub1_id)
        subscriptions = notification_manager.get_subscriptions()
        assert len(subscriptions) == 1
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, notification_manager):
        """Test rate limiting for notifications."""
        callback_calls = []
        
        def rate_limited_callback(event: DataUpdateEvent):
            callback_calls.append(event)
        
        # Add callback with rate limit
        notification_manager.add_callback(
            rate_limited_callback,
            rate_limit=2,  # Max 2 calls per second
            rate_window=1
        )
        
        # Send multiple events quickly
        events = [
            DataUpdateEvent(
                event_type=EventType.DATA_UPDATED,
                provider_name=f"provider_{i}",
                data_type="test"
            )
            for i in range(5)
        ]
        
        for event in events:
            await notification_manager.notify_change(event)
        
        # Should be rate limited
        assert len(callback_calls) <= 2
    
    @pytest.mark.asyncio
    async def test_conditional_notifications(self, notification_manager):
        """Test conditional notification based on event content."""
        callback_calls = []
        
        def conditional_callback(event: DataUpdateEvent):
            callback_calls.append(event)
        
        # Add callback with condition
        def high_priority_condition(event: DataUpdateEvent) -> bool:
            return event.metadata.get("priority") == "high"
        
        notification_manager.add_callback(
            conditional_callback,
            condition=high_priority_condition
        )
        
        # Send high priority event
        high_priority_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test",
            metadata={"priority": "high"}
        )
        await notification_manager.notify_change(high_priority_event)
        
        # Send low priority event
        low_priority_event = DataUpdateEvent(
            event_type=EventType.DATA_UPDATED,
            provider_name="test",
            data_type="test",
            metadata={"priority": "low"}
        )
        await notification_manager.notify_change(low_priority_event)
        
        # Only high priority event should trigger callback
        assert len(callback_calls) == 1
        assert callback_calls[0].metadata["priority"] == "high"
    
    def test_callback_statistics(self, notification_manager):
        """Test callback execution statistics."""
        def test_callback(event: DataUpdateEvent):
            pass
        
        callback_id = notification_manager.add_callback(test_callback)
        
        # Send events
        events = [
            DataUpdateEvent(
                event_type=EventType.DATA_UPDATED,
                provider_name=f"provider_{i}",
                data_type="test"
            )
            for i in range(3)
        ]
        
        for event in events:
            asyncio.run(notification_manager.notify_change(event))
        
        # Check statistics
        stats = notification_manager.get_callback_statistics(callback_id)
        assert stats["call_count"] == 3
        assert stats["total_execution_time"] > 0


class TestEventType:
    """Test event type enumeration."""
    
    def test_event_type_values(self):
        """Test event type enumeration values."""
        assert EventType.DATA_UPDATED.value == "DATA_UPDATED"
        assert EventType.DATA_DELETED.value == "DATA_DELETED"
        assert EventType.PROVIDER_ADDED.value == "PROVIDER_ADDED"
        assert EventType.PROVIDER_REMOVED.value == "PROVIDER_REMOVED"
        assert EventType.SYNC_STARTED.value == "SYNC_STARTED"
        assert EventType.SYNC_COMPLETED.value == "SYNC_COMPLETED"
        assert EventType.ERROR_OCCURRED.value == "ERROR_OCCURRED"
    
    def test_event_type_from_string(self):
        """Test creating event type from string."""
        assert EventType("DATA_UPDATED") == EventType.DATA_UPDATED
        assert EventType("PROVIDER_ADDED") == EventType.PROVIDER_ADDED


if __name__ == "__main__":
    pytest.main([__file__])