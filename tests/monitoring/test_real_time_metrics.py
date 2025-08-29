"""Tests for real-time metrics system."""

import asyncio
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from compliance_sentinel.monitoring.real_time_metrics import (
    RealTimeMetrics, MetricsConfig, MetricValue, MetricAlert, MetricType, MetricSeverity,
    MetricTimer, get_metrics, record_metric, increment_counter, set_gauge, time_operation,
    timed_operation
)


class TestMetricsConfig:
    """Test cases for MetricsConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = MetricsConfig()
        
        assert config.collection_enabled is True
        assert config.collection_interval_seconds == 60
        assert config.max_metric_history == 1000
        assert config.retention_hours == 24
        assert config.export_enabled is False
        assert config.export_format == "prometheus"
        assert config.alerts_enabled is True
    
    @patch.dict('os.environ', {
        'METRICS_ENABLED': 'false',
        'METRICS_COLLECTION_INTERVAL': '30',
        'METRICS_MAX_HISTORY': '500',
        'METRICS_RETENTION_HOURS': '12'
    })
    def test_environment_config(self):
        """Test configuration from environment variables."""
        config = MetricsConfig()
        
        assert config.collection_enabled is False
        assert config.collection_interval_seconds == 30
        assert config.max_metric_history == 500
        assert config.retention_hours == 12
    
    def test_invalid_config_validation(self):
        """Test configuration validation with invalid values."""
        with pytest.raises(ValueError, match="Collection interval must be at least 1 second"):
            MetricsConfig(collection_interval_seconds=0)
        
        with pytest.raises(ValueError, match="Max metric history must be at least 1"):
            MetricsConfig(max_metric_history=0)
        
        with pytest.raises(ValueError, match="Retention hours must be at least 1"):
            MetricsConfig(retention_hours=0)


class TestMetricValue:
    """Test cases for MetricValue."""
    
    def test_metric_value_creation(self):
        """Test creating a metric value."""
        metric = MetricValue(
            name="test_metric",
            value=42.0,
            metric_type=MetricType.GAUGE,
            tags={"service": "test"}
        )
        
        assert metric.name == "test_metric"
        assert metric.value == 42.0
        assert metric.metric_type == MetricType.GAUGE
        assert metric.tags == {"service": "test"}
        assert isinstance(metric.timestamp, datetime)
    
    def test_metric_value_to_dict(self):
        """Test converting metric value to dictionary."""
        metric = MetricValue(
            name="test_metric",
            value=42.0,
            metric_type=MetricType.COUNTER
        )
        
        result = metric.to_dict()
        
        assert result["name"] == "test_metric"
        assert result["value"] == 42.0
        assert result["type"] == "counter"
        assert "timestamp" in result
        assert result["tags"] == {}
        assert result["labels"] == {}


class TestMetricAlert:
    """Test cases for MetricAlert."""
    
    def test_alert_creation(self):
        """Test creating a metric alert."""
        alert = MetricAlert(
            metric_name="error_rate",
            condition=">",
            threshold=10.0,
            severity=MetricSeverity.WARNING,
            message="High error rate"
        )
        
        assert alert.metric_name == "error_rate"
        assert alert.condition == ">"
        assert alert.threshold == 10.0
        assert alert.severity == MetricSeverity.WARNING
        assert alert.enabled is True
    
    def test_alert_should_trigger_conditions(self):
        """Test alert trigger conditions."""
        alert = MetricAlert(
            metric_name="test",
            condition=">",
            threshold=10.0,
            severity=MetricSeverity.WARNING,
            message="Test alert"
        )
        
        assert alert.should_trigger(15.0) is True
        assert alert.should_trigger(5.0) is False
        assert alert.should_trigger(10.0) is False
        
        # Test different conditions
        alert.condition = ">="
        assert alert.should_trigger(10.0) is True
        
        alert.condition = "<"
        assert alert.should_trigger(5.0) is True
        assert alert.should_trigger(15.0) is False
        
        alert.condition = "=="
        assert alert.should_trigger(10.0) is True
        assert alert.should_trigger(10.1) is False
    
    def test_alert_cooldown(self):
        """Test alert cooldown functionality."""
        alert = MetricAlert(
            metric_name="test",
            condition=">",
            threshold=10.0,
            severity=MetricSeverity.WARNING,
            message="Test alert",
            cooldown_seconds=60
        )
        
        # First trigger should work
        assert alert.should_trigger(15.0) is True
        alert.last_triggered = datetime.utcnow()
        
        # Second trigger within cooldown should not work
        assert alert.should_trigger(15.0) is False
        
        # After cooldown, should work again
        alert.last_triggered = datetime.utcnow() - timedelta(seconds=61)
        assert alert.should_trigger(15.0) is True
    
    def test_disabled_alert(self):
        """Test disabled alert doesn't trigger."""
        alert = MetricAlert(
            metric_name="test",
            condition=">",
            threshold=10.0,
            severity=MetricSeverity.WARNING,
            message="Test alert",
            enabled=False
        )
        
        assert alert.should_trigger(15.0) is False


class TestRealTimeMetrics:
    """Test cases for RealTimeMetrics."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = MetricsConfig(
            collection_enabled=True,
            collection_interval_seconds=1,
            max_metric_history=100,
            alerts_enabled=True
        )
        self.metrics = RealTimeMetrics(self.config)
    
    def test_metrics_initialization(self):
        """Test metrics system initialization."""
        assert self.metrics.config == self.config
        assert len(self.metrics.current_values) > 0  # Should have built-in metrics
        assert len(self.metrics.metric_metadata) > 0
        assert isinstance(self.metrics.alerts, dict)
    
    def test_register_metric(self):
        """Test registering a new metric."""
        self.metrics.register_metric(
            "test_counter",
            MetricType.COUNTER,
            "Test counter metric",
            {"service": "test"}
        )
        
        assert "test_counter" in self.metrics.metric_metadata
        assert "test_counter" in self.metrics.current_values
        assert self.metrics.current_values["test_counter"] == 0.0
        
        metadata = self.metrics.metric_metadata["test_counter"]
        assert metadata["type"] == MetricType.COUNTER
        assert metadata["description"] == "Test counter metric"
        assert metadata["tags"] == {"service": "test"}
    
    def test_record_counter_metric(self):
        """Test recording counter metric values."""
        self.metrics.register_metric("test_counter", MetricType.COUNTER, "Test counter")
        
        self.metrics.record_metric("test_counter", 1.0)
        assert self.metrics.current_values["test_counter"] == 1.0
        
        self.metrics.record_metric("test_counter", 2.0)
        assert self.metrics.current_values["test_counter"] == 3.0  # Counter should accumulate
        
        # Check history
        history = self.metrics.get_metric_history("test_counter")
        assert len(history) == 2
        assert history[-1].value == 3.0
    
    def test_record_gauge_metric(self):
        """Test recording gauge metric values."""
        self.metrics.register_metric("test_gauge", MetricType.GAUGE, "Test gauge")
        
        self.metrics.record_metric("test_gauge", 10.0)
        assert self.metrics.current_values["test_gauge"] == 10.0
        
        self.metrics.record_metric("test_gauge", 20.0)
        assert self.metrics.current_values["test_gauge"] == 20.0  # Gauge should replace
        
        # Check history
        history = self.metrics.get_metric_history("test_gauge")
        assert len(history) == 2
        assert history[-1].value == 20.0
    
    def test_increment_counter(self):
        """Test increment counter convenience method."""
        self.metrics.register_metric("test_counter", MetricType.COUNTER, "Test counter")
        
        self.metrics.increment_counter("test_counter")
        assert self.metrics.current_values["test_counter"] == 1.0
        
        self.metrics.increment_counter("test_counter", 5.0)
        assert self.metrics.current_values["test_counter"] == 6.0
    
    def test_set_gauge(self):
        """Test set gauge convenience method."""
        self.metrics.register_metric("test_gauge", MetricType.GAUGE, "Test gauge")
        
        self.metrics.set_gauge("test_gauge", 42.0)
        assert self.metrics.current_values["test_gauge"] == 42.0
        
        self.metrics.set_gauge("test_gauge", 84.0)
        assert self.metrics.current_values["test_gauge"] == 84.0
    
    def test_record_timer(self):
        """Test recording timer metrics."""
        self.metrics.register_metric("test_timer", MetricType.TIMER, "Test timer")
        
        self.metrics.record_timer("test_timer", 150.5)
        assert self.metrics.current_values["test_timer"] == 150.5
        
        history = self.metrics.get_metric_history("test_timer")
        assert len(history) == 1
        assert history[0].value == 150.5
    
    def test_metric_timer_context_manager(self):
        """Test MetricTimer context manager."""
        self.metrics.register_metric("operation_duration", MetricType.TIMER, "Operation duration")
        
        with self.metrics.time_operation("operation_duration"):
            time.sleep(0.01)  # Sleep for 10ms
        
        duration = self.metrics.get_metric_value("operation_duration")
        assert duration is not None
        assert duration >= 10.0  # Should be at least 10ms
    
    def test_add_and_trigger_alert(self):
        """Test adding and triggering alerts."""
        self.metrics.register_metric("error_count", MetricType.COUNTER, "Error count")
        
        # Add alert
        alert = MetricAlert(
            metric_name="error_count",
            condition=">",
            threshold=5.0,
            severity=MetricSeverity.WARNING,
            message="High error count"
        )
        self.metrics.add_alert(alert)
        
        # Set up alert callback
        triggered_alerts = []
        def alert_callback(alert, value):
            triggered_alerts.append((alert, value))
        
        self.metrics.add_alert_callback(alert_callback)
        
        # Trigger alert
        self.metrics.record_metric("error_count", 10.0)
        
        assert len(triggered_alerts) == 1
        assert triggered_alerts[0][0].message == "High error count"
        assert triggered_alerts[0][1] == 10.0
    
    def test_get_metrics_summary(self):
        """Test getting metrics summary."""
        self.metrics.register_metric("test_metric", MetricType.GAUGE, "Test metric")
        self.metrics.set_gauge("test_metric", 42.0)
        
        summary = self.metrics.get_metrics_summary()
        
        assert "total_metrics" in summary
        assert "collection_enabled" in summary
        assert "alerts_enabled" in summary
        assert "metrics" in summary
        assert "test_metric" in summary["metrics"]
        assert summary["metrics"]["test_metric"]["current_value"] == 42.0
    
    def test_export_json_format(self):
        """Test exporting metrics in JSON format."""
        self.metrics.register_metric("test_metric", MetricType.GAUGE, "Test metric")
        self.metrics.set_gauge("test_metric", 42.0)
        
        json_export = self.metrics.export_metrics("json")
        
        assert "timestamp" in json_export
        assert "metrics" in json_export
        assert "test_metric" in json_export
        assert "42.0" in json_export
    
    def test_export_prometheus_format(self):
        """Test exporting metrics in Prometheus format."""
        self.metrics.register_metric("test_counter", MetricType.COUNTER, "Test counter metric")
        self.metrics.increment_counter("test_counter", 5.0)
        
        prom_export = self.metrics.export_metrics("prometheus")
        
        assert "# HELP test_counter Test counter metric" in prom_export
        assert "# TYPE test_counter counter" in prom_export
        assert "test_counter 5.0" in prom_export
    
    def test_cleanup_old_metrics(self):
        """Test cleaning up old metrics."""
        # Set very short retention for testing
        self.metrics.config.retention_hours = 0.001  # ~3.6 seconds
        
        self.metrics.register_metric("test_metric", MetricType.GAUGE, "Test metric")
        self.metrics.set_gauge("test_metric", 1.0)
        
        # Wait a bit and add another value
        time.sleep(0.01)
        self.metrics.set_gauge("test_metric", 2.0)
        
        # Should have 2 values
        history = self.metrics.get_metric_history("test_metric")
        assert len(history) == 2
        
        # Clean up old metrics
        self.metrics.cleanup_old_metrics()
        
        # Should still have recent values (cleanup threshold is very short but not immediate)
        history_after = self.metrics.get_metric_history("test_metric")
        assert len(history_after) >= 1
    
    @pytest.mark.asyncio
    async def test_start_stop_collection(self):
        """Test starting and stopping metrics collection."""
        assert not self.metrics._running
        
        await self.metrics.start_collection()
        assert self.metrics._running
        assert self.metrics._collection_task is not None
        
        # Let it run briefly
        await asyncio.sleep(0.1)
        
        await self.metrics.stop_collection()
        assert not self.metrics._running
    
    def test_disabled_collection(self):
        """Test that metrics are not recorded when collection is disabled."""
        config = MetricsConfig(collection_enabled=False)
        metrics = RealTimeMetrics(config)
        
        metrics.register_metric("test_metric", MetricType.GAUGE, "Test metric")
        initial_count = len(metrics.metrics["test_metric"])
        
        metrics.record_metric("test_metric", 42.0)
        
        # Should not have recorded the metric
        assert len(metrics.metrics["test_metric"]) == initial_count


class TestConvenienceFunctions:
    """Test convenience functions and decorators."""
    
    def test_global_functions(self):
        """Test global convenience functions."""
        # These should work with the global metrics instance
        record_metric("test_global", 42.0)
        increment_counter("test_global_counter", 5.0)
        set_gauge("test_global_gauge", 100.0)
        
        global_metrics = get_metrics()
        assert global_metrics.get_metric_value("test_global") == 42.0
        assert global_metrics.get_metric_value("test_global_counter") == 5.0
        assert global_metrics.get_metric_value("test_global_gauge") == 100.0
    
    def test_time_operation_context_manager(self):
        """Test global time_operation context manager."""
        with time_operation("test_operation_timing"):
            time.sleep(0.01)
        
        global_metrics = get_metrics()
        duration = global_metrics.get_metric_value("test_operation_timing")
        assert duration is not None
        assert duration >= 10.0
    
    def test_timed_operation_decorator_sync(self):
        """Test timed_operation decorator on synchronous function."""
        @timed_operation("decorated_sync_function")
        def slow_function():
            time.sleep(0.01)
            return "result"
        
        result = slow_function()
        assert result == "result"
        
        global_metrics = get_metrics()
        duration = global_metrics.get_metric_value("decorated_sync_function")
        assert duration is not None
        assert duration >= 10.0
    
    @pytest.mark.asyncio
    async def test_timed_operation_decorator_async(self):
        """Test timed_operation decorator on asynchronous function."""
        @timed_operation("decorated_async_function")
        async def slow_async_function():
            await asyncio.sleep(0.01)
            return "async_result"
        
        result = await slow_async_function()
        assert result == "async_result"
        
        global_metrics = get_metrics()
        duration = global_metrics.get_metric_value("decorated_async_function")
        assert duration is not None
        assert duration >= 10.0


if __name__ == "__main__":
    pytest.main([__file__])