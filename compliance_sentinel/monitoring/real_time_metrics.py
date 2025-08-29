"""Real-time metrics collection and monitoring for compliance sentinel."""

import os
import time
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from enum import Enum
import json
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class MetricSeverity(Enum):
    """Severity levels for metric alerts."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class MetricValue:
    """Represents a single metric value with metadata."""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary representation."""
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "labels": self.labels
        }


@dataclass
class MetricAlert:
    """Represents a metric alert condition."""
    metric_name: str
    condition: str  # e.g., ">", "<", "==", "!=", ">=", "<="
    threshold: float
    severity: MetricSeverity
    message: str
    enabled: bool = True
    cooldown_seconds: int = 300  # 5 minutes default
    last_triggered: Optional[datetime] = None
    
    def should_trigger(self, value: float) -> bool:
        """Check if alert should trigger based on value."""
        if not self.enabled:
            return False
        
        # Check cooldown period
        if self.last_triggered:
            cooldown_elapsed = (datetime.now(timezone.utc) - self.last_triggered).total_seconds()
            if cooldown_elapsed < self.cooldown_seconds:
                return False
        
        # Evaluate condition
        if self.condition == ">":
            return value > self.threshold
        elif self.condition == "<":
            return value < self.threshold
        elif self.condition == ">=":
            return value >= self.threshold
        elif self.condition == "<=":
            return value <= self.threshold
        elif self.condition == "==":
            return value == self.threshold
        elif self.condition == "!=":
            return value != self.threshold
        
        return False


@dataclass
class MetricsConfig:
    """Configuration for real-time metrics collection."""
    # Collection settings
    collection_enabled: bool = field(default_factory=lambda: os.getenv("METRICS_ENABLED", "true").lower() == "true")
    collection_interval_seconds: int = field(default_factory=lambda: int(os.getenv("METRICS_COLLECTION_INTERVAL", "60")))
    
    # Storage settings
    max_metric_history: int = field(default_factory=lambda: int(os.getenv("METRICS_MAX_HISTORY", "1000")))
    retention_hours: int = field(default_factory=lambda: int(os.getenv("METRICS_RETENTION_HOURS", "24")))
    
    # Export settings
    export_enabled: bool = field(default_factory=lambda: os.getenv("METRICS_EXPORT_ENABLED", "false").lower() == "true")
    export_endpoint: Optional[str] = field(default_factory=lambda: os.getenv("METRICS_EXPORT_ENDPOINT"))
    export_format: str = field(default_factory=lambda: os.getenv("METRICS_EXPORT_FORMAT", "prometheus"))
    
    # Alert settings
    alerts_enabled: bool = field(default_factory=lambda: os.getenv("METRICS_ALERTS_ENABLED", "true").lower() == "true")
    alert_webhook_url: Optional[str] = field(default_factory=lambda: os.getenv("METRICS_ALERT_WEBHOOK_URL"))
    
    def __post_init__(self):
        """Validate metrics configuration."""
        if self.collection_interval_seconds < 1:
            raise ValueError("Collection interval must be at least 1 second")
        if self.max_metric_history < 1:
            raise ValueError("Max metric history must be at least 1")
        if self.retention_hours < 1:
            raise ValueError("Retention hours must be at least 1")


class RealTimeMetrics:
    """Real-time metrics collection and monitoring system."""
    
    def __init__(self, config: Optional[MetricsConfig] = None):
        """Initialize real-time metrics system."""
        self.config = config or MetricsConfig()
        
        # Metric storage
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.config.max_metric_history))
        self.current_values: Dict[str, float] = {}
        self.metric_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Alerts
        self.alerts: Dict[str, MetricAlert] = {}
        self.alert_callbacks: List[Callable[[MetricAlert, float], None]] = []
        
        # Threading
        self._lock = threading.RLock()
        self._collection_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Built-in metrics
        self._initialize_builtin_metrics()
        
        logger.info(f"Real-time metrics initialized with config: {self.config}")
    
    def _initialize_builtin_metrics(self) -> None:
        """Initialize built-in metrics for system monitoring."""
        # Configuration reload metrics
        self.register_metric("config_reloads_total", MetricType.COUNTER, "Total configuration reloads")
        self.register_metric("config_reload_duration_ms", MetricType.HISTOGRAM, "Configuration reload duration")
        self.register_metric("config_reload_errors_total", MetricType.COUNTER, "Configuration reload errors")
        
        # Cache performance metrics
        self.register_metric("cache_hits_total", MetricType.COUNTER, "Total cache hits")
        self.register_metric("cache_misses_total", MetricType.COUNTER, "Total cache misses")
        self.register_metric("cache_hit_ratio", MetricType.GAUGE, "Cache hit ratio percentage")
        self.register_metric("cache_size_bytes", MetricType.GAUGE, "Current cache size in bytes")
        self.register_metric("cache_evictions_total", MetricType.COUNTER, "Total cache evictions")
        
        # External service metrics
        self.register_metric("external_service_requests_total", MetricType.COUNTER, "Total external service requests")
        self.register_metric("external_service_errors_total", MetricType.COUNTER, "Total external service errors")
        self.register_metric("external_service_latency_ms", MetricType.HISTOGRAM, "External service latency")
        self.register_metric("external_service_timeouts_total", MetricType.COUNTER, "External service timeouts")
        
        # Circuit breaker metrics
        self.register_metric("circuit_breaker_state", MetricType.GAUGE, "Circuit breaker state (0=closed, 1=open, 2=half-open)")
        self.register_metric("circuit_breaker_trips_total", MetricType.COUNTER, "Total circuit breaker trips")
        self.register_metric("circuit_breaker_recoveries_total", MetricType.COUNTER, "Total circuit breaker recoveries")
        
        # Fallback usage metrics
        self.register_metric("fallback_activations_total", MetricType.COUNTER, "Total fallback activations")
        self.register_metric("fallback_success_total", MetricType.COUNTER, "Successful fallback operations")
        self.register_metric("fallback_failures_total", MetricType.COUNTER, "Failed fallback operations")
        
        # Health metrics
        self.register_metric("system_health_score", MetricType.GAUGE, "Overall system health score (0-100)")
        self.register_metric("component_health_checks_total", MetricType.COUNTER, "Total component health checks")
        self.register_metric("component_health_failures_total", MetricType.COUNTER, "Component health check failures")
        
        # Performance metrics
        self.register_metric("memory_usage_bytes", MetricType.GAUGE, "Current memory usage in bytes")
        self.register_metric("cpu_usage_percent", MetricType.GAUGE, "Current CPU usage percentage")
        self.register_metric("active_connections", MetricType.GAUGE, "Number of active connections")
        
        # Setup default alerts
        self._setup_default_alerts()
    
    def _setup_default_alerts(self) -> None:
        """Setup default alert conditions."""
        if not self.config.alerts_enabled:
            return
        
        # High error rate alert
        self.add_alert(MetricAlert(
            metric_name="external_service_errors_total",
            condition=">",
            threshold=10,
            severity=MetricSeverity.WARNING,
            message="High external service error rate detected",
            cooldown_seconds=300
        ))
        
        # Circuit breaker trip alert
        self.add_alert(MetricAlert(
            metric_name="circuit_breaker_trips_total",
            condition=">",
            threshold=0,
            severity=MetricSeverity.ERROR,
            message="Circuit breaker has tripped",
            cooldown_seconds=600
        ))
        
        # Low cache hit ratio alert
        self.add_alert(MetricAlert(
            metric_name="cache_hit_ratio",
            condition="<",
            threshold=50.0,
            severity=MetricSeverity.WARNING,
            message="Cache hit ratio is below 50%",
            cooldown_seconds=900
        ))
        
        # High memory usage alert
        self.add_alert(MetricAlert(
            metric_name="memory_usage_bytes",
            condition=">",
            threshold=1024 * 1024 * 1024,  # 1GB
            severity=MetricSeverity.WARNING,
            message="Memory usage is above 1GB",
            cooldown_seconds=300
        ))
    
    def register_metric(self, name: str, metric_type: MetricType, description: str, tags: Optional[Dict[str, str]] = None) -> None:
        """Register a new metric for collection."""
        with self._lock:
            self.metric_metadata[name] = {
                "type": metric_type,
                "description": description,
                "tags": tags or {},
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Initialize current value
            if metric_type == MetricType.COUNTER:
                self.current_values[name] = 0.0
            elif metric_type == MetricType.GAUGE:
                self.current_values[name] = 0.0
            
            logger.debug(f"Registered metric: {name} ({metric_type.value})")
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a metric value."""
        if not self.config.collection_enabled:
            return
        
        with self._lock:
            # Update current value
            metadata = self.metric_metadata.get(name, {})
            metric_type = metadata.get("type", MetricType.GAUGE)
            
            if metric_type == MetricType.COUNTER:
                self.current_values[name] = self.current_values.get(name, 0.0) + value
            else:
                self.current_values[name] = value
            
            # Store metric value with timestamp
            metric_value = MetricValue(
                name=name,
                value=self.current_values[name],
                metric_type=metric_type,
                tags=tags or {}
            )
            
            self.metrics[name].append(metric_value)
            
            # Check alerts
            if self.config.alerts_enabled:
                self._check_alerts(name, self.current_values[name])
    
    def increment_counter(self, name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric."""
        self.record_metric(name, value, tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge metric value."""
        self.record_metric(name, value, tags)
    
    def record_timer(self, name: str, duration_ms: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a timer/histogram metric."""
        self.record_metric(name, duration_ms, tags)
    
    def time_operation(self, metric_name: str, tags: Optional[Dict[str, str]] = None):
        """Context manager to time an operation."""
        return MetricTimer(self, metric_name, tags)
    
    def add_alert(self, alert: MetricAlert) -> None:
        """Add a metric alert condition."""
        with self._lock:
            self.alerts[alert.metric_name] = alert
            logger.info(f"Added alert for metric {alert.metric_name}: {alert.condition} {alert.threshold}")
    
    def remove_alert(self, metric_name: str) -> None:
        """Remove a metric alert condition."""
        with self._lock:
            if metric_name in self.alerts:
                del self.alerts[metric_name]
                logger.info(f"Removed alert for metric {metric_name}")
    
    def add_alert_callback(self, callback: Callable[[MetricAlert, float], None]) -> None:
        """Add a callback function to be called when alerts trigger."""
        self.alert_callbacks.append(callback)
    
    def _check_alerts(self, metric_name: str, value: float) -> None:
        """Check if any alerts should trigger for the given metric."""
        alert = self.alerts.get(metric_name)
        if not alert:
            return
        
        if alert.should_trigger(value):
            alert.last_triggered = datetime.now(timezone.utc)
            logger.warning(f"Alert triggered: {alert.message} (value: {value}, threshold: {alert.threshold})")
            
            # Call alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert, value)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
    
    def get_metric_value(self, name: str) -> Optional[float]:
        """Get the current value of a metric."""
        with self._lock:
            return self.current_values.get(name)
    
    def get_metric_history(self, name: str, limit: Optional[int] = None) -> List[MetricValue]:
        """Get the history of a metric."""
        with self._lock:
            history = list(self.metrics.get(name, []))
            if limit:
                history = history[-limit:]
            return history
    
    def get_all_metrics(self) -> Dict[str, float]:
        """Get all current metric values."""
        with self._lock:
            return dict(self.current_values)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics and their status."""
        with self._lock:
            summary = {
                "total_metrics": len(self.current_values),
                "collection_enabled": self.config.collection_enabled,
                "alerts_enabled": self.config.alerts_enabled,
                "active_alerts": len(self.alerts),
                "metrics": {}
            }
            
            for name, value in self.current_values.items():
                metadata = self.metric_metadata.get(name, {})
                summary["metrics"][name] = {
                    "current_value": value,
                    "type": metadata.get("type", {}).value if hasattr(metadata.get("type", {}), "value") else "unknown",
                    "description": metadata.get("description", ""),
                    "history_count": len(self.metrics.get(name, []))
                }
            
            return summary
    
    def export_metrics(self, format_type: str = "json") -> str:
        """Export metrics in the specified format."""
        with self._lock:
            if format_type.lower() == "prometheus":
                return self._export_prometheus_format()
            elif format_type.lower() == "json":
                return self._export_json_format()
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_json_format(self) -> str:
        """Export metrics in JSON format."""
        export_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": {}
        }
        
        for name, value in self.current_values.items():
            metadata = self.metric_metadata.get(name, {})
            export_data["metrics"][name] = {
                "value": value,
                "type": metadata.get("type", {}).value if hasattr(metadata.get("type", {}), "value") else "unknown",
                "description": metadata.get("description", ""),
                "tags": metadata.get("tags", {})
            }
        
        return json.dumps(export_data, indent=2)
    
    def _export_prometheus_format(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        for name, value in self.current_values.items():
            metadata = self.metric_metadata.get(name, {})
            description = metadata.get("description", "")
            metric_type = metadata.get("type", {})
            
            # Add help and type comments
            if description:
                lines.append(f"# HELP {name} {description}")
            
            if hasattr(metric_type, "value"):
                prom_type = "counter" if metric_type == MetricType.COUNTER else "gauge"
                lines.append(f"# TYPE {name} {prom_type}")
            
            # Add metric value
            lines.append(f"{name} {value}")
        
        return "\\n".join(lines)
    
    async def start_collection(self) -> None:
        """Start the metrics collection background task."""
        if self._running:
            logger.warning("Metrics collection is already running")
            return
        
        self._running = True
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Started real-time metrics collection")
    
    async def stop_collection(self) -> None:
        """Stop the metrics collection background task."""
        if not self._running:
            return
        
        self._running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped real-time metrics collection")
    
    async def _collection_loop(self) -> None:
        """Background loop for collecting system metrics."""
        while self._running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(self.config.collection_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(self.config.collection_interval_seconds)
    
    async def _collect_system_metrics(self) -> None:
        """Collect system-level metrics."""
        try:
            import psutil
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.set_gauge("memory_usage_bytes", memory.used)
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.set_gauge("cpu_usage_percent", cpu_percent)
            
            # Calculate cache hit ratio if we have cache metrics
            cache_hits = self.get_metric_value("cache_hits_total") or 0
            cache_misses = self.get_metric_value("cache_misses_total") or 0
            total_requests = cache_hits + cache_misses
            
            if total_requests > 0:
                hit_ratio = (cache_hits / total_requests) * 100
                self.set_gauge("cache_hit_ratio", hit_ratio)
            
        except ImportError:
            logger.debug("psutil not available, skipping system metrics collection")
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def cleanup_old_metrics(self) -> None:
        """Clean up old metric data based on retention policy."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.config.retention_hours)
        
        with self._lock:
            for name, metric_deque in self.metrics.items():
                # Remove old entries
                while metric_deque and metric_deque[0].timestamp < cutoff_time:
                    metric_deque.popleft()
        
        logger.debug(f"Cleaned up metrics older than {self.config.retention_hours} hours")


class MetricTimer:
    """Context manager for timing operations."""
    
    def __init__(self, metrics: RealTimeMetrics, metric_name: str, tags: Optional[Dict[str, str]] = None):
        self.metrics = metrics
        self.metric_name = metric_name
        self.tags = tags
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration_ms = (time.time() - self.start_time) * 1000
            self.metrics.record_timer(self.metric_name, duration_ms, self.tags)


# Global metrics instance
_global_metrics = RealTimeMetrics()


def get_metrics() -> RealTimeMetrics:
    """Get the global metrics instance."""
    return _global_metrics


# Convenience functions
def record_metric(name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
    """Record a metric value using the global metrics instance."""
    _global_metrics.record_metric(name, value, tags)


def increment_counter(name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None) -> None:
    """Increment a counter using the global metrics instance."""
    _global_metrics.increment_counter(name, value, tags)


def set_gauge(name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
    """Set a gauge value using the global metrics instance."""
    _global_metrics.set_gauge(name, value, tags)


def time_operation(metric_name: str, tags: Optional[Dict[str, str]] = None):
    """Time an operation using the global metrics instance."""
    return _global_metrics.time_operation(metric_name, tags)


# Decorator for timing functions
def timed_operation(metric_name: str, tags: Optional[Dict[str, str]] = None):
    """Decorator to time function execution."""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            async def async_wrapper(*args, **kwargs):
                with time_operation(metric_name, tags):
                    return await func(*args, **kwargs)
            return async_wrapper
        else:
            def sync_wrapper(*args, **kwargs):
                with time_operation(metric_name, tags):
                    return func(*args, **kwargs)
            return sync_wrapper
    return decorator