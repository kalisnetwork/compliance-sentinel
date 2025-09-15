"""Metrics collection system for security and performance monitoring."""

import time
import threading
import logging
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
import statistics
import json

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class MetricAggregation(Enum):
    """Metric aggregation methods."""
    SUM = "sum"
    AVERAGE = "average"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    PERCENTILE_95 = "p95"
    PERCENTILE_99 = "p99"


@dataclass
class Metric:
    """Represents a metric data point."""
    
    name: str
    value: Union[int, float]
    metric_type: MetricType
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Additional data
    unit: Optional[str] = None
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            'name': self.name,
            'value': self.value,
            'type': self.metric_type.value,
            'tags': self.tags,
            'timestamp': self.timestamp.isoformat(),
            'unit': self.unit,
            'description': self.description
        }


@dataclass
class SystemMetrics:
    """System performance metrics."""
    
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    memory_usage_bytes: int = 0
    disk_usage_percent: float = 0.0
    disk_io_read_bytes: int = 0
    disk_io_write_bytes: int = 0
    network_bytes_sent: int = 0
    network_bytes_received: int = 0
    
    # Process metrics
    process_count: int = 0
    thread_count: int = 0
    file_descriptor_count: int = 0
    
    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_metrics(self) -> List[Metric]:
        """Convert to list of metrics."""
        return [
            Metric("system.cpu.usage", self.cpu_usage_percent, MetricType.GAUGE, unit="percent"),
            Metric("system.memory.usage", self.memory_usage_percent, MetricType.GAUGE, unit="percent"),
            Metric("system.memory.bytes", self.memory_usage_bytes, MetricType.GAUGE, unit="bytes"),
            Metric("system.disk.usage", self.disk_usage_percent, MetricType.GAUGE, unit="percent"),
            Metric("system.disk.io.read", self.disk_io_read_bytes, MetricType.COUNTER, unit="bytes"),
            Metric("system.disk.io.write", self.disk_io_write_bytes, MetricType.COUNTER, unit="bytes"),
            Metric("system.network.sent", self.network_bytes_sent, MetricType.COUNTER, unit="bytes"),
            Metric("system.network.received", self.network_bytes_received, MetricType.COUNTER, unit="bytes"),
            Metric("system.process.count", self.process_count, MetricType.GAUGE),
            Metric("system.thread.count", self.thread_count, MetricType.GAUGE),
            Metric("system.fd.count", self.file_descriptor_count, MetricType.GAUGE)
        ]


@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    
    # Vulnerability counts
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Analysis metrics
    files_analyzed: int = 0
    lines_analyzed: int = 0
    analysis_duration_seconds: float = 0.0
    
    # Compliance metrics
    compliance_violations: int = 0
    compliance_score: float = 0.0
    
    # Alert metrics
    alerts_sent: int = 0
    alerts_acknowledged: int = 0
    
    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_metrics(self) -> List[Metric]:
        """Convert to list of metrics."""
        return [
            Metric("security.vulnerabilities.critical", self.critical_vulnerabilities, MetricType.GAUGE),
            Metric("security.vulnerabilities.high", self.high_vulnerabilities, MetricType.GAUGE),
            Metric("security.vulnerabilities.medium", self.medium_vulnerabilities, MetricType.GAUGE),
            Metric("security.vulnerabilities.low", self.low_vulnerabilities, MetricType.GAUGE),
            Metric("security.analysis.files", self.files_analyzed, MetricType.COUNTER),
            Metric("security.analysis.lines", self.lines_analyzed, MetricType.COUNTER),
            Metric("security.analysis.duration", self.analysis_duration_seconds, MetricType.TIMER, unit="seconds"),
            Metric("security.compliance.violations", self.compliance_violations, MetricType.GAUGE),
            Metric("security.compliance.score", self.compliance_score, MetricType.GAUGE, unit="percent"),
            Metric("security.alerts.sent", self.alerts_sent, MetricType.COUNTER),
            Metric("security.alerts.acknowledged", self.alerts_acknowledged, MetricType.COUNTER)
        ]


@dataclass
class PerformanceMetrics:
    """Performance metrics."""
    
    # Request metrics
    requests_total: int = 0
    requests_per_second: float = 0.0
    response_time_avg: float = 0.0
    response_time_p95: float = 0.0
    response_time_p99: float = 0.0
    
    # Error metrics
    errors_total: int = 0
    error_rate: float = 0.0
    
    # Queue metrics
    queue_size: int = 0
    queue_processing_time: float = 0.0
    
    # Cache metrics
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0
    
    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_metrics(self) -> List[Metric]:
        """Convert to list of metrics."""
        return [
            Metric("performance.requests.total", self.requests_total, MetricType.COUNTER),
            Metric("performance.requests.rate", self.requests_per_second, MetricType.GAUGE, unit="rps"),
            Metric("performance.response.time.avg", self.response_time_avg, MetricType.GAUGE, unit="ms"),
            Metric("performance.response.time.p95", self.response_time_p95, MetricType.GAUGE, unit="ms"),
            Metric("performance.response.time.p99", self.response_time_p99, MetricType.GAUGE, unit="ms"),
            Metric("performance.errors.total", self.errors_total, MetricType.COUNTER),
            Metric("performance.errors.rate", self.error_rate, MetricType.GAUGE, unit="percent"),
            Metric("performance.queue.size", self.queue_size, MetricType.GAUGE),
            Metric("performance.queue.processing_time", self.queue_processing_time, MetricType.GAUGE, unit="ms"),
            Metric("performance.cache.hits", self.cache_hits, MetricType.COUNTER),
            Metric("performance.cache.misses", self.cache_misses, MetricType.COUNTER),
            Metric("performance.cache.hit_rate", self.cache_hit_rate, MetricType.GAUGE, unit="percent")
        ]


class MetricsCollector:
    """Main metrics collection system."""
    
    def __init__(self, collection_interval: int = 60):
        """Initialize metrics collector."""
        self.collection_interval = collection_interval
        self.logger = logging.getLogger(__name__)
        
        # Metrics storage
        self.metrics_history = defaultdict(lambda: deque(maxlen=1000))
        self.current_metrics = {}
        
        # Collection state
        self.is_running = False
        self.collection_thread = None
        
        # Metric collectors
        self.metric_collectors = {}
        
        # Statistics
        self.collection_stats = {
            'collections_completed': 0,
            'collections_failed': 0,
            'metrics_collected': 0,
            'last_collection_time': None
        }
        
        # Register default collectors
        self._register_default_collectors()
    
    def _register_default_collectors(self):
        """Register default metric collectors."""
        
        # System metrics collector
        self.register_collector('system', self._collect_system_metrics)
        
        # Security metrics collector
        self.register_collector('security', self._collect_security_metrics)
        
        # Performance metrics collector
        self.register_collector('performance', self._collect_performance_metrics)
    
    def register_collector(self, name: str, collector_func: Callable[[], List[Metric]]):
        """Register a metric collector function."""
        self.metric_collectors[name] = collector_func
        self.logger.info(f"Registered metric collector: {name}")
    
    def unregister_collector(self, name: str) -> bool:
        """Unregister a metric collector."""
        if name in self.metric_collectors:
            del self.metric_collectors[name]
            self.logger.info(f"Unregistered metric collector: {name}")
            return True
        return False
    
    def record_metric(self, metric: Metric):
        """Record a single metric."""
        
        # Store in history
        self.metrics_history[metric.name].append(metric)
        
        # Update current value
        self.current_metrics[metric.name] = metric
        
        self.collection_stats['metrics_collected'] += 1
    
    def record_counter(self, name: str, value: Union[int, float] = 1, tags: Optional[Dict[str, str]] = None):
        """Record a counter metric."""
        metric = Metric(name, value, MetricType.COUNTER, tags or {})
        self.record_metric(metric)
    
    def record_gauge(self, name: str, value: Union[int, float], tags: Optional[Dict[str, str]] = None):
        """Record a gauge metric."""
        metric = Metric(name, value, MetricType.GAUGE, tags or {})
        self.record_metric(metric)
    
    def record_timer(self, name: str, duration: float, tags: Optional[Dict[str, str]] = None):
        """Record a timer metric."""
        metric = Metric(name, duration, MetricType.TIMER, tags or {}, unit="seconds")
        self.record_metric(metric)
    
    def record_security_issue(self, issue: SecurityIssue):
        """Record metrics from security issue."""
        
        # Count by severity
        severity_name = f"security.vulnerabilities.{issue.severity.value.lower()}"
        self.record_counter(severity_name, tags={'rule_id': issue.rule_id, 'category': issue.category.value})
        
        # Record file analysis
        self.record_counter("security.analysis.files", tags={'file_type': issue.file_path.split('.')[-1] if '.' in issue.file_path else 'unknown'})
    
    def start_collection(self):
        """Start metrics collection."""
        
        if self.is_running:
            self.logger.warning("Metrics collection is already running")
            return
        
        self.is_running = True
        self.logger.info("Starting metrics collection")
        
        # Start collection thread
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            name="MetricsCollector",
            daemon=True
        )
        self.collection_thread.start()
    
    def stop_collection(self):
        """Stop metrics collection."""
        
        if not self.is_running:
            return
        
        self.logger.info("Stopping metrics collection")
        self.is_running = False
        
        # Wait for collection thread
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=5)
    
    def _collection_loop(self):
        """Main collection loop."""
        
        while self.is_running:
            try:
                # Collect metrics from all registered collectors
                self._collect_all_metrics()
                
                # Update statistics
                self.collection_stats['collections_completed'] += 1
                self.collection_stats['last_collection_time'] = datetime.now()
                
                # Sleep until next collection
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in metrics collection loop: {e}")
                self.collection_stats['collections_failed'] += 1
                time.sleep(self.collection_interval)
    
    def _collect_all_metrics(self):
        """Collect metrics from all registered collectors."""
        
        for collector_name, collector_func in self.metric_collectors.items():
            try:
                metrics = collector_func()
                
                for metric in metrics:
                    self.record_metric(metric)
                    
            except Exception as e:
                self.logger.error(f"Error collecting metrics from {collector_name}: {e}")
    
    def _collect_system_metrics(self) -> List[Metric]:
        """Collect system metrics."""
        
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network usage
            network = psutil.net_io_counters()
            
            # Process info
            process = psutil.Process()
            
            system_metrics = SystemMetrics(
                cpu_usage_percent=cpu_percent,
                memory_usage_percent=memory.percent,
                memory_usage_bytes=memory.used,
                disk_usage_percent=disk.percent,
                disk_io_read_bytes=disk_io.read_bytes if disk_io else 0,
                disk_io_write_bytes=disk_io.write_bytes if disk_io else 0,
                network_bytes_sent=network.bytes_sent,
                network_bytes_received=network.bytes_recv,
                process_count=len(psutil.pids()),
                thread_count=process.num_threads(),
                file_descriptor_count=process.num_fds() if hasattr(process, 'num_fds') else 0
            )
            
            return system_metrics.to_metrics()
            
        except ImportError:
            # psutil not available, return empty metrics
            self.logger.warning("psutil not available for system metrics collection")
            return []
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return []
    
    def _collect_security_metrics(self) -> List[Metric]:
        """Collect security metrics."""
        
        # This would integrate with the security analysis system
        # For now, return basic metrics based on current state
        
        security_metrics = SecurityMetrics(
            critical_vulnerabilities=len([m for m in self.current_metrics.values() 
                                        if m.name == "security.vulnerabilities.critical"]),
            high_vulnerabilities=len([m for m in self.current_metrics.values() 
                                    if m.name == "security.vulnerabilities.high"]),
            medium_vulnerabilities=len([m for m in self.current_metrics.values() 
                                      if m.name == "security.vulnerabilities.medium"]),
            low_vulnerabilities=len([m for m in self.current_metrics.values() 
                                   if m.name == "security.vulnerabilities.low"])
        )
        
        return security_metrics.to_metrics()
    
    def _collect_performance_metrics(self) -> List[Metric]:
        """Collect performance metrics."""
        
        # Calculate performance metrics from collected data
        response_times = [m.value for m in self.metrics_history.get("performance.response.time", [])]
        
        performance_metrics = PerformanceMetrics(
            requests_total=sum(m.value for m in self.metrics_history.get("performance.requests.total", [])),
            response_time_avg=statistics.mean(response_times) if response_times else 0.0,
            response_time_p95=statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else 0.0,
            response_time_p99=statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else 0.0,
            errors_total=sum(m.value for m in self.metrics_history.get("performance.errors.total", [])),
            cache_hits=sum(m.value for m in self.metrics_history.get("performance.cache.hits", [])),
            cache_misses=sum(m.value for m in self.metrics_history.get("performance.cache.misses", []))
        )
        
        # Calculate derived metrics
        if performance_metrics.cache_hits + performance_metrics.cache_misses > 0:
            performance_metrics.cache_hit_rate = (performance_metrics.cache_hits / 
                                                (performance_metrics.cache_hits + performance_metrics.cache_misses)) * 100
        
        return performance_metrics.to_metrics()
    
    def get_metric_history(self, metric_name: str, limit: int = 100) -> List[Metric]:
        """Get metric history."""
        
        history = list(self.metrics_history.get(metric_name, []))
        return history[-limit:]
    
    def get_current_metrics(self) -> Dict[str, Metric]:
        """Get current metric values."""
        return self.current_metrics.copy()
    
    def get_aggregated_metric(self, metric_name: str, aggregation: MetricAggregation, 
                            time_window: Optional[timedelta] = None) -> Optional[float]:
        """Get aggregated metric value."""
        
        history = self.metrics_history.get(metric_name, [])
        
        if not history:
            return None
        
        # Filter by time window if specified
        if time_window:
            cutoff_time = datetime.now() - time_window
            history = [m for m in history if m.timestamp >= cutoff_time]
        
        if not history:
            return None
        
        values = [m.value for m in history]
        
        # Apply aggregation
        if aggregation == MetricAggregation.SUM:
            return sum(values)
        elif aggregation == MetricAggregation.AVERAGE:
            return statistics.mean(values)
        elif aggregation == MetricAggregation.MIN:
            return min(values)
        elif aggregation == MetricAggregation.MAX:
            return max(values)
        elif aggregation == MetricAggregation.COUNT:
            return len(values)
        elif aggregation == MetricAggregation.PERCENTILE_95:
            return statistics.quantiles(values, n=20)[18] if len(values) > 20 else max(values)
        elif aggregation == MetricAggregation.PERCENTILE_99:
            return statistics.quantiles(values, n=100)[98] if len(values) > 100 else max(values)
        
        return None
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        
        return {
            'is_running': self.is_running,
            'collection_interval': self.collection_interval,
            'registered_collectors': list(self.metric_collectors.keys()),
            'metrics_stored': len(self.current_metrics),
            'total_metric_points': sum(len(history) for history in self.metrics_history.values()),
            'collection_stats': self.collection_stats.copy()
        }
    
    def export_metrics(self, format_type: str = 'json') -> str:
        """Export metrics in specified format."""
        
        if format_type == 'json':
            return json.dumps({
                'timestamp': datetime.now().isoformat(),
                'metrics': {name: metric.to_dict() for name, metric in self.current_metrics.items()},
                'stats': self.get_collection_stats()
            }, indent=2)
        
        elif format_type == 'prometheus':
            # Export in Prometheus format
            lines = []
            
            for metric in self.current_metrics.values():
                # Convert metric name to Prometheus format
                prom_name = metric.name.replace('.', '_')
                
                # Add help and type comments
                if metric.description:
                    lines.append(f"# HELP {prom_name} {metric.description}")
                
                lines.append(f"# TYPE {prom_name} {metric.metric_type.value}")
                
                # Add metric line with tags
                if metric.tags:
                    tag_str = ','.join([f'{k}="{v}"' for k, v in metric.tags.items()])
                    lines.append(f"{prom_name}{{{tag_str}}} {metric.value}")
                else:
                    lines.append(f"{prom_name} {metric.value}")
            
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")


# Context manager for timing metrics
class TimerContext:
    """Context manager for timing operations."""
    
    def __init__(self, collector: MetricsCollector, metric_name: str, tags: Optional[Dict[str, str]] = None):
        """Initialize timer context."""
        self.collector = collector
        self.metric_name = metric_name
        self.tags = tags or {}
        self.start_time = None
    
    def __enter__(self):
        """Start timing."""
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and record metric."""
        if self.start_time:
            duration = time.time() - self.start_time
            self.collector.record_timer(self.metric_name, duration, self.tags)


# Utility functions

def create_metrics_collector(collection_interval: int = 60) -> MetricsCollector:
    """Create and configure metrics collector."""
    return MetricsCollector(collection_interval)


def timer(collector: MetricsCollector, metric_name: str, tags: Optional[Dict[str, str]] = None):
    """Decorator for timing function execution."""
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            with TimerContext(collector, metric_name, tags):
                return func(*args, **kwargs)
        return wrapper
    return decorator


class Timer:
    """Timer class for measuring execution time."""
    
    def __init__(self, name: str, collector: Optional[MetricsCollector] = None, tags: Optional[Dict[str, str]] = None):
        """Initialize timer."""
        self.name = name
        self.collector = collector
        self.tags = tags or {}
        self.start_time = None
        self.end_time = None
    
    def start(self):
        """Start the timer."""
        self.start_time = time.time()
        return self
    
    def stop(self):
        """Stop the timer and record metric if collector is provided."""
        self.end_time = time.time()
        if self.collector and self.start_time:
            duration = self.end_time - self.start_time
            self.collector.record_timer(self.name, duration, self.tags)
        return self
    
    def elapsed(self) -> Optional[float]:
        """Get elapsed time."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return time.time() - self.start_time
        return None
    
    def __enter__(self):
        """Context manager entry."""
        return self.start()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()