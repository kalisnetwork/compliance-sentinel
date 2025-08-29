"""Performance benchmarking suite with load simulation and scalability validation."""

import asyncio
import logging
import time
import statistics
import psutil
import threading
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import concurrent.futures
import multiprocessing
import numpy as np

from compliance_sentinel.core.interfaces import SecurityIssue, AnalysisResult
from compliance_sentinel.performance.parallel_processor import ProcessingTask, ParallelProcessor


logger = logging.getLogger(__name__)


class BenchmarkType(Enum):
    """Types of performance benchmarks."""
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    SCALABILITY = "scalability"
    MEMORY_USAGE = "memory_usage"
    CPU_UTILIZATION = "cpu_utilization"
    CONCURRENCY = "concurrency"
    STRESS_TEST = "stress_test"


class LoadPattern(Enum):
    """Load testing patterns."""
    CONSTANT = "constant"
    RAMP_UP = "ramp_up"
    SPIKE = "spike"
    STEP = "step"
    RANDOM = "random"


@dataclass
class BenchmarkConfig:
    """Configuration for performance benchmarks."""
    
    # Test parameters
    duration_seconds: int = 60
    warmup_seconds: int = 10
    cooldown_seconds: int = 5
    
    # Load configuration
    load_pattern: LoadPattern = LoadPattern.CONSTANT
    initial_load: int = 1
    max_load: int = 100
    load_increment: int = 10
    
    # Sampling
    sample_interval_seconds: float = 1.0
    
    # Thresholds
    max_response_time_ms: float = 1000.0
    min_throughput_ops_sec: float = 10.0
    max_memory_mb: float = 1000.0
    max_cpu_percent: float = 80.0
    
    # Test data
    test_data_size: int = 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'duration_seconds': self.duration_seconds,
            'warmup_seconds': self.warmup_seconds,
            'cooldown_seconds': self.cooldown_seconds,
            'load_pattern': self.load_pattern.value,
            'initial_load': self.initial_load,
            'max_load': self.max_load,
            'load_increment': self.load_increment,
            'sample_interval_seconds': self.sample_interval_seconds,
            'max_response_time_ms': self.max_response_time_ms,
            'min_throughput_ops_sec': self.min_throughput_ops_sec,
            'max_memory_mb': self.max_memory_mb,
            'max_cpu_percent': self.max_cpu_percent,
            'test_data_size': self.test_data_size
        }


@dataclass
class BenchmarkResult:
    """Result of performance benchmark."""
    
    benchmark_name: str
    benchmark_type: BenchmarkType
    
    # Timing
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Performance metrics
    throughput_ops_sec: float = 0.0
    avg_response_time_ms: float = 0.0
    p50_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    
    # Resource usage
    avg_cpu_percent: float = 0.0
    peak_cpu_percent: float = 0.0
    avg_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    
    # Success/failure metrics
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    error_rate: float = 0.0
    
    # Raw data
    response_times: List[float] = field(default_factory=list)
    cpu_samples: List[float] = field(default_factory=list)
    memory_samples: List[float] = field(default_factory=list)
    
    # Issues found
    performance_issues: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        return (self.successful_operations / self.total_operations * 100) if self.total_operations > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'benchmark_name': self.benchmark_name,
            'benchmark_type': self.benchmark_type.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'throughput_ops_sec': self.throughput_ops_sec,
            'avg_response_time_ms': self.avg_response_time_ms,
            'p50_response_time_ms': self.p50_response_time_ms,
            'p95_response_time_ms': self.p95_response_time_ms,
            'p99_response_time_ms': self.p99_response_time_ms,
            'avg_cpu_percent': self.avg_cpu_percent,
            'peak_cpu_percent': self.peak_cpu_percent,
            'avg_memory_mb': self.avg_memory_mb,
            'peak_memory_mb': self.peak_memory_mb,
            'total_operations': self.total_operations,
            'successful_operations': self.successful_operations,
            'failed_operations': self.failed_operations,
            'success_rate': self.success_rate,
            'error_rate': self.error_rate,
            'performance_issues': self.performance_issues
        }


class PerformanceBenchmark:
    """Base class for performance benchmarks."""
    
    def __init__(self, name: str, benchmark_type: BenchmarkType):
        """Initialize benchmark."""
        self.name = name
        self.benchmark_type = benchmark_type
        self.logger = logging.getLogger(__name__)
        
        # Monitoring
        self.monitoring_active = False
        self.monitor_thread = None
        self.resource_samples = []
        
    async def run_benchmark(self, 
                          target_function: Callable,
                          config: BenchmarkConfig,
                          test_data: Any = None) -> BenchmarkResult:
        """Run performance benchmark."""
        
        result = BenchmarkResult(
            benchmark_name=self.name,
            benchmark_type=self.benchmark_type
        )
        
        try:
            # Start resource monitoring
            self._start_monitoring(config.sample_interval_seconds)
            
            # Warmup phase
            if config.warmup_seconds > 0:
                await self._warmup_phase(target_function, config, test_data)
            
            # Main benchmark phase
            result = await self._execute_benchmark(target_function, config, test_data, result)
            
            # Cooldown phase
            if config.cooldown_seconds > 0:
                await asyncio.sleep(config.cooldown_seconds)
            
            # Stop monitoring and collect results
            self._stop_monitoring()
            self._process_resource_samples(result)
            
            # Calculate final metrics
            self._calculate_metrics(result, config)
            
            # Check performance thresholds
            self._check_thresholds(result, config)
            
            result.end_time = datetime.now()
            result.duration_seconds = (result.end_time - result.start_time).total_seconds()
            
        except Exception as e:
            self.logger.error(f"Benchmark {self.name} failed: {e}")
            result.performance_issues.append(f"Benchmark execution error: {str(e)}")
            result.end_time = datetime.now()
        
        return result
    
    async def _warmup_phase(self, target_function: Callable, config: BenchmarkConfig, test_data: Any):
        """Execute warmup phase."""
        self.logger.info(f"Starting warmup phase for {config.warmup_seconds} seconds")
        
        warmup_end = time.time() + config.warmup_seconds
        
        while time.time() < warmup_end:
            try:
                if asyncio.iscoroutinefunction(target_function):
                    await target_function(test_data)
                else:
                    target_function(test_data)
                
                await asyncio.sleep(0.01)  # Small delay
            except Exception:
                pass  # Ignore warmup errors
    
    async def _execute_benchmark(self, 
                               target_function: Callable,
                               config: BenchmarkConfig,
                               test_data: Any,
                               result: BenchmarkResult) -> BenchmarkResult:
        """Execute main benchmark phase (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement _execute_benchmark")
    
    def _start_monitoring(self, sample_interval: float):
        """Start resource monitoring."""
        self.monitoring_active = True
        self.resource_samples = []
        
        def monitor_resources():
            while self.monitoring_active:
                try:
                    cpu_percent = psutil.cpu_percent()
                    memory_info = psutil.virtual_memory()
                    memory_mb = memory_info.used / (1024 * 1024)
                    
                    self.resource_samples.append({
                        'timestamp': time.time(),
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb
                    })
                    
                    time.sleep(sample_interval)
                    
                except Exception as e:
                    self.logger.error(f"Error monitoring resources: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
        self.monitor_thread.start()
    
    def _stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _process_resource_samples(self, result: BenchmarkResult):
        """Process collected resource samples."""
        if not self.resource_samples:
            return
        
        cpu_values = [sample['cpu_percent'] for sample in self.resource_samples]
        memory_values = [sample['memory_mb'] for sample in self.resource_samples]
        
        result.cpu_samples = cpu_values
        result.memory_samples = memory_values
        result.avg_cpu_percent = statistics.mean(cpu_values)
        result.peak_cpu_percent = max(cpu_values)
        result.avg_memory_mb = statistics.mean(memory_values)
        result.peak_memory_mb = max(memory_values)
    
    def _calculate_metrics(self, result: BenchmarkResult, config: BenchmarkConfig):
        """Calculate performance metrics."""
        if result.response_times:
            result.avg_response_time_ms = statistics.mean(result.response_times)
            
            # Calculate percentiles
            sorted_times = sorted(result.response_times)
            n = len(sorted_times)
            
            if n > 0:
                result.p50_response_time_ms = sorted_times[int(n * 0.5)]
                result.p95_response_time_ms = sorted_times[int(n * 0.95)]
                result.p99_response_time_ms = sorted_times[int(n * 0.99)]
        
        # Calculate throughput
        if result.duration_seconds > 0:
            result.throughput_ops_sec = result.successful_operations / result.duration_seconds
        
        # Calculate error rate
        if result.total_operations > 0:
            result.error_rate = (result.failed_operations / result.total_operations) * 100
    
    def _check_thresholds(self, result: BenchmarkResult, config: BenchmarkConfig):
        """Check performance against thresholds."""
        if result.avg_response_time_ms > config.max_response_time_ms:
            result.performance_issues.append(
                f"Average response time {result.avg_response_time_ms:.1f}ms exceeds threshold {config.max_response_time_ms}ms"
            )
        
        if result.throughput_ops_sec < config.min_throughput_ops_sec:
            result.performance_issues.append(
                f"Throughput {result.throughput_ops_sec:.1f} ops/sec below threshold {config.min_throughput_ops_sec} ops/sec"
            )
        
        if result.peak_memory_mb > config.max_memory_mb:
            result.performance_issues.append(
                f"Peak memory usage {result.peak_memory_mb:.1f}MB exceeds threshold {config.max_memory_mb}MB"
            )
        
        if result.peak_cpu_percent > config.max_cpu_percent:
            result.performance_issues.append(
                f"Peak CPU usage {result.peak_cpu_percent:.1f}% exceeds threshold {config.max_cpu_percent}%"
            )


class ThroughputBenchmark(PerformanceBenchmark):
    """Throughput benchmark implementation."""
    
    def __init__(self):
        """Initialize throughput benchmark."""
        super().__init__("Throughput Test", BenchmarkType.THROUGHPUT)
    
    async def _execute_benchmark(self, 
                               target_function: Callable,
                               config: BenchmarkConfig,
                               test_data: Any,
                               result: BenchmarkResult) -> BenchmarkResult:
        """Execute throughput benchmark."""
        
        end_time = time.time() + config.duration_seconds
        
        while time.time() < end_time:
            start_op = time.time()
            
            try:
                if asyncio.iscoroutinefunction(target_function):
                    await target_function(test_data)
                else:
                    target_function(test_data)
                
                result.successful_operations += 1
                
            except Exception as e:
                result.failed_operations += 1
                self.logger.debug(f"Operation failed: {e}")
            
            # Record response time
            response_time = (time.time() - start_op) * 1000  # Convert to ms
            result.response_times.append(response_time)
            result.total_operations += 1
        
        return result


class LatencyBenchmark(PerformanceBenchmark):
    """Latency benchmark implementation."""
    
    def __init__(self):
        """Initialize latency benchmark."""
        super().__init__("Latency Test", BenchmarkType.LATENCY)
    
    async def _execute_benchmark(self, 
                               target_function: Callable,
                               config: BenchmarkConfig,
                               test_data: Any,
                               result: BenchmarkResult) -> BenchmarkResult:
        """Execute latency benchmark with controlled intervals."""
        
        end_time = time.time() + config.duration_seconds
        operation_interval = 1.0  # 1 second between operations
        
        while time.time() < end_time:
            start_op = time.time()
            
            try:
                if asyncio.iscoroutinefunction(target_function):
                    await target_function(test_data)
                else:
                    target_function(test_data)
                
                result.successful_operations += 1
                
            except Exception as e:
                result.failed_operations += 1
                self.logger.debug(f"Operation failed: {e}")
            
            # Record response time
            response_time = (time.time() - start_op) * 1000  # Convert to ms
            result.response_times.append(response_time)
            result.total_operations += 1
            
            # Wait for next operation
            await asyncio.sleep(operation_interval)
        
        return result


class ScalabilityBenchmark(PerformanceBenchmark):
    """Scalability benchmark implementation."""
    
    def __init__(self):
        """Initialize scalability benchmark."""
        super().__init__("Scalability Test", BenchmarkType.SCALABILITY)
    
    async def _execute_benchmark(self, 
                               target_function: Callable,
                               config: BenchmarkConfig,
                               test_data: Any,
                               result: BenchmarkResult) -> BenchmarkResult:
        """Execute scalability benchmark with increasing load."""
        
        current_load = config.initial_load
        phase_duration = config.duration_seconds // ((config.max_load - config.initial_load) // config.load_increment + 1)
        
        while current_load <= config.max_load:
            self.logger.info(f"Testing with load: {current_load}")
            
            # Run concurrent operations
            tasks = []
            phase_start = time.time()
            phase_end = phase_start + phase_duration
            
            # Create concurrent tasks
            semaphore = asyncio.Semaphore(current_load)
            
            async def run_operation():
                async with semaphore:
                    start_op = time.time()
                    try:
                        if asyncio.iscoroutinefunction(target_function):
                            await target_function(test_data)
                        else:
                            await asyncio.get_event_loop().run_in_executor(None, target_function, test_data)
                        
                        result.successful_operations += 1
                        
                    except Exception as e:
                        result.failed_operations += 1
                        self.logger.debug(f"Operation failed: {e}")
                    
                    # Record response time
                    response_time = (time.time() - start_op) * 1000
                    result.response_times.append(response_time)
                    result.total_operations += 1
            
            # Generate load for this phase
            while time.time() < phase_end:
                task = asyncio.create_task(run_operation())
                tasks.append(task)
                
                # Small delay to control rate
                await asyncio.sleep(0.01)
            
            # Wait for phase to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Increase load for next phase
            current_load += config.load_increment
        
        return result


class ConcurrencyBenchmark(PerformanceBenchmark):
    """Concurrency benchmark implementation."""
    
    def __init__(self):
        """Initialize concurrency benchmark."""
        super().__init__("Concurrency Test", BenchmarkType.CONCURRENCY)
    
    async def _execute_benchmark(self, 
                               target_function: Callable,
                               config: BenchmarkConfig,
                               test_data: Any,
                               result: BenchmarkResult) -> BenchmarkResult:
        """Execute concurrency benchmark."""
        
        concurrent_operations = config.max_load
        operations_per_worker = config.test_data_size // concurrent_operations
        
        async def worker():
            worker_operations = 0
            worker_successes = 0
            worker_failures = 0
            worker_times = []
            
            for _ in range(operations_per_worker):
                start_op = time.time()
                
                try:
                    if asyncio.iscoroutinefunction(target_function):
                        await target_function(test_data)
                    else:
                        await asyncio.get_event_loop().run_in_executor(None, target_function, test_data)
                    
                    worker_successes += 1
                    
                except Exception as e:
                    worker_failures += 1
                    self.logger.debug(f"Worker operation failed: {e}")
                
                response_time = (time.time() - start_op) * 1000
                worker_times.append(response_time)
                worker_operations += 1
            
            return {
                'operations': worker_operations,
                'successes': worker_successes,
                'failures': worker_failures,
                'times': worker_times
            }
        
        # Create and run workers
        workers = [asyncio.create_task(worker()) for _ in range(concurrent_operations)]
        worker_results = await asyncio.gather(*workers, return_exceptions=True)
        
        # Aggregate results
        for worker_result in worker_results:
            if isinstance(worker_result, dict):
                result.total_operations += worker_result['operations']
                result.successful_operations += worker_result['successes']
                result.failed_operations += worker_result['failures']
                result.response_times.extend(worker_result['times'])
        
        return result


class BenchmarkSuite:
    """Collection of performance benchmarks."""
    
    def __init__(self):
        """Initialize benchmark suite."""
        self.benchmarks = {
            BenchmarkType.THROUGHPUT: ThroughputBenchmark(),
            BenchmarkType.LATENCY: LatencyBenchmark(),
            BenchmarkType.SCALABILITY: ScalabilityBenchmark(),
            BenchmarkType.CONCURRENCY: ConcurrencyBenchmark()
        }
        
        self.results = {}
        self.logger = logging.getLogger(__name__)
    
    async def run_benchmark_suite(self,
                                target_function: Callable,
                                config: BenchmarkConfig,
                                test_data: Any = None,
                                benchmark_types: Optional[List[BenchmarkType]] = None) -> Dict[str, BenchmarkResult]:
        """Run a suite of benchmarks."""
        
        if benchmark_types is None:
            benchmark_types = list(self.benchmarks.keys())
        
        results = {}
        
        for benchmark_type in benchmark_types:
            if benchmark_type in self.benchmarks:
                self.logger.info(f"Running {benchmark_type.value} benchmark")
                
                benchmark = self.benchmarks[benchmark_type]
                result = await benchmark.run_benchmark(target_function, config, test_data)
                results[benchmark_type.value] = result
                
                self.logger.info(f"Completed {benchmark_type.value} benchmark: "
                               f"{result.throughput_ops_sec:.1f} ops/sec, "
                               f"{result.avg_response_time_ms:.1f}ms avg response time")
        
        self.results = results
        return results
    
    def get_suite_summary(self) -> Dict[str, Any]:
        """Get summary of benchmark suite results."""
        if not self.results:
            return {}
        
        summary = {
            'total_benchmarks': len(self.results),
            'benchmarks': {},
            'overall_performance': {},
            'issues_found': []
        }
        
        # Aggregate metrics
        all_throughputs = []
        all_response_times = []
        all_success_rates = []
        
        for benchmark_name, result in self.results.items():
            summary['benchmarks'][benchmark_name] = {
                'throughput_ops_sec': result.throughput_ops_sec,
                'avg_response_time_ms': result.avg_response_time_ms,
                'success_rate': result.success_rate,
                'peak_memory_mb': result.peak_memory_mb,
                'peak_cpu_percent': result.peak_cpu_percent,
                'issues_count': len(result.performance_issues)
            }
            
            if result.throughput_ops_sec > 0:
                all_throughputs.append(result.throughput_ops_sec)
            if result.avg_response_time_ms > 0:
                all_response_times.append(result.avg_response_time_ms)
            all_success_rates.append(result.success_rate)
            
            # Collect issues
            summary['issues_found'].extend(result.performance_issues)
        
        # Calculate overall performance
        if all_throughputs:
            summary['overall_performance']['avg_throughput'] = statistics.mean(all_throughputs)
            summary['overall_performance']['max_throughput'] = max(all_throughputs)
        
        if all_response_times:
            summary['overall_performance']['avg_response_time'] = statistics.mean(all_response_times)
            summary['overall_performance']['min_response_time'] = min(all_response_times)
        
        if all_success_rates:
            summary['overall_performance']['avg_success_rate'] = statistics.mean(all_success_rates)
        
        return summary


# Specialized benchmarks for different components

class AnalyzerBenchmark(BenchmarkSuite):
    """Benchmark suite for security analyzers."""
    
    def __init__(self):
        """Initialize analyzer benchmark."""
        super().__init__()
    
    async def benchmark_analyzer(self,
                               analyzer_func: Callable,
                               test_files: List[str],
                               config: Optional[BenchmarkConfig] = None) -> Dict[str, BenchmarkResult]:
        """Benchmark security analyzer performance."""
        
        if config is None:
            config = BenchmarkConfig(
                duration_seconds=30,
                max_load=10,
                max_response_time_ms=5000,  # 5 seconds for analysis
                min_throughput_ops_sec=1.0
            )
        
        # Create test function
        async def analyze_test_file():
            if test_files:
                file_path = test_files[0]  # Use first file for testing
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if asyncio.iscoroutinefunction(analyzer_func):
                        return await analyzer_func(content, file_path)
                    else:
                        return analyzer_func(content, file_path)
                except Exception as e:
                    raise Exception(f"Analysis failed: {e}")
        
        return await self.run_benchmark_suite(analyze_test_file, config)


class MLModelBenchmark(BenchmarkSuite):
    """Benchmark suite for ML models."""
    
    def __init__(self):
        """Initialize ML model benchmark."""
        super().__init__()
    
    async def benchmark_model(self,
                            model: Any,
                            test_data: np.ndarray,
                            config: Optional[BenchmarkConfig] = None) -> Dict[str, BenchmarkResult]:
        """Benchmark ML model performance."""
        
        if config is None:
            config = BenchmarkConfig(
                duration_seconds=60,
                max_load=50,
                max_response_time_ms=100,  # 100ms for inference
                min_throughput_ops_sec=10.0
            )
        
        # Create test function
        def predict_sample():
            sample_idx = np.random.randint(0, len(test_data))
            sample = test_data[sample_idx:sample_idx+1]
            return model.predict(sample)
        
        return await self.run_benchmark_suite(predict_sample, config)


class IntegrationBenchmark(BenchmarkSuite):
    """Benchmark suite for integration components."""
    
    def __init__(self):
        """Initialize integration benchmark."""
        super().__init__()
    
    async def benchmark_integration(self,
                                  integration_func: Callable,
                                  test_payload: Any,
                                  config: Optional[BenchmarkConfig] = None) -> Dict[str, BenchmarkResult]:
        """Benchmark integration performance."""
        
        if config is None:
            config = BenchmarkConfig(
                duration_seconds=45,
                max_load=20,
                max_response_time_ms=2000,  # 2 seconds for integration calls
                min_throughput_ops_sec=5.0
            )
        
        # Create test function
        async def integration_test():
            if asyncio.iscoroutinefunction(integration_func):
                return await integration_func(test_payload)
            else:
                return integration_func(test_payload)
        
        return await self.run_benchmark_suite(integration_test, config)


# Utility functions for benchmarking

def create_synthetic_test_data(size: int = 1000) -> List[str]:
    """Create synthetic test data for benchmarking."""
    test_files = []
    
    for i in range(size):
        # Create synthetic code content
        content = f"""
// Test file {i}
function processData(input) {{
    if (!input) {{
        throw new Error('Invalid input');
    }}
    
    const result = input.map(item => {{
        return {{
            id: item.id,
            value: item.value * 2,
            timestamp: new Date().toISOString()
        }};
    }});
    
    return result;
}}

class DataProcessor {{
    constructor(config) {{
        this.config = config;
        this.cache = new Map();
    }}
    
    process(data) {{
        const key = this.generateKey(data);
        
        if (this.cache.has(key)) {{
            return this.cache.get(key);
        }}
        
        const processed = processData(data);
        this.cache.set(key, processed);
        
        return processed;
    }}
    
    generateKey(data) {{
        return JSON.stringify(data);
    }}
}}
        """
        test_files.append(content)
    
    return test_files


async def run_comprehensive_benchmark(target_function: Callable,
                                    test_data: Any = None,
                                    duration_seconds: int = 120) -> Dict[str, Any]:
    """Run comprehensive performance benchmark."""
    
    config = BenchmarkConfig(
        duration_seconds=duration_seconds,
        warmup_seconds=10,
        max_load=100,
        load_increment=20
    )
    
    suite = BenchmarkSuite()
    results = await suite.run_benchmark_suite(target_function, config, test_data)
    
    return {
        'results': {name: result.to_dict() for name, result in results.items()},
        'summary': suite.get_suite_summary()
    }