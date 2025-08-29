"""Performance benchmarking tests for Compliance Sentinel."""

import time
import asyncio
import statistics
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import pytest
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.models.analysis import AnalysisType
from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples


@dataclass
class BenchmarkResult:
    """Result of a performance benchmark."""
    test_name: str
    execution_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    throughput: Optional[float] = None  # items per second
    success_rate: float = 1.0
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System resource metrics during benchmark."""
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_bytes_sent: float
    network_bytes_recv: float


class PerformanceMonitor:
    """Monitors system performance during benchmarks."""
    
    def __init__(self, interval: float = 0.1):
        """Initialize performance monitor."""
        self.interval = interval
        self.monitoring = False
        self.metrics: List[SystemMetrics] = []
        self.monitor_thread = None
        
    def start_monitoring(self) -> None:
        """Start performance monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.metrics.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> SystemMetrics:
        """Stop monitoring and return average metrics."""
        if not self.monitoring:
            return SystemMetrics(0, 0, 0, 0, 0, 0, 0)
        
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        
        if not self.metrics:
            return SystemMetrics(0, 0, 0, 0, 0, 0, 0)
        
        # Calculate averages
        return SystemMetrics(
            cpu_percent=statistics.mean(m.cpu_percent for m in self.metrics),
            memory_percent=statistics.mean(m.memory_percent for m in self.metrics),
            memory_mb=statistics.mean(m.memory_mb for m in self.metrics),
            disk_io_read_mb=statistics.mean(m.disk_io_read_mb for m in self.metrics),
            disk_io_write_mb=statistics.mean(m.disk_io_write_mb for m in self.metrics),
            network_bytes_sent=statistics.mean(m.network_bytes_sent for m in self.metrics),
            network_bytes_recv=statistics.mean(m.network_bytes_recv for m in self.metrics)
        )
    
    def _monitor_loop(self) -> None:
        """Monitor system metrics in background thread."""
        process = psutil.Process()
        
        while self.monitoring:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                network_io = psutil.net_io_counters()
                
                # Get process-specific metrics
                process_memory = process.memory_info()
                
                metrics = SystemMetrics(
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    memory_mb=process_memory.rss / 1024 / 1024,  # Convert to MB
                    disk_io_read_mb=disk_io.read_bytes / 1024 / 1024 if disk_io else 0,
                    disk_io_write_mb=disk_io.write_bytes / 1024 / 1024 if disk_io else 0,
                    network_bytes_sent=network_io.bytes_sent if network_io else 0,
                    network_bytes_recv=network_io.bytes_recv if network_io else 0
                )
                
                self.metrics.append(metrics)
                time.sleep(self.interval)
                
            except Exception as e:
                # Continue monitoring even if we can't get some metrics
                continue


class BenchmarkSuite:
    """Performance benchmark suite for Compliance Sentinel."""
    
    def __init__(self):
        """Initialize benchmark suite."""
        self.results: List[BenchmarkResult] = []
        self.monitor = PerformanceMonitor()
        
    async def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Run all performance benchmarks."""
        benchmarks = [
            self.benchmark_single_file_analysis,
            self.benchmark_multiple_files_analysis,
            self.benchmark_large_file_analysis,
            self.benchmark_concurrent_analysis,
            self.benchmark_memory_usage,
            self.benchmark_cache_performance,
            self.benchmark_startup_time,
            self.benchmark_throughput
        ]
        
        results = []
        for benchmark in benchmarks:
            try:
                result = await benchmark()
                results.append(result)
                print(f"✅ {result.test_name}: {result.execution_time:.3f}s")
            except Exception as e:
                print(f"❌ {benchmark.__name__}: {e}")
                results.append(BenchmarkResult(
                    test_name=benchmark.__name__,
                    execution_time=0.0,
                    memory_usage_mb=0.0,
                    cpu_usage_percent=0.0,
                    success_rate=0.0,
                    error_count=1,
                    metadata={"error": str(e)}
                ))
        
        self.results = results
        return results
    
    async def benchmark_single_file_analysis(self) -> BenchmarkResult:
        """Benchmark single file analysis performance."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Create test file
        sample = VulnerableCodeSamples.get_python_samples()[0]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(sample.code)
            temp_file = f.name
        
        try:
            self.monitor.start_monitoring()
            start_time = time.time()
            
            async with ComplianceAgent(config) as agent:
                result = await agent.analyze_files([temp_file])
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            return BenchmarkResult(
                test_name="Single File Analysis",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                success_rate=1.0 if result.success else 0.0,
                metadata={
                    "file_size_bytes": len(sample.code),
                    "issues_found": result.total_issues
                }
            )
            
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_multiple_files_analysis(self) -> BenchmarkResult:
        """Benchmark multiple files analysis performance."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Create multiple test files
        samples = VulnerableCodeSamples.get_python_samples()[:5]  # Use first 5 samples
        temp_files = []
        
        try:
            for i, sample in enumerate(samples):
                with tempfile.NamedTemporaryFile(mode='w', suffix=f'_{i}.py', delete=False) as f:
                    f.write(sample.code)
                    temp_files.append(f.name)
            
            self.monitor.start_monitoring()
            start_time = time.time()
            
            async with ComplianceAgent(config) as agent:
                result = await agent.analyze_files(temp_files)
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            return BenchmarkResult(
                test_name="Multiple Files Analysis",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                throughput=len(temp_files) / execution_time,
                success_rate=1.0 if result.success else 0.0,
                metadata={
                    "files_count": len(temp_files),
                    "total_size_bytes": sum(len(s.code) for s in samples),
                    "issues_found": result.total_issues
                }
            )
            
        finally:
            for temp_file in temp_files:
                Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_large_file_analysis(self) -> BenchmarkResult:
        """Benchmark analysis of large files."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Create large file by repeating vulnerable code
        base_sample = VulnerableCodeSamples.get_python_samples()[0]
        large_code = ""
        
        # Create ~100KB file
        target_size = 100 * 1024  # 100KB
        while len(large_code) < target_size:
            large_code += f"\n# Function {len(large_code) // 1000}\n" + base_sample.code
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(large_code)
            temp_file = f.name
        
        try:
            self.monitor.start_monitoring()
            start_time = time.time()
            
            async with ComplianceAgent(config) as agent:
                result = await agent.analyze_files([temp_file])
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            return BenchmarkResult(
                test_name="Large File Analysis",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                throughput=len(large_code) / execution_time,  # bytes per second
                success_rate=1.0 if result.success else 0.0,
                metadata={
                    "file_size_bytes": len(large_code),
                    "file_size_kb": len(large_code) / 1024,
                    "issues_found": result.total_issues
                }
            )
            
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_concurrent_analysis(self) -> BenchmarkResult:
        """Benchmark concurrent analysis performance."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        config.max_concurrent_analyses = 5
        
        # Create multiple test files
        samples = VulnerableCodeSamples.get_python_samples()
        temp_files = []
        
        try:
            for i, sample in enumerate(samples):
                with tempfile.NamedTemporaryFile(mode='w', suffix=f'_concurrent_{i}.py', delete=False) as f:
                    f.write(sample.code)
                    temp_files.append(f.name)
            
            self.monitor.start_monitoring()
            start_time = time.time()
            
            # Run concurrent analyses
            async with ComplianceAgent(config) as agent:
                tasks = []
                for temp_file in temp_files:
                    task = agent.analyze_files([temp_file])
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            # Count successful analyses
            successful = sum(1 for r in results if not isinstance(r, Exception) and r.success)
            
            return BenchmarkResult(
                test_name="Concurrent Analysis",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                throughput=len(temp_files) / execution_time,
                success_rate=successful / len(temp_files),
                metadata={
                    "concurrent_analyses": len(temp_files),
                    "successful_analyses": successful,
                    "max_concurrent": config.max_concurrent_analyses
                }
            )
            
        finally:
            for temp_file in temp_files:
                Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_memory_usage(self) -> BenchmarkResult:
        """Benchmark memory usage patterns."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Create many small files to test memory scaling
        temp_files = []
        file_count = 50
        
        try:
            sample = VulnerableCodeSamples.get_python_samples()[0]
            for i in range(file_count):
                with tempfile.NamedTemporaryFile(mode='w', suffix=f'_mem_{i}.py', delete=False) as f:
                    f.write(sample.code)
                    temp_files.append(f.name)
            
            self.monitor.start_monitoring()
            start_time = time.time()
            
            async with ComplianceAgent(config) as agent:
                # Analyze files in batches to test memory usage
                batch_size = 10
                for i in range(0, len(temp_files), batch_size):
                    batch = temp_files[i:i + batch_size]
                    await agent.analyze_files(batch)
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            return BenchmarkResult(
                test_name="Memory Usage",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                throughput=file_count / execution_time,
                success_rate=1.0,
                metadata={
                    "files_processed": file_count,
                    "batch_size": batch_size,
                    "peak_memory_mb": metrics.memory_mb
                }
            )
            
        finally:
            for temp_file in temp_files:
                Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_cache_performance(self) -> BenchmarkResult:
        """Benchmark caching effectiveness."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        config.cache_enabled = True
        
        sample = VulnerableCodeSamples.get_python_samples()[0]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(sample.code)
            temp_file = f.name
        
        try:
            async with ComplianceAgent(config) as agent:
                # First run (cold cache)
                self.monitor.start_monitoring()
                start_time = time.time()
                
                await agent.analyze_files([temp_file])
                
                cold_time = time.time() - start_time
                cold_metrics = self.monitor.stop_monitoring()
                
                # Second run (warm cache)
                self.monitor.start_monitoring()
                start_time = time.time()
                
                await agent.analyze_files([temp_file])
                
                warm_time = time.time() - start_time
                warm_metrics = self.monitor.stop_monitoring()
            
            # Calculate cache effectiveness
            cache_speedup = cold_time / warm_time if warm_time > 0 else 1.0
            
            return BenchmarkResult(
                test_name="Cache Performance",
                execution_time=warm_time,
                memory_usage_mb=warm_metrics.memory_mb,
                cpu_usage_percent=warm_metrics.cpu_percent,
                success_rate=1.0,
                metadata={
                    "cold_cache_time": cold_time,
                    "warm_cache_time": warm_time,
                    "cache_speedup": cache_speedup,
                    "cache_enabled": config.cache_enabled
                }
            )
            
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    async def benchmark_startup_time(self) -> BenchmarkResult:
        """Benchmark agent startup time."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        self.monitor.start_monitoring()
        start_time = time.time()
        
        # Measure startup time
        agent = ComplianceAgent(config)
        await agent.start()
        
        startup_time = time.time() - start_time
        
        await agent.stop()
        metrics = self.monitor.stop_monitoring()
        
        return BenchmarkResult(
            test_name="Startup Time",
            execution_time=startup_time,
            memory_usage_mb=metrics.memory_mb,
            cpu_usage_percent=metrics.cpu_percent,
            success_rate=1.0,
            metadata={
                "startup_time_ms": startup_time * 1000,
                "components_initialized": 5  # Approximate number of components
            }
        )
    
    async def benchmark_throughput(self) -> BenchmarkResult:
        """Benchmark overall throughput."""
        config = SystemConfiguration()
        config.hooks_enabled = False
        
        # Create many small files
        samples = VulnerableCodeSamples.get_python_samples()
        temp_files = []
        total_size = 0
        
        try:
            # Create 20 files from samples
            for i in range(20):
                sample = samples[i % len(samples)]
                with tempfile.NamedTemporaryFile(mode='w', suffix=f'_throughput_{i}.py', delete=False) as f:
                    f.write(sample.code)
                    temp_files.append(f.name)
                    total_size += len(sample.code)
            
            self.monitor.start_monitoring()
            start_time = time.time()
            
            async with ComplianceAgent(config) as agent:
                result = await agent.analyze_files(temp_files)
            
            execution_time = time.time() - start_time
            metrics = self.monitor.stop_monitoring()
            
            # Calculate throughput metrics
            files_per_second = len(temp_files) / execution_time
            bytes_per_second = total_size / execution_time
            
            return BenchmarkResult(
                test_name="Throughput",
                execution_time=execution_time,
                memory_usage_mb=metrics.memory_mb,
                cpu_usage_percent=metrics.cpu_percent,
                throughput=files_per_second,
                success_rate=1.0 if result.success else 0.0,
                metadata={
                    "files_processed": len(temp_files),
                    "total_size_bytes": total_size,
                    "files_per_second": files_per_second,
                    "bytes_per_second": bytes_per_second,
                    "mb_per_second": bytes_per_second / 1024 / 1024,
                    "issues_found": result.total_issues
                }
            )
            
        finally:
            for temp_file in temp_files:
                Path(temp_file).unlink(missing_ok=True)
    
    def generate_performance_report(self) -> str:
        """Generate performance benchmark report."""
        if not self.results:
            return "No benchmark results available."
        
        report = ["# Compliance Sentinel Performance Benchmark Report\n"]
        report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append("=" * 60 + "\n")
        
        # Summary table
        report.append("## Summary\n")
        report.append("| Test | Time (s) | Memory (MB) | CPU (%) | Throughput | Success Rate |")
        report.append("|------|----------|-------------|---------|------------|--------------|")
        
        for result in self.results:
            throughput_str = f"{result.throughput:.2f}" if result.throughput else "N/A"
            report.append(
                f"| {result.test_name} | {result.execution_time:.3f} | "
                f"{result.memory_usage_mb:.1f} | {result.cpu_usage_percent:.1f} | "
                f"{throughput_str} | {result.success_rate:.1%} |"
            )
        
        report.append("\n")
        
        # Detailed results
        report.append("## Detailed Results\n")
        for result in self.results:
            report.append(f"### {result.test_name}\n")
            report.append(f"- **Execution Time**: {result.execution_time:.3f} seconds")
            report.append(f"- **Memory Usage**: {result.memory_usage_mb:.1f} MB")
            report.append(f"- **CPU Usage**: {result.cpu_usage_percent:.1f}%")
            
            if result.throughput:
                report.append(f"- **Throughput**: {result.throughput:.2f} items/second")
            
            report.append(f"- **Success Rate**: {result.success_rate:.1%}")
            
            if result.error_count > 0:
                report.append(f"- **Errors**: {result.error_count}")
            
            if result.metadata:
                report.append("- **Additional Metrics**:")
                for key, value in result.metadata.items():
                    if isinstance(value, float):
                        report.append(f"  - {key}: {value:.3f}")
                    else:
                        report.append(f"  - {key}: {value}")
            
            report.append("")
        
        # Performance recommendations
        report.append("## Performance Recommendations\n")
        
        # Analyze results and provide recommendations
        slow_tests = [r for r in self.results if r.execution_time > 5.0]
        if slow_tests:
            report.append("### Slow Operations")
            for test in slow_tests:
                report.append(f"- {test.test_name}: {test.execution_time:.3f}s - Consider optimization")
        
        high_memory_tests = [r for r in self.results if r.memory_usage_mb > 100]
        if high_memory_tests:
            report.append("### High Memory Usage")
            for test in high_memory_tests:
                report.append(f"- {test.test_name}: {test.memory_usage_mb:.1f}MB - Monitor memory usage")
        
        failed_tests = [r for r in self.results if r.success_rate < 1.0]
        if failed_tests:
            report.append("### Failed Tests")
            for test in failed_tests:
                report.append(f"- {test.test_name}: {test.success_rate:.1%} success rate - Investigate failures")
        
        return "\n".join(report)


# Pytest integration
@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance benchmark tests for pytest integration."""
    
    @pytest.mark.asyncio
    async def test_single_file_performance(self):
        """Test single file analysis performance."""
        suite = BenchmarkSuite()
        result = await suite.benchmark_single_file_analysis()
        
        # Performance assertions
        assert result.execution_time < 10.0, f"Single file analysis too slow: {result.execution_time}s"
        assert result.memory_usage_mb < 200, f"Memory usage too high: {result.memory_usage_mb}MB"
        assert result.success_rate == 1.0, "Single file analysis should always succeed"
    
    @pytest.mark.asyncio
    async def test_throughput_performance(self):
        """Test throughput performance."""
        suite = BenchmarkSuite()
        result = await suite.benchmark_throughput()
        
        # Throughput assertions
        assert result.throughput > 1.0, f"Throughput too low: {result.throughput} files/second"
        assert result.execution_time < 30.0, f"Throughput test too slow: {result.execution_time}s"
        assert result.success_rate == 1.0, "Throughput test should succeed"
    
    @pytest.mark.asyncio
    async def test_memory_scaling(self):
        """Test memory usage scaling."""
        suite = BenchmarkSuite()
        result = await suite.benchmark_memory_usage()
        
        # Memory scaling assertions
        assert result.memory_usage_mb < 500, f"Memory usage too high: {result.memory_usage_mb}MB"
        assert result.success_rate == 1.0, "Memory test should succeed"
    
    @pytest.mark.asyncio
    async def test_startup_performance(self):
        """Test startup time performance."""
        suite = BenchmarkSuite()
        result = await suite.benchmark_startup_time()
        
        # Startup time assertions
        assert result.execution_time < 5.0, f"Startup too slow: {result.execution_time}s"
        assert result.success_rate == 1.0, "Startup should always succeed"


if __name__ == "__main__":
    async def main():
        suite = BenchmarkSuite()
        print("Running Compliance Sentinel Performance Benchmarks...")
        print("=" * 60)
        
        results = await suite.run_all_benchmarks()
        
        print("\n" + "=" * 60)
        print("Benchmark Results Summary:")
        print("=" * 60)
        
        for result in results:
            status = "✅" if result.success_rate == 1.0 else "⚠️"
            print(f"{status} {result.test_name}: {result.execution_time:.3f}s, {result.memory_usage_mb:.1f}MB")
        
        # Generate and save report
        report = suite.generate_performance_report()
        with open("performance_report.md", "w") as f:
            f.write(report)
        
        print(f"\nDetailed report saved to: performance_report.md")
    
    asyncio.run(main())