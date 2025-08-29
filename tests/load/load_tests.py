"""Load testing for Compliance Sentinel concurrent analysis requests."""

import asyncio
import time
import statistics
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
from pathlib import Path
import pytest
import psutil
import threading
from queue import Queue
import random

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.models.analysis import AnalysisType
from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples


@dataclass
class LoadTestResult:
    """Result of a load test."""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_duration: float
    average_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    success_rate: float
    error_rate: float
    peak_memory_mb: float
    average_cpu_percent: float
    errors: List[str] = field(default_factory=list)
    response_times: List[float] = field(default_factory=list)
    
    @property
    def percentile_95(self) -> float:
        """Get 95th percentile response time."""
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        index = int(0.95 * len(sorted_times))
        return sorted_times[index] if index < len(sorted_times) else sorted_times[-1]
    
    @property
    def percentile_99(self) -> float:
        """Get 99th percentile response time."""
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        index = int(0.99 * len(sorted_times))
        return sorted_times[index] if index < len(sorted_times) else sorted_times[-1]


@dataclass
class LoadTestConfig:
    """Configuration for load tests."""
    concurrent_users: int = 10
    requests_per_user: int = 5
    ramp_up_time: float = 5.0  # seconds
    test_duration: float = 60.0  # seconds
    think_time_min: float = 0.1  # seconds
    think_time_max: float = 1.0  # seconds
    timeout: float = 30.0  # seconds per request


class ResourceMonitor:
    """Monitors system resources during load tests."""
    
    def __init__(self, interval: float = 1.0):
        """Initialize resource monitor."""
        self.interval = interval
        self.monitoring = False
        self.cpu_samples = []
        self.memory_samples = []
        self.monitor_thread = None
        
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.cpu_samples.clear()
        self.memory_samples.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, float]:
        """Stop monitoring and return statistics."""
        if not self.monitoring:
            return {"peak_memory_mb": 0.0, "average_cpu_percent": 0.0}
        
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        
        return {
            "peak_memory_mb": max(self.memory_samples) if self.memory_samples else 0.0,
            "average_cpu_percent": statistics.mean(self.cpu_samples) if self.cpu_samples else 0.0
        }
    
    def _monitor_loop(self) -> None:
        """Monitor resources in background thread."""
        process = psutil.Process()
        
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                self.cpu_samples.append(cpu_percent)
                self.memory_samples.append(memory_mb)
                
                time.sleep(self.interval)
                
            except Exception:
                continue


class LoadTestRunner:
    """Runs load tests against Compliance Sentinel."""
    
    def __init__(self):
        """Initialize load test runner."""
        self.resource_monitor = ResourceMonitor()
        self.test_files = []
        
    def setup_test_files(self, count: int = 20) -> List[str]:
        """Create test files for load testing."""
        if self.test_files:
            return self.test_files
        
        samples = VulnerableCodeSamples.get_python_samples()
        
        for i in range(count):
            sample = samples[i % len(samples)]
            
            # Add some variation to make files unique
            code = f"# Load test file {i}\n" + sample.code
            
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'_load_{i}.py', delete=False) as f:
                f.write(code)
                self.test_files.append(f.name)
        
        return self.test_files
    
    def cleanup_test_files(self) -> None:
        """Clean up test files."""
        for file_path in self.test_files:
            Path(file_path).unlink(missing_ok=True)
        self.test_files.clear()
    
    async def run_load_test(self, config: LoadTestConfig) -> LoadTestResult:
        """Run a load test with specified configuration."""
        print(f"Starting load test: {config.concurrent_users} users, {config.requests_per_user} requests each")
        
        # Setup
        test_files = self.setup_test_files(config.concurrent_users * 2)
        self.resource_monitor.start_monitoring()
        
        # Track results
        results = Queue()
        start_time = time.time()
        
        try:
            # Create tasks for concurrent users
            tasks = []
            for user_id in range(config.concurrent_users):
                task = asyncio.create_task(
                    self._simulate_user(user_id, config, test_files, results)
                )
                tasks.append(task)
                
                # Ramp up delay
                if config.ramp_up_time > 0:
                    await asyncio.sleep(config.ramp_up_time / config.concurrent_users)
            
            # Wait for all users to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
            total_duration = time.time() - start_time
            
            # Collect results
            response_times = []
            errors = []
            successful_requests = 0
            failed_requests = 0
            
            while not results.empty():
                result = results.get()
                if result['success']:
                    successful_requests += 1
                    response_times.append(result['response_time'])
                else:
                    failed_requests += 1
                    errors.append(result['error'])
            
            # Get resource statistics
            resource_stats = self.resource_monitor.stop_monitoring()
            
            # Calculate statistics
            total_requests = successful_requests + failed_requests
            success_rate = successful_requests / total_requests if total_requests > 0 else 0.0
            error_rate = failed_requests / total_requests if total_requests > 0 else 0.0
            requests_per_second = total_requests / total_duration if total_duration > 0 else 0.0
            
            return LoadTestResult(
                test_name=f"Load Test ({config.concurrent_users} users)",
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                total_duration=total_duration,
                average_response_time=statistics.mean(response_times) if response_times else 0.0,
                min_response_time=min(response_times) if response_times else 0.0,
                max_response_time=max(response_times) if response_times else 0.0,
                requests_per_second=requests_per_second,
                success_rate=success_rate,
                error_rate=error_rate,
                peak_memory_mb=resource_stats["peak_memory_mb"],
                average_cpu_percent=resource_stats["average_cpu_percent"],
                errors=errors[:10],  # Keep only first 10 errors
                response_times=response_times
            )
            
        finally:
            self.resource_monitor.stop_monitoring()
    
    async def _simulate_user(
        self, 
        user_id: int, 
        config: LoadTestConfig, 
        test_files: List[str], 
        results: Queue
    ) -> None:
        """Simulate a single user making requests."""
        system_config = SystemConfiguration()
        system_config.hooks_enabled = False
        system_config.analysis_timeout = config.timeout
        
        try:
            async with ComplianceAgent(system_config) as agent:
                for request_num in range(config.requests_per_user):
                    # Select random test file
                    test_file = random.choice(test_files)
                    
                    # Make request
                    start_time = time.time()
                    try:
                        result = await asyncio.wait_for(
                            agent.analyze_files([test_file]),
                            timeout=config.timeout
                        )
                        
                        response_time = time.time() - start_time
                        
                        results.put({
                            'user_id': user_id,
                            'request_num': request_num,
                            'success': result.success,
                            'response_time': response_time,
                            'error': None
                        })
                        
                    except asyncio.TimeoutError:
                        response_time = time.time() - start_time
                        results.put({
                            'user_id': user_id,
                            'request_num': request_num,
                            'success': False,
                            'response_time': response_time,
                            'error': 'Request timeout'
                        })
                        
                    except Exception as e:
                        response_time = time.time() - start_time
                        results.put({
                            'user_id': user_id,
                            'request_num': request_num,
                            'success': False,
                            'response_time': response_time,
                            'error': str(e)
                        })
                    
                    # Think time between requests
                    if request_num < config.requests_per_user - 1:
                        think_time = random.uniform(config.think_time_min, config.think_time_max)
                        await asyncio.sleep(think_time)
                        
        except Exception as e:
            # User-level error
            results.put({
                'user_id': user_id,
                'request_num': -1,
                'success': False,
                'response_time': 0.0,
                'error': f'User {user_id} failed: {e}'
            })
    
    async def run_stress_test(self) -> LoadTestResult:
        """Run stress test with increasing load."""
        print("Running stress test with increasing load...")
        
        # Start with low load and increase
        configs = [
            LoadTestConfig(concurrent_users=5, requests_per_user=3),
            LoadTestConfig(concurrent_users=10, requests_per_user=3),
            LoadTestConfig(concurrent_users=20, requests_per_user=3),
            LoadTestConfig(concurrent_users=50, requests_per_user=2),
        ]
        
        all_results = []
        
        for i, config in enumerate(configs):
            print(f"Stress test phase {i+1}/{len(configs)}: {config.concurrent_users} users")
            result = await self.run_load_test(config)
            all_results.append(result)
            
            # Brief pause between phases
            await asyncio.sleep(2.0)
        
        # Aggregate results
        total_requests = sum(r.total_requests for r in all_results)
        successful_requests = sum(r.successful_requests for r in all_results)
        failed_requests = sum(r.failed_requests for r in all_results)
        total_duration = sum(r.total_duration for r in all_results)
        
        all_response_times = []
        all_errors = []
        for r in all_results:
            all_response_times.extend(r.response_times)
            all_errors.extend(r.errors)
        
        return LoadTestResult(
            test_name="Stress Test (Progressive Load)",
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            total_duration=total_duration,
            average_response_time=statistics.mean(all_response_times) if all_response_times else 0.0,
            min_response_time=min(all_response_times) if all_response_times else 0.0,
            max_response_time=max(all_response_times) if all_response_times else 0.0,
            requests_per_second=total_requests / total_duration if total_duration > 0 else 0.0,
            success_rate=successful_requests / total_requests if total_requests > 0 else 0.0,
            error_rate=failed_requests / total_requests if total_requests > 0 else 0.0,
            peak_memory_mb=max(r.peak_memory_mb for r in all_results),
            average_cpu_percent=statistics.mean([r.average_cpu_percent for r in all_results]),
            errors=all_errors[:20],  # Keep first 20 errors
            response_times=all_response_times
        )
    
    async def run_spike_test(self) -> LoadTestResult:
        """Run spike test with sudden load increase."""
        print("Running spike test...")
        
        # Sudden spike in load
        config = LoadTestConfig(
            concurrent_users=100,
            requests_per_user=2,
            ramp_up_time=1.0,  # Very fast ramp up
            timeout=15.0
        )
        
        return await self.run_load_test(config)
    
    async def run_endurance_test(self) -> LoadTestResult:
        """Run endurance test with sustained load."""
        print("Running endurance test...")
        
        # Sustained moderate load
        config = LoadTestConfig(
            concurrent_users=15,
            requests_per_user=10,  # More requests per user
            ramp_up_time=10.0,
            timeout=20.0
        )
        
        return await self.run_load_test(config)
    
    def generate_load_test_report(self, results: List[LoadTestResult]) -> str:
        """Generate load test report."""
        report = ["# Compliance Sentinel Load Test Report\n"]
        report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append("=" * 60 + "\n")
        
        # Summary table
        report.append("## Test Results Summary\n")
        report.append("| Test | Requests | Success Rate | Avg Response (s) | RPS | Peak Memory (MB) |")
        report.append("|------|----------|--------------|------------------|-----|------------------|")
        
        for result in results:
            report.append(
                f"| {result.test_name} | {result.total_requests} | "
                f"{result.success_rate:.1%} | {result.average_response_time:.3f} | "
                f"{result.requests_per_second:.1f} | {result.peak_memory_mb:.1f} |"
            )
        
        report.append("\n")
        
        # Detailed results
        report.append("## Detailed Results\n")
        for result in results:
            report.append(f"### {result.test_name}\n")
            report.append(f"- **Total Requests**: {result.total_requests}")
            report.append(f"- **Successful**: {result.successful_requests}")
            report.append(f"- **Failed**: {result.failed_requests}")
            report.append(f"- **Success Rate**: {result.success_rate:.1%}")
            report.append(f"- **Error Rate**: {result.error_rate:.1%}")
            report.append(f"- **Total Duration**: {result.total_duration:.1f}s")
            report.append(f"- **Requests per Second**: {result.requests_per_second:.1f}")
            report.append(f"- **Average Response Time**: {result.average_response_time:.3f}s")
            report.append(f"- **Min Response Time**: {result.min_response_time:.3f}s")
            report.append(f"- **Max Response Time**: {result.max_response_time:.3f}s")
            report.append(f"- **95th Percentile**: {result.percentile_95:.3f}s")
            report.append(f"- **99th Percentile**: {result.percentile_99:.3f}s")
            report.append(f"- **Peak Memory Usage**: {result.peak_memory_mb:.1f}MB")
            report.append(f"- **Average CPU Usage**: {result.average_cpu_percent:.1f}%")
            
            if result.errors:
                report.append(f"- **Sample Errors**:")
                for error in result.errors[:5]:  # Show first 5 errors
                    report.append(f"  - {error}")
            
            report.append("")
        
        # Performance analysis
        report.append("## Performance Analysis\n")
        
        # Find best and worst performing tests
        if results:
            best_rps = max(results, key=lambda r: r.requests_per_second)
            worst_rps = min(results, key=lambda r: r.requests_per_second)
            
            report.append(f"- **Best Throughput**: {best_rps.test_name} ({best_rps.requests_per_second:.1f} RPS)")
            report.append(f"- **Lowest Throughput**: {worst_rps.test_name} ({worst_rps.requests_per_second:.1f} RPS)")
            
            best_response = min(results, key=lambda r: r.average_response_time)
            worst_response = max(results, key=lambda r: r.average_response_time)
            
            report.append(f"- **Best Response Time**: {best_response.test_name} ({best_response.average_response_time:.3f}s)")
            report.append(f"- **Worst Response Time**: {worst_response.test_name} ({worst_response.average_response_time:.3f}s)")
            
            # Memory usage analysis
            high_memory = [r for r in results if r.peak_memory_mb > 200]
            if high_memory:
                report.append(f"- **High Memory Usage Tests**: {len(high_memory)}")
                for test in high_memory:
                    report.append(f"  - {test.test_name}: {test.peak_memory_mb:.1f}MB")
            
            # Error analysis
            failed_tests = [r for r in results if r.error_rate > 0.1]  # More than 10% error rate
            if failed_tests:
                report.append(f"- **Tests with High Error Rates**:")
                for test in failed_tests:
                    report.append(f"  - {test.test_name}: {test.error_rate:.1%} error rate")
        
        return "\n".join(report)


# Pytest integration
@pytest.mark.load
class TestLoadTesting:
    """Load testing for pytest integration."""
    
    @pytest.mark.asyncio
    async def test_basic_load(self):
        """Test basic load handling."""
        runner = LoadTestRunner()
        
        try:
            config = LoadTestConfig(concurrent_users=5, requests_per_user=2)
            result = await runner.run_load_test(config)
            
            # Basic load should handle well
            assert result.success_rate >= 0.9, f"Success rate too low: {result.success_rate:.1%}"
            assert result.average_response_time < 10.0, f"Response time too slow: {result.average_response_time:.3f}s"
            assert result.requests_per_second > 0.5, f"Throughput too low: {result.requests_per_second:.1f} RPS"
            
        finally:
            runner.cleanup_test_files()
    
    @pytest.mark.asyncio
    async def test_moderate_load(self):
        """Test moderate load handling."""
        runner = LoadTestRunner()
        
        try:
            config = LoadTestConfig(concurrent_users=10, requests_per_user=3)
            result = await runner.run_load_test(config)
            
            # Moderate load should still perform reasonably
            assert result.success_rate >= 0.8, f"Success rate too low: {result.success_rate:.1%}"
            assert result.average_response_time < 15.0, f"Response time too slow: {result.average_response_time:.3f}s"
            assert result.peak_memory_mb < 500, f"Memory usage too high: {result.peak_memory_mb:.1f}MB"
            
        finally:
            runner.cleanup_test_files()
    
    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_stress_load(self):
        """Test stress load handling."""
        runner = LoadTestRunner()
        
        try:
            result = await runner.run_stress_test()
            
            # Stress test may have some failures but should not crash
            assert result.success_rate >= 0.5, f"Success rate too low under stress: {result.success_rate:.1%}"
            assert result.peak_memory_mb < 1000, f"Memory usage too high: {result.peak_memory_mb:.1f}MB"
            
        finally:
            runner.cleanup_test_files()


if __name__ == "__main__":
    async def main():
        runner = LoadTestRunner()
        
        try:
            print("Starting Compliance Sentinel Load Tests...")
            print("=" * 60)
            
            # Run different types of load tests
            tests = [
                ("Basic Load", runner.run_load_test(LoadTestConfig(concurrent_users=5, requests_per_user=3))),
                ("Moderate Load", runner.run_load_test(LoadTestConfig(concurrent_users=10, requests_per_user=3))),
                ("High Load", runner.run_load_test(LoadTestConfig(concurrent_users=20, requests_per_user=2))),
                ("Spike Test", runner.run_spike_test()),
                ("Endurance Test", runner.run_endurance_test())
            ]
            
            results = []
            for test_name, test_coro in tests:
                print(f"\nRunning {test_name}...")
                result = await test_coro
                results.append(result)
                
                status = "✅" if result.success_rate >= 0.8 else "⚠️"
                print(f"{status} {test_name}: {result.success_rate:.1%} success, {result.requests_per_second:.1f} RPS")
            
            # Generate report
            report = runner.generate_load_test_report(results)
            with open("load_test_report.md", "w") as f:
                f.write(report)
            
            print(f"\nLoad test report saved to: load_test_report.md")
            
        finally:
            runner.cleanup_test_files()
    
    asyncio.run(main())