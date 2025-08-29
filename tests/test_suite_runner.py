"""Comprehensive test suite runner for Compliance Sentinel."""

import asyncio
import time
import sys
from pathlib import Path
from typing import Dict, Any, List
import argparse

# Import test modules
from tests.performance.benchmarks import BenchmarkSuite
from tests.security.security_tests import SecurityTestFramework
from tests.load.load_tests import LoadTestRunner, LoadTestConfig


class ComprehensiveTestSuite:
    """Orchestrates all types of testing for Compliance Sentinel."""
    
    def __init__(self):
        """Initialize comprehensive test suite."""
        self.results = {
            'unit_tests': None,
            'integration_tests': None,
            'performance_tests': None,
            'security_tests': None,
            'load_tests': None
        }
        
    async def run_all_tests(self, include_slow: bool = False) -> Dict[str, Any]:
        """Run all test suites."""
        print("🚀 Starting Comprehensive Compliance Sentinel Test Suite")
        print("=" * 70)
        
        start_time = time.time()
        
        # Run unit and integration tests with pytest
        print("\n📋 Running Unit and Integration Tests...")
        unit_result = await self._run_pytest_tests(include_slow)
        self.results['unit_tests'] = unit_result
        
        # Run performance benchmarks
        print("\n⚡ Running Performance Benchmarks...")
        perf_result = await self._run_performance_tests()
        self.results['performance_tests'] = perf_result
        
        # Run security tests
        print("\n🔒 Running Security Tests...")
        security_result = await self._run_security_tests()
        self.results['security_tests'] = security_result
        
        # Run load tests (optional for slow tests)
        if include_slow:
            print("\n📈 Running Load Tests...")
            load_result = await self._run_load_tests()
            self.results['load_tests'] = load_result
        else:
            print("\n📈 Skipping Load Tests (use --include-slow to run)")
            self.results['load_tests'] = {'status': 'skipped'}
        
        total_time = time.time() - start_time
        
        # Generate comprehensive report
        report = self._generate_comprehensive_report(total_time)
        
        print("\n" + "=" * 70)
        print("📊 Test Suite Complete!")
        print(f"⏱️  Total Time: {total_time:.1f} seconds")
        print("=" * 70)
        
        return {
            'results': self.results,
            'report': report,
            'total_time': total_time
        }
    
    async def _run_pytest_tests(self, include_slow: bool) -> Dict[str, Any]:
        """Run pytest unit and integration tests."""
        import subprocess
        
        try:
            # Base pytest command
            cmd = [
                sys.executable, "-m", "pytest",
                "tests/",
                "-v",
                "--tb=short",
                "--durations=10"
            ]
            
            # Add markers based on options
            if include_slow:
                cmd.extend(["-m", "not load"])  # Exclude load tests (run separately)
            else:
                cmd.extend(["-m", "not (performance or security or load or slow)"])
            
            # Run pytest
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            output_lines = result.stdout.split('\n')
            summary_line = next((line for line in output_lines if 'passed' in line and 'failed' in line), '')
            
            return {
                'status': 'passed' if result.returncode == 0 else 'failed',
                'return_code': result.returncode,
                'summary': summary_line,
                'output': result.stdout,
                'errors': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'return_code': -1,
                'summary': 'Tests timed out after 5 minutes',
                'output': '',
                'errors': 'Test execution timed out'
            }
        except Exception as e:
            return {
                'status': 'error',
                'return_code': -1,
                'summary': f'Error running tests: {e}',
                'output': '',
                'errors': str(e)
            }
    
    async def _run_performance_tests(self) -> Dict[str, Any]:
        """Run performance benchmark tests."""
        try:
            suite = BenchmarkSuite()
            results = await suite.run_all_benchmarks()
            
            # Calculate summary statistics
            successful = len([r for r in results if r.success_rate == 1.0])
            total = len(results)
            avg_time = sum(r.execution_time for r in results) / total if total > 0 else 0
            avg_memory = sum(r.memory_usage_mb for r in results) / total if total > 0 else 0
            
            return {
                'status': 'completed',
                'total_benchmarks': total,
                'successful_benchmarks': successful,
                'success_rate': successful / total if total > 0 else 0,
                'average_execution_time': avg_time,
                'average_memory_usage': avg_memory,
                'results': results,
                'report': suite.generate_performance_report()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': [],
                'report': f'Performance tests failed: {e}'
            }
    
    async def _run_security_tests(self) -> Dict[str, Any]:
        """Run security tests."""
        try:
            framework = SecurityTestFramework()
            results = await framework.run_all_security_tests()
            
            # Calculate summary statistics
            passed = len([r for r in results if r['status'] == 'PASSED'])
            total = len(results)
            critical_failures = len([r for r in results if r['status'] == 'FAILED' and r.get('severity') == 'CRITICAL'])
            high_failures = len([r for r in results if r['status'] == 'FAILED' and r.get('severity') == 'HIGH'])
            
            return {
                'status': 'completed',
                'total_tests': total,
                'passed_tests': passed,
                'failed_tests': total - passed,
                'success_rate': passed / total if total > 0 else 0,
                'critical_failures': critical_failures,
                'high_failures': high_failures,
                'results': results,
                'report': framework.generate_security_report()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': [],
                'report': f'Security tests failed: {e}'
            }
    
    async def _run_load_tests(self) -> Dict[str, Any]:
        """Run load tests."""
        try:
            runner = LoadTestRunner()
            
            # Run different load test scenarios
            configs = [
                ("Light Load", LoadTestConfig(concurrent_users=5, requests_per_user=2)),
                ("Moderate Load", LoadTestConfig(concurrent_users=10, requests_per_user=3)),
                ("Heavy Load", LoadTestConfig(concurrent_users=20, requests_per_user=2))
            ]
            
            results = []
            for test_name, config in configs:
                print(f"  Running {test_name}...")
                result = await runner.run_load_test(config)
                results.append(result)
            
            # Calculate summary statistics
            total_requests = sum(r.total_requests for r in results)
            successful_requests = sum(r.successful_requests for r in results)
            avg_response_time = sum(r.average_response_time for r in results) / len(results)
            avg_rps = sum(r.requests_per_second for r in results) / len(results)
            
            runner.cleanup_test_files()
            
            return {
                'status': 'completed',
                'total_scenarios': len(results),
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'success_rate': successful_requests / total_requests if total_requests > 0 else 0,
                'average_response_time': avg_response_time,
                'average_rps': avg_rps,
                'results': results,
                'report': runner.generate_load_test_report(results)
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': [],
                'report': f'Load tests failed: {e}'
            }
    
    def _generate_comprehensive_report(self, total_time: float) -> str:
        """Generate comprehensive test report."""
        report = ["# Compliance Sentinel Comprehensive Test Report\n"]
        report.append(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total execution time: {total_time:.1f} seconds\n")
        report.append("=" * 70 + "\n")
        
        # Executive Summary
        report.append("## Executive Summary\n")
        
        # Unit/Integration Tests
        unit_result = self.results.get('unit_tests', {})
        if unit_result and unit_result.get('status') == 'passed':
            report.append("✅ **Unit & Integration Tests**: PASSED")
        elif unit_result and unit_result.get('status') == 'failed':
            report.append("❌ **Unit & Integration Tests**: FAILED")
        else:
            report.append("⚠️ **Unit & Integration Tests**: ERROR/TIMEOUT")
        
        if unit_result.get('summary'):
            report.append(f"   - {unit_result['summary']}")
        
        # Performance Tests
        perf_result = self.results.get('performance_tests', {})
        if perf_result.get('status') == 'completed':
            success_rate = perf_result.get('success_rate', 0)
            if success_rate >= 0.9:
                report.append("✅ **Performance Tests**: PASSED")
            elif success_rate >= 0.7:
                report.append("⚠️ **Performance Tests**: PARTIAL")
            else:
                report.append("❌ **Performance Tests**: FAILED")
            
            report.append(f"   - {perf_result.get('successful_benchmarks', 0)}/{perf_result.get('total_benchmarks', 0)} benchmarks passed")
            report.append(f"   - Average execution time: {perf_result.get('average_execution_time', 0):.3f}s")
            report.append(f"   - Average memory usage: {perf_result.get('average_memory_usage', 0):.1f}MB")
        else:
            report.append("❌ **Performance Tests**: ERROR")
        
        # Security Tests
        security_result = self.results.get('security_tests', {})
        if security_result.get('status') == 'completed':
            critical_failures = security_result.get('critical_failures', 0)
            high_failures = security_result.get('high_failures', 0)
            
            if critical_failures == 0 and high_failures == 0:
                report.append("✅ **Security Tests**: PASSED")
            elif critical_failures == 0:
                report.append("⚠️ **Security Tests**: PARTIAL (High severity issues found)")
            else:
                report.append("❌ **Security Tests**: FAILED (Critical vulnerabilities found)")
            
            report.append(f"   - {security_result.get('passed_tests', 0)}/{security_result.get('total_tests', 0)} tests passed")
            if critical_failures > 0:
                report.append(f"   - {critical_failures} critical vulnerabilities")
            if high_failures > 0:
                report.append(f"   - {high_failures} high severity vulnerabilities")
        else:
            report.append("❌ **Security Tests**: ERROR")
        
        # Load Tests
        load_result = self.results.get('load_tests', {})
        if load_result.get('status') == 'completed':
            success_rate = load_result.get('success_rate', 0)
            if success_rate >= 0.9:
                report.append("✅ **Load Tests**: PASSED")
            elif success_rate >= 0.7:
                report.append("⚠️ **Load Tests**: PARTIAL")
            else:
                report.append("❌ **Load Tests**: FAILED")
            
            report.append(f"   - {load_result.get('successful_requests', 0)}/{load_result.get('total_requests', 0)} requests successful")
            report.append(f"   - Average response time: {load_result.get('average_response_time', 0):.3f}s")
            report.append(f"   - Average throughput: {load_result.get('average_rps', 0):.1f} RPS")
        elif load_result.get('status') == 'skipped':
            report.append("⏭️ **Load Tests**: SKIPPED")
        else:
            report.append("❌ **Load Tests**: ERROR")
        
        report.append("\n")
        
        # Detailed Results
        report.append("## Detailed Results\n")
        
        # Add individual test reports
        for test_type, result in self.results.items():
            if result and isinstance(result, dict) and 'report' in result:
                report.append(f"### {test_type.replace('_', ' ').title()}\n")
                report.append(result['report'])
                report.append("\n")
        
        # Recommendations
        report.append("## Recommendations\n")
        
        recommendations = []
        
        # Unit test recommendations
        if unit_result.get('status') == 'failed':
            recommendations.append("🔧 Fix failing unit/integration tests before deployment")
        
        # Performance recommendations
        if perf_result.get('success_rate', 1) < 0.9:
            recommendations.append("⚡ Investigate performance issues in failing benchmarks")
        
        if perf_result.get('average_memory_usage', 0) > 200:
            recommendations.append("💾 Consider memory optimization - average usage is high")
        
        # Security recommendations
        if security_result.get('critical_failures', 0) > 0:
            recommendations.append("🚨 URGENT: Address critical security vulnerabilities immediately")
        
        if security_result.get('high_failures', 0) > 0:
            recommendations.append("⚠️ Address high severity security issues before production")
        
        # Load test recommendations
        if load_result.get('success_rate', 1) < 0.8:
            recommendations.append("📈 Investigate load handling issues - success rate is low")
        
        if load_result.get('average_response_time', 0) > 5.0:
            recommendations.append("🐌 Response times are high under load - consider optimization")
        
        if not recommendations:
            recommendations.append("✅ All tests passed successfully - system is ready for deployment")
        
        for rec in recommendations:
            report.append(f"- {rec}")
        
        report.append("\n")
        
        # Test Coverage Summary
        report.append("## Test Coverage Summary\n")
        report.append("- **Unit Tests**: Core functionality and individual components")
        report.append("- **Integration Tests**: End-to-end workflows and component interaction")
        report.append("- **Performance Tests**: Speed, memory usage, and throughput benchmarks")
        report.append("- **Security Tests**: Vulnerability scanning and security validation")
        report.append("- **Load Tests**: Concurrent user simulation and stress testing")
        
        return "\n".join(report)
    
    def save_reports(self, output_dir: str = "test_reports") -> None:
        """Save all test reports to files."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Save individual reports
        for test_type, result in self.results.items():
            if result and isinstance(result, dict) and 'report' in result:
                report_file = output_path / f"{test_type}_report.md"
                with open(report_file, 'w') as f:
                    f.write(result['report'])
                print(f"📄 Saved {test_type} report to {report_file}")
        
        # Save comprehensive report
        if hasattr(self, '_comprehensive_report'):
            comprehensive_file = output_path / "comprehensive_report.md"
            with open(comprehensive_file, 'w') as f:
                f.write(self._comprehensive_report)
            print(f"📄 Saved comprehensive report to {comprehensive_file}")


async def main():
    """Main entry point for test suite runner."""
    parser = argparse.ArgumentParser(description="Run Compliance Sentinel comprehensive test suite")
    parser.add_argument("--include-slow", action="store_true", 
                       help="Include slow tests (load tests, endurance tests)")
    parser.add_argument("--output-dir", default="test_reports",
                       help="Directory to save test reports")
    parser.add_argument("--unit-only", action="store_true",
                       help="Run only unit and integration tests")
    parser.add_argument("--performance-only", action="store_true",
                       help="Run only performance tests")
    parser.add_argument("--security-only", action="store_true",
                       help="Run only security tests")
    parser.add_argument("--load-only", action="store_true",
                       help="Run only load tests")
    
    args = parser.parse_args()
    
    suite = ComprehensiveTestSuite()
    
    try:
        if args.unit_only:
            print("Running unit and integration tests only...")
            result = await suite._run_pytest_tests(args.include_slow)
            suite.results['unit_tests'] = result
        elif args.performance_only:
            print("Running performance tests only...")
            result = await suite._run_performance_tests()
            suite.results['performance_tests'] = result
        elif args.security_only:
            print("Running security tests only...")
            result = await suite._run_security_tests()
            suite.results['security_tests'] = result
        elif args.load_only:
            print("Running load tests only...")
            result = await suite._run_load_tests()
            suite.results['load_tests'] = result
        else:
            # Run all tests
            await suite.run_all_tests(args.include_slow)
        
        # Save reports
        suite.save_reports(args.output_dir)
        
        print(f"\n📁 All reports saved to {args.output_dir}/")
        
    except KeyboardInterrupt:
        print("\n⏹️ Test suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())