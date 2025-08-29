#!/usr/bin/env python3
"""Comprehensive system validation for Compliance Sentinel."""

import sys
import tempfile
import asyncio
from pathlib import Path
import traceback
import time

def test_core_imports():
    """Test core module imports."""
    print("🔍 Testing Core Imports")
    print("-" * 30)
    
    tests = [
        ("Core Interfaces", "from compliance_sentinel.core.interfaces import SecurityIssue, Severity"),
        ("Analysis Models", "from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType"),
        ("Configuration", "from compliance_sentinel.models.config import SystemConfiguration"),
        ("Config Manager", "from compliance_sentinel.config.config_manager import ConfigManager"),
        ("Utilities", "from compliance_sentinel.utils import ConfigLoader, CacheManager"),
    ]
    
    results = []
    for test_name, import_stmt in tests:
        try:
            exec(import_stmt)
            print(f"✅ {test_name}")
            results.append(True)
        except Exception as e:
            print(f"❌ {test_name}: {e}")
            results.append(False)
    
    return results

def test_data_models():
    """Test data model creation and validation."""
    print("\n🔍 Testing Data Models")
    print("-" * 30)
    
    results = []
    
    # Test SecurityIssue
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from datetime import datetime
        import uuid
        
        issue = SecurityIssue(
            id=str(uuid.uuid4()),
            severity=Severity.HIGH,
            category=SecurityCategory.HARDCODED_SECRETS,
            file_path='test.py',
            line_number=1,
            description='Test security issue',
            rule_id='TEST-001',
            confidence=0.9,
            remediation_suggestions=['Fix the issue'],
            created_at=datetime.now()
        )
        print(f"✅ SecurityIssue: {issue.severity.value} - {issue.description}")
        results.append(True)
    except Exception as e:
        print(f"❌ SecurityIssue: {e}")
        results.append(False)
    
    # Test SystemConfiguration
    try:
        from compliance_sentinel.models.config import SystemConfiguration
        
        config = SystemConfiguration()
        print(f"✅ SystemConfiguration: {config.max_concurrent_analyses} max analyses")
        results.append(True)
    except Exception as e:
        print(f"❌ SystemConfiguration: {e}")
        results.append(False)
    
    # Test AnalysisRequest
    try:
        from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
        
        request = AnalysisRequest(
            file_paths=['test.py'],
            analysis_type=AnalysisType.SECURITY_SCAN
        )
        print(f"✅ AnalysisRequest: {request.analysis_type.value}")
        results.append(True)
    except Exception as e:
        print(f"❌ AnalysisRequest: {e}")
        results.append(False)
    
    return results

def test_configuration_system():
    """Test configuration management system."""
    print("\n🔍 Testing Configuration System")
    print("-" * 30)
    
    results = []
    
    # Test ConfigManager
    try:
        from compliance_sentinel.config.config_manager import ConfigManager
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config_manager = ConfigManager(Path(temp_dir))
            config = config_manager.create_default_config("test-project")
            
            print(f"✅ ConfigManager: Created config for '{config.project_name}'")
            print(f"   - {len(config.custom_rules)} custom rules")
            print(f"   - {len(config.mcp_servers)} MCP servers")
            results.append(True)
    except Exception as e:
        print(f"❌ ConfigManager: {e}")
        results.append(False)
    
    # Test Configuration Validation
    try:
        from compliance_sentinel.config.validator import ConfigValidator
        
        validator = ConfigValidator()
        print(f"✅ ConfigValidator: Initialized successfully")
        results.append(True)
    except Exception as e:
        print(f"❌ ConfigValidator: {e}")
        results.append(False)
    
    return results

def test_test_fixtures():
    """Test test fixtures and sample data."""
    print("\n🔍 Testing Test Fixtures")
    print("-" * 30)
    
    results = []
    
    # Test Vulnerable Code Samples
    try:
        from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples
        
        python_samples = VulnerableCodeSamples.get_python_samples()
        js_samples = VulnerableCodeSamples.get_javascript_samples()
        java_samples = VulnerableCodeSamples.get_java_samples()
        
        print(f"✅ Vulnerable Code Samples:")
        print(f"   - Python: {len(python_samples)} samples")
        print(f"   - JavaScript: {len(js_samples)} samples")
        print(f"   - Java: {len(java_samples)} samples")
        
        # Test a sample
        if python_samples:
            sample = python_samples[0]
            print(f"   - Sample '{sample.name}': {len(sample.expected_issues)} expected issues")
        
        results.append(True)
    except Exception as e:
        print(f"❌ Vulnerable Code Samples: {e}")
        results.append(False)
    
    return results

def test_ide_integration():
    """Test IDE integration components."""
    print("\n🔍 Testing IDE Integration")
    print("-" * 30)
    
    results = []
    
    # Test Feedback Formatter
    try:
        from compliance_sentinel.ide.feedback_formatter import IDEFeedbackFormatter, IDEType
        
        formatter = IDEFeedbackFormatter(IDEType.KIRO)
        print(f"✅ IDEFeedbackFormatter: {formatter.ide_type.value} IDE support")
        results.append(True)
    except Exception as e:
        print(f"❌ IDEFeedbackFormatter: {e}")
        results.append(False)
    
    # Test Code Highlighter
    try:
        from compliance_sentinel.ide.code_highlighter import CodeHighlighter
        
        highlighter = CodeHighlighter()
        print(f"✅ CodeHighlighter: Initialized successfully")
        results.append(True)
    except Exception as e:
        print(f"❌ CodeHighlighter: {e}")
        results.append(False)
    
    # Test Contextual Help
    try:
        from compliance_sentinel.ide.contextual_help import ContextualHelpProvider
        
        help_provider = ContextualHelpProvider()
        print(f"✅ ContextualHelpProvider: {len(help_provider.help_database)} help entries")
        results.append(True)
    except Exception as e:
        print(f"❌ ContextualHelpProvider: {e}")
        results.append(False)
    
    # Test Progress Indicators
    try:
        from compliance_sentinel.ide.progress_indicators import ProgressTracker, ProgressType
        
        tracker = ProgressTracker("test-1", "Test Progress")
        print(f"✅ ProgressTracker: {tracker.progress_info.title}")
        results.append(True)
    except Exception as e:
        print(f"❌ ProgressTracker: {e}")
        results.append(False)
    
    return results

def test_analysis_workflow():
    """Test analysis workflow components."""
    print("\n🔍 Testing Analysis Workflow")
    print("-" * 30)
    
    results = []
    
    # Test with sample vulnerable code
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from compliance_sentinel.ide.feedback_formatter import IDEFeedbackFormatter, IDEType
        from datetime import datetime
        import uuid
        
        # Create sample issues
        issues = [
            SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.HIGH,
                category=SecurityCategory.HARDCODED_SECRETS,
                file_path='test.py',
                line_number=1,
                description='Hardcoded password detected',
                rule_id='B105',
                confidence=0.9,
                remediation_suggestions=['Use environment variables'],
                created_at=datetime.now()
            ),
            SecurityIssue(
                id=str(uuid.uuid4()),
                severity=Severity.CRITICAL,
                category=SecurityCategory.SQL_INJECTION,
                file_path='test.py',
                line_number=5,
                description='SQL injection vulnerability',
                rule_id='B608',
                confidence=0.95,
                remediation_suggestions=['Use parameterized queries'],
                created_at=datetime.now()
            )
        ]
        
        # Test feedback formatting
        formatter = IDEFeedbackFormatter(IDEType.KIRO)
        feedback = formatter.format_issues(issues)
        
        print(f"✅ Analysis Workflow:")
        print(f"   - {len(issues)} security issues created")
        print(f"   - {len(feedback.diagnostics)} diagnostics generated")
        print(f"   - {len(feedback.quick_fixes)} quick fixes available")
        print(f"   - {len(feedback.code_actions)} code actions available")
        
        results.append(True)
    except Exception as e:
        print(f"❌ Analysis Workflow: {e}")
        results.append(False)
    
    return results

def test_deployment_validation():
    """Test deployment validation script."""
    print("\n🔍 Testing Deployment Validation")
    print("-" * 30)
    
    results = []
    
    try:
        # Import the deployment validator
        sys.path.append('scripts')
        from validate_deployment import DeploymentValidator
        
        validator = DeploymentValidator()
        print(f"✅ DeploymentValidator: Initialized successfully")
        results.append(True)
    except Exception as e:
        print(f"❌ DeploymentValidator: {e}")
        results.append(False)
    
    return results

async def run_async_tests():
    """Run asynchronous tests."""
    print("\n🔍 Testing Async Components")
    print("-" * 30)
    
    results = []
    
    # Test Progress Tracking
    try:
        from compliance_sentinel.ide.progress_indicators import ProgressTracker, ProgressType, ProgressStep
        
        tracker = ProgressTracker("async-test", "Async Test", progress_type=ProgressType.DETERMINATE)
        tracker.add_step("step1", "Test Step 1", "Testing async functionality")
        
        tracker.start()
        tracker.start_step("step1")
        
        # Simulate some work
        await asyncio.sleep(0.1)
        
        tracker.complete_step("step1")
        tracker.complete()
        
        info = tracker.get_progress_info()
        print(f"✅ Async Progress Tracking: {info.percentage}% complete")
        results.append(True)
    except Exception as e:
        print(f"❌ Async Progress Tracking: {e}")
        results.append(False)
    
    return results

def main():
    """Run comprehensive system validation."""
    print("🚀 Compliance Sentinel System Validation")
    print("=" * 60)
    
    start_time = time.time()
    all_results = []
    
    # Run synchronous tests
    test_functions = [
        test_core_imports,
        test_data_models,
        test_configuration_system,
        test_test_fixtures,
        test_ide_integration,
        test_analysis_workflow,
        test_deployment_validation,
    ]
    
    for test_func in test_functions:
        try:
            results = test_func()
            all_results.extend(results)
        except Exception as e:
            print(f"\n❌ Test function {test_func.__name__} crashed: {e}")
            traceback.print_exc()
            all_results.append(False)
    
    # Run async tests
    try:
        async_results = asyncio.run(run_async_tests())
        all_results.extend(async_results)
    except Exception as e:
        print(f"\n❌ Async tests crashed: {e}")
        traceback.print_exc()
        all_results.append(False)
    
    # Calculate results
    total_time = time.time() - start_time
    passed = sum(all_results)
    total = len(all_results)
    success_rate = passed / total if total > 0 else 0
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 System Validation Summary")
    print("=" * 60)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {success_rate:.1%}")
    print(f"Execution Time: {total_time:.2f} seconds")
    
    if success_rate >= 0.8:
        print("\n🎉 System validation successful!")
        print("✅ Compliance Sentinel is ready for use!")
        return 0
    elif success_rate >= 0.6:
        print("\n⚠️ System validation partially successful.")
        print("🔧 Some components may need attention.")
        return 1
    else:
        print("\n❌ System validation failed.")
        print("🚨 Multiple components need fixing.")
        return 2

if __name__ == "__main__":
    exit(main())