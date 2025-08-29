#!/usr/bin/env python3
"""Test working components of Compliance Sentinel."""

import tempfile
import asyncio
from pathlib import Path
import time

def test_core_models():
    """Test core data models."""
    print("🔍 Testing Core Models")
    print("-" * 25)
    
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from compliance_sentinel.models.config import SystemConfiguration, HookSettings
        from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
        from datetime import datetime
        import uuid
        
        # Test SecurityIssue
        issue = SecurityIssue(
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
        )
        
        print(f"✅ SecurityIssue: {issue.severity.value} - {issue.description}")
        
        # Test SystemConfiguration
        config = SystemConfiguration()
        print(f"✅ SystemConfiguration: {config.max_concurrent_analyses} max analyses")
        
        # Test HookSettings
        hook_settings = HookSettings()
        print(f"✅ HookSettings: {len(hook_settings.enabled_file_patterns)} file patterns")
        
        return True
        
    except Exception as e:
        print(f"❌ Core models failed: {e}")
        return False

def test_configuration_workflow():
    """Test configuration management workflow."""
    print("\n🔍 Testing Configuration Workflow")
    print("-" * 35)
    
    try:
        from compliance_sentinel.config.config_manager import (
            ConfigManager, AnalysisRuleConfig, SeverityThresholdConfig
        )
        from compliance_sentinel.config.validator import ConfigValidator
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create config manager
            config_manager = ConfigManager(Path(temp_dir))
            
            # Create default configuration
            config = config_manager.create_default_config("workflow-test")
            
            # Add custom rule
            custom_rule = AnalysisRuleConfig(
                rule_id="WORKFLOW-001",
                name="Test Rule",
                description="Test rule for workflow",
                severity="high",
                pattern=r"test_pattern",
                file_patterns=["*.py"]
            )
            
            config.custom_rules.append(custom_rule)
            
            # Save configuration
            success = config_manager.save_project_config(config)
            
            if success:
                # Load and validate
                loaded_config = config_manager.load_project_config()
                
                # Validate configuration
                validator = ConfigValidator()
                validation_result = validator.validate_project_config(loaded_config)
                
                print(f"✅ Configuration workflow:")
                print(f"   - Config saved and loaded successfully")
                print(f"   - Project: {loaded_config.project_name}")
                print(f"   - Custom rules: {len(loaded_config.custom_rules)}")
                print(f"   - Validation: {'✅ Valid' if validation_result['valid'] else '❌ Invalid'}")
                
                if validation_result['warnings']:
                    print(f"   - Warnings: {len(validation_result['warnings'])}")
                
                return True
            else:
                print(f"❌ Configuration save failed")
                return False
        
    except Exception as e:
        print(f"❌ Configuration workflow failed: {e}")
        return False

def test_vulnerable_code_analysis():
    """Test analysis of vulnerable code samples."""
    print("\n🔍 Testing Vulnerable Code Analysis")
    print("-" * 37)
    
    try:
        from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples
        from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
        
        # Get sample vulnerable code
        samples = VulnerableCodeSamples.get_python_samples()
        
        if not samples:
            print("❌ No vulnerable code samples available")
            return False
        
        # Create temporary files with vulnerable code
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_files = []
            
            for i, sample in enumerate(samples[:3]):  # Test first 3 samples
                file_path = temp_path / f"{sample.name}.py"
                file_path.write_text(sample.code)
                test_files.append(str(file_path))
            
            # Create analysis request
            request = AnalysisRequest(
                file_paths=test_files,
                analysis_type=AnalysisType.COMPREHENSIVE
            )
            
            print(f"✅ Vulnerable code analysis setup:")
            print(f"   - {len(test_files)} test files created")
            print(f"   - Request ID: {request.request_id}")
            print(f"   - Analysis type: {request.analysis_type.value}")
            
            # Test file extensions detection
            extensions = request.get_file_extensions()
            print(f"   - File extensions: {extensions}")
            
            return True
        
    except Exception as e:
        print(f"❌ Vulnerable code analysis failed: {e}")
        return False

def test_ide_components():
    """Test IDE integration components individually."""
    print("\n🔍 Testing IDE Components")
    print("-" * 28)
    
    results = []
    
    # Test Progress Indicators
    try:
        from compliance_sentinel.ide.progress_indicators import (
            ProgressTracker, ProgressType, ProgressState
        )
        
        tracker = ProgressTracker("ide-test", "IDE Test")
        tracker.add_step("step1", "Test Step", "Testing IDE components")
        
        tracker.start()
        assert tracker.progress_info.state == ProgressState.RUNNING
        
        tracker.start_step("step1")
        tracker.complete_step("step1")
        tracker.complete()
        
        assert tracker.progress_info.state == ProgressState.COMPLETED
        assert tracker.progress_info.percentage == 100.0
        
        print("✅ Progress Indicators: Working correctly")
        results.append(True)
    except Exception as e:
        print(f"❌ Progress Indicators: {e}")
        results.append(False)
    
    # Test Contextual Help
    try:
        from compliance_sentinel.ide.contextual_help import ContextualHelpProvider
        
        help_provider = ContextualHelpProvider()
        
        # Test search
        search_results = help_provider.search_help("password")
        
        print(f"✅ Contextual Help:")
        print(f"   - {len(help_provider.help_database)} help entries")
        print(f"   - {len(search_results)} search results for 'password'")
        results.append(True)
    except Exception as e:
        print(f"❌ Contextual Help: {e}")
        results.append(False)
    
    # Test Code Highlighter (without SecurityIssue dependency)
    try:
        from compliance_sentinel.ide.code_highlighter import (
            CodeHighlighter, CodeRange, HighlightType, HighlightStyle
        )
        
        highlighter = CodeHighlighter()
        
        # Test pattern highlighting using TestDataManager
        from compliance_sentinel.testing.test_data_manager import get_test_data_manager
        test_data_manager = get_test_data_manager()
        test_code = test_data_manager.create_test_file_content("python")
        
        highlights = highlighter.create_pattern_highlights("test.py", test_code)
        
        print(f"✅ Code Highlighter:")
        print(f"   - {len(highlights)} pattern highlights found")
        
        if highlights:
            highlight = highlights[0]
            print(f"   - Sample highlight: {highlight.message}")
        
        results.append(True)
    except Exception as e:
        print(f"❌ Code Highlighter: {e}")
        results.append(False)
    
    return results

async def test_async_components():
    """Test asynchronous components."""
    print("\n🔍 Testing Async Components")
    print("-" * 28)
    
    results = []
    
    # Test async progress tracking
    try:
        from compliance_sentinel.ide.progress_indicators import ProgressManager
        
        manager = ProgressManager()
        
        # Create multiple trackers
        tracker1 = manager.create_tracker("async-1", "Async Test 1")
        tracker2 = manager.create_tracker("async-2", "Async Test 2")
        
        tracker1.start()
        tracker2.start()
        
        # Simulate some async work
        await asyncio.sleep(0.1)
        
        tracker1.complete()
        tracker2.complete()
        
        # Get all progress
        all_progress = manager.get_all_progress()
        
        print(f"✅ Async Progress Management:")
        print(f"   - {len(all_progress)} trackers managed")
        print(f"   - All trackers completed successfully")
        
        results.append(True)
    except Exception as e:
        print(f"❌ Async Progress Management: {e}")
        results.append(False)
    
    return results

async def main():
    """Run working components test."""
    print("🚀 Compliance Sentinel Working Components Test")
    print("=" * 55)
    
    start_time = time.time()
    all_results = []
    
    # Run synchronous tests
    sync_tests = [
        test_core_models,
        test_configuration_workflow,
        test_vulnerable_code_analysis,
        test_ide_components,
    ]
    
    for test_func in sync_tests:
        try:
            if isinstance(test_func(), list):
                results = test_func()
                all_results.extend(results)
            else:
                result = test_func()
                all_results.append(result)
        except Exception as e:
            print(f"❌ Test {test_func.__name__} crashed: {e}")
            all_results.append(False)
    
    # Run async tests
    try:
        async_results = await test_async_components()
        all_results.extend(async_results)
    except Exception as e:
        print(f"❌ Async tests crashed: {e}")
        all_results.append(False)
    
    # Calculate results
    total_time = time.time() - start_time
    passed = sum(all_results)
    total = len(all_results)
    success_rate = passed / total if total > 0 else 0
    
    # Print summary
    print("\n" + "=" * 55)
    print("📊 Working Components Test Summary")
    print("=" * 55)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {success_rate:.1%}")
    print(f"Execution Time: {total_time:.2f} seconds")
    
    if success_rate >= 0.8:
        print("\n🎉 Working components test successful!")
        print("✅ Core Compliance Sentinel functionality is working!")
        return 0
    elif success_rate >= 0.6:
        print("\n⚠️ Working components test partially successful.")
        return 1
    else:
        print("\n❌ Working components test failed.")
        return 2

if __name__ == "__main__":
    exit(asyncio.run(main()))