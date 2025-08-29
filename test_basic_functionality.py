#!/usr/bin/env python3
"""Basic functionality test for Compliance Sentinel."""

import tempfile
from pathlib import Path
import asyncio

def test_basic_imports():
    """Test that basic imports work."""
    print("🔍 Testing basic imports...")
    
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from compliance_sentinel.models.config import SystemConfiguration, HookSettings
        from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
        print("✅ Basic imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_model_creation():
    """Test creating basic models."""
    print("🔍 Testing model creation...")
    
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, SecurityCategory
        from compliance_sentinel.models.config import SystemConfiguration
        from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
        from datetime import datetime
        import uuid
        
        # Create a security issue
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
        
        # Create configuration
        config = SystemConfiguration()
        
        # Create analysis request
        request = AnalysisRequest(
            file_paths=['test.py'],
            analysis_type=AnalysisType.SECURITY_SCAN
        )
        
        print(f"✅ Models created successfully")
        print(f"   Issue: {issue.description} ({issue.severity.value})")
        print(f"   Config: {config.max_concurrent_analyses} max analyses")
        print(f"   Request: {len(request.file_paths)} files to analyze")
        return True
        
    except Exception as e:
        print(f"❌ Model creation failed: {e}")
        return False

def test_vulnerable_code_samples():
    """Test vulnerable code samples."""
    print("🔍 Testing vulnerable code samples...")
    
    try:
        from tests.fixtures.vulnerable_code_samples import VulnerableCodeSamples
        
        # Get Python samples
        python_samples = VulnerableCodeSamples.get_python_samples()
        
        print(f"✅ Vulnerable code samples loaded")
        print(f"   Found {len(python_samples)} Python samples")
        
        # Test a sample
        if python_samples:
            sample = python_samples[0]
            print(f"   Sample: {sample.name} ({len(sample.expected_issues)} expected issues)")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerable code samples failed: {e}")
        return False

def test_config_manager():
    """Test configuration manager."""
    print("🔍 Testing configuration manager...")
    
    try:
        from compliance_sentinel.config.config_manager import ConfigManager
        
        # Create config manager with temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            config_manager = ConfigManager(Path(temp_dir))
            
            # Create default config
            config = config_manager.create_default_config("test-project")
            
            print(f"✅ Configuration manager working")
            print(f"   Project: {config.project_name}")
            print(f"   Custom rules: {len(config.custom_rules)}")
            print(f"   MCP servers: {len(config.mcp_servers)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration manager failed: {e}")
        return False

async def test_basic_analysis():
    """Test basic analysis functionality."""
    print("🔍 Testing basic analysis...")
    
    try:
        # Create a test file with vulnerable code
        # Use TestDataManager for test content
        from compliance_sentinel.testing.test_data_manager import get_test_data_manager
        test_data_manager = get_test_data_manager()
        test_code = test_data_manager.create_test_file_content("python")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_code)
            test_file = f.name
        
        try:
            # Try to import and test analysis components
            from compliance_sentinel.models.analysis import AnalysisRequest, AnalysisType
            from compliance_sentinel.models.config import SystemConfiguration
            
            # Create analysis request
            request = AnalysisRequest(
                file_paths=[test_file],
                analysis_type=AnalysisType.SECURITY_SCAN
            )
            
            config = SystemConfiguration()
            
            print(f"✅ Basic analysis setup successful")
            print(f"   Test file: {test_file}")
            print(f"   Request ID: {request.request_id}")
            print(f"   Analysis type: {request.analysis_type.value}")
            
            return True
            
        finally:
            # Clean up test file
            Path(test_file).unlink(missing_ok=True)
            
    except Exception as e:
        print(f"❌ Basic analysis failed: {e}")
        return False

def main():
    """Run all basic tests."""
    print("🚀 Running Compliance Sentinel Basic Functionality Tests")
    print("=" * 60)
    
    tests = [
        test_basic_imports,
        test_model_creation,
        test_vulnerable_code_samples,
        test_config_manager,
    ]
    
    async_tests = [
        test_basic_analysis,
    ]
    
    results = []
    
    # Run synchronous tests
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            results.append(False)
        print()
    
    # Run asynchronous tests
    for test in async_tests:
        try:
            result = asyncio.run(test())
            results.append(result)
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            results.append(False)
        print()
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print("=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    print(f"Passed: {passed}/{total} ({passed/total:.1%})")
    
    if passed == total:
        print("🎉 All basic functionality tests passed!")
        return 0
    else:
        print("⚠️ Some tests failed. Check the output above.")
        return 1

if __name__ == "__main__":
    exit(main())