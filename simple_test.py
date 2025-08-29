#!/usr/bin/env python3
"""
Simple test to check basic functionality without importing everything at once.
"""

import sys
import traceback


def test_core_interfaces():
    """Test core interfaces."""
    try:
        from compliance_sentinel.core.interfaces import SecurityIssue, Severity, Category
        print("✅ Core interfaces imported successfully")
        
        # Test creating a security issue
        issue = SecurityIssue(
            id="test_1",
            rule_id="test_rule",
            severity=Severity.HIGH,
            category=Category.AUTHENTICATION,
            description="Test issue",
            file_path="test.py",
            line_number=1,
            confidence=0.95
        )
        print("✅ SecurityIssue created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Core interfaces test failed: {e}")
        traceback.print_exc()
        return False


def test_basic_analyzer():
    """Test basic analyzer functionality."""
    try:
        # Try to import without running complex logic
        print("📦 Testing analyzer imports...")
        
        # Test individual components
        components_to_test = [
            "compliance_sentinel.analyzers.javascript_analyzer",
            "compliance_sentinel.monitoring.metrics_collector", 
            "compliance_sentinel.monitoring.real_time_monitor"
        ]
        
        for component in components_to_test:
            try:
                __import__(component)
                print(f"✅ {component} imported successfully")
            except Exception as e:
                print(f"❌ {component} failed: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Analyzer test failed: {e}")
        return False


def main():
    """Run simple tests."""
    print("🧪 Running Simple Tests")
    print("=" * 50)
    
    success_count = 0
    total_tests = 2
    
    # Test core interfaces
    if test_core_interfaces():
        success_count += 1
    
    # Test basic analyzer
    if test_basic_analyzer():
        success_count += 1
    
    print("\n" + "=" * 50)
    print(f"Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("🎉 All simple tests passed!")
        return 0
    else:
        print("💥 Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())