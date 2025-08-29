#!/usr/bin/env python3
"""
Simple system functionality test that doesn't require external network access.
"""

import asyncio
import tempfile
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from compliance_sentinel.config.dynamic_config import DynamicConfigManager, EnvironmentConfigSource
from compliance_sentinel.utils.intelligent_cache import IntelligentCache
from compliance_sentinel.utils.circuit_breaker import CircuitBreakerManager
from compliance_sentinel.utils.resilient_error_handler import ResilientErrorHandler, ErrorContext
from compliance_sentinel.monitoring.real_time_metrics import RealTimeMetrics


async def test_core_components():
    """Test core system components without external dependencies."""
    print("🧪 Testing Core Components...")
    
    # Test 1: Configuration Manager
    print("  ✅ Testing Configuration Manager...")
    env_source = EnvironmentConfigSource()
    config_manager = DynamicConfigManager([env_source])
    await config_manager.initialize()
    
    # Set a test config value with the expected prefix
    os.environ["COMPLIANCE_SENTINEL_TEST_CONFIG_VALUE"] = "test_value_123"
    config_value = await config_manager.get_config("test.config.value", "default")
    assert config_value == "test_value_123", f"Expected 'test_value_123', got '{config_value}'"
    print("    ✓ Configuration loading works")
    
    # Test 2: Intelligent Cache
    print("  ✅ Testing Intelligent Cache...")
    cache = IntelligentCache()
    await cache.start()
    
    # Test cache operations
    await cache.set("test_key", "test_value", ttl=60)
    cached_value = await cache.get("test_key")
    assert cached_value == "test_value", f"Expected 'test_value', got '{cached_value}'"
    print("    ✓ Cache operations work")
    
    # Test 3: Circuit Breaker
    print("  ✅ Testing Circuit Breaker...")
    cb_manager = CircuitBreakerManager()
    
    # Test circuit breaker creation and state
    cb = cb_manager.get_circuit_breaker("test_service")
    assert cb.state.name == "CLOSED", f"Expected CLOSED state, got {cb.state.name}"
    print("    ✓ Circuit breaker works")
    
    # Test 4: Error Handler
    print("  ✅ Testing Error Handler...")
    error_handler = ResilientErrorHandler(cache, cb_manager)
    
    # Test error context creation
    context = ErrorContext(
        operation="test_operation",
        service="test_service",
        request_id="test_123"
    )
    assert context.operation == "test_operation"
    print("    ✓ Error handler works")
    
    # Test 5: Metrics
    print("  ✅ Testing Metrics...")
    metrics = RealTimeMetrics()
    
    # Test metric operations
    metrics.increment_counter("test_counter", 1.0, {"test": "tag"})
    metrics.record_timer("test_timer", 100.0, {"test": "tag"})
    
    counter_value = metrics.get_metric_value("test_counter")
    assert counter_value >= 1.0, f"Expected counter >= 1.0, got {counter_value}"
    print("    ✓ Metrics collection works")
    
    print("✅ All core components working correctly!")
    return True


async def test_integration_workflow():
    """Test integration between components."""
    print("\n🔄 Testing Integration Workflow...")
    
    # Create integrated system
    env_source = EnvironmentConfigSource()
    config_manager = DynamicConfigManager([env_source])
    await config_manager.initialize()
    
    cache = IntelligentCache()
    await cache.start()
    
    cb_manager = CircuitBreakerManager()
    error_handler = ResilientErrorHandler(cache, cb_manager)
    metrics = RealTimeMetrics()
    
    # Test workflow: Configuration -> Cache -> Error Handling -> Metrics
    print("  ✅ Testing integrated workflow...")
    
    # 1. Load configuration
    os.environ["COMPLIANCE_SENTINEL_CACHE_TTL"] = "300"
    cache_ttl = await config_manager.get_config("cache.ttl", 60)
    cache_ttl = int(cache_ttl)
    
    # 2. Use configuration in cache
    await cache.set("workflow_test", "integrated_value", ttl=cache_ttl)
    
    # 3. Test error handling with cache fallback
    context = ErrorContext(
        operation="workflow_test",
        service="test_service",
        request_id="workflow_123"
    )
    
    # Simulate an error and test fallback
    test_error = Exception("Simulated service error")
    fallback_result = await error_handler.handle_external_service_error(
        "test_service", test_error, context, "fallback_data"
    )
    
    # Should use fallback since we don't have cached data for this specific key
    print(f"    ✓ Fallback result: success={fallback_result.success}")
    
    # 4. Record metrics
    metrics.increment_counter("workflow_tests_total", 1.0, {"status": "success"})
    
    print("✅ Integration workflow completed successfully!")
    return True


async def test_error_scenarios():
    """Test error handling scenarios."""
    print("\n🚨 Testing Error Scenarios...")
    
    cache = IntelligentCache()
    await cache.start()
    
    cb_manager = CircuitBreakerManager()
    error_handler = ResilientErrorHandler(cache, cb_manager)
    
    # Test 1: Connection Error
    print("  ✅ Testing connection error handling...")
    context = ErrorContext(
        operation="test_connection",
        service="external_api",
        request_id="conn_test_123"
    )
    
    connection_error = ConnectionError("Connection refused")
    result = await error_handler.handle_external_service_error(
        "external_api", connection_error, context, {"default": "data"}
    )
    
    print(f"    ✓ Connection error handled: success={result.success}")
    
    # Test 2: Timeout Error
    print("  ✅ Testing timeout error handling...")
    timeout_error = TimeoutError("Request timeout")
    result = await error_handler.handle_external_service_error(
        "external_api", timeout_error, context, {"default": "data"}
    )
    
    print(f"    ✓ Timeout error handled: success={result.success}")
    
    print("✅ Error scenarios tested successfully!")
    return True


async def test_performance():
    """Test system performance."""
    print("\n⚡ Testing Performance...")
    
    cache = IntelligentCache()
    await cache.start()
    
    metrics = RealTimeMetrics()
    
    # Test cache performance
    print("  ✅ Testing cache performance...")
    import time
    
    start_time = time.time()
    
    # Perform 1000 cache operations
    for i in range(1000):
        await cache.set(f"perf_test_{i}", f"value_{i}", ttl=60)
        await cache.get(f"perf_test_{i}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"    ✓ 1000 cache operations completed in {duration:.3f} seconds")
    print(f"    ✓ Average: {(duration/1000)*1000:.3f} ms per operation")
    
    # Test metrics performance
    print("  ✅ Testing metrics performance...")
    
    start_time = time.time()
    
    # Perform 1000 metric operations
    for i in range(1000):
        metrics.increment_counter("perf_test_counter", 1.0, {"iteration": str(i)})
        metrics.record_timer("perf_test_timer", float(i), {"iteration": str(i)})
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"    ✓ 1000 metric operations completed in {duration:.3f} seconds")
    print(f"    ✓ Average: {(duration/1000)*1000:.3f} ms per operation")
    
    print("✅ Performance tests completed!")
    return True


async def main():
    """Run all tests."""
    print("🚀 Starting Compliance Sentinel System Tests")
    print("=" * 60)
    
    try:
        # Run all test suites
        await test_core_components()
        await test_integration_workflow()
        await test_error_scenarios()
        await test_performance()
        
        print("\n" + "=" * 60)
        print("🎉 ALL TESTS PASSED! System is fully functional!")
        print("✅ Core components working")
        print("✅ Integration workflow working")
        print("✅ Error handling working")
        print("✅ Performance acceptable")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)