#!/usr/bin/env python3
"""Comprehensive test runner for Compliance Sentinel."""

import subprocess
import sys
import os
from pathlib import Path

def run_test_suite(test_path, description):
    """Run a test suite and return results."""
    print(f"\n🧪 Running {description}...")
    print("=" * 60)
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            test_path, 
            "-v", 
            "--tb=short",
            "-x"  # Stop on first failure for cleaner output
        ], capture_output=True, text=True, timeout=300)
        
        # Parse results
        output_lines = result.stdout.split('\n')
        passed = len([line for line in output_lines if " PASSED " in line])
        failed = len([line for line in output_lines if " FAILED " in line])
        errors = len([line for line in output_lines if " ERROR " in line])
        
        if result.returncode == 0:
            status = "✅ PASSED"
        else:
            status = "❌ FAILED"
        
        print(f"{status} - {passed} passed, {failed} failed, {errors} errors")
        
        if failed > 0 or errors > 0:
            print("\nFailure details:")
            print(result.stdout[-1000:])  # Last 1000 chars
        
        return {
            "status": "passed" if result.returncode == 0 else "failed",
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "output": result.stdout
        }
        
    except subprocess.TimeoutExpired:
        print("⏰ TIMEOUT - Tests took too long")
        return {"status": "timeout", "passed": 0, "failed": 0, "errors": 1}
    except Exception as e:
        print(f"💥 ERROR - {e}")
        return {"status": "error", "passed": 0, "failed": 0, "errors": 1}

def main():
    """Run comprehensive test suite."""
    print("🚀 Compliance Sentinel - Comprehensive Test Suite")
    print("=" * 60)
    
    # Test suites to run
    test_suites = [
        ("tests/config/", "Configuration System"),
        ("tests/monitoring/", "Monitoring & Metrics"),
        ("tests/utils/test_circuit_breaker.py", "Circuit Breaker"),
        ("tests/testing/", "Production Data Validation"),
        ("tests/logging/", "Environment-Aware Logging"),
        ("tests/sync/test_change_notification.py", "Change Notifications"),
        ("tests/sync/test_data_synchronizer.py", "Data Synchronization"),
    ]
    
    results = {}
    total_passed = 0
    total_failed = 0
    total_errors = 0
    
    # Run each test suite
    for test_path, description in test_suites:
        if os.path.exists(test_path):
            result = run_test_suite(test_path, description)
            results[description] = result
            total_passed += result["passed"]
            total_failed += result["failed"]
            total_errors += result["errors"]
        else:
            print(f"⚠️  Skipping {description} - path not found: {test_path}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    for description, result in results.items():
        status_icon = "✅" if result["status"] == "passed" else "❌"
        print(f"{status_icon} {description}: {result['passed']} passed, {result['failed']} failed, {result['errors']} errors")
    
    print(f"\n🎯 OVERALL RESULTS:")
    print(f"   Total Passed: {total_passed}")
    print(f"   Total Failed: {total_failed}")
    print(f"   Total Errors: {total_errors}")
    
    success_rate = (total_passed / (total_passed + total_failed + total_errors)) * 100 if (total_passed + total_failed + total_errors) > 0 else 0
    print(f"   Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("\n🎉 EXCELLENT! System is production-ready!")
    elif success_rate >= 60:
        print("\n👍 GOOD! Minor fixes needed.")
    else:
        print("\n🔧 NEEDS WORK! Major fixes required.")
    
    # Free API setup reminder
    print("\n" + "=" * 60)
    print("🆓 FREE API SETUP REMINDER")
    print("=" * 60)
    print("To complete the setup, you need these FREE API keys:")
    print("1. GitHub Token (free): https://github.com/settings/tokens")
    print("2. NVD API Key (optional, free): https://nvd.nist.gov/developers/request-an-api-key")
    print("3. See docs/configuration/FREE_APIS_SETUP.md for details")
    
    return 0 if success_rate >= 80 else 1

if __name__ == "__main__":
    sys.exit(main())