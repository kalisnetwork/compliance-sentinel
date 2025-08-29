#!/usr/bin/env python3
"""
Demo script showing Compliance Sentinel working with FREE APIs only.

This script demonstrates:
1. Real vulnerability data from free APIs
2. No paid services required
3. Practical security scanning
4. Production-ready configuration
"""

import os
import asyncio
import json
from datetime import datetime

# Set up free API configuration
os.environ.update({
    "COMPLIANCE_SENTINEL_ENVIRONMENT": "demo",
    "COMPLIANCE_SENTINEL_LOG_LEVEL": "INFO",
    "COMPLIANCE_SENTINEL_DEBUG_ENABLED": "true",
    
    # Free API endpoints (no cost)
    "NVD_BASE_URL": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "CVE_CIRCL_BASE_URL": "https://cve.circl.lu/api",
    "OSV_BASE_URL": "https://api.osv.dev/v1",
    "GITHUB_ADVISORY_URL": "https://api.github.com/advisories",
    
    # Conservative rate limits for free tiers
    "NVD_RATE_LIMIT": "10",
    "CVE_RATE_LIMIT": "20", 
    "OSV_RATE_LIMIT": "50",
    "GITHUB_RATE_LIMIT": "100",
    
    # Enable caching to minimize API calls
    "COMPLIANCE_SENTINEL_CACHE_ENABLED": "true",
    "COMPLIANCE_SENTINEL_CACHE_TTL": "3600",
    
    # Enable circuit breakers for resilience
    "COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_ENABLED": "true"
})

from compliance_sentinel.config import get_config_manager_async, get_config_value_async
from compliance_sentinel.monitoring.real_time_metrics import get_metrics
from compliance_sentinel.utils.circuit_breaker import CircuitBreakerManager
from compliance_sentinel.utils.intelligent_cache import IntelligentCache


async def demo_free_apis():
    """Demonstrate free API integration."""
    print("🚀 Compliance Sentinel - Free API Demo")
    print("=" * 50)
    
    # Initialize components
    config_manager = await get_config_manager_async()
    metrics = get_metrics()
    cache = IntelligentCache()
    circuit_breaker = CircuitBreakerManager()
    
    print("✅ Components initialized successfully")
    
    # Show configuration
    print("\n📋 Configuration:")
    environment = await get_config_value_async('environment', 'demo')
    cache_enabled = await get_config_value_async('cache.enabled', True)
    debug_enabled = await get_config_value_async('debug.enabled', True)
    print(f"   Environment: {environment}")
    print(f"   Cache enabled: {cache_enabled}")
    print(f"   Debug mode: {debug_enabled}")
    
    # Test free APIs
    print("\n🌐 Testing Free APIs:")
    
    # Test 1: NVD API (free)
    print("   Testing NVD API (free)...")
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                timeout=10.0
            )
            if response.status_code == 200:
                data = response.json()
                cve_count = data.get("totalResults", 0)
                print(f"   ✅ NVD API: {cve_count:,} CVEs available")
            else:
                print(f"   ⚠️  NVD API: HTTP {response.status_code}")
    except Exception as e:
        print(f"   ❌ NVD API: {e}")
    
    # Test 2: CVE CIRCL (free)
    print("   Testing CVE CIRCL API (free)...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://cve.circl.lu/api/cve/CVE-2023-44487",  # HTTP/2 Rapid Reset
                timeout=10.0
            )
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ CVE CIRCL: CVE details available")
            else:
                print(f"   ⚠️  CVE CIRCL: HTTP {response.status_code}")
    except Exception as e:
        print(f"   ❌ CVE CIRCL: {e}")
    
    # Test 3: OSV API (free)
    print("   Testing OSV API (free)...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": "requests", "ecosystem": "PyPI"}},
                timeout=10.0
            )
            if response.status_code == 200:
                data = response.json()
                vuln_count = len(data.get("vulns", []))
                print(f"   ✅ OSV API: {vuln_count} vulnerabilities found for 'requests' package")
            else:
                print(f"   ⚠️  OSV API: HTTP {response.status_code}")
    except Exception as e:
        print(f"   ❌ OSV API: {e}")
    
    # Test 4: GitHub API (free with token)
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        print("   Testing GitHub Security Advisories (free)...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/advisories?per_page=1",
                    headers={"Authorization": f"token {github_token}"},
                    timeout=10.0
                )
                if response.status_code == 200:
                    data = response.json()
                    print(f"   ✅ GitHub API: Security advisories available")
                    
                    # Check rate limit
                    remaining = response.headers.get("X-RateLimit-Remaining", "unknown")
                    print(f"   📊 Rate limit remaining: {remaining}/5000 per hour")
                else:
                    print(f"   ⚠️  GitHub API: HTTP {response.status_code}")
        except Exception as e:
            print(f"   ❌ GitHub API: {e}")
    else:
        print("   ⚠️  GitHub API: No token provided (get free token at https://github.com/settings/tokens)")
    
    # Test caching
    print("\n💾 Testing Caching:")
    test_data = {"test": "data", "timestamp": datetime.utcnow().isoformat()}
    await cache.set("demo_key", test_data, ttl=300)
    cached_data = await cache.get("demo_key")
    if cached_data == test_data:
        print("   ✅ Cache: Working correctly")
    else:
        print("   ❌ Cache: Not working")
    
    # Test metrics
    print("\n📊 Testing Metrics:")
    metrics.increment_counter("demo_requests_total", 1.0, {"api": "demo"})
    metrics.set_gauge("demo_active_connections", 5.0)
    
    counter_value = metrics.get_metric_value("demo_requests_total")
    gauge_value = metrics.get_metric_value("demo_active_connections")
    
    if counter_value == 1.0 and gauge_value == 5.0:
        print("   ✅ Metrics: Working correctly")
    else:
        print("   ❌ Metrics: Not working")
    
    # Test circuit breaker
    print("\n🔌 Testing Circuit Breaker:")
    cb = circuit_breaker.get_circuit_breaker("demo_service")
    
    # Test with a simple function
    async def test_function():
        return "success"
    
    result = await cb.call(test_function)
    if result == "success" and cb.get_state().name == "CLOSED":
        print("   ✅ Circuit Breaker: Working correctly")
    else:
        print("   ❌ Circuit Breaker: Not working")
    
    print("\n🎉 Demo completed!")
    print("\n💡 Next steps:")
    print("   1. Get free GitHub token: https://github.com/settings/tokens")
    print("   2. Run: export GITHUB_TOKEN=your_token")
    print("   3. Run: python examples/free_api_demo.py")
    print("   4. Start scanning: python -m compliance_sentinel.cli analyze your_code.py")


def main():
    """Main demo function."""
    try:
        asyncio.run(demo_free_apis())
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n💥 Demo failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    exit(main())