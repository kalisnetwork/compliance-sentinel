#!/usr/bin/env python3
"""
Simple integration test for Compliance Sentinel.
"""
import asyncio
import tempfile
from pathlib import Path

async def test_end_to_end():
    """Test the complete workflow."""
    print("🧪 Running Compliance Sentinel Integration Test")
    print("=" * 50)
    
    # Create test file with security issues
    test_content = '''
import subprocess
import hashlib

# Hardcoded password
PASSWORD = "admin123"

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Command injection
def run_cmd(cmd):
    subprocess.run(f"ls {cmd}", shell=True)

# Weak crypto
def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    try:
        # Test 1: Builtin analyzer
        print("\n🔍 Test 1: Builtin Security Analyzer")
        from compliance_sentinel.analyzers.builtin_analyzer import BuiltinSecurityAnalyzer
        
        analyzer = BuiltinSecurityAnalyzer()
        issues = await analyzer.analyze_file(test_file)
        
        print(f"   Found {len(issues)} issues:")
        for issue in issues:
            print(f"   - {issue.rule_id}: {issue.description} (line {issue.line_number})")
        
        assert len(issues) >= 3, f"Expected at least 3 issues, got {len(issues)}"
        print("   ✅ Builtin analyzer test passed")
        
        # Test 2: Compliance Agent
        print("\n🤖 Test 2: Compliance Agent")
        from compliance_sentinel.core.compliance_agent import ComplianceAgent
        from compliance_sentinel.models.analysis import AnalysisType
        
        agent = ComplianceAgent()
        await agent.initialize()
        
        result = await agent.analyze_files(
            file_paths=[test_file],
            analysis_type=AnalysisType.VULNERABILITY_SCAN
        )
        
        print(f"   Analysis success: {result.success}")
        print(f"   Issues found: {len(result.issues)}")
        
        assert result.success, "Analysis should succeed"
        assert len(result.issues) >= 3, f"Expected at least 3 issues, got {len(result.issues)}"
        print("   ✅ Compliance agent test passed")
        
        # Test 3: Free API Integration
        print("\n🌐 Test 3: Free API Integration")
        from compliance_sentinel.providers.vulnerability_provider import VulnerabilityDataProvider
        from compliance_sentinel.utils.intelligent_cache import IntelligentCache
        
        config = {
            "nvd_base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "osv_base_url": "https://api.osv.dev/v1",
            "use_caching": True
        }
        
        cache_manager = IntelligentCache()
        provider = VulnerabilityDataProvider(config, cache_manager)
        
        initialized = await provider.initialize()
        health = await provider.health_check()
        
        print(f"   Provider initialized: {initialized}")
        print(f"   Health check: {health}")
        
        assert initialized, "Provider should initialize"
        assert health, "Health check should pass"
        print("   ✅ Free API integration test passed")
        
        print("\n🎉 All integration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        Path(test_file).unlink(missing_ok=True)

if __name__ == "__main__":
    success = asyncio.run(test_end_to_end())
    exit(0 if success else 1)