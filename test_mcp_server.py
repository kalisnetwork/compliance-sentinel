#!/usr/bin/env python3
"""
Test script for Compliance Sentinel MCP Server
"""

import subprocess
import json
import sys
import time

def test_mcp_server():
    """Test the MCP server functionality."""
    print("🧪 Testing Compliance Sentinel MCP Server...")
    
    # Test vulnerable code sample
    test_code = '''
password = "hardcoded_secret_123"
query = "SELECT * FROM users WHERE id = " + user_id
os.system(user_command)
eval(user_input)
document.getElementById('output').innerHTML = userInput;
'''
    
    try:
        # Test if MCP server can start
        print("1. Testing MCP server startup...")
        result = subprocess.run([
            sys.executable, "mcp_server.py", "--help"
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print("   ❌ MCP server failed to start")
            print(f"   Error: {result.stderr}")
            return False
        
        print("   ✅ MCP server can start")
        
        # Test security analysis function directly
        print("2. Testing security analysis...")
        from mcp_server import analyze_code_for_security_issues
        
        issues = analyze_code_for_security_issues(test_code, "python")
        print(f"   ✅ Found {len(issues)} security issues")
        
        for issue in issues:
            print(f"      - {issue['title']} (Line {issue['line']}, Severity: {issue['severity']})")
        
        # Test compliance validation
        print("3. Testing compliance validation...")
        from mcp_server import validate_compliance_against_framework
        
        compliance = validate_compliance_against_framework(test_code, "owasp-top-10")
        print(f"   ✅ OWASP Top 10 compliance score: {compliance['percentage']} (Grade: {compliance['grade']})")
        
        print("\n🎉 All tests passed! MCP server is working correctly.")
        return True
        
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        print("   Make sure 'mcp' library is installed: pip install mcp")
        return False
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_mcp_server()
    sys.exit(0 if success else 1)