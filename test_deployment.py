#!/usr/bin/env python3
"""Test script to verify deployment readiness."""

import asyncio
import json
import requests
import subprocess
import sys
import time
from pathlib import Path

def test_local_server():
    """Test the web server locally."""
    print("🧪 Testing local deployment...")
    
    # Start server in background
    print("Starting web server...")
    process = subprocess.Popen([
        sys.executable, "web_mcp_server.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait for server to start
    time.sleep(3)
    
    try:
        # Test health endpoint
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
        
        # Test analyze endpoint
        test_code = 'password = "secret123"\nquery = "SELECT * FROM users WHERE id = " + user_id'
        response = requests.post(
            "http://localhost:8000/analyze",
            json={"code": test_code, "language": "python"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            issues = result.get("analysis", {}).get("total_issues", 0)
            print(f"✅ Analysis test passed - Found {issues} issues")
        else:
            print(f"❌ Analysis test failed: {response.status_code}")
            return False
        
        print("🎉 All tests passed! Ready for deployment.")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    finally:
        process.terminate()

if __name__ == "__main__":
    success = test_local_server()
    sys.exit(0 if success else 1)