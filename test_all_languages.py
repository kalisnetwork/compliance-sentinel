#!/usr/bin/env python3
"""
Multi-language security analysis test script
Tests Compliance Sentinel with various programming languages
"""

import requests
import json

API_URL = "https://compliance-sentinel.vercel.app/analyze"

# Test cases for different languages
TEST_CASES = {
    "python": '''
password = "hardcoded123"
query = "SELECT * FROM users WHERE id = " + user_id
subprocess.run(user_input, shell=True)
eval(malicious_code)
''',
    
    "javascript": '''
const API_KEY = "secret-key-123";
document.innerHTML = userInput;
eval(userCode);
''',
    
    "java": '''
public class Test {
    private static final String PASSWORD = "admin123";
    
    public void query(String userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
    }
}
''',
    
    "go": '''
package main

const API_SECRET = "go-secret-456"

func getUser(userID string) {
    query := "SELECT * FROM users WHERE id = " + userID
}
''',
    
    "php": '''
<?php
$password = "php-secret-789";
$query = "SELECT * FROM users WHERE id = " . $userId;
eval($userCode);
?>
''',
    
    "ruby": '''
password = "ruby-secret-123"
query = "SELECT * FROM users WHERE id = #{user_id}"
eval(user_input)
''',
    
    "csharp": '''
public class SecurityTest 
{
    private const string ApiKey = "csharp-secret-456";
    
    public void GetUser(string userId) 
    {
        string sql = "SELECT * FROM users WHERE id = " + userId;
    }
}
''',
    
    "cpp": '''
#include <string>

const std::string PASSWORD = "cpp-secret-789";

void getUser(std::string userId) {
    std::string query = "SELECT * FROM users WHERE id = " + userId;
}
'''
}

def test_language(language, code):
    """Test security analysis for a specific language."""
    print(f"\n🔍 Testing {language.upper()}...")
    print("=" * 50)
    
    try:
        response = requests.post(
            API_URL,
            json={"code": code, "language": language},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("success"):
                analysis = result["analysis"]
                issues = analysis.get("issues", [])
                
                print(f"✅ Language: {analysis.get('language', 'unknown')}")
                print(f"📊 Lines analyzed: {analysis.get('lines_analyzed', 0)}")
                print(f"🚨 Total issues: {analysis.get('total_issues', 0)}")
                
                if issues:
                    severity_counts = analysis.get('severity_counts', {})
                    print(f"🔴 HIGH: {severity_counts.get('HIGH', 0)}")
                    print(f"🟡 MEDIUM: {severity_counts.get('MEDIUM', 0)}")
                    print(f"🔵 LOW: {severity_counts.get('LOW', 0)}")
                    
                    print("\n📋 Issues found:")
                    for i, issue in enumerate(issues[:3], 1):  # Show first 3 issues
                        print(f"  {i}. {issue.get('type', 'unknown').replace('_', ' ').title()}")
                        print(f"     Line {issue.get('line', '?')}: {issue.get('line_content', 'N/A')[:50]}...")
                else:
                    print("✅ No security issues detected!")
            else:
                print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            
    except requests.RequestException as e:
        print(f"❌ Network error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    """Run security analysis tests for all supported languages."""
    print("🔒 Compliance Sentinel - Multi-Language Security Analysis Test")
    print("=" * 60)
    print(f"🌐 API Endpoint: {API_URL}")
    print(f"📝 Testing {len(TEST_CASES)} languages...")
    
    # Test API health first
    try:
        health_response = requests.get(f"{API_URL.replace('/analyze', '/health')}", timeout=5)
        if health_response.status_code == 200:
            print("✅ API is healthy and ready")
        else:
            print("⚠️ API health check failed")
    except:
        print("⚠️ Could not check API health")
    
    # Test each language
    for language, code in TEST_CASES.items():
        test_language(language, code)
    
    print("\n" + "=" * 60)
    print("🎉 Multi-language security analysis test completed!")
    print("\n📖 Supported Languages:")
    for lang in TEST_CASES.keys():
        print(f"  ✅ {lang.capitalize()}")
    
    print(f"\n🔧 Integration Guide: See EDITOR_SETUP_GUIDE.md")
    print(f"👥 Team Setup: See TEAM_SHARING_GUIDE.md")

if __name__ == "__main__":
    main()