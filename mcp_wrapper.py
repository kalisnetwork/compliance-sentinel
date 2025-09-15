#!/usr/bin/env python3
"""
Simple MCP wrapper that calls our working Vercel API.
This avoids MCP library dependency issues.
"""

import json
import sys
import requests
from typing import Dict, Any

def analyze_code_via_api(code: str, language: str = "python") -> Dict[str, Any]:
    """Analyze code using our Vercel API."""
    try:
        response = requests.post(
            "https://compliance-sentinel.vercel.app/analyze",
            json={"code": code, "language": language},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "success": False,
                "error": f"API returned status {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"API call failed: {str(e)}"
        }

def format_analysis_result(result: Dict[str, Any]) -> str:
    """Format analysis result for display."""
    if not result.get("success"):
        return f"❌ **Error:** {result.get('error', 'Unknown error')}"
    
    analysis = result.get("analysis", {})
    issues = analysis.get("issues", [])
    
    output = f"🔒 **Compliance Sentinel Security Analysis**\n\n"
    output += f"**📊 Analysis Summary:**\n"
    output += f"- **Language:** {analysis.get('language', 'Unknown').title()}\n"
    output += f"- **Lines Analyzed:** {analysis.get('lines_analyzed', 0)}\n"
    output += f"- **Issues Found:** {analysis.get('total_issues', 0)}\n\n"
    
    severity_counts = analysis.get("severity_counts", {})
    if any(count > 0 for count in severity_counts.values()):
        output += f"**🚨 Issues by Severity:**\n"
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                output += f"- {emoji} **{severity}:** {count} issues\n"
        output += "\n"
    
    if issues:
        output += f"**🔍 Detailed Issues:**\n\n"
        for i, issue in enumerate(issues, 1):
            severity_emoji = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(issue.get("severity"), "⚪")
            issue_type = issue.get("type", "unknown").replace("_", " ").title()
            
            output += f"**{i}. {severity_emoji} {issue_type}** (Line {issue.get('line', '?')})\n"
            output += f"   - **Description:** {issue.get('description', 'No description')}\n"
            output += f"   - **Code:** `{issue.get('line_content', 'N/A')}`\n"
            output += f"   - **🔧 Fix:** {issue.get('remediation', 'No remediation provided')}\n\n"
    else:
        output += f"✅ **Excellent!** No security issues found in your code.\n"
        output += f"Your code follows security best practices! 🎉\n"
    
    return output

def main():
    """Main entry point for MCP wrapper."""
    if len(sys.argv) < 2:
        print("Usage: python3 mcp_wrapper.py <code>")
        sys.exit(1)
    
    # Get code from command line argument or stdin
    if sys.argv[1] == "-":
        code = sys.stdin.read()
    else:
        code = sys.argv[1]
    
    # Get language from environment or default to python
    language = sys.argv[2] if len(sys.argv) > 2 else "python"
    
    # Analyze the code
    result = analyze_code_via_api(code, language)
    
    # Format and print the result
    formatted_result = format_analysis_result(result)
    print(formatted_result)

if __name__ == "__main__":
    main()