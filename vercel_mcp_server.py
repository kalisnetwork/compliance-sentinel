#!/usr/bin/env python3
"""
Vercel-powered MCP Server for Compliance Sentinel
Uses the Vercel API instead of local patterns
"""

import json
import sys
import requests
from typing import Dict, Any

VERCEL_API_URL = "https://compliance-sentinel.vercel.app/analyze"

def analyze_code_via_vercel(code: str, language: str = "python") -> Dict[str, Any]:
    """Analyze code using Vercel API."""
    try:
        response = requests.post(
            VERCEL_API_URL,
            json={"code": code, "language": language},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "success": False,
                "error": f"API returned status {response.status_code}"
            }
    
    except requests.RequestException as e:
        return {
            "success": False,
            "error": f"Network error: {str(e)}"
        }

def format_vercel_result(vercel_response: Dict[str, Any]) -> str:
    """Format Vercel API response for MCP."""
    if not vercel_response.get("success", False):
        return f"❌ **Analysis Error:** {vercel_response.get('error', 'Unknown error')}"
    
    analysis = vercel_response.get("analysis", {})
    issues = analysis.get("issues", [])
    
    result = f"🔒 **Security Analysis Results** (via Vercel)\n\n"
    result += f"**Language:** {analysis.get('language', 'unknown')}\n"
    result += f"**Lines Analyzed:** {analysis.get('lines_analyzed', 0)}\n"
    result += f"**Total Issues:** {analysis.get('total_issues', 0)}\n\n"
    
    if issues:
        severity_counts = analysis.get('severity_counts', {})
        
        if severity_counts.get('HIGH', 0) > 0:
            result += f"🚨 **HIGH Severity:** {severity_counts['HIGH']} issues\n"
        if severity_counts.get('MEDIUM', 0) > 0:
            result += f"⚠️ **MEDIUM Severity:** {severity_counts['MEDIUM']} issues\n"
        if severity_counts.get('LOW', 0) > 0:
            result += f"ℹ️ **LOW Severity:** {severity_counts['LOW']} issues\n"
        
        result += f"\n**Detailed Issues:**\n"
        for i, issue in enumerate(issues, 1):
            result += f"\n{i}. **{issue.get('type', 'Unknown').replace('_', ' ').title()}** (Line {issue.get('line', '?')})\n"
            result += f"   - **Severity:** {issue.get('severity', 'UNKNOWN')}\n"
            result += f"   - **Description:** {issue.get('description', 'No description')}\n"
            result += f"   - **Code:** `{issue.get('line_content', 'N/A')}`\n"
            result += f"   - **Fix:** {issue.get('remediation', 'No remediation provided')}\n"
    else:
        result += f"\n✅ **No security issues detected!**\n"
    
    return result

def handle_mcp_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle MCP protocol requests."""
    method = request.get("method", "")
    params = request.get("params", {})
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "compliance-sentinel-vercel",
                    "version": "1.0.0"
                }
            }
        }
    
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "analyze_code",
                        "description": "Analyze code for security vulnerabilities using Vercel API",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Source code to analyze"
                                },
                                "language": {
                                    "type": "string",
                                    "description": "Programming language",
                                    "default": "python"
                                }
                            },
                            "required": ["code"]
                        }
                    }
                ]
            }
        }
    
    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        
        if tool_name == "analyze_code":
            code = arguments.get("code", "")
            language = arguments.get("language", "python")
            
            if not code.strip():
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32602,
                        "message": "Code is required and cannot be empty"
                    }
                }
            
            vercel_response = analyze_code_via_vercel(code, language)
            formatted_result = format_vercel_result(vercel_response)
            
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": formatted_result
                        }
                    ]
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Unknown tool: {tool_name}"
                }
            }
    
    else:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": -32601,
                "message": f"Unknown method: {method}"
            }
        }

def main():
    """Main MCP server loop."""
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            
            try:
                request = json.loads(line)
                response = handle_mcp_request(request)
                print(json.dumps(response), flush=True)
            except json.JSONDecodeError as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {str(e)}"
                    }
                }
                print(json.dumps(error_response), flush=True)
            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id") if 'request' in locals() else None,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {str(e)}"
                    }
                }
                print(json.dumps(error_response), flush=True)
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write(f"Fatal error: {str(e)}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()