#!/usr/bin/env python3
"""
Simple MCP Server for Compliance Sentinel
Compatible with Kiro IDE and other MCP clients
"""

import json
import sys
import re
from typing import Dict, List, Any

# Security patterns for analysis
SECURITY_PATTERNS = {
    "hardcoded_credentials": {
        "patterns": [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"secret\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']",
            r"token\s*=\s*[\"'][^\"']+[\"']"
        ],
        "severity": "HIGH",
        "title": "Hardcoded Credentials",
        "description": "Hardcoded credentials detected in source code",
        "remediation": "Use environment variables or secure vaults for sensitive data"
    },
    "sql_injection": {
        "patterns": [
            r"SELECT.*\+.*",
            r"INSERT.*\+.*", 
            r"UPDATE.*\+.*",
            r"DELETE.*\+.*"
        ],
        "severity": "HIGH",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection through string concatenation",
        "remediation": "Use parameterized queries or prepared statements"
    },
    "command_injection": {
        "patterns": [
            r"os\.system\(",
            r"subprocess.*shell\s*=\s*True",
            r"eval\(",
            r"exec\("
        ],
        "severity": "HIGH",
        "title": "Command Injection Risk",
        "description": "Potentially dangerous function that could lead to command injection",
        "remediation": "Validate and sanitize all inputs, avoid shell=True"
    }
}

def analyze_code(code: str, language: str = "python") -> Dict[str, Any]:
    """Analyze code for security issues."""
    issues = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for issue_type, pattern_info in SECURITY_PATTERNS.items():
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": issue_type,
                        "severity": pattern_info["severity"],
                        "title": pattern_info["title"],
                        "description": pattern_info["description"],
                        "line": line_num,
                        "line_content": line.strip(),
                        "remediation": pattern_info["remediation"]
                    })
                    break
    
    return {
        "total_issues": len(issues),
        "issues": issues,
        "language": language,
        "lines_analyzed": len(lines)
    }

def format_analysis_result(analysis: Dict[str, Any]) -> str:
    """Format analysis results for display."""
    result = f"🔒 **Security Analysis Results**\n\n"
    result += f"**Language:** {analysis['language']}\n"
    result += f"**Lines Analyzed:** {analysis['lines_analyzed']}\n"
    result += f"**Total Issues:** {analysis['total_issues']}\n\n"
    
    if analysis['issues']:
        # Count severity levels
        high_count = len([i for i in analysis['issues'] if i['severity'] == 'HIGH'])
        medium_count = len([i for i in analysis['issues'] if i['severity'] == 'MEDIUM'])
        
        if high_count > 0:
            result += f"🚨 **HIGH Severity:** {high_count} issues\n"
        if medium_count > 0:
            result += f"⚠️ **MEDIUM Severity:** {medium_count} issues\n"
        
        result += f"\n**Detailed Issues:**\n"
        for i, issue in enumerate(analysis['issues'], 1):
            result += f"\n{i}. **{issue['title']}** (Line {issue['line']})\n"
            result += f"   - **Severity:** {issue['severity']}\n"
            result += f"   - **Description:** {issue['description']}\n"
            result += f"   - **Code:** `{issue['line_content']}`\n"
            result += f"   - **Fix:** {issue['remediation']}\n"
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
                    "name": "compliance-sentinel",
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
                        "description": "Analyze code for security vulnerabilities",
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
            
            analysis = analyze_code(code, language)
            formatted_result = format_analysis_result(analysis)
            
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
        # Read JSON-RPC requests from stdin
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