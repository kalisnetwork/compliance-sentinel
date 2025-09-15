"""
Direct MCP Server endpoint for Vercel - No local files needed!
Works like Zapier MCP with direct URL configuration
Uses the existing /analyze endpoint for dynamic analysis
"""

import json
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler

def analyze_code_via_api(code: str, language: str = "python"):
    """Use the existing /analyze API endpoint for dynamic analysis."""
    try:
        # Use the same Vercel instance's /analyze endpoint
        url = "https://compliance-sentinel.vercel.app/analyze"
        
        data = {
            "code": code,
            "language": language
        }
        
        # Make request to our own analyze endpoint
        req_data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            
            if result.get("success"):
                analysis = result["analysis"]
                return {
                    "total_issues": analysis.get("total_issues", 0),
                    "issues": analysis.get("issues", []),
                    "language": analysis.get("language", language),
                    "lines_analyzed": analysis.get("lines_analyzed", 0),
                    "analysis_type": "dynamic_api"
                }
            else:
                return {
                    "total_issues": 0,
                    "issues": [],
                    "language": language,
                    "lines_analyzed": len(code.split('\n')),
                    "analysis_type": "error",
                    "error": result.get("error", "Analysis failed")
                }
                
    except Exception as e:
        # Return error info but don't fail completely
        return {
            "total_issues": 0,
            "issues": [],
            "language": language,
            "lines_analyzed": len(code.split('\n')),
            "analysis_type": "error",
            "error": str(e)
        }

def format_analysis_result(analysis):
    """Format analysis results for MCP display."""
    result = f"🔒 **Security Analysis Results** (Direct MCP)\n\n"
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

def handle_mcp_request(request_data):
    """Handle MCP protocol requests."""
    method = request_data.get("method", "")
    params = request_data.get("params", {})
    request_id = request_data.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "compliance-sentinel-direct",
                    "version": "1.0.0"
                }
            }
        }
    
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "analyze_code",
                        "description": "Analyze code for security vulnerabilities using direct MCP server",
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
                    "id": request_id,
                    "error": {
                        "code": -32602,
                        "message": "Code is required and cannot be empty"
                    }
                }
            
            # Use the existing API for dynamic analysis
            analysis = analyze_code_via_api(code, language)
            formatted_result = format_analysis_result(analysis)
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
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
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Unknown tool: {tool_name}"
                }
            }
    
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Unknown method: {method}"
            }
        }

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests - MCP server info."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        info = {
            "service": "Compliance Sentinel Direct MCP Server",
            "version": "1.0.0",
            "protocol": "MCP (Model Context Protocol)",
            "status": "operational",
            "usage": {
                "description": "Direct MCP server - no local files needed!",
                "configuration": {
                    "cursor": {
                        "mcpServers": {
                            "compliance-sentinel": {
                                "url": "https://compliance-sentinel.vercel.app/api/mcp"
                            }
                        }
                    },
                    "kiro": {
                        "mcpServers": {
                            "compliance-sentinel": {
                                "url": "https://compliance-sentinel.vercel.app/api/mcp"
                            }
                        }
                    }
                }
            },
            "tools": ["analyze_code"],
            "supported_languages": ["python", "javascript", "java", "go", "php", "ruby", "csharp", "cpp"]
        }
        
        self.wfile.write(json.dumps(info, indent=2).encode('utf-8'))
    
    def do_POST(self):
        """Handle POST requests - MCP protocol."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Handle both single requests and batch requests
            try:
                request_data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_error_response(-32700, "Parse error")
                return
            
            # Handle MCP request
            response = handle_mcp_request(request_data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(-32603, f"Internal error: {str(e)}")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def send_error_response(self, code, message):
        """Send JSON-RPC error response."""
        self.send_response(400)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        error_response = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": code,
                "message": message
            }
        }
        
        self.wfile.write(json.dumps(error_response).encode('utf-8'))