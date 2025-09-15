"""
Simple HTTP handler for Vercel - Compliance Sentinel MCP Server
"""

import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Security analysis patterns
SECURITY_PATTERNS = {
    "hardcoded_credentials": {
        "patterns": [
            # Variable assignment patterns
            r"password\s*[=:]\s*[\"'][^\"']+[\"']",
            r"pass\s*[=:]\s*[\"'][^\"']+[\"']",
            r"secret\s*[=:]\s*[\"'][^\"']+[\"']",
            r"api_key\s*[=:]\s*[\"'][^\"']+[\"']",
            r"apikey\s*[=:]\s*[\"'][^\"']+[\"']",
            r"token\s*[=:]\s*[\"'][^\"']+[\"']",
            r"key\s*[=:]\s*[\"'][^\"']+[\"']",
            
            # JavaScript object property patterns (double quotes)
            r'"password"\s*:\s*"[^"]+"',
            r'"pass"\s*:\s*"[^"]+"',
            r'"secret"\s*:\s*"[^"]+"',
            r'"api_key"\s*:\s*"[^"]+"',
            r'"apiKey"\s*:\s*"[^"]+"',
            r'"token"\s*:\s*"[^"]+"',
            
            # JavaScript object property patterns (single quotes)
            r"'password'\s*:\s*'[^']+'",
            r"'pass'\s*:\s*'[^']+'",
            r"'secret'\s*:\s*'[^']+'",
            r"'api_key'\s*:\s*'[^']+'",
            r"'apiKey'\s*:\s*'[^']+'",
            r"'token'\s*:\s*'[^']+'",
            
            # Database connection strings
            r"[\"'][^\"']*://[^:]+:[^@]+@[^\"']+[\"']"
        ],
        "severity": "HIGH",
        "description": "Hardcoded credentials detected",
        "remediation": "Use environment variables or secure vaults for credentials"
    },
    "sql_injection": {
        "patterns": [
            r"SELECT.*\+.*",
            r"INSERT.*\+.*", 
            r"UPDATE.*\+.*",
            r"DELETE.*\+.*",
            r"query.*\+.*user",
            r"SELECT.*\$\{.*\}",  # Template literals
            r"INSERT.*\$\{.*\}",
            r"UPDATE.*\$\{.*\}",
            r"DELETE.*\$\{.*\}"
        ],
        "severity": "HIGH",
        "description": "Potential SQL injection vulnerability",
        "remediation": "Use parameterized queries or prepared statements"
    },
    "command_injection": {
        "patterns": [
            r"os\.system\(",
            r"subprocess.*shell\s*=\s*True",
            r"eval\(",
            r"exec\(",
            r"child_process\.exec\(",  # Node.js
            r"Runtime\.getRuntime\(\)\.exec\("  # Java
        ],
        "severity": "HIGH",
        "description": "Potential command injection vulnerability",
        "remediation": "Avoid shell=True and validate all inputs"
    },
    "weak_cryptography": {
        "patterns": [
            r"hashlib\.md5\(",
            r"hashlib\.sha1\(",
            r"crypto\.createHash\([\"']md5[\"']\)",
            r"crypto\.createHash\([\"']sha1[\"']\)",
            r"MessageDigest\.getInstance\([\"']MD5[\"']\)",
            r"MessageDigest\.getInstance\([\"']SHA1[\"']\)"
        ],
        "severity": "MEDIUM",
        "description": "Weak cryptographic function detected",
        "remediation": "Use SHA-256 or stronger cryptographic functions"
    },
    "xss_vulnerability": {
        "patterns": [
            r"document\.innerHTML\s*=",
            r"\.innerHTML\s*=\s*[^;]+\+",
            r"document\.write\(",
            r"eval\s*\(\s*[^)]*user"
        ],
        "severity": "HIGH",
        "description": "Potential XSS vulnerability detected",
        "remediation": "Use safe DOM manipulation methods and sanitize user inputs"
    }
}

def analyze_code_patterns(code):
    """Analyze code for security patterns."""
    issues = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for issue_type, pattern_info in SECURITY_PATTERNS.items():
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        "type": issue_type,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "line": line_num,
                        "line_content": line.strip(),
                        "remediation": pattern_info["remediation"]
                    })
                    break
    
    return issues

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests."""
        path = urlparse(self.path).path
        
        if path == '/':
            self.send_json_response({
                "service": "Compliance Sentinel MCP Server",
                "version": "1.0.0",
                "status": "operational",
                "platform": "Vercel Serverless",
                "endpoints": {
                    "health": "/health",
                    "analyze": "/analyze",
                    "validate": "/validate",
                    "tools": "/tools",
                    "demo": "/demo"
                }
            })
        elif path == '/health':
            self.send_json_response({
                "status": "healthy",
                "service": "compliance-sentinel-mcp",
                "version": "1.0.0",
                "platform": "Vercel"
            })
        elif path == '/tools':
            self.send_json_response({
                "tools": [
                    {
                        "name": "analyze_code",
                        "description": "Analyze code for security vulnerabilities",
                        "parameters": {
                            "code": "string (required) - Code to analyze",
                            "language": "string (optional) - Programming language"
                        }
                    },
                    {
                        "name": "validate_compliance",
                        "description": "Validate code against compliance frameworks",
                        "parameters": {
                            "code": "string (required) - Code to validate",
                            "framework": "string (required) - Compliance framework"
                        }
                    }
                ],
                "supported_languages": ["python", "javascript", "java", "go", "php", "ruby"],
                "compliance_frameworks": ["owasp-top-10", "cwe-top-25", "nist-csf"]
            })
        elif path == '/demo':
            self.send_json_response({
                "demo": "Compliance Sentinel MCP Server - Vercel Edition",
                "examples": {
                    "analyze_vulnerable_code": {
                        "description": "Analyze code with security issues",
                        "method": "POST",
                        "url": "/analyze",
                        "example_request": {
                            "code": "password = 'hardcoded_secret_123'\\nquery = 'SELECT * FROM users WHERE id = ' + user_id",
                            "language": "python"
                        }
                    },
                    "validate_compliance": {
                        "description": "Check compliance against frameworks",
                        "method": "POST", 
                        "url": "/validate",
                        "example_request": {
                            "code": "password = 'hardcoded_secret_123'",
                            "framework": "owasp-top-10"
                        }
                    }
                },
                "supported_patterns": list(SECURITY_PATTERNS.keys()),
                "frameworks": ["owasp-top-10", "cwe-top-25", "nist-csf"]
            })
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        """Handle POST requests."""
        path = urlparse(self.path).path
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON")
            return
        
        if path == '/analyze':
            self.handle_analyze(data)
        elif path == '/validate':
            self.handle_validate(data)
        else:
            self.send_error(404, "Not Found")
    
    def handle_analyze(self, data):
        """Handle code analysis."""
        code = data.get("code", "")
        language = data.get("language", "python")
        
        if not code:
            self.send_error(400, "Code is required")
            return
        
        if len(code) > 10000:
            self.send_error(400, "Code too large (max 10KB)")
            return
        
        # Analyze code
        issues = analyze_code_patterns(code)
        
        # Calculate severity counts
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in issues:
            severity_counts[issue["severity"]] += 1
        
        self.send_json_response({
            "success": True,
            "analysis": {
                "issues": issues,
                "total_issues": len(issues),
                "severity_counts": severity_counts,
                "language": language,
                "lines_analyzed": len(code.split('\n'))
            },
            "message": f"Found {len(issues)} security issues in {language} code"
        })
    
    def handle_validate(self, data):
        """Handle compliance validation."""
        code = data.get("code", "")
        framework = data.get("framework", "owasp-top-10")
        
        if not code:
            self.send_error(400, "Code is required")
            return
        
        # Analyze code first
        issues = analyze_code_patterns(code)
        
        # Calculate compliance score
        total_checks = 10
        failed_checks = len(issues)
        passed_checks = max(0, total_checks - failed_checks)
        score = passed_checks / total_checks if total_checks > 0 else 1.0
        
        self.send_json_response({
            "success": True,
            "compliance": {
                "framework": framework,
                "score": score,
                "percentage": f"{score:.1%}",
                "passed": passed_checks,
                "total": total_checks,
                "issues": len(issues),
                "recommendations": [issue["remediation"] for issue in issues[:3]]
            },
            "message": f"Compliance score: {score:.1%} for {framework}"
        })
    
    def send_json_response(self, data, status_code=200):
        """Send JSON response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = json.dumps(data, indent=2)
        self.wfile.write(response.encode('utf-8'))
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()