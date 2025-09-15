"""
Vercel-compatible MCP Server for Compliance Sentinel.
This runs as a serverless function on Vercel.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add parent directory to Python path for imports
current_dir = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(current_dir))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Compliance Sentinel MCP Server",
    description="Model Context Protocol server for security analysis - Vercel Edition",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple security analysis patterns
SECURITY_PATTERNS = {
    "hardcoded_credentials": {
        "patterns": [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"secret\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']",
            r"token\s*=\s*[\"'][^\"']+[\"']"
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
            r"f[\"']SELECT.*{.*}.*[\"']"
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
            r"exec\("
        ],
        "severity": "HIGH",
        "description": "Potential command injection vulnerability",
        "remediation": "Avoid shell=True and validate all inputs"
    },
    "xss_vulnerability": {
        "patterns": [
            r"innerHTML\s*=",
            r"document\.write\(",
            r"\.html\(.*\+.*\)"
        ],
        "severity": "MEDIUM",
        "description": "Potential XSS vulnerability",
        "remediation": "Sanitize user inputs and use safe DOM manipulation"
    },
    "weak_crypto": {
        "patterns": [
            r"hashlib\.md5\(",
            r"hashlib\.sha1\(",
            r"crypto\.createHash\([\"']md5[\"']\)",
            r"crypto\.createHash\([\"']sha1[\"']\)"
        ],
        "severity": "MEDIUM",
        "description": "Weak cryptographic algorithm",
        "remediation": "Use SHA-256 or stronger hashing algorithms"
    }
}

def analyze_code_patterns(code: str) -> List[Dict[str, Any]]:
    """Analyze code for security patterns."""
    import re
    
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
                    break  # Only report one issue per line
    
    return issues

@app.get("/")
async def root():
    """Root endpoint."""
    return {
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
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "compliance-sentinel-mcp",
        "version": "1.0.0",
        "platform": "Vercel"
    }

@app.get("/tools")
async def list_tools():
    """List available MCP tools."""
    return {
        "tools": [
            {
                "name": "analyze_code",
                "description": "Analyze code for security vulnerabilities",
                "parameters": {
                    "code": "string (required) - Code to analyze",
                    "language": "string (optional) - Programming language",
                    "compliance_frameworks": "array (optional) - Frameworks to check"
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
    }

@app.post("/analyze")
async def analyze_code(request: Request):
    """Analyze code for security issues."""
    try:
        data = await request.json()
        code = data.get("code", "")
        language = data.get("language", "python")
        
        if not code:
            raise HTTPException(status_code=400, detail="Code is required")
        
        if len(code) > 10000:  # Limit code size for serverless
            raise HTTPException(status_code=400, detail="Code too large (max 10KB)")
        
        # Analyze code
        issues = analyze_code_patterns(code)
        
        # Calculate severity counts
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in issues:
            severity_counts[issue["severity"]] += 1
        
        return {
            "success": True,
            "analysis": {
                "issues": issues,
                "total_issues": len(issues),
                "severity_counts": severity_counts,
                "language": language,
                "lines_analyzed": len(code.split('\n'))
            },
            "message": f"Found {len(issues)} security issues in {language} code"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/validate")
async def validate_compliance(request: Request):
    """Validate code against compliance framework."""
    try:
        data = await request.json()
        code = data.get("code", "")
        framework = data.get("framework", "owasp-top-10")
        
        if not code:
            raise HTTPException(status_code=400, detail="Code is required")
        
        # Analyze code first
        issues = analyze_code_patterns(code)
        
        # Map issues to compliance framework
        framework_mapping = {
            "owasp-top-10": {
                "hardcoded_credentials": "A07:2021 – Identification and Authentication Failures",
                "sql_injection": "A03:2021 – Injection",
                "command_injection": "A03:2021 – Injection", 
                "xss_vulnerability": "A03:2021 – Injection",
                "weak_crypto": "A02:2021 – Cryptographic Failures"
            },
            "cwe-top-25": {
                "hardcoded_credentials": "CWE-798: Use of Hard-coded Credentials",
                "sql_injection": "CWE-89: SQL Injection",
                "command_injection": "CWE-78: OS Command Injection",
                "xss_vulnerability": "CWE-79: Cross-site Scripting",
                "weak_crypto": "CWE-327: Use of a Broken Cryptographic Algorithm"
            }
        }
        
        # Calculate compliance score
        total_checks = 10  # Mock total compliance checks
        failed_checks = len(issues)
        passed_checks = max(0, total_checks - failed_checks)
        score = passed_checks / total_checks if total_checks > 0 else 1.0
        
        # Map issues to framework violations
        violations = []
        mapping = framework_mapping.get(framework, {})
        for issue in issues:
            violation = mapping.get(issue["type"], f"Unknown violation: {issue['type']}")
            violations.append({
                "rule": violation,
                "description": issue["description"],
                "line": issue["line"],
                "severity": issue["severity"]
            })
        
        return {
            "success": True,
            "compliance": {
                "framework": framework,
                "score": score,
                "percentage": f"{score:.1%}",
                "passed": passed_checks,
                "total": total_checks,
                "violations": violations,
                "recommendations": [issue["remediation"] for issue in issues]
            },
            "message": f"Compliance score: {score:.1%} for {framework}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")

@app.get("/demo")
async def demo_page():
    """Demo page with examples."""
    return {
        "demo": "Compliance Sentinel MCP Server - Vercel Edition",
        "live_url": "https://your-app.vercel.app",
        "examples": {
            "analyze_vulnerable_code": {
                "description": "Analyze code with security issues",
                "method": "POST",
                "url": "/analyze",
                "example_request": {
                    "code": "password = \"hardcoded_secret_123\"\nquery = \"SELECT * FROM users WHERE id = \" + user_id\nos.system(user_input)",
                    "language": "python"
                },
                "curl_example": "curl -X POST https://your-app.vercel.app/analyze -H 'Content-Type: application/json' -d '{\"code\":\"password = \\\"secret123\\\"\",\"language\":\"python\"}'"
            },
            "validate_compliance": {
                "description": "Check compliance against frameworks",
                "method": "POST", 
                "url": "/validate",
                "example_request": {
                    "code": "password = \"hardcoded_secret_123\"",
                    "framework": "owasp-top-10"
                },
                "curl_example": "curl -X POST https://your-app.vercel.app/validate -H 'Content-Type: application/json' -d '{\"code\":\"password = \\\"secret123\\\"\",\"framework\":\"owasp-top-10\"}'"
            }
        },
        "supported_patterns": list(SECURITY_PATTERNS.keys()),
        "frameworks": ["owasp-top-10", "cwe-top-25", "nist-csf"]
    }

# Export the app for Vercel
handler = app