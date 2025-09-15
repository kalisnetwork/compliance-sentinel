#!/usr/bin/env python3
"""
Web-compatible MCP Server for hosting platforms.
This version runs as a web service that can be deployed to Railway, Render, etc.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Add current directory to Python path
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Compliance Sentinel MCP Server",
    description="Model Context Protocol server for security analysis",
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

# Mock implementations for hosting (replace with actual implementations)
class MockComplianceAgent:
    """Mock compliance agent for hosting demo."""
    
    async def analyze_code(self, code: str, language: str = "python", **kwargs) -> Dict[str, Any]:
        """Mock code analysis."""
        issues = []
        
        # Simple pattern matching for demo
        if "password" in code.lower() and ("=" in code or ":" in code):
            issues.append({
                "type": "hardcoded_credentials",
                "severity": "HIGH",
                "description": "Potential hardcoded password detected",
                "line": 1,
                "remediation": "Use environment variables for sensitive data"
            })
        
        if "select" in code.lower() and "+" in code:
            issues.append({
                "type": "sql_injection",
                "severity": "HIGH", 
                "description": "Potential SQL injection vulnerability",
                "line": 1,
                "remediation": "Use parameterized queries"
            })
        
        return {
            "issues": issues,
            "total_issues": len(issues),
            "severity_counts": {
                "HIGH": len([i for i in issues if i["severity"] == "HIGH"]),
                "MEDIUM": len([i for i in issues if i["severity"] == "MEDIUM"]),
                "LOW": len([i for i in issues if i["severity"] == "LOW"])
            }
        }
    
    async def validate_compliance(self, code: str, framework: str, **kwargs) -> Dict[str, Any]:
        """Mock compliance validation."""
        analysis = await self.analyze_code(code)
        issues = analysis["issues"]
        
        # Calculate compliance score
        total_checks = 10  # Mock total checks
        failed_checks = len(issues)
        passed_checks = total_checks - failed_checks
        score = passed_checks / total_checks if total_checks > 0 else 1.0
        
        return {
            "framework": framework,
            "score": score,
            "passed": passed_checks,
            "total": total_checks,
            "failed_checks": [
                {
                    "name": issue["type"],
                    "description": issue["description"]
                }
                for issue in issues
            ],
            "recommendations": [
                issue["remediation"] for issue in issues
            ]
        }

# Initialize mock agent
compliance_agent = MockComplianceAgent()

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Compliance Sentinel MCP Server",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "analyze": "/analyze",
            "validate": "/validate",
            "tools": "/tools",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "compliance-sentinel-mcp",
        "version": "1.0.0"
    }

@app.get("/tools")
async def list_tools():
    """List available MCP tools."""
    return {
        "tools": [
            {
                "name": "analyze_code",
                "description": "Analyze code for security vulnerabilities",
                "parameters": ["code", "language", "compliance_frameworks"]
            },
            {
                "name": "analyze_file", 
                "description": "Analyze a specific file for security issues",
                "parameters": ["file_path", "compliance_frameworks"]
            },
            {
                "name": "validate_compliance",
                "description": "Validate code against compliance frameworks",
                "parameters": ["code", "framework"]
            }
        ]
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
        
        result = await compliance_agent.analyze_code(code, language)
        
        return {
            "success": True,
            "analysis": result,
            "message": f"Found {result['total_issues']} security issues"
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/validate")
async def validate_compliance(request: Request):
    """Validate code against compliance framework."""
    try:
        data = await request.json()
        code = data.get("code", "")
        framework = data.get("framework", "owasp-top-10")
        
        if not code:
            raise HTTPException(status_code=400, detail="Code is required")
        
        result = await compliance_agent.validate_compliance(code, framework)
        
        return {
            "success": True,
            "compliance": result,
            "message": f"Compliance score: {result['score']:.1%}"
        }
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/demo")
async def demo_page():
    """Demo page with example usage."""
    return {
        "demo": "Compliance Sentinel MCP Server",
        "examples": {
            "analyze_vulnerable_code": {
                "method": "POST",
                "url": "/analyze",
                "body": {
                    "code": 'password = "hardcoded_secret_123"\nquery = "SELECT * FROM users WHERE id = " + user_id',
                    "language": "python"
                }
            },
            "validate_compliance": {
                "method": "POST", 
                "url": "/validate",
                "body": {
                    "code": 'password = "hardcoded_secret_123"',
                    "framework": "owasp-top-10"
                }
            }
        },
        "mcp_config": {
            "mcpServers": {
                "compliance-sentinel": {
                    "command": "curl",
                    "args": ["-X", "POST", f"{os.getenv('RAILWAY_PUBLIC_DOMAIN', 'localhost:8000')}/analyze"],
                    "disabled": False
                }
            }
        }
    }

def main():
    """Main entry point for web server."""
    port = int(os.getenv("PORT", 8000))
    host = "0.0.0.0"  # Heroku requires 0.0.0.0
    
    logger.info(f"Starting Compliance Sentinel MCP Web Server on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    main()