#!/usr/bin/env python3
"""
Compliance Sentinel MCP Server
A Model Context Protocol server for real-time security analysis and compliance validation.
"""

import asyncio
import json
import logging
import re
import sys
from typing import Any, Dict, List, Optional

# MCP server imports
try:
    from mcp.server import Server
    from mcp.server.models import InitializationOptions
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        CallToolRequest,
        CallToolResult,
        ListToolsRequest,
        TextContent,
        Tool,
    )
except ImportError:
    print("Error: MCP library not installed. Install with: pip install mcp", file=sys.stderr)
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/compliance_sentinel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("compliance-sentinel")

# Security analysis patterns
SECURITY_PATTERNS = {
    "hardcoded_credentials": {
        "patterns": [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"secret\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']",
            r"token\s*=\s*[\"'][^\"']+[\"']",
            r"access_key\s*=\s*[\"'][^\"']+[\"']",
            r"private_key\s*=\s*[\"'][^\"']+[\"']"
        ],
        "severity": "HIGH",
        "title": "Hardcoded Credentials",
        "description": "Hardcoded credentials detected in source code",
        "remediation": "Use environment variables or secure vaults for sensitive data",
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 – Identification and Authentication Failures"
    },
    "sql_injection": {
        "patterns": [
            r"SELECT.*\+.*",
            r"INSERT.*\+.*", 
            r"UPDATE.*\+.*",
            r"DELETE.*\+.*",
            r"query.*\+.*user",
            r"f[\"']SELECT.*{.*}.*[\"']",
            r"\.format\(.*\).*SELECT",
            r"%.*SELECT.*%"
        ],
        "severity": "HIGH",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection through string concatenation",
        "remediation": "Use parameterized queries or prepared statements",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 – Injection"
    },
    "command_injection": {
        "patterns": [
            r"os\.system\(",
            r"subprocess.*shell\s*=\s*True",
            r"eval\(",
            r"exec\(",
            r"popen\(",
            r"call\(.*shell\s*=\s*True"
        ],
        "severity": "HIGH",
        "title": "Command Injection Risk",
        "description": "Potentially dangerous function that could lead to command injection",
        "remediation": "Validate and sanitize all inputs, avoid shell=True",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 – Injection"
    },
    "xss_vulnerability": {
        "patterns": [
            r"innerHTML\s*=",
            r"document\.write\(",
            r"\.html\(.*\+.*\)",
            r"dangerouslySetInnerHTML",
            r"v-html\s*="
        ],
        "severity": "MEDIUM",
        "title": "Cross-Site Scripting (XSS)",
        "description": "Potential XSS vulnerability through unsafe DOM manipulation",
        "remediation": "Sanitize user inputs and use safe DOM manipulation methods",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 – Injection"
    },
    "weak_crypto": {
        "patterns": [
            r"hashlib\.md5\(",
            r"hashlib\.sha1\(",
            r"crypto\.createHash\([\"']md5[\"']\)",
            r"crypto\.createHash\([\"']sha1[\"']\)",
            r"MD5\(",
            r"SHA1\("
        ],
        "severity": "MEDIUM",
        "title": "Weak Cryptographic Algorithm",
        "description": "Use of weak or deprecated cryptographic algorithms",
        "remediation": "Use SHA-256 or stronger hashing algorithms",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 – Cryptographic Failures"
    },
    "insecure_random": {
        "patterns": [
            r"random\.random\(",
            r"Math\.random\(",
            r"rand\(\)",
            r"srand\("
        ],
        "severity": "MEDIUM",
        "title": "Insecure Random Number Generation",
        "description": "Use of non-cryptographic random number generators for security purposes",
        "remediation": "Use cryptographically secure random number generators",
        "cwe_id": "CWE-338",
        "owasp_category": "A02:2021 – Cryptographic Failures"
    }
}

# Compliance frameworks mapping
COMPLIANCE_FRAMEWORKS = {
    "owasp-top-10": {
        "name": "OWASP Top 10 (2021)",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures", 
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery"
        }
    },
    "cwe-top-25": {
        "name": "CWE Top 25 Most Dangerous Software Errors",
        "categories": {
            "CWE-79": "Cross-site Scripting",
            "CWE-89": "SQL Injection", 
            "CWE-78": "OS Command Injection",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-327": "Use of a Broken Cryptographic Algorithm",
            "CWE-338": "Use of Cryptographically Weak PRNG"
        }
    },
    "nist-csf": {
        "name": "NIST Cybersecurity Framework",
        "categories": {
            "ID": "Identify",
            "PR": "Protect",
            "DE": "Detect", 
            "RS": "Respond",
            "RC": "Recover"
        }
    }
}

def analyze_code_patterns(code: str, language: str = "python") -> List[Dict[str, Any]]:
    """Analyze code for security patterns."""
    issues = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        
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
                        "remediation": pattern_info["remediation"],
                        "cwe_id": pattern_info["cwe_id"],
                        "owasp_category": pattern_info["owasp_category"]
                    })
                    break  # Only report one issue per line
    
    return issues

def validate_compliance(code: str, framework: str) -> Dict[str, Any]:
    """Validate code against compliance framework."""
    issues = analyze_code_patterns(code)
    
    # Framework-specific scoring
    framework_weights = {
        "owasp-top-10": {"HIGH": 3, "MEDIUM": 2, "LOW": 1},
        "cwe-top-25": {"HIGH": 4, "MEDIUM": 2, "LOW": 1},
        "nist-csf": {"HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    }
    
    weights = framework_weights.get(framework, {"HIGH": 3, "MEDIUM": 2, "LOW": 1})
    
    # Calculate score
    total_weight = sum(weights.get(issue["severity"], 1) for issue in issues)
    max_possible = 20  # Assume max 20 points of issues
    score = max(0, (max_possible - total_weight) / max_possible)
    
    # Determine grade
    if score >= 0.9:
        grade = "A"
    elif score >= 0.7:
        grade = "B"
    elif score >= 0.5:
        grade = "C"
    else:
        grade = "D"
    
    return {
        "framework": framework,
        "framework_name": COMPLIANCE_FRAMEWORKS.get(framework, {}).get("name", framework),
        "score": score,
        "percentage": f"{score:.1%}",
        "grade": grade,
        "total_issues": len(issues),
        "critical_issues": len([i for i in issues if i["severity"] == "CRITICAL"]),
        "high_issues": len([i for i in issues if i["severity"] == "HIGH"]),
        "medium_issues": len([i for i in issues if i["severity"] == "MEDIUM"]),
        "low_issues": len([i for i in issues if i["severity"] == "LOW"]),
        "passed_checks": max(0, 10 - len(issues)),
        "total_checks": 10,
        "violations": issues,
        "recommendations": [issue["remediation"] for issue in issues[:5]]
    }

# Create MCP server
server = Server("compliance-sentinel")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available security analysis tools."""
    return [
        Tool(
            name="analyze_code",
            description="Analyze code for security vulnerabilities and compliance issues",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The source code to analyze for security issues"
                    },
                    "language": {
                        "type": "string", 
                        "description": "Programming language (python, javascript, java, etc.)",
                        "default": "python"
                    },
                    "include_remediation": {
                        "type": "boolean",
                        "description": "Include remediation suggestions in the output",
                        "default": True
                    }
                },
                "required": ["code"]
            }
        ),
        Tool(
            name="validate_compliance",
            description="Validate code against security compliance frameworks (OWASP, CWE, NIST)",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The source code to validate for compliance"
                    },
                    "framework": {
                        "type": "string",
                        "description": "Compliance framework to validate against",
                        "enum": ["owasp-top-10", "cwe-top-25", "nist-csf"],
                        "default": "owasp-top-10"
                    }
                },
                "required": ["code"]
            }
        ),
        Tool(
            name="get_security_patterns",
            description="Get list of supported security vulnerability patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern_type": {
                        "type": "string",
                        "description": "Filter by specific pattern type (optional)"
                    }
                }
            }
        ),
        Tool(
            name="get_compliance_frameworks",
            description="Get information about supported compliance frameworks",
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": "Get details for specific framework (optional)"
                    }
                }
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
    """Handle tool calls."""
    try:
        if name == "analyze_code":
            code = arguments.get("code", "")
            language = arguments.get("language", "python")
            include_remediation = arguments.get("include_remediation", True)
            
            if not code.strip():
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: Code is required and cannot be empty")]
                )
            
            # Analyze code
            issues = analyze_code_patterns(code, language)
            
            # Calculate severity counts
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for issue in issues:
                severity_counts[issue["severity"]] += 1
            
            # Format results
            result = {
                "analysis_summary": {
                    "total_issues": len(issues),
                    "severity_counts": severity_counts,
                    "language": language,
                    "lines_analyzed": len(code.split('\n'))
                },
                "security_issues": issues if include_remediation else [
                    {k: v for k, v in issue.items() if k != "remediation"} 
                    for issue in issues
                ]
            }
            
            # Create formatted output
            output = f"🔒 **Security Analysis Results**\n\n"
            output += f"**Language:** {language}\n"
            output += f"**Lines Analyzed:** {len(code.split('\n'))}\n"
            output += f"**Total Issues:** {len(issues)}\n\n"
            
            if severity_counts["HIGH"] > 0:
                output += f"🚨 **HIGH Severity:** {severity_counts['HIGH']} issues\n"
            if severity_counts["MEDIUM"] > 0:
                output += f"⚠️ **MEDIUM Severity:** {severity_counts['MEDIUM']} issues\n"
            if severity_counts["LOW"] > 0:
                output += f"ℹ️ **LOW Severity:** {severity_counts['LOW']} issues\n"
            
            if issues:
                output += f"\n**Detailed Issues:**\n"
                for i, issue in enumerate(issues, 1):
                    output += f"\n{i}. **{issue['title']}** (Line {issue['line']})\n"
                    output += f"   - **Severity:** {issue['severity']}\n"
                    output += f"   - **Description:** {issue['description']}\n"
                    output += f"   - **Code:** `{issue['line_content']}`\n"
                    if include_remediation:
                        output += f"   - **Remediation:** {issue['remediation']}\n"
                    output += f"   - **CWE ID:** {issue['cwe_id']}\n"
                    output += f"   - **OWASP Category:** {issue['owasp_category']}\n"
            else:
                output += f"\n✅ **No security issues detected!**\n"
            
            return CallToolResult(
                content=[TextContent(type="text", text=output)]
            )
        
        elif name == "validate_compliance":
            code = arguments.get("code", "")
            framework = arguments.get("framework", "owasp-top-10")
            
            if not code.strip():
                return CallToolResult(
                    content=[TextContent(type="text", text="Error: Code is required and cannot be empty")]
                )
            
            # Validate compliance
            compliance_result = validate_compliance(code, framework)
            
            # Format output
            output = f"📋 **Compliance Validation Results**\n\n"
            output += f"**Framework:** {compliance_result['framework_name']}\n"
            output += f"**Overall Score:** {compliance_result['percentage']} (Grade: {compliance_result['grade']})\n"
            output += f"**Total Issues:** {compliance_result['total_issues']}\n\n"
            
            if compliance_result['high_issues'] > 0:
                output += f"🚨 **High Priority Issues:** {compliance_result['high_issues']}\n"
            if compliance_result['medium_issues'] > 0:
                output += f"⚠️ **Medium Priority Issues:** {compliance_result['medium_issues']}\n"
            
            output += f"\n**Compliance Status:**\n"
            output += f"- Passed Checks: {compliance_result['passed_checks']}/{compliance_result['total_checks']}\n"
            
            if compliance_result['violations']:
                output += f"\n**Compliance Violations:**\n"
                for i, violation in enumerate(compliance_result['violations'][:5], 1):
                    output += f"{i}. {violation['title']} (Line {violation['line']})\n"
                    output += f"   - {violation['owasp_category']}\n"
            
            if compliance_result['recommendations']:
                output += f"\n**Top Recommendations:**\n"
                for i, rec in enumerate(compliance_result['recommendations'][:3], 1):
                    output += f"{i}. {rec}\n"
            
            return CallToolResult(
                content=[TextContent(type="text", text=output)]
            )
        
        elif name == "get_security_patterns":
            pattern_type = arguments.get("pattern_type")
            
            if pattern_type and pattern_type in SECURITY_PATTERNS:
                pattern = SECURITY_PATTERNS[pattern_type]
                output = f"🔍 **Security Pattern: {pattern['title']}**\n\n"
                output += f"**Severity:** {pattern['severity']}\n"
                output += f"**Description:** {pattern['description']}\n"
                output += f"**CWE ID:** {pattern['cwe_id']}\n"
                output += f"**OWASP Category:** {pattern['owasp_category']}\n"
                output += f"**Remediation:** {pattern['remediation']}\n"
            else:
                output = f"🔍 **Supported Security Patterns**\n\n"
                for pattern_id, pattern in SECURITY_PATTERNS.items():
                    output += f"**{pattern['title']}** (`{pattern_id}`)\n"
                    output += f"- Severity: {pattern['severity']}\n"
                    output += f"- CWE: {pattern['cwe_id']}\n"
                    output += f"- Description: {pattern['description']}\n\n"
            
            return CallToolResult(
                content=[TextContent(type="text", text=output)]
            )
        
        elif name == "get_compliance_frameworks":
            framework = arguments.get("framework")
            
            if framework and framework in COMPLIANCE_FRAMEWORKS:
                fw = COMPLIANCE_FRAMEWORKS[framework]
                output = f"📋 **Compliance Framework: {fw['name']}**\n\n"
                output += f"**Categories:**\n"
                for cat_id, cat_name in fw['categories'].items():
                    output += f"- {cat_id}: {cat_name}\n"
            else:
                output = f"📋 **Supported Compliance Frameworks**\n\n"
                for fw_id, fw in COMPLIANCE_FRAMEWORKS.items():
                    output += f"**{fw['name']}** (`{fw_id}`)\n"
                    output += f"- Categories: {len(fw['categories'])}\n\n"
            
            return CallToolResult(
                content=[TextContent(type="text", text=output)]
            )
        
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error: Unknown tool '{name}'")]
            )
    
    except Exception as e:
        logger.error(f"Error in tool '{name}': {e}")
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {str(e)}")]
        )

async def main():
    """Run the MCP server."""
    logger.info("Starting Compliance Sentinel MCP Server...")
    
    # Create logs directory if it doesn't exist
    import os
    os.makedirs("logs", exist_ok=True)
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="compliance-sentinel",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())