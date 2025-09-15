#!/usr/bin/env python3
"""
Compliance Sentinel MCP Server

A Model Context Protocol server that provides security analysis and compliance checking tools.
This server integrates with IDEs through MCP to provide real-time security analysis.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Sequence
import sys
import os

# Add the compliance_sentinel package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)

from compliance_sentinel.core.compliance_agent import ComplianceAgent
from compliance_sentinel.analyzers.coordinator import AnalysisCoordinator
from compliance_sentinel.config.config_manager import ConfigManager
from compliance_sentinel.models.analysis import SecurityIssue, AnalysisResult
from compliance_sentinel.utils.logging_config import setup_logging

# Configure logging
setup_logging()
logger = logging.getLogger(__name__)

class ComplianceSentinelMCPServer:
    """MCP Server for Compliance Sentinel security analysis."""
    
    def __init__(self):
        self.server = Server("compliance-sentinel")
        self.config_manager = ConfigManager()
        self.compliance_agent = ComplianceAgent(self.config_manager)
        self.analysis_coordinator = AnalysisCoordinator(self.config_manager)
        
        # Register handlers
        self._register_tools()
        self._register_resources()
    
    def _register_tools(self):
        """Register MCP tools for security analysis."""
        
        @self.server.list_tools()
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
                                "description": "The code to analyze"
                            },
                            "language": {
                                "type": "string",
                                "description": "Programming language (python, javascript, java, go, etc.)",
                                "default": "python"
                            },
                            "file_path": {
                                "type": "string",
                                "description": "Optional file path for context",
                                "default": ""
                            },
                            "compliance_frameworks": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Compliance frameworks to check against (owasp, cwe, nist, etc.)",
                                "default": ["owasp", "cwe"]
                            }
                        },
                        "required": ["code"]
                    }
                ),
                Tool(
                    name="analyze_file",
                    description="Analyze a specific file for security issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file to analyze"
                            },
                            "compliance_frameworks": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Compliance frameworks to check against",
                                "default": ["owasp", "cwe"]
                            }
                        },
                        "required": ["file_path"]
                    }
                ),
                Tool(
                    name="analyze_directory",
                    description="Analyze all files in a directory for security issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "directory_path": {
                                "type": "string",
                                "description": "Path to the directory to analyze"
                            },
                            "recursive": {
                                "type": "boolean",
                                "description": "Whether to analyze subdirectories recursively",
                                "default": True
                            },
                            "file_extensions": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "File extensions to analyze (e.g., ['.py', '.js', '.java'])",
                                "default": [".py", ".js", ".java", ".go", ".ts", ".jsx", ".tsx"]
                            },
                            "compliance_frameworks": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Compliance frameworks to check against",
                                "default": ["owasp", "cwe"]
                            }
                        },
                        "required": ["directory_path"]
                    }
                ),
                Tool(
                    name="check_dependencies",
                    description="Check project dependencies for known vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_path": {
                                "type": "string",
                                "description": "Path to the project root"
                            },
                            "package_files": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Package files to check (requirements.txt, package.json, etc.)",
                                "default": ["requirements.txt", "package.json", "go.mod", "pom.xml"]
                            }
                        },
                        "required": ["project_path"]
                    }
                ),
                Tool(
                    name="get_security_recommendations",
                    description="Get security recommendations for identified issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "issues": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string"},
                                        "severity": {"type": "string"},
                                        "description": {"type": "string"},
                                        "file_path": {"type": "string"},
                                        "line_number": {"type": "integer"}
                                    }
                                },
                                "description": "Security issues to get recommendations for"
                            }
                        },
                        "required": ["issues"]
                    }
                ),
                Tool(
                    name="validate_compliance",
                    description="Validate code against specific compliance frameworks",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code_or_path": {
                                "type": "string",
                                "description": "Code content or file/directory path to validate"
                            },
                            "framework": {
                                "type": "string",
                                "description": "Compliance framework (owasp-top-10, cwe-top-25, nist-csf, iso-27001, soc2)",
                                "enum": ["owasp-top-10", "cwe-top-25", "nist-csf", "iso-27001", "soc2"]
                            },
                            "is_path": {
                                "type": "boolean",
                                "description": "Whether code_or_path is a file/directory path",
                                "default": False
                            }
                        },
                        "required": ["code_or_path", "framework"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls for security analysis."""
            try:
                if name == "analyze_code":
                    return await self._analyze_code(arguments)
                elif name == "analyze_file":
                    return await self._analyze_file(arguments)
                elif name == "analyze_directory":
                    return await self._analyze_directory(arguments)
                elif name == "check_dependencies":
                    return await self._check_dependencies(arguments)
                elif name == "get_security_recommendations":
                    return await self._get_security_recommendations(arguments)
                elif name == "validate_compliance":
                    return await self._validate_compliance(arguments)
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except Exception as e:
                logger.error(f"Tool call failed for {name}: {e}", exc_info=True)
                return [TextContent(type="text", text=f"Error executing {name}: {str(e)}")]
    
    def _register_resources(self):
        """Register MCP resources for security data."""
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available security resources."""
            return [
                Resource(
                    uri="compliance://frameworks",
                    name="Compliance Frameworks",
                    description="Available compliance frameworks and their requirements",
                    mimeType="application/json"
                ),
                Resource(
                    uri="compliance://security-rules",
                    name="Security Rules",
                    description="Security analysis rules and patterns",
                    mimeType="application/json"
                ),
                Resource(
                    uri="compliance://vulnerability-database",
                    name="Vulnerability Database",
                    description="Known vulnerability patterns and signatures",
                    mimeType="application/json"
                )
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read security resource data."""
            try:
                if uri == "compliance://frameworks":
                    frameworks = {
                        "owasp-top-10": {
                            "name": "OWASP Top 10",
                            "version": "2021",
                            "categories": [
                                "Broken Access Control",
                                "Cryptographic Failures",
                                "Injection",
                                "Insecure Design",
                                "Security Misconfiguration",
                                "Vulnerable and Outdated Components",
                                "Identification and Authentication Failures",
                                "Software and Data Integrity Failures",
                                "Security Logging and Monitoring Failures",
                                "Server-Side Request Forgery"
                            ]
                        },
                        "cwe-top-25": {
                            "name": "CWE Top 25",
                            "version": "2023",
                            "categories": [
                                "Out-of-bounds Write",
                                "Improper Neutralization of Input",
                                "Out-of-bounds Read",
                                "Improper Input Validation",
                                "Improper Neutralization of Special Elements in SQL Commands",
                                "Use After Free",
                                "Improper Limitation of a Pathname",
                                "Cross-site Scripting",
                                "OS Command Injection",
                                "Use of Hard-coded Credentials"
                            ]
                        }
                    }
                    return json.dumps(frameworks, indent=2)
                elif uri == "compliance://security-rules":
                    # Return security rules from the config
                    rules = self.config_manager.get_security_rules()
                    return json.dumps(rules, indent=2)
                elif uri == "compliance://vulnerability-database":
                    # Return vulnerability patterns
                    vuln_db = {
                        "patterns": [
                            {
                                "id": "hardcoded_secrets",
                                "pattern": r"(password|secret|key|token)\s*=\s*[\"'][^\"']{3,}[\"']",
                                "severity": "HIGH",
                                "category": "AUTHENTICATION"
                            },
                            {
                                "id": "sql_injection",
                                "pattern": r"SELECT.*\+.*|INSERT.*\+.*|UPDATE.*\+.*",
                                "severity": "HIGH",
                                "category": "INJECTION"
                            },
                            {
                                "id": "command_injection",
                                "pattern": r"subprocess.*shell\s*=\s*True",
                                "severity": "HIGH",
                                "category": "INJECTION"
                            }
                        ]
                    }
                    return json.dumps(vuln_db, indent=2)
                else:
                    return f"Unknown resource: {uri}"
            except Exception as e:
                logger.error(f"Resource read failed for {uri}: {e}")
                return f"Error reading resource {uri}: {str(e)}"
    
    async def _analyze_code(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Analyze code for security issues."""
        code = arguments["code"]
        language = arguments.get("language", "python")
        file_path = arguments.get("file_path", "")
        compliance_frameworks = arguments.get("compliance_frameworks", ["owasp", "cwe"])
        
        try:
            # Perform security analysis
            result = await self.analysis_coordinator.analyze_code(
                code=code,
                language=language,
                file_path=file_path,
                compliance_frameworks=compliance_frameworks
            )
            
            # Format results
            response = self._format_analysis_result(result)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return [TextContent(type="text", text=f"Analysis failed: {str(e)}")]
    
    async def _analyze_file(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Analyze a file for security issues."""
        file_path = arguments["file_path"]
        compliance_frameworks = arguments.get("compliance_frameworks", ["owasp", "cwe"])
        
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return [TextContent(type="text", text=f"File not found: {file_path}")]
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Detect language from file extension
            language = self._detect_language(file_path)
            
            # Perform analysis
            result = await self.analysis_coordinator.analyze_code(
                code=code,
                language=language,
                file_path=file_path,
                compliance_frameworks=compliance_frameworks
            )
            
            response = self._format_analysis_result(result)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            return [TextContent(type="text", text=f"File analysis failed: {str(e)}")]
    
    async def _analyze_directory(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Analyze a directory for security issues."""
        directory_path = arguments["directory_path"]
        recursive = arguments.get("recursive", True)
        file_extensions = arguments.get("file_extensions", [".py", ".js", ".java", ".go", ".ts", ".jsx", ".tsx"])
        compliance_frameworks = arguments.get("compliance_frameworks", ["owasp", "cwe"])
        
        try:
            if not os.path.exists(directory_path):
                return [TextContent(type="text", text=f"Directory not found: {directory_path}")]
            
            # Find files to analyze
            files_to_analyze = []
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        if any(file.endswith(ext) for ext in file_extensions):
                            files_to_analyze.append(os.path.join(root, file))
            else:
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path) and any(file.endswith(ext) for ext in file_extensions):
                        files_to_analyze.append(file_path)
            
            if not files_to_analyze:
                return [TextContent(type="text", text=f"No files found to analyze in: {directory_path}")]
            
            # Analyze each file
            all_results = []
            for file_path in files_to_analyze:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    
                    language = self._detect_language(file_path)
                    result = await self.analysis_coordinator.analyze_code(
                        code=code,
                        language=language,
                        file_path=file_path,
                        compliance_frameworks=compliance_frameworks
                    )
                    all_results.append((file_path, result))
                except Exception as e:
                    logger.warning(f"Failed to analyze {file_path}: {e}")
                    continue
            
            # Format combined results
            response = self._format_directory_results(all_results)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Directory analysis failed: {e}")
            return [TextContent(type="text", text=f"Directory analysis failed: {str(e)}")]
    
    async def _check_dependencies(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Check project dependencies for vulnerabilities."""
        project_path = arguments["project_path"]
        package_files = arguments.get("package_files", ["requirements.txt", "package.json", "go.mod", "pom.xml"])
        
        try:
            if not os.path.exists(project_path):
                return [TextContent(type="text", text=f"Project path not found: {project_path}")]
            
            # Find package files
            found_files = []
            for package_file in package_files:
                file_path = os.path.join(project_path, package_file)
                if os.path.exists(file_path):
                    found_files.append(file_path)
            
            if not found_files:
                return [TextContent(type="text", text=f"No package files found in: {project_path}")]
            
            # Analyze dependencies
            dependency_results = []
            for file_path in found_files:
                try:
                    result = await self.analysis_coordinator.analyze_dependencies(file_path)
                    dependency_results.append((file_path, result))
                except Exception as e:
                    logger.warning(f"Failed to analyze dependencies in {file_path}: {e}")
                    continue
            
            response = self._format_dependency_results(dependency_results)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Dependency check failed: {e}")
            return [TextContent(type="text", text=f"Dependency check failed: {str(e)}")]
    
    async def _get_security_recommendations(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Get security recommendations for issues."""
        issues = arguments["issues"]
        
        try:
            recommendations = []
            for issue in issues:
                recommendation = await self.compliance_agent.get_remediation_suggestion(issue)
                recommendations.append({
                    "issue": issue,
                    "recommendation": recommendation
                })
            
            response = self._format_recommendations(recommendations)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Failed to get recommendations: {e}")
            return [TextContent(type="text", text=f"Failed to get recommendations: {str(e)}")]
    
    async def _validate_compliance(self, arguments: Dict[str, Any]) -> List[TextContent]:
        """Validate against compliance framework."""
        code_or_path = arguments["code_or_path"]
        framework = arguments["framework"]
        is_path = arguments.get("is_path", False)
        
        try:
            if is_path:
                if not os.path.exists(code_or_path):
                    return [TextContent(type="text", text=f"Path not found: {code_or_path}")]
                
                if os.path.isfile(code_or_path):
                    with open(code_or_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    language = self._detect_language(code_or_path)
                    file_path = code_or_path
                else:
                    # Directory - analyze all files
                    return await self._analyze_directory({
                        "directory_path": code_or_path,
                        "compliance_frameworks": [framework]
                    })
            else:
                code = code_or_path
                language = "python"  # Default
                file_path = ""
            
            # Perform compliance validation
            result = await self.compliance_agent.validate_compliance(
                code=code,
                language=language,
                framework=framework,
                file_path=file_path
            )
            
            response = self._format_compliance_result(result, framework)
            return [TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Compliance validation failed: {e}")
            return [TextContent(type="text", text=f"Compliance validation failed: {str(e)}")]
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift'
        }
        return language_map.get(ext, 'unknown')
    
    def _format_analysis_result(self, result: AnalysisResult) -> str:
        """Format analysis result for display."""
        if not result or not result.issues:
            return "✅ No security issues found!"
        
        output = []
        output.append(f"🔍 Security Analysis Results")
        output.append(f"Found {len(result.issues)} security issues:")
        output.append("")
        
        # Group by severity
        severity_groups = {}
        for issue in result.issues:
            severity = issue.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(issue)
        
        # Display by severity (Critical, High, Medium, Low)
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if severity in severity_groups:
                issues = severity_groups[severity]
                emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '💡'}[severity]
                output.append(f"{emoji} {severity} ({len(issues)} issues):")
                
                for issue in issues:
                    output.append(f"  • {issue.title}")
                    output.append(f"    {issue.description}")
                    if issue.file_path:
                        location = f"{issue.file_path}"
                        if issue.line_number:
                            location += f":{issue.line_number}"
                        output.append(f"    📍 {location}")
                    if issue.remediation:
                        output.append(f"    💡 Fix: {issue.remediation}")
                    output.append("")
        
        return "\n".join(output)
    
    def _format_directory_results(self, results: List[tuple]) -> str:
        """Format directory analysis results."""
        if not results:
            return "No files were analyzed."
        
        output = []
        output.append(f"📁 Directory Analysis Results")
        output.append(f"Analyzed {len(results)} files:")
        output.append("")
        
        total_issues = 0
        files_with_issues = 0
        
        for file_path, result in results:
            if result and result.issues:
                files_with_issues += 1
                issue_count = len(result.issues)
                total_issues += issue_count
                
                output.append(f"📄 {os.path.basename(file_path)} ({issue_count} issues)")
                
                # Show top 3 most severe issues per file
                sorted_issues = sorted(result.issues, key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.severity, 0), reverse=True)
                for issue in sorted_issues[:3]:
                    emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '💡'}.get(issue.severity, '•')
                    output.append(f"  {emoji} {issue.title}")
                
                if len(sorted_issues) > 3:
                    output.append(f"  ... and {len(sorted_issues) - 3} more issues")
                output.append("")
        
        if files_with_issues == 0:
            output.append("✅ No security issues found in any files!")
        else:
            output.append(f"📊 Summary: {total_issues} total issues in {files_with_issues} files")
        
        return "\n".join(output)
    
    def _format_dependency_results(self, results: List[tuple]) -> str:
        """Format dependency analysis results."""
        if not results:
            return "No dependency files were analyzed."
        
        output = []
        output.append("📦 Dependency Vulnerability Analysis")
        output.append("")
        
        total_vulns = 0
        
        for file_path, result in results:
            output.append(f"📄 {os.path.basename(file_path)}")
            
            if result and hasattr(result, 'vulnerabilities') and result.vulnerabilities:
                vulns = result.vulnerabilities
                total_vulns += len(vulns)
                
                # Group by severity
                severity_groups = {}
                for vuln in vulns:
                    severity = vuln.get('severity', 'UNKNOWN')
                    if severity not in severity_groups:
                        severity_groups[severity] = []
                    severity_groups[severity].append(vuln)
                
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if severity in severity_groups:
                        count = len(severity_groups[severity])
                        emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '💡'}[severity]
                        output.append(f"  {emoji} {severity}: {count} vulnerabilities")
                        
                        # Show details for critical/high
                        if severity in ['CRITICAL', 'HIGH']:
                            for vuln in severity_groups[severity][:3]:  # Show top 3
                                pkg_name = vuln.get('package', 'Unknown')
                                vuln_id = vuln.get('id', 'Unknown')
                                output.append(f"    • {pkg_name}: {vuln_id}")
            else:
                output.append("  ✅ No vulnerabilities found")
            
            output.append("")
        
        if total_vulns > 0:
            output.append(f"⚠️ Total: {total_vulns} vulnerabilities found across all dependencies")
        else:
            output.append("✅ No dependency vulnerabilities found!")
        
        return "\n".join(output)
    
    def _format_recommendations(self, recommendations: List[Dict]) -> str:
        """Format security recommendations."""
        if not recommendations:
            return "No recommendations available."
        
        output = []
        output.append("💡 Security Recommendations")
        output.append("")
        
        for i, rec in enumerate(recommendations, 1):
            issue = rec['issue']
            recommendation = rec['recommendation']
            
            output.append(f"{i}. {issue.get('type', 'Security Issue')}")
            output.append(f"   Severity: {issue.get('severity', 'Unknown')}")
            output.append(f"   Description: {issue.get('description', 'No description')}")
            output.append(f"   💡 Recommendation: {recommendation}")
            
            if issue.get('file_path'):
                location = issue['file_path']
                if issue.get('line_number'):
                    location += f":{issue['line_number']}"
                output.append(f"   📍 Location: {location}")
            
            output.append("")
        
        return "\n".join(output)
    
    def _format_compliance_result(self, result: Dict, framework: str) -> str:
        """Format compliance validation result."""
        output = []
        output.append(f"📋 Compliance Validation: {framework.upper()}")
        output.append("")
        
        if not result:
            output.append("❌ Compliance validation failed")
            return "\n".join(output)
        
        score = result.get('score', 0)
        passed = result.get('passed', 0)
        total = result.get('total', 0)
        
        if score >= 0.8:
            emoji = "✅"
        elif score >= 0.6:
            emoji = "⚠️"
        else:
            emoji = "❌"
        
        output.append(f"{emoji} Compliance Score: {score:.1%} ({passed}/{total} checks passed)")
        output.append("")
        
        # Show failed checks
        failed_checks = result.get('failed_checks', [])
        if failed_checks:
            output.append("❌ Failed Compliance Checks:")
            for check in failed_checks:
                output.append(f"  • {check.get('name', 'Unknown check')}")
                output.append(f"    {check.get('description', 'No description')}")
            output.append("")
        
        # Show recommendations
        recommendations = result.get('recommendations', [])
        if recommendations:
            output.append("💡 Compliance Recommendations:")
            for rec in recommendations:
                output.append(f"  • {rec}")
            output.append("")
        
        return "\n".join(output)
    
    async def run(self):
        """Run the MCP server."""
        logger.info("Starting Compliance Sentinel MCP Server")
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="compliance-sentinel",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=None,
                        experimental_capabilities={}
                    )
                )
            )


async def main():
    """Main entry point."""
    server = ComplianceSentinelMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())