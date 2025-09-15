# Compliance Sentinel MCP Server

A Model Context Protocol (MCP) server that provides real-time security analysis and compliance checking tools for IDEs and development environments.

## Overview

The Compliance Sentinel MCP Server integrates with IDEs through the Model Context Protocol to provide:

- **Real-time Security Analysis**: Analyze code as you write it
- **Multi-language Support**: Python, JavaScript, Java, Go, TypeScript, and more
- **Compliance Validation**: Check against OWASP, CWE, NIST, ISO 27001, SOC 2
- **Dependency Scanning**: Identify vulnerabilities in project dependencies
- **Security Recommendations**: Get actionable remediation advice

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your IDE's MCP settings using the provided `mcp_config.json`:
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python",
      "args": ["mcp_server.py"],
      "env": {
        "PYTHONPATH": ".",
        "LOG_LEVEL": "INFO"
      },
      "disabled": false,
      "autoApprove": [
        "analyze_code",
        "analyze_file", 
        "analyze_directory",
        "check_dependencies",
        "get_security_recommendations",
        "validate_compliance"
      ]
    }
  }
}
```

## Available Tools

### 1. `analyze_code`
Analyze code snippets for security vulnerabilities and compliance issues.

**Parameters:**
- `code` (required): The code to analyze
- `language` (optional): Programming language (default: python)
- `file_path` (optional): File path for context
- `compliance_frameworks` (optional): Frameworks to check against

**Example:**
```python
# This will be analyzed for security issues
password = "hardcoded_secret_123"
query = "SELECT * FROM users WHERE id = " + user_id
```

### 2. `analyze_file`
Analyze a specific file for security issues.

**Parameters:**
- `file_path` (required): Path to the file to analyze
- `compliance_frameworks` (optional): Compliance frameworks to check

### 3. `analyze_directory`
Analyze all files in a directory for security issues.

**Parameters:**
- `directory_path` (required): Path to directory
- `recursive` (optional): Analyze subdirectories (default: true)
- `file_extensions` (optional): File types to analyze
- `compliance_frameworks` (optional): Frameworks to check

### 4. `check_dependencies`
Check project dependencies for known vulnerabilities.

**Parameters:**
- `project_path` (required): Path to project root
- `package_files` (optional): Package files to check

### 5. `get_security_recommendations`
Get security recommendations for identified issues.

**Parameters:**
- `issues` (required): Array of security issues to get recommendations for

### 6. `validate_compliance`
Validate code against specific compliance frameworks.

**Parameters:**
- `code_or_path` (required): Code content or file/directory path
- `framework` (required): Compliance framework (owasp-top-10, cwe-top-25, etc.)
- `is_path` (optional): Whether input is a path (default: false)

## Available Resources

### 1. `compliance://frameworks`
Information about available compliance frameworks and their requirements.

### 2. `compliance://security-rules`
Security analysis rules and patterns used by the system.

### 3. `compliance://vulnerability-database`
Known vulnerability patterns and signatures.

## Supported Languages

- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Java (.java)
- Go (.go)
- PHP (.php)
- Ruby (.rb)
- C# (.cs)
- C++ (.cpp)
- C (.c)
- Rust (.rs)
- Kotlin (.kt)
- Swift (.swift)

## Compliance Frameworks

- **OWASP Top 10 (2021)**: Web application security risks
- **CWE Top 25 (2023)**: Most dangerous software weaknesses
- **NIST Cybersecurity Framework**: Comprehensive security framework
- **ISO/IEC 27001**: Information security management
- **SOC 2**: Service organization controls

## Security Rules

The server includes built-in detection for:

- Hardcoded secrets and credentials
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Insecure cryptographic practices
- Authentication and authorization flaws
- Input validation issues
- And many more...

## Usage in IDEs

### Kiro IDE
1. Copy the `mcp_config.json` to your workspace `.kiro/settings/` directory
2. Restart Kiro or reload MCP servers
3. Use the tools through chat or commands

### Other MCP-Compatible IDEs
1. Configure the MCP server using the provided configuration
2. Ensure Python and dependencies are available in the environment
3. Start using the security analysis tools

## Environment Variables

- `LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `PYTHONPATH`: Ensure the compliance_sentinel package is in the path
- `MCP_CACHE_TTL_SECONDS`: Cache TTL for analysis results (default: 1800)
- `MCP_MAX_RETRY_ATTEMPTS`: Maximum retry attempts for external services (default: 3)

## Running Standalone

You can also run the MCP server standalone for testing:

```bash
python mcp_server.py
```

The server will start and communicate via stdio, following the MCP protocol.

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `PYTHONPATH` includes the project root
2. **Permission Errors**: Check file permissions for analyzed directories
3. **Network Issues**: Some features require internet access for vulnerability databases

### Logging

Enable debug logging by setting `LOG_LEVEL=DEBUG` in the environment.

### Performance

For large codebases:
- Use `recursive=false` for directory analysis when possible
- Limit `file_extensions` to relevant types
- Consider analyzing specific files instead of entire directories

## Contributing

This MCP server is part of the larger Compliance Sentinel project. See the main README for contribution guidelines.

## License

See the main project LICENSE file for licensing information.