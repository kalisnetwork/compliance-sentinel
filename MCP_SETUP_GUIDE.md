# 🔒 Compliance Sentinel MCP Server Setup Guide

Transform your IDE into a **real-time security analysis powerhouse** with the Compliance Sentinel MCP Server!

## 🚀 Quick Setup (2 minutes)

### Step 1: Install MCP Dependencies

```bash
# Install MCP library
pip install mcp

# Or install all dependencies
pip install -r requirements_mcp.txt
```

### Step 2: Configure in Kiro IDE

Create or update `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python3",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/compliance-sentinel",
      "disabled": false,
      "autoApprove": ["analyze_code", "validate_compliance", "get_security_patterns"]
    }
  }
}
```

### Step 3: Test the Connection

```bash
# Test the MCP server directly
python3 mcp_server.py
```

## 🎯 How to Use

### In Kiro IDE Chat:

**Analyze Code for Security Issues:**
```
Analyze this Python code for security vulnerabilities:

```python
password = "hardcoded_secret_123"
query = "SELECT * FROM users WHERE id = " + user_id
os.system(user_command)
eval(user_input)
```

**Validate Compliance:**
```
Validate this code against OWASP Top 10:

```javascript
document.getElementById('output').innerHTML = userInput;
var query = "SELECT * FROM users WHERE name = '" + userName + "'";
```

**Get Security Patterns:**
```
Show me all supported security vulnerability patterns
```

**Get Compliance Frameworks:**
```
What compliance frameworks do you support?
```

## 🔧 Available MCP Tools

### 1. `analyze_code`
**Purpose:** Analyze source code for security vulnerabilities

**Parameters:**
- `code` (required): Source code to analyze
- `language` (optional): Programming language (python, javascript, java, etc.)
- `include_remediation` (optional): Include fix suggestions (default: true)

**Example:**
```json
{
  "code": "password = 'secret123'",
  "language": "python",
  "include_remediation": true
}
```

### 2. `validate_compliance`
**Purpose:** Validate code against security compliance frameworks

**Parameters:**
- `code` (required): Source code to validate
- `framework` (optional): Compliance framework (owasp-top-10, cwe-top-25, nist-csf)

**Example:**
```json
{
  "code": "eval(userInput)",
  "framework": "owasp-top-10"
}
```

### 3. `get_security_patterns`
**Purpose:** Get information about supported security patterns

**Parameters:**
- `pattern_type` (optional): Specific pattern to get details for

### 4. `get_compliance_frameworks`
**Purpose:** Get information about supported compliance frameworks

**Parameters:**
- `framework` (optional): Specific framework to get details for

## 🔒 Security Patterns Detected

### High Severity:
- ✅ **Hardcoded Credentials** (CWE-798)
- ✅ **SQL Injection** (CWE-89)
- ✅ **Command Injection** (CWE-78)

### Medium Severity:
- ✅ **Cross-Site Scripting (XSS)** (CWE-79)
- ✅ **Weak Cryptography** (CWE-327)
- ✅ **Insecure Random** (CWE-338)

## 📋 Compliance Frameworks

### OWASP Top 10 (2021)
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A07: Identification and Authentication Failures
- And more...

### CWE Top 25 Most Dangerous Software Errors
- CWE-79: Cross-site Scripting
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- And more...

### NIST Cybersecurity Framework
- ID: Identify
- PR: Protect
- DE: Detect
- RS: Respond
- RC: Recover

## 🌍 Multi-Language Support

- ✅ **Python** - Full pattern detection
- ✅ **JavaScript/TypeScript** - XSS, injection patterns
- ✅ **Java** - Enterprise security patterns
- ✅ **Go** - Modern language patterns
- ✅ **PHP** - Web security patterns
- ✅ **Ruby** - Rails security patterns
- ✅ **C#** - .NET security patterns
- ✅ **C/C++** - Memory safety patterns

## 🛠️ Advanced Configuration

### Custom Pattern Detection
Add your own security patterns by modifying `SECURITY_PATTERNS` in `mcp_server.py`.

### Logging Configuration
Logs are written to `logs/compliance_sentinel.log` for debugging and monitoring.

### Performance Tuning
- Code analysis is optimized for files up to 10,000 lines
- Pattern matching uses compiled regex for speed
- Results are cached for repeated analysis

## 🔄 Integration Examples

### VS Code Extension
```javascript
// Call MCP server from VS Code extension
const result = await mcpClient.callTool('analyze_code', {
  code: editor.document.getText(),
  language: editor.document.languageId
});
```

### CLI Usage
```bash
# Direct MCP server testing
echo '{"code": "password = \"secret\"", "language": "python"}' | python3 mcp_server.py
```

### API Integration
```python
# Integrate with existing security tools
import subprocess
import json

def analyze_with_mcp(code, language="python"):
    result = subprocess.run([
        "python3", "mcp_server.py"
    ], input=json.dumps({
        "tool": "analyze_code",
        "arguments": {"code": code, "language": language}
    }), capture_output=True, text=True)
    return json.loads(result.stdout)
```

## 🚨 Troubleshooting

### Common Issues:

**1. "MCP server connection timed out"**
- Check that `mcp` library is installed: `pip install mcp`
- Verify the path in your MCP configuration
- Test the server directly: `python3 mcp_server.py`

**2. "Module 'mcp' not found"**
- Install MCP: `pip install mcp`
- Check Python path and virtual environment

**3. "Permission denied"**
- Make sure `mcp_server.py` is executable: `chmod +x mcp_server.py`
- Check file paths in configuration

**4. "Tool not found"**
- Verify tool names: `analyze_code`, `validate_compliance`, etc.
- Check MCP server logs in `logs/compliance_sentinel.log`

### Debug Mode:
```bash
# Run with debug logging
PYTHONPATH=. python3 -m logging.basicConfig --level=DEBUG mcp_server.py
```

## 🎉 Success!

Your MCP server is now ready to provide **real-time security analysis** in your IDE!

**Features you now have:**
- ✅ **Real-time vulnerability detection**
- ✅ **Compliance validation**
- ✅ **Multi-language support**
- ✅ **Detailed remediation guidance**
- ✅ **Integration with any MCP-compatible IDE**

**Start analyzing code now by asking your IDE to check for security issues!** 🔒✨

## 📚 Additional Resources

- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Need help?** Check the logs at `logs/compliance_sentinel.log` or open an issue on GitHub!