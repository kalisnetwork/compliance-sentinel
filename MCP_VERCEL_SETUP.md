# Compliance Sentinel MCP Server - Vercel Setup

## 🚀 Quick Setup for Developers

This MCP server uses the **Vercel-hosted Compliance Sentinel API** for security analysis, making it easy to share across teams without local dependencies.

### Prerequisites

- Python 3.7+
- Kiro IDE or any MCP-compatible client
- Internet connection (for Vercel API calls)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/kalisnetwork/compliance-sentinel
cd compliance-sentinel
```

2. **Install dependencies:**
```bash
pip install requests
```

3. **Configure MCP in Kiro:**

Add to your `.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python3",
      "args": ["vercel_mcp_server.py"],
      "disabled": false,
      "autoApprove": ["analyze_code"]
    }
  }
}
```

4. **Restart Kiro** or reconnect MCP servers

### Usage

The MCP server provides one tool: `analyze_code`

**In Kiro chat:**
```
Analyze this code for security issues:

password = "hardcoded123"
query = "SELECT * FROM users WHERE id = " + user_id
```

**Response:**
```
🔒 Security Analysis Results (via Vercel)

Language: python
Lines Analyzed: 2
Total Issues: 2

🚨 HIGH Severity: 2 issues

1. Hardcoded Credentials (Line 1)
   - Severity: HIGH
   - Description: Hardcoded credentials detected
   - Code: password = "hardcoded123"
   - Fix: Use environment variables or secure vaults for credentials

2. Sql Injection (Line 2)
   - Severity: HIGH
   - Description: Potential SQL injection vulnerability
   - Code: query = "SELECT * FROM users WHERE id = " + user_id
   - Fix: Use parameterized queries or prepared statements
```

### Supported Languages

- Python
- JavaScript/TypeScript
- Java
- Go
- PHP
- Ruby
- C#
- C++

### Security Patterns Detected

- **Hardcoded Credentials** (passwords, API keys, tokens)
- **SQL Injection** (string concatenation in queries)
- **Command Injection** (shell=True, eval, exec)
- **Weak Cryptography** (MD5, SHA1)
- **Path Traversal** (unsafe file operations)
- **XSS Vulnerabilities** (innerHTML usage)
- **Deserialization** (pickle.loads)

### API Endpoint

The MCP server connects to: `https://compliance-sentinel.vercel.app/analyze`

### Troubleshooting

**Connection Issues:**
```bash
# Test the API directly
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"test123\"", "language": "python"}'
```

**MCP Server Issues:**
```bash
# Test the MCP server locally
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 vercel_mcp_server.py
```

### For Teams

**Shared Configuration:**
All team members can use the same MCP configuration - no local setup required beyond the Python file.

**CI/CD Integration:**
```bash
# Use the same API in your CI/CD pipeline
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d @code_to_analyze.json
```

**Custom Deployment:**
Teams can deploy their own instance to Vercel:
```bash
vercel --prod
```

### Benefits

✅ **No Local Dependencies** - Uses cloud API  
✅ **Always Updated** - Latest security patterns  
✅ **Team Consistency** - Same analysis for everyone  
✅ **Scalable** - Handles large codebases  
✅ **Fast Setup** - 2-minute configuration  

### Support

- **Issues:** [GitHub Issues](https://github.com/kalisnetwork/compliance-sentinel/issues)
- **API Status:** [https://compliance-sentinel.vercel.app/health](https://compliance-sentinel.vercel.app/health)
- **Documentation:** [README.md](./README.md)