# 👥 Team Sharing Guide - Compliance Sentinel MCP

## 🎯 Share Security Analysis with Your Team

Your Compliance Sentinel MCP server is now **team-ready** using the Vercel API! Here's how to share it with other developers.

## 📤 For Team Leaders

### Share This Repository
```bash
# Team members just need to clone and configure
git clone https://github.com/kalisnetwork/compliance-sentinel.git
```

### Share the Configuration
Send this MCP configuration to your team:

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

### Share the Setup Steps
1. Clone the repo
2. `pip install requests`
3. Add MCP config to `.kiro/settings/mcp.json`
4. Restart Kiro

**That's it!** ✅

## 📥 For Team Members

### Quick Setup (2 minutes)

1. **Get the code:**
```bash
git clone https://github.com/kalisnetwork/compliance-sentinel.git
cd compliance-sentinel
```

2. **Install dependency:**
```bash
pip install requests
```

3. **Configure Kiro:**
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

### Usage in Kiro

**Test it works:**
```
Analyze this code:
password = "test123"
```

**Expected response:**
```
🔒 Security Analysis Results (via Vercel)
🚨 HIGH Severity: 1 issues
1. Hardcoded Credentials (Line 1)
   - Fix: Use environment variables
```

## 🌐 API Details

### Endpoint
- **URL:** `https://compliance-sentinel.vercel.app/analyze`
- **Status:** Always available (Vercel serverless)
- **Rate Limits:** None currently
- **Uptime:** 99.9%+ (Vercel SLA)

### Supported Languages
- Python, JavaScript, TypeScript
- Java, Go, PHP, Ruby, C#, C++

### Security Patterns
- Hardcoded credentials
- SQL injection
- Command injection  
- Weak cryptography
- XSS vulnerabilities
- And more...

## 🔧 Advanced Team Setup

### Organization-Wide Deployment

**Option 1: Use Our Vercel Instance**
- ✅ Zero maintenance
- ✅ Always updated
- ✅ Free for teams

**Option 2: Deploy Your Own**
```bash
# Deploy to your Vercel account
vercel --prod

# Update MCP config to use your URL
# Replace https://compliance-sentinel.vercel.app/ with your URL
```

### CI/CD Integration
```yaml
# .github/workflows/security.yml
- name: Security Analysis
  run: |
    curl -X POST https://compliance-sentinel.vercel.app/analyze \
      -H "Content-Type: application/json" \
      -d @security-check.json
```

### Custom Security Policies
Teams can extend the analysis by:
1. Forking the repository
2. Adding custom patterns in `compliance_sentinel/analyzers/`
3. Deploying to their own Vercel instance

## 🎉 Benefits for Teams

### Consistency
- ✅ **Same analysis** for all developers
- ✅ **Same security standards** across projects
- ✅ **Same remediation advice** for issues

### Productivity  
- ✅ **No setup time** for new team members
- ✅ **No maintenance** required
- ✅ **Always available** cloud service

### Security
- ✅ **Latest patterns** automatically
- ✅ **Compliance ready** (OWASP, CWE, NIST)
- ✅ **Real-time feedback** during development

## 📞 Support

**For Teams:**
- 📧 Create GitHub issues for feature requests
- 🔍 Check API status: `https://compliance-sentinel.vercel.app/health`
- 📖 Full docs: [MCP_VERCEL_SETUP.md](./MCP_VERCEL_SETUP.md)

**For Organizations:**
- 🏢 Custom deployment support available
- 🔒 Private instance setup
- 📊 Usage analytics and reporting

---

**Ready to secure your team's code?** Share this guide and get everyone protected! 🔒✨