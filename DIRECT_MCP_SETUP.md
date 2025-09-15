# 🚀 Direct MCP Server - Zero Setup Required!

## 🎯 **Just Add This URL - No Downloads Needed!**

Your Compliance Sentinel now works like **Zapier MCP** - just add the URL and you're ready!

### **Direct MCP URL:**
```
https://compliance-sentinel.vercel.app/api/mcp
```

---

## 🔧 **Editor Configurations**

### **Cursor AI** (Recommended)
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

### **Kiro IDE**
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

### **Any MCP-Compatible Client**
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

---

## ✅ **Setup Steps (30 seconds)**

### **For Cursor AI:**
1. Open Cursor settings
2. Find MCP configuration
3. Add the JSON above
4. Restart Cursor
5. **Done!** ✨

### **For Kiro IDE:**
1. Edit `.kiro/settings/mcp.json`
2. Add the configuration above
3. Restart Kiro or reconnect MCP
4. **Done!** ✨

### **For Other Editors:**
1. Find MCP settings in your editor
2. Add the URL configuration
3. Restart the editor
4. **Done!** ✨

---

## 🧪 **Test It Works**

**In your editor's chat:**
```
Analyze this code for security issues:

password = "hardcoded123"
query = "SELECT * FROM users WHERE id = " + user_id
```

**Expected Response:**
```
🔒 Security Analysis Results (Direct MCP)

Language: python
Lines Analyzed: 2
Total Issues: 2

🚨 HIGH Severity: 2 issues

1. Hardcoded Credentials (Line 1)
   - Severity: HIGH
   - Description: Hardcoded credentials detected
   - Code: password = "hardcoded123"
   - Fix: Use environment variables or secure vaults

2. SQL Injection Vulnerability (Line 2)
   - Severity: HIGH
   - Description: Potential SQL injection vulnerability
   - Code: query = "SELECT * FROM users WHERE id = " + user_id
   - Fix: Use parameterized queries or prepared statements
```

---

## 🌐 **Supported Languages**

✅ **Python** - Hardcoded secrets, SQL injection, command injection  
✅ **JavaScript/TypeScript** - XSS, eval usage, hardcoded credentials  
✅ **Java** - SQL injection, hardcoded secrets, unsafe operations  
✅ **Go** - SQL injection, hardcoded credentials, command injection  
✅ **PHP** - SQL injection, hardcoded secrets, eval usage  
✅ **Ruby** - Command injection, hardcoded credentials, eval usage  
✅ **C#** - SQL injection, hardcoded secrets, unsafe operations  
✅ **C++** - Hardcoded credentials, SQL injection, unsafe functions  

---

## 🔍 **What It Detects**

### **Security Vulnerabilities:**
- **Hardcoded Credentials** (passwords, API keys, tokens)
- **SQL Injection** (string concatenation in queries)
- **Command Injection** (shell=True, eval, exec)
- **XSS Vulnerabilities** (innerHTML usage)
- **Weak Cryptography** (MD5, SHA1)
- **Path Traversal** (unsafe file operations)
- **Deserialization** (pickle.loads)

### **Compliance Frameworks:**
- **OWASP Top 10** security risks
- **CWE Top 25** most dangerous errors
- **NIST Cybersecurity Framework**

---

## 🚀 **Benefits**

### **Zero Setup:**
- ✅ **No downloads** required
- ✅ **No local files** to manage
- ✅ **No dependencies** to install
- ✅ **No configuration** files

### **Always Updated:**
- ✅ **Latest security patterns** automatically
- ✅ **New vulnerability detection** added regularly
- ✅ **Performance improvements** deployed instantly
- ✅ **Bug fixes** applied immediately

### **Team Ready:**
- ✅ **Same analysis** for all developers
- ✅ **Consistent results** across projects
- ✅ **Easy sharing** - just share the URL
- ✅ **No version conflicts** between team members

---

## 🔧 **Advanced Usage**

### **API Status Check:**
```bash
curl https://compliance-sentinel.vercel.app/api/mcp
```

### **Direct API Usage:**
```bash
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"test123\"", "language": "python"}'
```

### **Health Check:**
```bash
curl https://compliance-sentinel.vercel.app/health
```

---

## 🎯 **Comparison**

| Feature | Direct MCP URL | Local Files | 
|---------|----------------|-------------|
| **Setup Time** | 30 seconds | 5+ minutes |
| **Downloads** | None | Git clone + dependencies |
| **Updates** | Automatic | Manual git pull |
| **Team Sharing** | Share URL | Share entire repo |
| **Maintenance** | Zero | Regular updates needed |
| **Consistency** | Always same | Version conflicts |

---

## 🆚 **Like Other MCP Services**

**Zapier MCP:**
```json
{"url": "https://actions.zapier.com/mcp/sk-xxx/sse"}
```

**Compliance Sentinel MCP:**
```json
{"url": "https://compliance-sentinel.vercel.app/api/mcp"}
```

**Same simplicity, better security analysis!** 🔒✨

---

## 📞 **Support**

- **API Status:** [https://compliance-sentinel.vercel.app/health](https://compliance-sentinel.vercel.app/health)
- **Issues:** [GitHub Issues](https://github.com/kalisnetwork/compliance-sentinel/issues)
- **Documentation:** [README.md](./README.md)

---

**Ready to secure your code in 30 seconds?** Just add the URL! 🚀