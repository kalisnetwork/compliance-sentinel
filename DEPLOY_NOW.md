# 🚀 Deploy Your MCP Server NOW (100% FREE)

## ⚡ Fastest Options (Click & Deploy)

### Option 1: Heroku (Since you have it!) ⭐
1. **Fork this repo** to your GitHub
2. **Click this button:** [![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/kalisnetwork/compliance-sentinel)
3. **Wait 2-3 minutes** for deployment
4. **Your MCP server is LIVE!** 🎉

### Option 2: Render (Alternative)
1. **Fork this repo** to your GitHub
2. **Click this button:** [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/kalisnetwork/compliance-sentinel)
3. **Wait 2-3 minutes** for deployment
4. **Your MCP server is LIVE!** 🎉

### Option 2: GitHub Codespaces (Instant)
1. **Go to your forked repo** on GitHub
2. **Click "Code" → "Codespaces" → "Create codespace"**
3. **Wait for setup** (2-3 minutes)
4. **Run:** `python web_mcp_server.py`
5. **Click the forwarded port** - Your server is live!

## 🧪 Test Your Deployment

Once deployed, test it:

```bash
# Replace YOUR_URL with your actual deployment URL
curl https://YOUR_URL.onrender.com/health

# Test security analysis
curl -X POST https://YOUR_URL.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"secret123\"", "language": "python"}'
```

## 🔧 Use in Your IDE

Add to `.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "curl",
      "args": ["-X", "POST", "https://YOUR_URL.onrender.com/analyze", "-H", "Content-Type: application/json", "-d", "@-"],
      "disabled": false
    }
  }
}
```

## 🎯 What You Get

- ✅ **Real-time security analysis**
- ✅ **Compliance validation** (OWASP, CWE, NIST)
- ✅ **Multi-language support**
- ✅ **REST API endpoints**
- ✅ **24/7 availability** (with free tier limits)

**Your MCP server will be live in under 5 minutes!** 🚀