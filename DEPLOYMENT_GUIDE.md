# 🚀 Deployment Guide - Compliance Sentinel MCP Server

This guide shows you how to deploy the Compliance Sentinel MCP Server to various free hosting platforms for real-time usage.

## 🎯 Completely FREE Deploy Options

### 1. Render (Recommended) ⭐

**Why Render?**
- ✅ **COMPLETELY FREE** - 750 hours/month
- ✅ Automatic HTTPS
- ✅ Custom domains
- ✅ GitHub integration
- ✅ Easy deployment
- ⚠️ Sleeps after 15min idle (wakes in ~30 seconds)

**One-Click Deploy:**
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/kalisnetwork/compliance-sentinel)

**Manual Deploy Steps:**
1. Fork this repository to your GitHub
2. Go to [Render.com](https://render.com)
3. Sign up with GitHub (free)
4. Click "New" → "Web Service"
5. Connect your GitHub repository
6. Use these settings:
   - **Build Command:** `pip install -r requirements-minimal.txt`
   - **Start Command:** `python web_mcp_server.py`
   - **Plan:** FREE

**Live URL:** `https://your-app-name.onrender.com`

### 2. Fly.io 🪰

**Deploy Steps:**
1. Go to [Render.com](https://render.com)
2. Sign up with GitHub
3. Click "New" → "Web Service"
4. Connect your GitHub repository
5. Use these settings:
   - **Build Command:** `pip install -r requirements-minimal.txt`
   - **Start Command:** `python web_mcp_server.py`
   - **Plan:** Free

### 3. Fly.io 🪰

**Deploy Steps:**
```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login and deploy
flyctl auth login
flyctl launch --no-deploy
flyctl deploy
```

### 4. GitHub Codespaces (Instant & Free) 🚀

**Why Codespaces?**
- ✅ **60 hours/month FREE**
- ✅ No deployment needed
- ✅ Runs in your browser
- ✅ Instant setup

**One-Click Start:**
1. Go to your forked repository on GitHub
2. Click the green "Code" button
3. Click "Codespaces" tab
4. Click "Create codespace on main"
5. Wait for setup (2-3 minutes)
6. Run: `python web_mcp_server.py`
7. Your server is live at the forwarded port!

### 5. Heroku 🟣

**Deploy Steps:**
```bash
# Install Heroku CLI, then:
heroku create your-app-name
git push heroku main
```

## 🧪 Testing Your Deployed Server

Once deployed, test your server:

### 1. Health Check
```bash
curl https://your-app-url.com/health
```

### 2. Analyze Code
```bash
curl -X POST https://your-app-url.com/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"hardcoded_secret_123\"\nquery = \"SELECT * FROM users WHERE id = \" + user_id",
    "language": "python"
  }'
```

### 3. Validate Compliance
```bash
curl -X POST https://your-app-url.com/validate \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"hardcoded_secret_123\"",
    "framework": "owasp-top-10"
  }'
```

## 🔧 Configure in Your IDE

### For Kiro IDE

1. Create `.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "https://your-app-url.com/analyze",
        "-H", "Content-Type: application/json",
        "-d", "@-"
      ],
      "disabled": false,
      "autoApprove": ["analyze_code", "validate_compliance"]
    }
  }
}
```

### For Other IDEs

Use the REST API endpoints directly:
- **Analyze Code:** `POST /analyze`
- **Validate Compliance:** `POST /validate`
- **List Tools:** `GET /tools`
- **Health Check:** `GET /health`

## 📊 Usage Examples

### Web Interface

Visit `https://your-app-url.com/demo` for interactive examples and API documentation.

### API Examples

**Analyze Python Code:**
```json
POST /analyze
{
  "code": "import os\npassword = 'secret123'\nquery = f'SELECT * FROM users WHERE id = {user_id}'",
  "language": "python"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "issues": [
      {
        "type": "hardcoded_credentials",
        "severity": "HIGH",
        "description": "Potential hardcoded password detected",
        "remediation": "Use environment variables for sensitive data"
      },
      {
        "type": "sql_injection", 
        "severity": "HIGH",
        "description": "Potential SQL injection vulnerability",
        "remediation": "Use parameterized queries"
      }
    ],
    "total_issues": 2
  }
}
```

## 🔒 Security Considerations

### For Production Use:
1. **Add Authentication:** Implement API keys or OAuth
2. **Rate Limiting:** Prevent abuse
3. **Input Validation:** Sanitize all inputs
4. **Logging:** Monitor usage and errors
5. **HTTPS Only:** Ensure secure communication

### Environment Variables:
```bash
# Optional configuration
LOG_LEVEL=INFO
MAX_CODE_SIZE=10000
RATE_LIMIT_PER_MINUTE=60
```

## 💰 Cost Breakdown (100% FREE Options)

| Platform | Free Tier | Limits | Best For |
|----------|-----------|--------|----------|
| **Render** | 750 hours/month | Sleeps after 15min idle | **Recommended - Best free option** |
| **Fly.io** | 3 shared VMs | 160GB/month transfer | No sleep, global deployment |
| **GitHub Codespaces** | 60 hours/month | Runs in browser | Instant testing & development |
| **Heroku** | 550-1000 hours/month | Sleeps after 30min idle | Classic & reliable |

## 🚀 Recommended Setup

**For Testing & Development:**
1. Deploy to Railway (easiest setup)
2. Use the web interface for testing
3. Configure your IDE to use the hosted API

**For Production:**
1. Use Railway or Fly.io for better uptime
2. Add authentication and rate limiting
3. Monitor usage and performance
4. Consider upgrading to paid plans for 24/7 uptime

## 🆘 Troubleshooting

### Common Issues:

**1. Server won't start:**
- Check logs in your hosting platform dashboard
- Ensure `requirements-minimal.txt` is being used
- Verify Python version (3.11+)

**2. API returns errors:**
- Check request format (JSON)
- Verify Content-Type header
- Check server logs for details

**3. Slow responses:**
- Free tiers have limited resources
- Consider caching for repeated requests
- Optimize code analysis patterns

### Getting Help:
- Check server logs in your hosting platform
- Test locally first: `python web_mcp_server.py`
- Open an issue on GitHub if problems persist

## 🎉 Next Steps

Once deployed:
1. ✅ Test all endpoints
2. ✅ Configure your IDE
3. ✅ Try analyzing real code
4. ✅ Share your deployment URL
5. ✅ Consider contributing improvements!

**Your MCP server is now live and ready for real-time security analysis!** 🔒✨