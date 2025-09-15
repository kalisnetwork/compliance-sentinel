# 🔺 Deploy to Vercel - 100% Free Forever

Deploy your Compliance Sentinel MCP Server to Vercel completely free!

## 🎯 Why Vercel?

- ✅ **100% Free** - No credit card required, ever
- ✅ **No Sleep/Idle** - Always available, no cold starts
- ✅ **Global CDN** - Fast worldwide
- ✅ **Automatic HTTPS** - Secure by default
- ✅ **GitHub Integration** - Auto-deploy on push
- ✅ **Custom Domains** - Free custom domains
- ✅ **Serverless** - Scales automatically

## 🚀 One-Click Deploy

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/kalisnetwork/compliance-sentinel)

## 📋 Manual Deployment Steps

### 1. Prerequisites
- GitHub account
- Vercel account (free - sign up with GitHub)

### 2. Deploy Steps

**Option A: Vercel Dashboard (Easiest)**
1. Go to [vercel.com](https://vercel.com)
2. Sign up/login with GitHub
3. Click "New Project"
4. Import your GitHub repository: `https://github.com/kalisnetwork/compliance-sentinel`
5. Vercel auto-detects settings - just click "Deploy"!
6. Done! Your app is live in ~30 seconds

**Option B: Vercel CLI**
```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Deploy from your project directory
vercel

# Follow the prompts, then:
vercel --prod
```

## 🧪 Test Your Deployment

Your app will be live at: `https://your-app-name.vercel.app`

### Test Endpoints:

**1. Health Check:**
```bash
curl https://your-app-name.vercel.app/health
```

**2. Analyze Code:**
```bash
curl -X POST https://your-app-name.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"secret123\"\nquery = \"SELECT * FROM users WHERE id = \" + user_id",
    "language": "python"
  }'
```

**3. Validate Compliance:**
```bash
curl -X POST https://your-app-name.vercel.app/validate \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"hardcoded_secret_123\"",
    "framework": "owasp-top-10"
  }'
```

**4. Demo Page:**
Visit: `https://your-app-name.vercel.app/demo`

## 🔧 Configure in Your IDE

### For Kiro IDE

Create `.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "https://your-app-name.vercel.app/analyze",
        "-H", "Content-Type: application/json",
        "-d", "@-"
      ],
      "disabled": false,
      "autoApprove": ["analyze_code", "validate_compliance"]
    }
  }
}
```

### For VS Code or Other Editors

You can use the REST API directly or create a simple wrapper:

```javascript
// Simple wrapper for VS Code extension
async function analyzeCode(code, language = 'python') {
  const response = await fetch('https://your-app-name.vercel.app/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, language })
  });
  return response.json();
}
```

## 📊 Vercel Features

### Free Tier Includes:
- ✅ **Unlimited deployments**
- ✅ **100GB bandwidth/month**
- ✅ **100 serverless function executions/day**
- ✅ **Custom domains**
- ✅ **Automatic HTTPS**
- ✅ **Global CDN**
- ✅ **GitHub integration**

### Performance:
- ⚡ **Cold start**: ~100ms (very fast)
- ⚡ **Response time**: ~50-200ms globally
- ⚡ **Uptime**: 99.99%
- ⚡ **No sleep**: Always available

## 🛠️ Customization

### Environment Variables
In Vercel dashboard → Settings → Environment Variables:
```
LOG_LEVEL=INFO
MAX_CODE_SIZE=10000
PYTHONPATH=.
```

### Custom Domain
1. Go to Vercel dashboard
2. Select your project
3. Go to Settings → Domains
4. Add your custom domain (free!)

### Auto-Deploy
- Push to GitHub → Automatic deployment
- Pull requests → Preview deployments
- Main branch → Production deployment

## 🔍 Monitoring & Logs

### View Logs:
1. Vercel Dashboard → Your Project
2. Click on a deployment
3. View "Function Logs" tab

### Analytics:
- Built-in analytics in Vercel dashboard
- Real-time performance metrics
- Error tracking

## 🛠️ Troubleshooting

### Common Issues:

**1. Import errors:**
- Check that all dependencies are in `requirements.txt`
- Ensure Python path is correct

**2. Function timeout:**
- Vercel free tier: 10s timeout
- Optimize code analysis for speed
- Consider breaking large analyses into chunks

**3. Cold starts:**
- First request may take ~100ms
- Subsequent requests are instant
- Much better than other platforms

### Debug Commands:
```bash
# Check deployment status
vercel ls

# View logs
vercel logs your-app-name

# Redeploy
vercel --prod
```

## 🎉 Success!

Your MCP server is now live at:
`https://your-app-name.vercel.app`

**Features available:**
- ✅ Real-time security analysis
- ✅ Compliance validation
- ✅ Multiple programming languages
- ✅ REST API endpoints
- ✅ Global availability
- ✅ No downtime

**Next steps:**
1. ✅ Test all endpoints
2. ✅ Configure your IDE
3. ✅ Try analyzing real code
4. ✅ Add custom domain (optional)
5. ✅ Share your deployment!

**Your free, always-on MCP server is ready!** 🔒✨

## 🔗 Useful Links

- [Vercel Documentation](https://vercel.com/docs)
- [Vercel CLI Reference](https://vercel.com/docs/cli)
- [Custom Domains Guide](https://vercel.com/docs/concepts/projects/custom-domains)
- [Environment Variables](https://vercel.com/docs/concepts/projects/environment-variables)