# 🚀 Deploy to Heroku (100% FREE)

## Method 1: GitHub Integration (Easiest)

### Step 1: Prepare Your Repository
1. **Fork this repository** to your GitHub account
2. **Make sure all files are committed** (they should be already)

### Step 2: Deploy via Heroku Dashboard
1. Go to [Heroku.com](https://heroku.com) and sign in
2. Click **"New"** → **"Create new app"**
3. Choose an app name (e.g., `your-name-mcp-server`)
4. Select region (US or Europe)
5. Click **"Create app"**

### Step 3: Connect to GitHub
1. In the **Deploy** tab, select **"GitHub"** as deployment method
2. Connect your GitHub account if not already connected
3. Search for your forked repository name
4. Click **"Connect"**

### Step 4: Configure Build
1. Scroll down to **"Manual deploy"** section
2. Select **"main"** branch
3. Click **"Deploy Branch"**
4. Wait 2-3 minutes for deployment

### Step 5: Test Your Deployment
Your app will be live at: `https://your-app-name.herokuapp.com`

Test it:
```bash
# Health check
curl https://your-app-name.herokuapp.com/health

# Security analysis test
curl -X POST https://your-app-name.herokuapp.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"secret123\"", "language": "python"}'
```

## Method 2: Heroku CLI (If you have it)

```bash
# Login to Heroku
heroku login

# Create app
heroku create your-app-name

# Deploy
git push heroku main

# Open your app
heroku open
```

## 🔧 Configure in Your IDE

Once deployed, add to your `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "https://your-app-name.herokuapp.com/analyze",
        "-H", "Content-Type: application/json",
        "-d", "@-"
      ],
      "disabled": false,
      "autoApprove": ["analyze_code", "validate_compliance"]
    }
  }
}
```

## 📊 Heroku Free Tier Details

- ✅ **550-1000 hours/month FREE**
- ✅ Custom domains
- ✅ HTTPS included
- ⚠️ Sleeps after 30 minutes of inactivity
- ⚠️ Wakes up in ~30 seconds when accessed

## 🎯 Available Endpoints

Once deployed, your MCP server provides:

- `GET /` - Service information
- `GET /health` - Health check
- `GET /tools` - List available tools
- `POST /analyze` - Analyze code for security issues
- `POST /validate` - Validate compliance
- `GET /demo` - API examples and documentation

## 🚀 Next Steps

1. ✅ Deploy to Heroku
2. ✅ Test all endpoints
3. ✅ Configure your IDE
4. ✅ Start analyzing code in real-time!

**Your MCP server will be live and ready for real-time security analysis!** 🔒✨