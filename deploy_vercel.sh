#!/bin/bash

# Deploy Compliance Sentinel MCP Server to Vercel
# Run this script to deploy your app to Vercel

echo "🔺 Deploying Compliance Sentinel MCP Server to Vercel"
echo "=================================================="

# Check if Vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "📦 Vercel CLI not found. Installing..."
    npm install -g vercel
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install Vercel CLI. Please install Node.js first:"
        echo "   https://nodejs.org/"
        exit 1
    fi
fi

# Check if user is logged in
if ! vercel whoami &> /dev/null; then
    echo "🔐 Please login to Vercel:"
    vercel login
fi

echo "🚀 Deploying to Vercel..."

# Deploy to Vercel
vercel --prod

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Deployment successful!"
    echo ""
    echo "🧪 Your app is live! Test it:"
    echo "   curl https://your-app.vercel.app/health"
    echo ""
    echo "📖 View deployment details:"
    echo "   vercel ls"
    echo ""
    echo "🔍 View logs:"
    echo "   vercel logs"
    echo ""
    echo "🌐 Open in browser:"
    echo "   vercel open"
else
    echo "❌ Deployment failed. Please check the logs:"
    echo "   vercel logs"
fi

echo ""
echo "💡 Pro tip: Your app auto-deploys when you push to GitHub!"
echo "   Just connect your repo in the Vercel dashboard."