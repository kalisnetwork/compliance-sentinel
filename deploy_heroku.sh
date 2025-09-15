#!/bin/bash

# Deploy Compliance Sentinel MCP Server to Heroku
# Run this script to deploy your app to Heroku

echo "🚀 Deploying Compliance Sentinel MCP Server to Heroku"
echo "=================================================="

# Check if Heroku CLI is installed
if ! command -v heroku &> /dev/null; then
    echo "❌ Heroku CLI not found. Please install it first:"
    echo "   https://devcenter.heroku.com/articles/heroku-cli"
    exit 1
fi

# Check if user is logged in
if ! heroku auth:whoami &> /dev/null; then
    echo "🔐 Please login to Heroku first:"
    heroku login
fi

# Get app name from user
read -p "Enter your Heroku app name (e.g., my-compliance-sentinel): " APP_NAME

if [ -z "$APP_NAME" ]; then
    echo "❌ App name is required"
    exit 1
fi

echo "📝 Creating Heroku app: $APP_NAME"

# Create Heroku app
heroku create $APP_NAME

if [ $? -ne 0 ]; then
    echo "❌ Failed to create app. It might already exist."
    echo "🔄 Trying to use existing app..."
fi

# Set environment variables
echo "⚙️  Setting environment variables..."
heroku config:set PYTHONPATH=. --app $APP_NAME
heroku config:set LOG_LEVEL=INFO --app $APP_NAME
heroku config:set WEB_CONCURRENCY=1 --app $APP_NAME

# Add Heroku remote if it doesn't exist
if ! git remote get-url heroku &> /dev/null; then
    heroku git:remote -a $APP_NAME
fi

# Deploy to Heroku
echo "🚀 Deploying to Heroku..."
git add .
git commit -m "Deploy to Heroku" || echo "No changes to commit"
git push heroku main

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Deployment successful!"
    echo "📱 Your app is live at: https://$APP_NAME.herokuapp.com"
    echo ""
    echo "🧪 Test your deployment:"
    echo "   curl https://$APP_NAME.herokuapp.com/health"
    echo ""
    echo "📖 View logs:"
    echo "   heroku logs --tail --app $APP_NAME"
    echo ""
    echo "🌐 Open in browser:"
    heroku open --app $APP_NAME
else
    echo "❌ Deployment failed. Check the logs:"
    echo "   heroku logs --tail --app $APP_NAME"
fi