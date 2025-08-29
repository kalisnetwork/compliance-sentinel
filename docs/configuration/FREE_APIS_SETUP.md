# Free APIs Setup Guide

This guide shows you how to set up Compliance Sentinel using **100% FREE APIs** with no cost to you.

## 🆓 **FREE API Sources Used**

### **1. National Vulnerability Database (NVD) - FREE**
- **Provider**: NIST (US Government)
- **Cost**: Completely free
- **Rate Limits**: 5 requests/10 seconds (no key), 50 requests/10 seconds (with free key)
- **Data**: Official CVE database with CVSS scores

```bash
# Optional: Get free API key for higher rate limits
# 1. Visit: https://nvd.nist.gov/developers/request-an-api-key
# 2. Fill out simple form (no payment info required)
# 3. Receive API key via email

export NVD_API_KEY=your_free_nvd_key  # Optional but recommended
```

### **2. CVE CIRCL - FREE**
- **Provider**: CIRCL (Computer Incident Response Center Luxembourg)
- **Cost**: Completely free
- **Rate Limits**: Generous (no strict limits)
- **Data**: CVE details with additional metadata

```bash
# No API key required
export CVE_CIRCL_BASE_URL=https://cve.circl.lu/api
```

### **3. OSV (Open Source Vulnerabilities) - FREE**
- **Provider**: Google
- **Cost**: Completely free
- **Rate Limits**: Very generous
- **Data**: Open source package vulnerabilities

```bash
# No API key required
export OSV_BASE_URL=https://api.osv.dev/v1
```

### **4. GitHub Security Advisories - FREE**
- **Provider**: GitHub
- **Cost**: Free tier (5000 requests/hour)
- **Rate Limits**: 5000/hour (more than enough)
- **Data**: Security advisories for GitHub repositories

```bash
# Get free personal access token:
# 1. Go to: https://github.com/settings/tokens
# 2. Click "Generate new token (classic)"
# 3. Select scope: "public_repo"
# 4. Copy token

export GITHUB_TOKEN=your_github_personal_access_token
```

## 🚀 **Quick Setup (5 minutes)**

### **Step 1: Get GitHub Token**
```bash
# 1. Visit: https://github.com/settings/tokens
# 2. Click "Generate new token (classic)"
# 3. Name: "Compliance Sentinel"
# 4. Expiration: 90 days (or longer)
# 5. Scopes: Check "public_repo"
# 6. Click "Generate token"
# 7. Copy the token (starts with ghp_)

export GITHUB_TOKEN=ghp_your_token_here
```

### **Step 2: Ready to Use!**
```bash
# No additional setup needed - all APIs work without keys!
# The system uses completely free APIs with generous rate limits
```

### **Step 3: Set Environment Variables**
```bash
# Create .env file
cat > .env << EOF
# Free API Configuration
GITHUB_TOKEN=ghp_your_github_token

# API Base URLs (all free)
NVD_BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
CVE_CIRCL_BASE_URL=https://cve.circl.lu/api
OSV_BASE_URL=https://api.osv.dev/v1
GITHUB_ADVISORY_URL=https://api.github.com/advisories

# Rate Limiting (conservative for free tiers)
NVD_RATE_LIMIT=10  # 10 requests/10 seconds (safe for free tier)
CVE_RATE_LIMIT=20  # 20 requests/minute
OSV_RATE_LIMIT=50  # 50 requests/minute
GITHUB_RATE_LIMIT=100  # 100 requests/hour (well under 5000 limit)

# Environment
COMPLIANCE_SENTINEL_ENVIRONMENT=development
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
EOF
```

## 🧪 **Test Your Setup**

### **Test 1: NVD API**
```bash
# Test without API key
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"

# Test with API key (if you have one)
curl -H "apiKey: your_nvd_key" \
     "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
```

### **Test 2: CVE CIRCL**
```bash
curl "https://cve.circl.lu/api/cve/CVE-2023-1234"
```

### **Test 3: OSV API**
```bash
curl -X POST "https://api.osv.dev/v1/query" \
     -H "Content-Type: application/json" \
     -d '{"package": {"name": "requests", "ecosystem": "PyPI"}}'
```

### **Test 4: GitHub API**
```bash
curl -H "Authorization: token your_github_token" \
     "https://api.github.com/advisories?per_page=1"
```

## 📊 **Rate Limits & Usage**

| API | Free Limit | Our Usage | Safety Margin |
|-----|------------|-----------|---------------|
| **NVD** | 5-50 req/10s | 10 req/10s | ✅ Safe |
| **CVE CIRCL** | No strict limit | 20 req/min | ✅ Safe |
| **OSV** | Very generous | 50 req/min | ✅ Safe |
| **GitHub** | 5000 req/hour | 100 req/hour | ✅ Very Safe |

## 🔧 **Configuration Examples**

### **Development Environment**
```bash
# .env.development
GITHUB_TOKEN=ghp_your_dev_token
NVD_API_KEY=your_nvd_key

# Conservative rate limits for development
NVD_RATE_LIMIT=5
CVE_RATE_LIMIT=10
OSV_RATE_LIMIT=20
GITHUB_RATE_LIMIT=50

# Enable debug logging
COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
COMPLIANCE_SENTINEL_DEBUG_ENABLED=true
```

### **Production Environment**
```bash
# .env.production
GITHUB_TOKEN=${GITHUB_TOKEN}  # From environment/secrets
NVD_API_KEY=${NVD_API_KEY}    # From environment/secrets

# Optimized rate limits for production
NVD_RATE_LIMIT=45  # Just under the 50/10s limit
CVE_RATE_LIMIT=30
OSV_RATE_LIMIT=100
GITHUB_RATE_LIMIT=200  # Still well under 5000/hour

# Production logging
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
```

## 🛡️ **Security Best Practices**

### **1. Protect Your Tokens**
```bash
# ❌ NEVER commit tokens to git
echo ".env*" >> .gitignore
echo "*.key" >> .gitignore

# ✅ Use environment variables in production
export GITHUB_TOKEN=$(cat /path/to/secure/github_token)
export NVD_API_KEY=$(cat /path/to/secure/nvd_key)
```

### **2. Token Rotation**
```bash
# Rotate GitHub tokens every 90 days
# Set calendar reminder to regenerate tokens
# Use different tokens for dev/staging/prod
```

### **3. Minimal Permissions**
```bash
# GitHub token scopes (minimal required):
# ✅ public_repo (for security advisories)
# ❌ Don't select: repo, admin, delete, etc.
```

## 🚨 **Troubleshooting**

### **Rate Limit Exceeded**
```bash
# If you hit rate limits, the system will:
# 1. Automatically back off and retry
# 2. Use cached data when available
# 3. Fall back to other APIs
# 4. Log warnings but continue operating

# Check rate limit status:
curl -I "https://api.github.com/rate_limit" \
     -H "Authorization: token your_token"
```

### **API Key Issues**
```bash
# Test your GitHub token:
curl -H "Authorization: token your_token" \
     "https://api.github.com/user"

# Should return your GitHub user info
```

### **Network Issues**
```bash
# Test connectivity to all APIs:
python -c "
import requests
apis = [
    'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1',
    'https://cve.circl.lu/api/cve/CVE-2023-1234',
    'https://api.osv.dev/v1/vulns/GHSA-h75v-3vvj-5mfj',
    'https://api.github.com/advisories?per_page=1'
]
for api in apis:
    try:
        r = requests.get(api, timeout=10)
        print(f'✅ {api}: {r.status_code}')
    except Exception as e:
        print(f'❌ {api}: {e}')
"
```

## 💡 **Pro Tips**

### **1. Maximize Free Tier Usage**
```bash
# Use intelligent caching to minimize API calls
COMPLIANCE_SENTINEL_CACHE_ENABLED=true
COMPLIANCE_SENTINEL_CACHE_TTL=3600  # 1 hour cache

# Enable circuit breakers to avoid wasting calls on failing APIs
COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_ENABLED=true
```

### **2. Monitor Your Usage**
```bash
# Enable metrics to track API usage
COMPLIANCE_SENTINEL_METRICS_ENABLED=true

# Check metrics at: http://localhost:9090/metrics
# Look for: external_service_requests_total
```

### **3. Fallback Strategy**
```bash
# The system automatically falls back between APIs:
# 1. Try NVD first (most authoritative)
# 2. Fall back to CVE CIRCL
# 3. Fall back to OSV
# 4. Fall back to GitHub Advisories
# 5. Use cached data if all fail
```

## 🎯 **Expected Performance**

With free APIs, you can expect:
- **~1000 vulnerability lookups/hour** (mixed across all APIs)
- **~100 compliance checks/hour**
- **Sub-second response times** (with caching)
- **99%+ uptime** (with fallbacks)

This is more than sufficient for most security scanning needs!

## 📞 **Support**

If you have issues with any free API:
- **NVD**: Contact NIST support (very responsive)
- **CVE CIRCL**: Check their status page
- **OSV**: File GitHub issue on google/osv.dev
- **GitHub**: Check GitHub status page

All these services have excellent uptime and support for free users.