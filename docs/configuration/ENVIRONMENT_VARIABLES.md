# Environment Variables Reference

This document provides a comprehensive reference for all environment variables used by Compliance Sentinel.

## Quick Start

Copy the appropriate template file for your environment:

```bash
# Development
cp docs/configuration/development.env.template .env.development

# Staging  
cp docs/configuration/staging.env.template .env.staging

# Production
cp docs/configuration/production.env.template .env.production
```

Then customize the values for your specific deployment. See the [Migration Guide](./MIGRATION_GUIDE.md) for detailed migration instructions.

## Table of Contents

- [Environment Settings](#environment-settings)
- [Logging Configuration](#logging-configuration)
- [System Configuration](#system-configuration)
- [MCP Server Configuration](#mcp-server-configuration)
- [External API Configuration](#external-api-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Rate Limiting Configuration](#rate-limiting-configuration)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [CLI Configuration](#cli-configuration)
- [Analysis Configuration](#analysis-configuration)
- [Hook Configuration](#hook-configuration)
- [Security Configuration](#security-configuration)

## Environment Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_ENVIRONMENT` | `development` | Deployment environment (development, staging, production) |
| `COMPLIANCE_SENTINEL_SERVICE_NAME` | `compliance-sentinel` | Service name for logging and metrics |
| `COMPLIANCE_SENTINEL_VERSION` | `unknown` | Application version |

## Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_LOG_LEVEL` | `INFO` | Application log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `COMPLIANCE_SENTINEL_ROOT_LOG_LEVEL` | `WARNING` | Root logger level |
| `COMPLIANCE_SENTINEL_LOG_FORMAT` | `structured` | Log format (simple, detailed, json, structured) |
| `COMPLIANCE_SENTINEL_CONSOLE_LOGGING` | `true` | Enable console logging |
| `COMPLIANCE_SENTINEL_FILE_LOGGING` | `false` | Enable file logging |
| `COMPLIANCE_SENTINEL_LOG_FILE` | - | Log file path (required if file logging enabled) |
| `COMPLIANCE_SENTINEL_JSON_LOGGING` | `false` | Enable JSON log format |
| `COMPLIANCE_SENTINEL_STRUCTURED_LOGGING` | `false` | Enable structured logging |
| `COMPLIANCE_SENTINEL_SECURITY_FILTER` | `true` | Enable security filter to redact sensitive data |
| `COMPLIANCE_SENTINEL_MAX_LOG_SIZE_MB` | `100` | Maximum log file size in MB |
| `COMPLIANCE_SENTINEL_LOG_BACKUP_COUNT` | `5` | Number of backup log files to keep |
| `COMPLIANCE_SENTINEL_SYSLOG_ENABLED` | `false` | Enable syslog integration |
| `COMPLIANCE_SENTINEL_SYSLOG_ADDRESS` | `localhost:514` | Syslog server address |

### Module-Specific Log Levels

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_MCP_LOG_LEVEL` | `INFO` | MCP server module log level |
| `COMPLIANCE_SENTINEL_ANALYZERS_LOG_LEVEL` | `INFO` | Analyzers module log level |
| `COMPLIANCE_SENTINEL_PROVIDERS_LOG_LEVEL` | `INFO` | Data providers module log level |
| `COMPLIANCE_SENTINEL_UTILS_LOG_LEVEL` | `WARNING` | Utilities module log level |
| `COMPLIANCE_SENTINEL_HTTPX_LOG_LEVEL` | `WARNING` | HTTP client log level |
| `COMPLIANCE_SENTINEL_URLLIB3_LOG_LEVEL` | `WARNING` | urllib3 log level |
| `COMPLIANCE_SENTINEL_ASYNCIO_LOG_LEVEL` | `WARNING` | asyncio log level |

## System Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_PYTHON_VERSION` | `3.11` | Required Python version |
| `COMPLIANCE_SENTINEL_ANALYSIS_TOOLS` | `["bandit", "semgrep"]` | JSON array of analysis tools |
| `COMPLIANCE_SENTINEL_MCP_SERVER_URL` | `http://localhost:8000` | MCP server URL |
| `COMPLIANCE_SENTINEL_CACHE_TTL` | `3600` | Default cache TTL in seconds |
| `COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES` | `5` | Maximum concurrent analysis processes |
| `COMPLIANCE_SENTINEL_SEVERITY_THRESHOLD` | `medium` | Minimum severity threshold |
| `COMPLIANCE_SENTINEL_ENABLE_EXTERNAL_INTELLIGENCE` | `true` | Enable external threat intelligence |
| `COMPLIANCE_SENTINEL_ANALYSIS_TIMEOUT` | `300` | Analysis timeout in seconds |
| `COMPLIANCE_SENTINEL_HOOKS_ENABLED` | `true` | Enable Kiro agent hooks |
| `COMPLIANCE_SENTINEL_IDE_FEEDBACK_ENABLED` | `true` | Enable IDE feedback |
| `COMPLIANCE_SENTINEL_SUMMARY_REPORTS_ENABLED` | `true` | Enable summary reports |
| `COMPLIANCE_SENTINEL_FILE_PATTERNS` | `["*.py", "*.js", "*.ts", "*.java"]` | JSON array of file patterns |
| `COMPLIANCE_SENTINEL_EXCLUDED_DIRECTORIES` | `["node_modules", ".git", "__pycache__"]` | JSON array of excluded directories |

## MCP Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_MCP_HOST` | `localhost` | MCP server bind host |
| `COMPLIANCE_SENTINEL_MCP_PORT` | `8000` | MCP server port |
| `COMPLIANCE_SENTINEL_MCP_WORKERS` | `4` | Number of worker processes |
| `COMPLIANCE_SENTINEL_MCP_ENABLE_CORS` | `true` | Enable CORS support |
| `COMPLIANCE_SENTINEL_MCP_API_KEY_REQUIRED` | `false` | Require API key for access |
| `COMPLIANCE_SENTINEL_MCP_RATE_LIMIT_REQUESTS` | `100` | Rate limit requests per window |
| `COMPLIANCE_SENTINEL_MCP_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `COMPLIANCE_SENTINEL_MCP_CACHE_ENABLED` | `true` | Enable response caching |
| `COMPLIANCE_SENTINEL_MCP_CACHE_SIZE` | `1000` | Maximum cached responses |

## External API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD API base URL |
| `MCP_CVE_BASE_URL` | `https://cve.circl.lu/api` | CVE CIRCL API base URL |
| `MCP_OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV API base URL |
| `MCP_NVD_DELAY_SECONDS` | `6.0` | Delay between NVD API requests |
| `MCP_CVE_DELAY_SECONDS` | `1.0` | Delay between CVE API requests |
| `MCP_REQUEST_TIMEOUT_SECONDS` | `30.0` | HTTP request timeout |
| `MCP_DEFAULT_SEARCH_LIMIT` | `10` | Default search result limit |
| `MCP_DEFAULT_LATEST_LIMIT` | `20` | Default latest vulnerabilities limit |
| `MCP_MAX_RETRY_ATTEMPTS` | `3` | Maximum retry attempts for failed requests |
| `MCP_RETRY_BASE_DELAY` | `2.0` | Base delay for retry backoff |
| `MCP_CACHE_TTL_SECONDS` | `1800` | Cache TTL for API responses |
| `MCP_COMPLIANCE_CACHE_TTL_SECONDS` | `3600` | Cache TTL for compliance data |
| `MCP_REQUIREMENTS_CACHE_TTL_SECONDS` | `86400` | Cache TTL for requirements data |

## Authentication Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_AUTH_JWT_SECRET` | *generated* | JWT signing secret (REQUIRED in production) |
| `COMPLIANCE_SENTINEL_AUTH_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `COMPLIANCE_SENTINEL_AUTH_JWT_EXPIRY_HOURS` | `24` | JWT token expiry in hours |
| `COMPLIANCE_SENTINEL_AUTH_API_KEY_LENGTH` | `32` | Generated API key length |
| `COMPLIANCE_SENTINEL_AUTH_DEFAULT_API_KEY_EXPIRY_DAYS` | `365` | Default API key expiry |
| `COMPLIANCE_SENTINEL_AUTH_ENABLE_DEFAULT_ADMIN_KEY` | `true` | Enable default admin key creation |
| `COMPLIANCE_SENTINEL_AUTH_PASSWORD_HASH_SCHEMES` | `["bcrypt"]` | JSON array of password hash schemes |
| `COMPLIANCE_SENTINEL_AUTH_ADMIN_API_KEY` | - | Pre-configured admin API key |

## Rate Limiting Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_RATE_LIMIT_TRUSTED_REQUESTS` | `1000` | Requests per window for trusted clients |
| `MCP_RATE_LIMIT_TRUSTED_WINDOW` | `3600` | Time window for trusted clients |
| `MCP_RATE_LIMIT_NORMAL_REQUESTS` | `100` | Requests per window for normal clients |
| `MCP_RATE_LIMIT_NORMAL_WINDOW` | `3600` | Time window for normal clients |
| `MCP_RATE_LIMIT_SUSPICIOUS_REQUESTS` | `10` | Requests per window for suspicious clients |
| `MCP_RATE_LIMIT_SUSPICIOUS_WINDOW` | `3600` | Time window for suspicious clients |
| `MCP_RATE_LIMIT_BLOCKED_REQUESTS` | `0` | Requests per window for blocked clients |
| `MCP_RATE_LIMIT_BLOCKED_WINDOW` | `3600` | Time window for blocked clients |
| `MCP_RATE_LIMITER_CLEANUP_INTERVAL` | `300` | Cleanup interval for rate limiter |

## Metrics and Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLED` | `true` | Enable metrics collection |
| `METRICS_COLLECTION_INTERVAL` | `60` | Metrics collection interval in seconds |
| `METRICS_MAX_HISTORY` | `1000` | Maximum metric history entries |
| `METRICS_RETENTION_HOURS` | `24` | Metric retention period in hours |
| `METRICS_EXPORT_ENABLED` | `false` | Enable metrics export |
| `METRICS_EXPORT_ENDPOINT` | - | Metrics export endpoint URL |
| `METRICS_EXPORT_FORMAT` | `prometheus` | Metrics export format |
| `METRICS_ALERTS_ENABLED` | `true` | Enable metric alerts |
| `METRICS_ALERT_WEBHOOK_URL` | - | Webhook URL for alerts |

## CLI Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_CLI_MAX_FILES` | `100` | Default maximum files to scan |
| `COMPLIANCE_SENTINEL_CLI_DEFAULT_PATTERN` | `**/*.py` | Default file pattern for scanning |
| `COMPLIANCE_SENTINEL_CLI_OUTPUT_FORMAT` | `text` | Default output format |
| `COMPLIANCE_SENTINEL_CLI_VERBOSE` | `false` | Enable verbose CLI output |
| `COMPLIANCE_SENTINEL_CLI_COLORS` | `true` | Enable colored CLI output |
| `COMPLIANCE_SENTINEL_CLI_PROGRESS` | `true` | Enable progress indicators |
| `COMPLIANCE_SENTINEL_CONFIG_DIR` | `.kiro/compliance-sentinel` | Configuration directory |

## Analysis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_ANALYSIS_OUTPUT_FORMAT` | `text` | Analysis output format |
| `COMPLIANCE_SENTINEL_ANALYSIS_SEVERITY_THRESHOLD` | `medium` | Analysis severity threshold |
| `COMPLIANCE_SENTINEL_ANALYSIS_FILE_EXTENSIONS` | `.py,.js,.ts,.java,.go` | Comma-separated file extensions |
| `COMPLIANCE_SENTINEL_ANALYSIS_RULES` | - | Comma-separated rule IDs to apply |
| `COMPLIANCE_SENTINEL_ANALYSIS_EXCLUDE_RULES` | - | Comma-separated rule IDs to exclude |
| `COMPLIANCE_SENTINEL_ANALYSIS_MAX_FILE_SIZE_MB` | `10` | Maximum file size to analyze |
| `COMPLIANCE_SENTINEL_ANALYSIS_TIMEOUT_SECONDS` | `300` | Analysis timeout per file |

## Hook Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_HOOK_FILE_PATTERNS` | `["*.py", "*.js", "*.ts"]` | JSON array of file patterns for hooks |
| `COMPLIANCE_SENTINEL_HOOK_EXCLUDED_DIRS` | `["node_modules", "__pycache__", ".git", ".venv", "venv"]` | JSON array of excluded directories |
| `COMPLIANCE_SENTINEL_HOOK_ANALYSIS_TIMEOUT` | `60` | Hook analysis timeout in seconds |
| `COMPLIANCE_SENTINEL_HOOK_ASYNC_PROCESSING` | `true` | Enable asynchronous hook processing |
| `COMPLIANCE_SENTINEL_HOOK_BATCH_SIZE` | `10` | Batch size for hook processing |
| `COMPLIANCE_SENTINEL_HOOK_DEBOUNCE_DELAY` | `0.5` | Debounce delay in seconds |

## Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_SENTINEL_DEBUG_ENABLED` | `false` | Enable debug features |
| `COMPLIANCE_SENTINEL_ALLOW_TEST_DATA` | `false` | Allow test data usage |
| `COMPLIANCE_SENTINEL_STRICT_VALIDATION` | `false` | Enable strict validation mode |

## Environment-Specific Recommendations

### Development Environment
```bash
COMPLIANCE_SENTINEL_ENVIRONMENT=development
COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
COMPLIANCE_SENTINEL_SEVERITY_THRESHOLD=low
COMPLIANCE_SENTINEL_ENABLE_EXTERNAL_INTELLIGENCE=true
COMPLIANCE_SENTINEL_HOOKS_ENABLED=true
COMPLIANCE_SENTINEL_DEBUG_ENABLED=true
COMPLIANCE_SENTINEL_ALLOW_TEST_DATA=true
```

### Staging Environment
```bash
COMPLIANCE_SENTINEL_ENVIRONMENT=staging
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
COMPLIANCE_SENTINEL_SEVERITY_THRESHOLD=medium
COMPLIANCE_SENTINEL_ENABLE_EXTERNAL_INTELLIGENCE=true
COMPLIANCE_SENTINEL_JSON_LOGGING=true
COMPLIANCE_SENTINEL_FILE_LOGGING=true
COMPLIANCE_SENTINEL_SECURITY_FILTER=true
```

### Production Environment
```bash
COMPLIANCE_SENTINEL_ENVIRONMENT=production
COMPLIANCE_SENTINEL_LOG_LEVEL=WARNING
COMPLIANCE_SENTINEL_SEVERITY_THRESHOLD=high
COMPLIANCE_SENTINEL_ENABLE_EXTERNAL_INTELLIGENCE=false
COMPLIANCE_SENTINEL_HOOKS_ENABLED=false
COMPLIANCE_SENTINEL_JSON_LOGGING=true
COMPLIANCE_SENTINEL_FILE_LOGGING=true
COMPLIANCE_SENTINEL_SECURITY_FILTER=true
COMPLIANCE_SENTINEL_STRICT_VALIDATION=true
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_ALLOW_TEST_DATA=false
```

## Security Best Practices

1. **Never commit secrets to version control**
   - Use environment variables or secret management systems
   - Use `.env` files locally (add to `.gitignore`)

2. **Use strong secrets in production**
   - Generate JWT secrets with: `openssl rand -base64 64`
   - Generate API keys with: `openssl rand -base64 48`

3. **Rotate secrets regularly**
   - Set appropriate expiry times for API keys
   - Implement secret rotation procedures

4. **Use appropriate log levels**
   - Development: DEBUG for detailed troubleshooting
   - Staging: INFO for operational visibility
   - Production: WARNING to reduce noise and improve performance

5. **Configure rate limiting appropriately**
   - Stricter limits in production
   - More permissive limits in development

6. **Enable security features in production**
   - Security filter for log redaction
   - Strict validation mode
   - Disable debug features and test data

## Configuration Validation

Use the CLI to validate your configuration:

```bash
# Validate current configuration
compliance-sentinel config validate

# Validate for specific environment
compliance-sentinel config validate --environment production

# Show current configuration
compliance-sentinel config show --format table

# Show configuration with sensitive values
compliance-sentinel config show --show-sensitive
```

## Troubleshooting

### Common Issues

1. **Invalid log level**: Ensure log levels are uppercase (DEBUG, INFO, WARNING, ERROR, CRITICAL)
2. **File permission errors**: Ensure log directories are writable
3. **Port conflicts**: Check that MCP server port is available
4. **Memory issues**: Adjust cache sizes and concurrent analysis limits
5. **Rate limiting**: Adjust rate limits based on your usage patterns

### Debug Configuration

Enable debug logging to troubleshoot configuration issues:

```bash
export COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
export COMPLIANCE_SENTINEL_CLI_VERBOSE=true
compliance-sentinel config validate
```

### Environment Variable Precedence

1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration files
4. Default values (lowest priority)

## Migration from Hardcoded Configuration

If migrating from hardcoded configuration:

1. **Identify hardcoded values** in your current setup
2. **Map to environment variables** using this reference
3. **Test in development** environment first
4. **Validate configuration** using CLI tools
5. **Deploy incrementally** through staging to production

Example migration:

```python
# Before (hardcoded)
cache_ttl = 3600
max_analyses = 5

# After (environment-driven)
cache_ttl = int(os.getenv("COMPLIANCE_SENTINEL_CACHE_TTL", "3600"))
max_analyses = int(os.getenv("COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES", "5"))
```