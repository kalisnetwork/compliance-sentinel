# Migration Guide: From Hardcoded to Dynamic Configuration

This guide helps you migrate from hardcoded configuration values to the new dynamic configuration system in Compliance Sentinel.

## Overview

The dynamic configuration system allows you to:
- Configure all settings via environment variables
- Use different configurations for different environments
- Hot-reload configuration without restarts
- Integrate with secret management systems
- Validate configuration at runtime

## Migration Steps

### 1. Identify Current Hardcoded Values

First, identify all hardcoded values in your current deployment. Common locations include:

```python
# OLD: Hardcoded values
class SystemConfiguration:
    def __init__(self):
        self.cache_ttl = 3600  # Hardcoded
        self.max_concurrent_analyses = 5  # Hardcoded
        self.log_level = "INFO"  # Hardcoded

# NEW: Dynamic configuration
class SystemConfiguration:
    def __init__(self):
        config_manager = DynamicConfigManager()
        system_config = config_manager.get_system_config()
        self.cache_ttl = system_config.get("cache_ttl", 3600)
        self.max_concurrent_analyses = system_config.get("max_concurrent_analyses", 5)
        self.log_level = system_config.get("log_level", "INFO")
```

### 2. Set Up Environment Variables

Create environment-specific configuration files:

#### Development Environment
```bash
# .env.development
COMPLIANCE_SENTINEL_ENVIRONMENT=development
COMPLIANCE_SENTINEL_DEBUG_ENABLED=true
COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
COMPLIANCE_SENTINEL_CACHE_TTL=1800
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=10
```

#### Production Environment
```bash
# .env.production
COMPLIANCE_SENTINEL_ENVIRONMENT=production
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
COMPLIANCE_SENTINEL_CACHE_TTL=3600
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=3
```

### 3. Update Code to Use Dynamic Configuration

#### Before (Hardcoded)
```python
class VulnerabilityProvider:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json"  # Hardcoded
        self.timeout = 30  # Hardcoded
        self.rate_limit = 50  # Hardcoded
```

#### After (Dynamic)
```python
class VulnerabilityProvider:
    def __init__(self):
        config_manager = DynamicConfigManager()
        provider_config = config_manager.get_provider_config("nvd")
        self.base_url = provider_config.get("base_url", "https://services.nvd.nist.gov/rest/json")
        self.timeout = provider_config.get("timeout", 30)
        self.rate_limit = provider_config.get("rate_limit", 50)
```

### 4. Update MCP Server Configuration

#### Before (Hardcoded)
```python
class MCPServerConfig:
    def __init__(self):
        self.host = "localhost"  # Hardcoded
        self.port = 8000  # Hardcoded
        self.workers = 1  # Hardcoded
```

#### After (Dynamic)
```python
class MCPServerConfig:
    def __init__(self):
        config_manager = DynamicConfigManager()
        mcp_config = config_manager.get_mcp_config()
        self.host = mcp_config.get("host", "localhost")
        self.port = mcp_config.get("port", 8000)
        self.workers = mcp_config.get("workers", 1)
```

### 5. Update Authentication Configuration

#### Before (Hardcoded)
```python
class AuthConfig:
    def __init__(self):
        self.jwt_secret = "hardcoded-secret-key"  # SECURITY RISK!
        self.jwt_expiry = 24  # Hardcoded
        self.api_key_length = 32  # Hardcoded
```

#### After (Dynamic with Secrets)
```python
class AuthConfig:
    def __init__(self):
        config_manager = DynamicConfigManager()
        auth_config = config_manager.get_auth_config()
        # JWT secret from environment or secret manager
        self.jwt_secret = auth_config.get("jwt_secret")
        if not self.jwt_secret:
            raise ValueError("JWT secret must be configured")
        self.jwt_expiry = auth_config.get("jwt_expiry_hours", 24)
        self.api_key_length = auth_config.get("api_key_length", 32)
```

### 6. Update Cache Configuration

#### Before (Hardcoded)
```python
class CacheConfig:
    def __init__(self):
        self.ttl = 3600  # Hardcoded
        self.max_size = 1000  # Hardcoded
        self.backend = "memory"  # Hardcoded
```

#### After (Dynamic)
```python
class CacheConfig:
    def __init__(self):
        config_manager = DynamicConfigManager()
        cache_config = config_manager.get_cache_config()
        self.ttl = cache_config.get("ttl", 3600)
        self.max_size = cache_config.get("max_size", 1000)
        self.backend = cache_config.get("backend", "memory")
```

### 7. Remove Test Data from Production Code

#### Before (Test Data in Production)
```python
class SecurityIssue:
    @classmethod
    def create_test_issue(cls):
        return cls(
            id="TEST-001",
            severity=Severity.HIGH,
            description="Test vulnerability",  # Test data in production!
            file_path="/test/file.py"
        )
```

#### After (Environment-Aware Test Data)
```python
class SecurityIssue:
    @classmethod
    def create_test_issue(cls):
        # Only allow test data in non-production environments
        config_manager = DynamicConfigManager()
        if config_manager.get_environment() == "production":
            raise ValueError("Test data not allowed in production")
        
        return cls(
            id="TEST-001",
            severity=Severity.HIGH,
            description="Test vulnerability",
            file_path="/test/file.py"
        )
```

## Environment-Specific Migration

### Development Environment Migration

1. **Create development configuration:**
```bash
# .env.development
COMPLIANCE_SENTINEL_ENVIRONMENT=development
COMPLIANCE_SENTINEL_DEBUG_ENABLED=true
COMPLIANCE_SENTINEL_LOG_LEVEL=DEBUG
COMPLIANCE_SENTINEL_CACHE_TTL=1800
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=10
COMPLIANCE_SENTINEL_FILE_WATCHER_DEBOUNCE_MS=500
```

2. **Enable development features:**
```python
config_manager = DynamicConfigManager()
if config_manager.is_development():
    # Enable additional logging
    # Allow test data
    # Reduce rate limits for testing
```

### Staging Environment Migration

1. **Create staging configuration:**
```bash
# .env.staging
COMPLIANCE_SENTINEL_ENVIRONMENT=staging
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
COMPLIANCE_SENTINEL_CACHE_TTL=2400
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=5
```

2. **Configure staging-specific behavior:**
```python
config_manager = DynamicConfigManager()
if config_manager.is_staging():
    # Use staging API endpoints
    # Enable performance monitoring
    # Use staging database
```

### Production Environment Migration

1. **Create production configuration:**
```bash
# .env.production
COMPLIANCE_SENTINEL_ENVIRONMENT=production
COMPLIANCE_SENTINEL_DEBUG_ENABLED=false
COMPLIANCE_SENTINEL_LOG_LEVEL=WARNING
COMPLIANCE_SENTINEL_CACHE_TTL=3600
COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=3
```

2. **Ensure production security:**
```python
config_manager = DynamicConfigManager()
if config_manager.is_production():
    # Disable debug features
    # Use secure defaults
    # Enable audit logging
    # Validate all secrets are present
```

## Secret Management Migration

### From Hardcoded Secrets

#### Before (INSECURE)
```python
class Config:
    JWT_SECRET = "hardcoded-secret-123"  # NEVER DO THIS!
    DB_PASSWORD = "admin123"  # SECURITY RISK!
    API_KEY = "test-api-key"  # INSECURE!
```

#### After (Secure)
```python
class Config:
    def __init__(self):
        config_manager = DynamicConfigManager()
        
        # Load from environment variables
        self.jwt_secret = os.getenv("COMPLIANCE_SENTINEL_AUTH_JWT_SECRET")
        if not self.jwt_secret:
            raise ValueError("JWT secret must be configured")
        
        # Load from secret manager
        secret_config = config_manager.get_secret_config()
        self.db_password = secret_config.get("database_password")
        self.api_key = secret_config.get("external_api_key")
```

### Using AWS Secrets Manager

```python
# Configure secret manager
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=aws
export COMPLIANCE_SENTINEL_SECRET_MANAGER_REGION=us-east-1
export COMPLIANCE_SENTINEL_SECRET_MANAGER_PREFIX=compliance-sentinel/prod/

# Secrets will be automatically loaded from:
# - compliance-sentinel/prod/jwt-secret
# - compliance-sentinel/prod/database-password
# - compliance-sentinel/prod/api-keys
```

### Using HashiCorp Vault

```python
# Configure Vault
export COMPLIANCE_SENTINEL_SECRET_MANAGER_TYPE=vault
export COMPLIANCE_SENTINEL_VAULT_URL=https://vault.company.com
export COMPLIANCE_SENTINEL_VAULT_TOKEN=${VAULT_TOKEN}
export COMPLIANCE_SENTINEL_VAULT_PATH=secret/compliance-sentinel/prod
```

## Testing Migration

### 1. Unit Test Updates

Update unit tests to use dynamic configuration:

```python
# Before
class TestVulnerabilityProvider(unittest.TestCase):
    def setUp(self):
        self.provider = VulnerabilityProvider()  # Used hardcoded config

# After
class TestVulnerabilityProvider(unittest.TestCase):
    def setUp(self):
        # Set test environment
        os.environ["COMPLIANCE_SENTINEL_ENVIRONMENT"] = "test"
        os.environ["COMPLIANCE_SENTINEL_NVD_BASE_URL"] = "https://test-api.example.com"
        self.provider = VulnerabilityProvider()
```

### 2. Integration Test Updates

```python
class TestIntegration(unittest.TestCase):
    def setUp(self):
        # Configure test environment
        test_env = {
            "COMPLIANCE_SENTINEL_ENVIRONMENT": "test",
            "COMPLIANCE_SENTINEL_CACHE_ENABLED": "false",
            "COMPLIANCE_SENTINEL_DEBUG_ENABLED": "true"
        }
        self.env_patcher = patch.dict(os.environ, test_env)
        self.env_patcher.start()
    
    def tearDown(self):
        self.env_patcher.stop()
```

## Validation and Rollback

### 1. Configuration Validation

Before deploying, validate your configuration:

```bash
# Validate development configuration
COMPLIANCE_SENTINEL_ENVIRONMENT=development python -m compliance_sentinel.cli config validate

# Validate production configuration
COMPLIANCE_SENTINEL_ENVIRONMENT=production python -m compliance_sentinel.cli config validate
```

### 2. Gradual Migration

Implement gradual migration with fallbacks:

```python
class Config:
    def __init__(self):
        config_manager = DynamicConfigManager()
        
        # Try dynamic configuration first, fallback to hardcoded
        try:
            self.cache_ttl = config_manager.get_system_config().get("cache_ttl")
        except Exception:
            self.cache_ttl = 3600  # Fallback to hardcoded value
            logger.warning("Using fallback configuration for cache_ttl")
```

### 3. Rollback Plan

If migration fails:

1. **Revert environment variables:**
```bash
# Remove new environment variables
unset COMPLIANCE_SENTINEL_CACHE_TTL
unset COMPLIANCE_SENTINEL_LOG_LEVEL
```

2. **Restore hardcoded values:**
```python
# Temporarily restore hardcoded values
class Config:
    def __init__(self):
        # Emergency fallback to hardcoded values
        self.cache_ttl = 3600
        self.log_level = "INFO"
```

3. **Monitor and fix issues:**
```bash
# Check application logs
tail -f /var/log/compliance-sentinel/app.log

# Validate configuration
python -m compliance_sentinel.cli config validate
```

## Common Migration Issues

### 1. Missing Environment Variables

**Problem:** Application fails to start due to missing required environment variables.

**Solution:**
```python
# Add validation with helpful error messages
def validate_required_config():
    required_vars = [
        "COMPLIANCE_SENTINEL_AUTH_JWT_SECRET",
        "COMPLIANCE_SENTINEL_REDIS_PASSWORD"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
```

### 2. Type Conversion Issues

**Problem:** Environment variables are strings but code expects other types.

**Solution:**
```python
# Use proper type conversion
config_manager = DynamicConfigManager()
cache_ttl = config_manager.get_int("cache_ttl", default=3600)
debug_enabled = config_manager.get_bool("debug_enabled", default=False)
rate_limit = config_manager.get_float("rate_limit", default=50.0)
```

### 3. Secret Access Issues

**Problem:** Cannot access secrets from secret manager.

**Solution:**
```python
# Add proper error handling and fallbacks
try:
    secret_config = config_manager.get_secret_config()
    jwt_secret = secret_config.get("jwt_secret")
except Exception as e:
    logger.error(f"Failed to load secrets: {e}")
    # Use environment variable as fallback
    jwt_secret = os.getenv("COMPLIANCE_SENTINEL_AUTH_JWT_SECRET")
    if not jwt_secret:
        raise ValueError("JWT secret must be configured")
```

## Post-Migration Checklist

- [ ] All hardcoded values replaced with dynamic configuration
- [ ] Environment-specific configurations created
- [ ] Secrets moved to secure secret management
- [ ] Test data removed from production code paths
- [ ] Configuration validation implemented
- [ ] Unit and integration tests updated
- [ ] Documentation updated
- [ ] Monitoring and alerting configured
- [ ] Rollback plan tested
- [ ] Team trained on new configuration system

## Support and Troubleshooting

For migration support:

1. **Check configuration validation:**
```bash
python -m compliance_sentinel.cli config validate --environment production
```

2. **View current configuration:**
```bash
python -m compliance_sentinel.cli config show --format json
```

3. **Test configuration reload:**
```bash
python -m compliance_sentinel.cli config reload
```

4. **Monitor application logs:**
```bash
tail -f /var/log/compliance-sentinel/app.log | grep -i "config"
```

For additional help, refer to the [Configuration Documentation](./ENVIRONMENT_VARIABLES.md) or contact the development team.