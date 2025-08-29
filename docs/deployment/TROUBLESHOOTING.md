# Troubleshooting Guide

This guide helps diagnose and resolve common issues with Compliance Sentinel deployments.

## Table of Contents

- [Configuration Issues](#configuration-issues)
- [Connection Problems](#connection-problems)
- [Performance Issues](#performance-issues)
- [Authentication Problems](#authentication-problems)
- [Cache Issues](#cache-issues)
- [External API Issues](#external-api-issues)
- [Container Issues](#container-issues)
- [Kubernetes Issues](#kubernetes-issues)
- [Monitoring and Logging](#monitoring-and-logging)
- [Recovery Procedures](#recovery-procedures)

## Configuration Issues

### Application Won't Start - Missing Environment Variables

**Symptoms:**
- Application exits immediately on startup
- Error messages about missing configuration
- "ValueError: Missing required environment variables"

**Diagnosis:**
```bash
# Check if required environment variables are set
env | grep COMPLIANCE_SENTINEL

# Validate configuration
python -m compliance_sentinel.cli config validate

# Check configuration loading
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
try:
    config = DynamicConfigManager()
    print('Configuration loaded successfully')
    print(config.get_system_config())
except Exception as e:
    print(f'Configuration error: {e}')
"
```

**Solutions:**
1. **Copy environment template:**
```bash
cp docs/configuration/production.env.template .env
# Edit .env with your values
```

2. **Set required variables:**
```bash
export COMPLIANCE_SENTINEL_AUTH_JWT_SECRET="your-jwt-secret-here"
export COMPLIANCE_SENTINEL_REDIS_PASSWORD="your-redis-password"
```

3. **Use configuration file:**
```bash
# Create config.yaml
cat <<EOF > config.yaml
system:
  environment: production
  log_level: INFO
auth:
  jwt_secret: your-jwt-secret
cache:
  backend: redis
  host: localhost
EOF

export COMPLIANCE_SENTINEL_CONFIG_FILE=config.yaml
```

### Invalid Configuration Values

**Symptoms:**
- Application starts but behaves unexpectedly
- Warning messages about invalid configuration
- Features not working as expected

**Diagnosis:**
```bash
# Show current configuration
python -m compliance_sentinel.cli config show --format json

# Validate configuration with specific environment
python -m compliance_sentinel.cli config validate --environment production

# Check type conversion issues
python -c "
import os
print('CACHE_TTL:', os.getenv('COMPLIANCE_SENTINEL_CACHE_TTL'), type(os.getenv('COMPLIANCE_SENTINEL_CACHE_TTL')))
print('DEBUG_ENABLED:', os.getenv('COMPLIANCE_SENTINEL_DEBUG_ENABLED'), type(os.getenv('COMPLIANCE_SENTINEL_DEBUG_ENABLED')))
"
```

**Solutions:**
1. **Fix type conversion:**
```bash
# Boolean values should be 'true' or 'false' (lowercase)
export COMPLIANCE_SENTINEL_DEBUG_ENABLED=false

# Numeric values should be valid numbers
export COMPLIANCE_SENTINEL_CACHE_TTL=3600
export COMPLIANCE_SENTINEL_REQUEST_TIMEOUT_SECONDS=30.0
```

2. **Validate enum values:**
```bash
# Valid log levels
export COMPLIANCE_SENTINEL_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Valid environments
export COMPLIANCE_SENTINEL_ENVIRONMENT=production  # development, staging, production, test
```

### Configuration Hot-Reload Not Working

**Symptoms:**
- Configuration changes don't take effect
- Need to restart application for changes
- "Configuration reload failed" messages

**Diagnosis:**
```bash
# Check if hot-reload is enabled
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
print('Hot reload enabled:', config.hot_reload_enabled)
"

# Test configuration reload
python -m compliance_sentinel.cli config reload
```

**Solutions:**
1. **Enable hot-reload:**
```bash
export COMPLIANCE_SENTINEL_CONFIG_HOT_RELOAD=true
```

2. **Check file permissions:**
```bash
# Ensure config files are readable
ls -la config/
chmod 644 config/*.yaml
```

3. **Manual reload:**
```bash
# Send SIGHUP to reload configuration
kill -HUP $(pgrep -f compliance-sentinel)
```

## Connection Problems

### Cannot Connect to Redis

**Symptoms:**
- "Connection refused" errors
- Cache operations failing
- "Redis connection timeout" messages

**Diagnosis:**
```bash
# Test Redis connectivity
redis-cli -h $COMPLIANCE_SENTINEL_REDIS_HOST -p $COMPLIANCE_SENTINEL_REDIS_PORT ping

# Check Redis status
systemctl status redis

# Test with authentication
redis-cli -h $COMPLIANCE_SENTINEL_REDIS_HOST -a $COMPLIANCE_SENTINEL_REDIS_PASSWORD ping

# Check network connectivity
telnet $COMPLIANCE_SENTINEL_REDIS_HOST $COMPLIANCE_SENTINEL_REDIS_PORT
```

**Solutions:**
1. **Start Redis service:**
```bash
sudo systemctl start redis
sudo systemctl enable redis
```

2. **Check Redis configuration:**
```bash
# Check Redis config
redis-cli CONFIG GET "*"

# Check if password is required
redis-cli CONFIG GET requirepass
```

3. **Update connection settings:**
```bash
export COMPLIANCE_SENTINEL_REDIS_HOST=localhost
export COMPLIANCE_SENTINEL_REDIS_PORT=6379
export COMPLIANCE_SENTINEL_REDIS_PASSWORD=your-password
export COMPLIANCE_SENTINEL_REDIS_SSL=false
```

### Database Connection Issues

**Symptoms:**
- "Database connection failed" errors
- "Connection pool exhausted" messages
- Slow database operations

**Diagnosis:**
```bash
# Test database connectivity
pg_isready -h $COMPLIANCE_SENTINEL_DB_HOST -p $COMPLIANCE_SENTINEL_DB_PORT -U $COMPLIANCE_SENTINEL_DB_USER

# Test connection with credentials
psql -h $COMPLIANCE_SENTINEL_DB_HOST -U $COMPLIANCE_SENTINEL_DB_USER -d $COMPLIANCE_SENTINEL_DB_NAME -c "SELECT 1;"

# Check connection pool settings
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
db_config = config.get_database_config()
print('Pool size:', db_config.get('pool_size'))
print('Max overflow:', db_config.get('max_overflow'))
"
```

**Solutions:**
1. **Check database service:**
```bash
sudo systemctl status postgresql
sudo systemctl start postgresql
```

2. **Verify credentials:**
```bash
# Test with psql
psql -h localhost -U username -d database_name

# Check user permissions
psql -c "SELECT current_user, current_database();"
```

3. **Adjust connection pool:**
```bash
export COMPLIANCE_SENTINEL_DB_POOL_SIZE=20
export COMPLIANCE_SENTINEL_DB_MAX_OVERFLOW=30
export COMPLIANCE_SENTINEL_DB_POOL_TIMEOUT=30
```

### External API Connection Failures

**Symptoms:**
- "Failed to fetch vulnerability data" errors
- "External service unavailable" messages
- Circuit breaker activation

**Diagnosis:**
```bash
# Test external API connectivity
curl -v https://services.nvd.nist.gov/rest/json/cves/2.0
curl -v https://cve.circl.lu/api/cve/CVE-2023-1234
curl -v https://api.osv.dev/v1/query

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Test with API key
curl -H "Authorization: Bearer $COMPLIANCE_SENTINEL_NVD_API_KEY" \
     https://services.nvd.nist.gov/rest/json/cves/2.0
```

**Solutions:**
1. **Configure proxy:**
```bash
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
export NO_PROXY=localhost,127.0.0.1
```

2. **Check API keys:**
```bash
# Verify API key is set
echo $COMPLIANCE_SENTINEL_NVD_API_KEY | wc -c

# Test API key validity
curl -H "Authorization: Bearer $COMPLIANCE_SENTINEL_NVD_API_KEY" \
     https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1
```

3. **Adjust timeouts:**
```bash
export COMPLIANCE_SENTINEL_REQUEST_TIMEOUT_SECONDS=60.0
export COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_FAILURE_THRESHOLD=10
```

## Performance Issues

### High Memory Usage

**Symptoms:**
- Out of memory errors
- Slow response times
- System becomes unresponsive

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep compliance-sentinel
free -h

# Check for memory leaks
python -m memory_profiler -m compliance_sentinel.mcp_server

# Monitor memory over time
while true; do
    ps -p $(pgrep -f compliance-sentinel) -o pid,vsz,rss,pmem,comm
    sleep 10
done
```

**Solutions:**
1. **Adjust cache settings:**
```bash
export COMPLIANCE_SENTINEL_CACHE_MAX_SIZE=500
export COMPLIANCE_SENTINEL_CACHE_CLEANUP_INTERVAL=60
```

2. **Limit concurrent operations:**
```bash
export COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=2
export COMPLIANCE_SENTINEL_WORKER_THREADS=2
```

3. **Configure garbage collection:**
```bash
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
```

### High CPU Usage

**Symptoms:**
- CPU usage consistently above 80%
- Slow response times
- Request timeouts

**Diagnosis:**
```bash
# Check CPU usage
top -p $(pgrep -f compliance-sentinel)
htop

# Profile CPU usage
python -m cProfile -o profile.stats -m compliance_sentinel.mcp_server

# Check for busy loops
strace -p $(pgrep -f compliance-sentinel) -c
```

**Solutions:**
1. **Optimize analysis settings:**
```bash
export COMPLIANCE_SENTINEL_MAX_CONCURRENT_ANALYSES=1
export COMPLIANCE_SENTINEL_FILE_WATCHER_DEBOUNCE_MS=2000
```

2. **Enable caching:**
```bash
export COMPLIANCE_SENTINEL_CACHE_ENABLED=true
export COMPLIANCE_SENTINEL_CACHE_TTL=7200
```

3. **Scale horizontally:**
```bash
# Run multiple instances behind load balancer
docker-compose up -d --scale compliance-sentinel=3
```

### Slow Response Times

**Symptoms:**
- API requests taking longer than expected
- Timeout errors
- Poor user experience

**Diagnosis:**
```bash
# Test response times
time curl http://localhost:8000/api/vulnerabilities/search?q=test

# Check metrics
curl http://localhost:9090/metrics | grep response_time

# Monitor with continuous testing
while true; do
    time curl -s http://localhost:8000/health > /dev/null
    sleep 5
done
```

**Solutions:**
1. **Enable caching:**
```bash
export COMPLIANCE_SENTINEL_CACHE_ENABLED=true
export COMPLIANCE_SENTINEL_CACHE_BACKEND=redis
```

2. **Optimize database queries:**
```bash
export COMPLIANCE_SENTINEL_DB_POOL_SIZE=20
export COMPLIANCE_SENTINEL_DB_QUERY_TIMEOUT=10
```

3. **Adjust timeouts:**
```bash
export COMPLIANCE_SENTINEL_REQUEST_TIMEOUT_SECONDS=15.0
export MCP_REQUEST_TIMEOUT_SECONDS=15.0
```

## Authentication Problems

### JWT Token Issues

**Symptoms:**
- "Invalid token" errors
- "Token expired" messages
- Authentication failures

**Diagnosis:**
```bash
# Check JWT secret
echo $COMPLIANCE_SENTINEL_AUTH_JWT_SECRET | wc -c

# Decode JWT token (without verification)
python -c "
import jwt
token = 'your-jwt-token-here'
print(jwt.decode(token, options={'verify_signature': False}))
"

# Test token generation
python -c "
from compliance_sentinel.mcp_server.auth import AuthenticationManager
auth = AuthenticationManager()
token = auth.create_jwt_token({'user': 'test'})
print('Token:', token)
"
```

**Solutions:**
1. **Generate strong JWT secret:**
```bash
export COMPLIANCE_SENTINEL_AUTH_JWT_SECRET=$(openssl rand -base64 64)
```

2. **Adjust token expiry:**
```bash
export COMPLIANCE_SENTINEL_AUTH_JWT_EXPIRY_HOURS=24
```

3. **Check token format:**
```bash
# Ensure token includes Bearer prefix
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8000/api/health
```

### API Key Problems

**Symptoms:**
- "Invalid API key" errors
- "API key not found" messages
- Access denied errors

**Diagnosis:**
```bash
# List API keys
python -m compliance_sentinel.cli auth list-api-keys

# Test API key
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/health

# Check API key format
python -c "
api_key = 'your-api-key'
print('Length:', len(api_key))
print('Prefix:', api_key[:10])
"
```

**Solutions:**
1. **Create new API key:**
```bash
python -m compliance_sentinel.cli auth create-api-key \
  --name "test-key" \
  --permissions read,write \
  --expires-in-days 30
```

2. **Check API key configuration:**
```bash
export COMPLIANCE_SENTINEL_AUTH_API_KEY_LENGTH=64
export COMPLIANCE_SENTINEL_AUTH_API_KEY_PREFIX=cs_prod_
```

3. **Verify permissions:**
```bash
python -m compliance_sentinel.cli auth show-api-key --key-id your-key-id
```

## Cache Issues

### Cache Not Working

**Symptoms:**
- Repeated external API calls
- Slow performance
- "Cache miss" in logs

**Diagnosis:**
```bash
# Check cache configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
cache_config = config.get_cache_config()
print('Cache enabled:', cache_config.get('enabled'))
print('Cache backend:', cache_config.get('backend'))
print('Cache TTL:', cache_config.get('ttl'))
"

# Test cache operations
python -c "
from compliance_sentinel.utils.intelligent_cache import IntelligentCache
cache = IntelligentCache()
cache.set('test', 'value', ttl=60)
print('Cache test:', cache.get('test'))
"

# Check Redis cache
redis-cli keys "*compliance*"
```

**Solutions:**
1. **Enable caching:**
```bash
export COMPLIANCE_SENTINEL_CACHE_ENABLED=true
export COMPLIANCE_SENTINEL_CACHE_BACKEND=redis
```

2. **Check Redis connection:**
```bash
redis-cli ping
redis-cli info memory
```

3. **Clear cache:**
```bash
redis-cli FLUSHALL
# Or specific pattern
redis-cli --scan --pattern "compliance*" | xargs redis-cli DEL
```

### Cache Corruption

**Symptoms:**
- "Failed to deserialize cache data" errors
- Unexpected cache values
- Application crashes when accessing cache

**Diagnosis:**
```bash
# Check cache contents
redis-cli --scan --pattern "compliance*" | head -10 | xargs redis-cli MGET

# Check for corrupted keys
python -c "
from compliance_sentinel.utils.intelligent_cache import IntelligentCache
cache = IntelligentCache()
try:
    value = cache.get('suspicious-key')
    print('Value:', value)
except Exception as e:
    print('Cache corruption:', e)
"
```

**Solutions:**
1. **Clear corrupted cache:**
```bash
redis-cli FLUSHALL
```

2. **Update cache serialization:**
```bash
export COMPLIANCE_SENTINEL_CACHE_SERIALIZATION=json
```

3. **Implement cache validation:**
```bash
export COMPLIANCE_SENTINEL_CACHE_VALIDATION=true
```

## Real-Time Data Integration Issues

### Data Synchronization Problems

**Symptoms:**
- Stale vulnerability data
- "Data sync failed" errors
- Inconsistent analysis results

**Diagnosis:**
```bash
# Check data sync status
python -c "
from compliance_sentinel.providers.data_synchronizer import DataSynchronizer
sync = DataSynchronizer()
print('Last sync:', sync.get_last_sync_time())
print('Sync status:', sync.get_sync_status())
"

# Check sync configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
print('Sync interval:', config.get_config('data_sync_interval'))
print('Auto sync enabled:', config.get_config('auto_sync_enabled'))
"

# Test manual sync
python -m compliance_sentinel.cli data sync --force
```

**Solutions:**
1. **Adjust sync intervals:**
```bash
export COMPLIANCE_SENTINEL_DATA_SYNC_INTERVAL=1800  # 30 minutes
export COMPLIANCE_SENTINEL_AUTO_SYNC_ENABLED=true
```

2. **Force data refresh:**
```bash
python -m compliance_sentinel.cli data sync --force --clear-cache
```

3. **Check external API connectivity:**
```bash
curl -v https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1
curl -v https://api.osv.dev/v1/query -d '{"package":{"name":"test"}}'
```

### Configuration Hot-Reload Issues

**Symptoms:**
- Configuration changes not taking effect
- "Hot reload failed" messages
- Need to restart for configuration changes

**Diagnosis:**
```bash
# Check hot-reload status
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
print('Hot reload enabled:', config.hot_reload_enabled)
print('Config sources:', config.get_config_sources())
"

# Test configuration reload
kill -HUP $(pgrep -f compliance-sentinel)

# Check file watchers
lsof | grep -E '\.(yaml|env)$'
```

**Solutions:**
1. **Enable hot-reload:**
```bash
export COMPLIANCE_SENTINEL_CONFIG_HOT_RELOAD=true
export COMPLIANCE_SENTINEL_CONFIG_WATCH_FILES=true
```

2. **Check file permissions:**
```bash
ls -la config/
chmod 644 config/*.yaml .env*
```

3. **Manual configuration reload:**
```bash
python -m compliance_sentinel.cli config reload
```

### Fallback Mechanism Issues

**Symptoms:**
- No fallback when external services fail
- "No fallback data available" errors
- System fails when APIs are down

**Diagnosis:**
```bash
# Check fallback configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
print('Fallback enabled:', config.get_config('fallback_enabled'))
print('Fallback cache only:', config.get_config('fallback_cache_only'))
"

# Test fallback behavior
python -c "
from compliance_sentinel.utils.resilient_error_handler import ResilientErrorHandler
handler = ResilientErrorHandler()
print('Fallback strategies:', handler.get_fallback_strategies())
"
```

**Solutions:**
1. **Enable fallback mechanisms:**
```bash
export COMPLIANCE_SENTINEL_FALLBACK_ENABLED=true
export COMPLIANCE_SENTINEL_FALLBACK_CACHE_ONLY=false
export COMPLIANCE_SENTINEL_FALLBACK_TIMEOUT=30
```

2. **Populate fallback cache:**
```bash
python -m compliance_sentinel.cli cache warm --all-providers
```

3. **Test fallback behavior:**
```bash
# Simulate API failure
export COMPLIANCE_SENTINEL_NVD_BASE_URL=http://invalid-url
python -m compliance_sentinel.cli analyze test_file.py
```

## External API Issues

### Rate Limiting

**Symptoms:**
- "Rate limit exceeded" errors
- HTTP 429 responses
- Delayed responses from external APIs

**Diagnosis:**
```bash
# Check rate limit configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
print('NVD rate limit:', config.get_provider_config('nvd').get('rate_limit'))
print('CVE rate limit:', config.get_provider_config('cve').get('rate_limit'))
"

# Monitor API calls
curl -v https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1
```

**Solutions:**
1. **Adjust rate limits:**
```bash
export COMPLIANCE_SENTINEL_NVD_RATE_LIMIT=10
export COMPLIANCE_SENTINEL_CVE_RATE_LIMIT=20
export COMPLIANCE_SENTINEL_OSV_RATE_LIMIT=50
```

2. **Enable request queuing:**
```bash
export COMPLIANCE_SENTINEL_REQUEST_QUEUE_ENABLED=true
export COMPLIANCE_SENTINEL_REQUEST_QUEUE_SIZE=100
```

3. **Use API keys:**
```bash
export COMPLIANCE_SENTINEL_NVD_API_KEY=your-nvd-api-key
export COMPLIANCE_SENTINEL_GITHUB_TOKEN=your-github-token
```

### Circuit Breaker Activation

**Symptoms:**
- "Circuit breaker open" messages
- External service calls being blocked
- Fallback data being used

**Diagnosis:**
```bash
# Check circuit breaker status
curl http://localhost:9090/metrics | grep circuit_breaker

# Check circuit breaker configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
cb_config = config.get_circuit_breaker_config()
print('Failure threshold:', cb_config.get('failure_threshold'))
print('Recovery timeout:', cb_config.get('recovery_timeout'))
"
```

**Solutions:**
1. **Adjust circuit breaker settings:**
```bash
export COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_FAILURE_THRESHOLD=10
export COMPLIANCE_SENTINEL_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=120
```

2. **Reset circuit breaker:**
```bash
python -c "
from compliance_sentinel.utils.circuit_breaker import CircuitBreakerManager
manager = CircuitBreakerManager()
manager.reset_all_circuit_breakers()
"
```

3. **Check external service health:**
```bash
curl -I https://services.nvd.nist.gov/rest/json/cves/2.0
curl -I https://cve.circl.lu/api/
```

## Container Issues

### Docker Container Won't Start

**Symptoms:**
- Container exits immediately
- "Container failed to start" errors
- No logs from container

**Diagnosis:**
```bash
# Check container logs
docker logs compliance-sentinel

# Check container status
docker ps -a | grep compliance-sentinel

# Inspect container
docker inspect compliance-sentinel

# Run container interactively
docker run -it --rm compliance-sentinel:latest /bin/bash
```

**Solutions:**
1. **Check environment variables:**
```bash
docker run --env-file .env.production compliance-sentinel:latest
```

2. **Fix file permissions:**
```bash
# In Dockerfile
RUN chown -R 1000:1000 /app
USER 1000:1000
```

3. **Check health probe:**
```bash
docker run -d --name test-container compliance-sentinel:latest
docker exec test-container curl -f http://localhost:8080/health
```

### Docker Compose Issues

**Symptoms:**
- Services not starting in correct order
- Network connectivity issues between services
- Volume mount problems

**Diagnosis:**
```bash
# Check service status
docker-compose ps

# View logs for all services
docker-compose logs

# Check networks
docker network ls
docker network inspect compliance-sentinel_default

# Check volumes
docker volume ls
docker volume inspect compliance-sentinel_redis-data
```

**Solutions:**
1. **Fix service dependencies:**
```yaml
# docker-compose.yml
services:
  compliance-sentinel:
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
```

2. **Check network configuration:**
```yaml
networks:
  compliance-network:
    driver: bridge
```

3. **Fix volume permissions:**
```bash
sudo chown -R 1000:1000 ./data
sudo chmod -R 755 ./data
```

## Kubernetes Issues

### Pod Not Starting

**Symptoms:**
- Pods stuck in "Pending" or "CrashLoopBackOff" state
- "ImagePullBackOff" errors
- Resource allocation issues

**Diagnosis:**
```bash
# Check pod status
kubectl get pods -n compliance-sentinel

# Describe pod for detailed information
kubectl describe pod <pod-name> -n compliance-sentinel

# Check pod logs
kubectl logs <pod-name> -n compliance-sentinel

# Check events
kubectl get events -n compliance-sentinel --sort-by='.lastTimestamp'
```

**Solutions:**
1. **Fix image pull issues:**
```bash
# Check image exists
docker pull compliance-sentinel:1.0.0

# Update image pull policy
kubectl patch deployment compliance-sentinel -p '{"spec":{"template":{"spec":{"containers":[{"name":"compliance-sentinel","imagePullPolicy":"Always"}]}}}}'
```

2. **Adjust resource requests:**
```yaml
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 2000m
    memory: 4Gi
```

3. **Check secrets and configmaps:**
```bash
kubectl get secrets -n compliance-sentinel
kubectl get configmaps -n compliance-sentinel
kubectl describe secret compliance-sentinel-secrets -n compliance-sentinel
```

### Service Discovery Issues

**Symptoms:**
- Services cannot communicate with each other
- DNS resolution failures
- Connection refused errors

**Diagnosis:**
```bash
# Check services
kubectl get services -n compliance-sentinel

# Test DNS resolution
kubectl exec -it <pod-name> -n compliance-sentinel -- nslookup redis-service

# Test service connectivity
kubectl exec -it <pod-name> -n compliance-sentinel -- curl http://redis-service:6379
```

**Solutions:**
1. **Check service configuration:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: redis-service
spec:
  selector:
    app.kubernetes.io/name: redis
  ports:
  - port: 6379
    targetPort: 6379
```

2. **Verify pod labels:**
```bash
kubectl get pods --show-labels -n compliance-sentinel
```

3. **Check network policies:**
```bash
kubectl get networkpolicies -n compliance-sentinel
```

## Monitoring and Logging

### Metrics Not Available

**Symptoms:**
- Prometheus cannot scrape metrics
- Grafana dashboards showing no data
- "/metrics" endpoint not responding

**Diagnosis:**
```bash
# Test metrics endpoint
curl http://localhost:9090/metrics

# Check Prometheus configuration
curl http://prometheus:9090/api/v1/targets

# Check metrics in application
python -c "
from compliance_sentinel.monitoring.real_time_metrics import get_metrics
metrics = get_metrics()
print('Metrics enabled:', metrics.enabled)
"
```

**Solutions:**
1. **Enable metrics:**
```bash
export COMPLIANCE_SENTINEL_METRICS_ENABLED=true
export COMPLIANCE_SENTINEL_METRICS_PORT=9090
```

2. **Check firewall:**
```bash
sudo ufw allow 9090/tcp
```

3. **Update Prometheus config:**
```yaml
scrape_configs:
  - job_name: 'compliance-sentinel'
    static_configs:
      - targets: ['compliance-sentinel:9090']
```

### Log Issues

**Symptoms:**
- No logs appearing
- Logs not in expected format
- Log rotation not working

**Diagnosis:**
```bash
# Check log configuration
python -c "
from compliance_sentinel.config.dynamic_config import DynamicConfigManager
config = DynamicConfigManager()
log_config = config.get_logging_config()
print('Log level:', log_config.get('level'))
print('Log format:', log_config.get('format'))
print('Log destination:', log_config.get('destination'))
"

# Check log files
ls -la /var/log/compliance-sentinel/
tail -f /var/log/compliance-sentinel/app.log
```

**Solutions:**
1. **Configure logging:**
```bash
export COMPLIANCE_SENTINEL_LOG_LEVEL=INFO
export COMPLIANCE_SENTINEL_LOG_FORMAT=json
export COMPLIANCE_SENTINEL_LOG_DESTINATION=file
export COMPLIANCE_SENTINEL_LOG_FILE_PATH=/var/log/compliance-sentinel/app.log
```

2. **Fix permissions:**
```bash
sudo mkdir -p /var/log/compliance-sentinel
sudo chown compliance-sentinel:compliance-sentinel /var/log/compliance-sentinel
sudo chmod 755 /var/log/compliance-sentinel
```

3. **Configure log rotation:**
```bash
sudo cp deployment/logrotate/compliance-sentinel /etc/logrotate.d/
sudo logrotate -d /etc/logrotate.d/compliance-sentinel
```

## Recovery Procedures

### Service Recovery

**Complete Service Restart:**
```bash
# Stop service
sudo systemctl stop compliance-sentinel

# Clear cache
redis-cli FLUSHALL

# Check configuration
python -m compliance_sentinel.cli config validate

# Start service
sudo systemctl start compliance-sentinel

# Check status
sudo systemctl status compliance-sentinel
```

### Database Recovery

**Database Connection Issues:**
```bash
# Restart database
sudo systemctl restart postgresql

# Check connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Kill hanging connections
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='compliance_sentinel';"
```

### Cache Recovery

**Redis Recovery:**
```bash
# Restart Redis
sudo systemctl restart redis

# Check Redis status
redis-cli info server

# Clear all cache
redis-cli FLUSHALL

# Test cache operations
redis-cli set test "value"
redis-cli get test
```

### Configuration Recovery

**Reset to Defaults:**
```bash
# Backup current configuration
cp .env .env.backup

# Reset to template
cp docs/configuration/production.env.template .env

# Edit with correct values
nano .env

# Validate configuration
python -m compliance_sentinel.cli config validate

# Restart service
sudo systemctl restart compliance-sentinel
```

## Emergency Procedures

### Complete System Recovery

1. **Stop all services:**
```bash
sudo systemctl stop compliance-sentinel
sudo systemctl stop redis
sudo systemctl stop postgresql
```

2. **Backup data:**
```bash
sudo cp -r /var/lib/redis /backup/redis-$(date +%Y%m%d)
sudo -u postgres pg_dump compliance_sentinel > /backup/db-$(date +%Y%m%d).sql
```

3. **Reset configuration:**
```bash
cp docs/configuration/production.env.template .env
# Edit with correct values
```

4. **Start services:**
```bash
sudo systemctl start postgresql
sudo systemctl start redis
sudo systemctl start compliance-sentinel
```

5. **Verify operation:**
```bash
curl http://localhost:8080/health
python -m compliance_sentinel.cli config validate
```

### Rollback Procedure

1. **Stop current version:**
```bash
sudo systemctl stop compliance-sentinel
```

2. **Restore previous version:**
```bash
sudo cp /backup/compliance-sentinel-previous /opt/compliance-sentinel/
```

3. **Restore configuration:**
```bash
sudo cp /backup/.env.previous .env
```

4. **Start service:**
```bash
sudo systemctl start compliance-sentinel
```

5. **Verify rollback:**
```bash
curl http://localhost:8080/health
tail -f /var/log/compliance-sentinel/app.log
```

## Getting Help

### Log Collection

Before contacting support, collect relevant logs:

```bash
#!/bin/bash
# collect-logs.sh
mkdir -p support-logs
cp /var/log/compliance-sentinel/*.log support-logs/
journalctl -u compliance-sentinel --since "24 hours ago" > support-logs/systemd.log
docker logs compliance-sentinel > support-logs/docker.log 2>&1
kubectl logs deployment/compliance-sentinel -n compliance-sentinel > support-logs/kubernetes.log
python -m compliance_sentinel.cli config show --format json > support-logs/config.json
tar -czf support-logs-$(date +%Y%m%d-%H%M%S).tar.gz support-logs/
```

### Support Information

When contacting support, include:
- Error messages and stack traces
- Configuration (with secrets redacted)
- System information (OS, Python version, etc.)
- Steps to reproduce the issue
- Recent changes to the system

### Contact Information

- **Technical Support**: support@compliance-sentinel.com
- **Emergency Support**: +1-555-SUPPORT
- **Documentation**: https://docs.compliance-sentinel.com
- **Community Forum**: https://community.compliance-sentinel.com