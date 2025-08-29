# Security Policy for Compliance Sentinel

This document defines simple security rules for code analysis.

## Security Rules

### hardcoded_secrets
- **Pattern**: `(password|secret|key|token)\s*=\s*["'][^"']{3,}["']`
- **Severity**: HIGH
- **Category**: AUTHENTICATION
- **Description**: Hardcoded secrets detected
- **Remediation**: Use environment variables

### sql_injection
- **Pattern**: `SELECT.*\+.*|INSERT.*\+.*|UPDATE.*\+.*`
- **Severity**: HIGH  
- **Category**: INJECTION
- **Description**: Potential SQL injection
- **Remediation**: Use parameterized queries

### command_injection
- **Pattern**: `subprocess.*shell\s*=\s*True`
- **Severity**: HIGH
- **Category**: INJECTION
- **Description**: Command injection risk
- **Remediation**: Avoid shell=True

### weak_crypto
- **Pattern**: `hashlib\.(md5|sha1)\(`
- **Severity**: MEDIUM
- **Category**: CRYPTOGRAPHY
- **Description**: Weak cryptographic function
- **Remediation**: Use SHA-256 or stronger