"""AI-powered secure code template generation using language models."""

import re
import json
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import logging

from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage


logger = logging.getLogger(__name__)


class TemplateCategory(Enum):
    """Categories of secure code templates."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    CRYPTOGRAPHY = "cryptography"
    DATABASE_ACCESS = "database_access"
    API_SECURITY = "api_security"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    TESTING = "testing"


@dataclass
class CodeTemplate:
    """Secure code template with metadata."""
    id: str
    name: str
    category: TemplateCategory
    language: ProgrammingLanguage
    description: str
    template_code: str
    parameters: Dict[str, Any]
    security_features: List[str]
    usage_examples: List[str]
    best_practices: List[str]
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert template to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category.value,
            'language': self.language.value,
            'description': self.description,
            'template_code': self.template_code,
            'parameters': self.parameters,
            'security_features': self.security_features,
            'usage_examples': self.usage_examples,
            'best_practices': self.best_practices,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class GenerationRequest:
    """Request for secure code generation."""
    description: str
    language: ProgrammingLanguage
    category: TemplateCategory
    requirements: List[str]
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class GeneratedCode:
    """Generated secure code with metadata."""
    code: str
    language: ProgrammingLanguage
    security_features: List[str]
    explanation: str
    warnings: List[str]
    dependencies: List[str]
    test_code: Optional[str] = None
    generated_at: datetime = None
    
    def __post_init__(self):
        if self.generated_at is None:
            self.generated_at = datetime.now()


class SecureCodeGenerator:
    """AI-powered secure code template generator."""
    
    def __init__(self):
        """Initialize secure code generator."""
        self.logger = logging.getLogger(f"{__name__}.code_generator")
        self.templates: Dict[str, CodeTemplate] = {}
        self._initialize_templates()
    
    def _initialize_templates(self) -> None:
        """Initialize predefined secure code templates."""
        self._add_authentication_templates()
        self._add_input_validation_templates()
        self._add_cryptography_templates()
        self._add_database_templates()
        self._add_api_security_templates()
        
        self.logger.info(f"Initialized {len(self.templates)} secure code templates")
    
    def _add_authentication_templates(self) -> None:
        """Add authentication-related templates."""
        # Python JWT authentication
        python_jwt_template = CodeTemplate(
            id="python_jwt_auth",
            name="JWT Authentication Handler",
            category=TemplateCategory.AUTHENTICATION,
            language=ProgrammingLanguage.PYTHON,
            description="Secure JWT token authentication with proper validation",
            template_code='''import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app

class JWTAuth:
    def __init__(self, secret_key: str, algorithm: str = 'HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry = timedelta(hours=24)
    
    def generate_token(self, user_id: str, roles: List[str] = None) -> str:
        """Generate secure JWT token with expiration."""
        payload = {
            'user_id': user_id,
            'roles': roles or [],
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={"require": ["exp", "iat", "jti"]}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
    
    def require_auth(self, roles: List[str] = None):
        """Decorator for protecting routes with JWT authentication."""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Missing or invalid token'}), 401
                
                try:
                    token = token.split(' ')[1]
                    payload = self.verify_token(token)
                    
                    # Check roles if specified
                    if roles:
                        user_roles = payload.get('roles', [])
                        if not any(role in user_roles for role in roles):
                            return jsonify({'error': 'Insufficient permissions'}), 403
                    
                    request.current_user = payload
                    return f(*args, **kwargs)
                
                except ValueError as e:
                    return jsonify({'error': str(e)}), 401
            
            return decorated_function
        return decorator

# Usage example:
# auth = JWTAuth(os.getenv('JWT_SECRET_KEY'))
# 
# @app.route('/protected')
# @auth.require_auth(['admin', 'user'])
# def protected_route():
#     return jsonify({'user': request.current_user})
''',
            parameters={
                'secret_key': 'JWT signing secret key',
                'algorithm': 'JWT signing algorithm (default: HS256)',
                'token_expiry': 'Token expiration time'
            },
            security_features=[
                'Secure JWT token generation with expiration',
                'Token signature verification',
                'Role-based access control',
                'Unique token IDs (JTI) for tracking',
                'Proper error handling for invalid tokens'
            ],
            usage_examples=[
                'Flask API authentication',
                'Microservice authentication',
                'Role-based route protection'
            ],
            best_practices=[
                'Use strong, random secret keys',
                'Set appropriate token expiration times',
                'Implement token blacklisting for logout',
                'Use HTTPS for token transmission',
                'Validate all required JWT claims'
            ],
            created_at=datetime.now()
        )
        
        self.templates[python_jwt_template.id] = python_jwt_template
        
        # JavaScript/Node.js authentication
        js_auth_template = CodeTemplate(
            id="nodejs_auth_middleware",
            name="Node.js Authentication Middleware",
            category=TemplateCategory.AUTHENTICATION,
            language=ProgrammingLanguage.JAVASCRIPT,
            description="Express.js authentication middleware with session management",
            template_code='''const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

class AuthMiddleware {
    constructor(jwtSecret, options = {}) {
        this.jwtSecret = jwtSecret;
        this.tokenExpiry = options.tokenExpiry || '24h';
        this.saltRounds = options.saltRounds || 12;
        
        // Rate limiting for auth endpoints
        this.authLimiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5, // 5 attempts per window
            message: 'Too many authentication attempts',
            standardHeaders: true,
            legacyHeaders: false
        });
    }
    
    async hashPassword(password) {
        """Hash password using bcrypt with salt."""
        return await bcrypt.hash(password, this.saltRounds);
    }
    
    async verifyPassword(password, hash) {
        """Verify password against hash."""
        return await bcrypt.compare(password, hash);
    }
    
    generateToken(userId, roles = []) {
        """Generate JWT token with user information."""
        const payload = {
            userId,
            roles,
            iat: Math.floor(Date.now() / 1000)
        };
        
        return jwt.sign(payload, this.jwtSecret, {
            expiresIn: this.tokenExpiry,
            issuer: 'your-app-name',
            audience: 'your-app-users'
        });
    }
    
    verifyToken(req, res, next) {
        """Middleware to verify JWT tokens."""
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or invalid token' });
        }
        
        const token = authHeader.substring(7);
        
        try {
            const decoded = jwt.verify(token, this.jwtSecret, {
                issuer: 'your-app-name',
                audience: 'your-app-users'
            });
            
            req.user = decoded;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expired' });
            } else if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({ error: 'Invalid token' });
            } else {
                return res.status(500).json({ error: 'Token verification failed' });
            }
        }
    }
    
    requireRoles(allowedRoles) {
        """Middleware to check user roles."""
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const userRoles = req.user.roles || [];
            const hasPermission = allowedRoles.some(role => userRoles.includes(role));
            
            if (!hasPermission) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            next();
        };
    }
}

// Usage:
// const auth = new AuthMiddleware(process.env.JWT_SECRET);
// app.use('/auth', auth.authLimiter);
// app.get('/protected', auth.verifyToken, auth.requireRoles(['admin']), handler);
''',
            parameters={
                'jwtSecret': 'JWT signing secret',
                'tokenExpiry': 'Token expiration time',
                'saltRounds': 'Bcrypt salt rounds for password hashing'
            },
            security_features=[
                'Secure password hashing with bcrypt',
                'JWT token generation and verification',
                'Rate limiting for authentication endpoints',
                'Role-based access control',
                'Proper error handling and status codes'
            ],
            usage_examples=[
                'Express.js API authentication',
                'User registration and login',
                'Protected route middleware'
            ],
            best_practices=[
                'Use environment variables for secrets',
                'Implement rate limiting on auth endpoints',
                'Use secure password hashing (bcrypt)',
                'Validate JWT claims properly',
                'Implement proper session management'
            ],
            created_at=datetime.now()
        )
        
        self.templates[js_auth_template.id] = js_auth_template
    
    def _add_input_validation_templates(self) -> None:
        """Add input validation templates."""
        python_validation_template = CodeTemplate(
            id="python_input_validation",
            name="Python Input Validation Framework",
            category=TemplateCategory.INPUT_VALIDATION,
            language=ProgrammingLanguage.PYTHON,
            description="Comprehensive input validation with sanitization",
            template_code='''import re
import html
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass

class ValidationType(Enum):
    EMAIL = "email"
    PHONE = "phone"
    URL = "url"
    ALPHANUMERIC = "alphanumeric"
    NUMERIC = "numeric"
    PASSWORD = "password"

@dataclass
class ValidationRule:
    """Validation rule configuration."""
    field_name: str
    required: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    validation_type: Optional[ValidationType] = None
    custom_validator: Optional[callable] = None

class InputValidator:
    """Secure input validation and sanitization."""
    
    # Predefined patterns for common validation types
    PATTERNS = {
        ValidationType.EMAIL: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        ValidationType.PHONE: r'^\+?1?[0-9]{10,15}$',
        ValidationType.URL: r'^https?://[^\s/$.?#].[^\s]*$',
        ValidationType.ALPHANUMERIC: r'^[a-zA-Z0-9]+$',
        ValidationType.NUMERIC: r'^[0-9]+$',
        ValidationType.PASSWORD: r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    }
    
    def __init__(self):
        self.rules: Dict[str, ValidationRule] = {}
    
    def add_rule(self, rule: ValidationRule) -> None:
        """Add validation rule for a field."""
        self.rules[rule.field_name] = rule
    
    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate input data against defined rules."""
        validated_data = {}
        errors = {}
        
        for field_name, rule in self.rules.items():
            try:
                value = data.get(field_name)
                validated_value = self._validate_field(value, rule)
                validated_data[field_name] = validated_value
            except ValidationError as e:
                errors[field_name] = str(e)
        
        if errors:
            raise ValidationError(f"Validation failed: {errors}")
        
        return validated_data
    
    def _validate_field(self, value: Any, rule: ValidationRule) -> Any:
        """Validate a single field."""
        # Check required
        if rule.required and (value is None or value == ""):
            raise ValidationError(f"{rule.field_name} is required")
        
        if value is None or value == "":
            return value
        
        # Convert to string for validation
        str_value = str(value).strip()
        
        # Length validation
        if rule.min_length and len(str_value) < rule.min_length:
            raise ValidationError(f"{rule.field_name} must be at least {rule.min_length} characters")
        
        if rule.max_length and len(str_value) > rule.max_length:
            raise ValidationError(f"{rule.field_name} must not exceed {rule.max_length} characters")
        
        # Pattern validation
        pattern = rule.pattern
        if rule.validation_type and rule.validation_type in self.PATTERNS:
            pattern = self.PATTERNS[rule.validation_type]
        
        if pattern and not re.match(pattern, str_value):
            raise ValidationError(f"{rule.field_name} format is invalid")
        
        # Custom validation
        if rule.custom_validator:
            if not rule.custom_validator(str_value):
                raise ValidationError(f"{rule.field_name} failed custom validation")
        
        return self._sanitize_input(str_value)
    
    def _sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent XSS and other attacks."""
        # HTML escape
        sanitized = html.escape(value)
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', sanitized)
        
        return sanitized.strip()

# Usage example:
validator = InputValidator()
validator.add_rule(ValidationRule(
    field_name="email",
    required=True,
    validation_type=ValidationType.EMAIL,
    max_length=255
))
validator.add_rule(ValidationRule(
    field_name="password",
    required=True,
    validation_type=ValidationType.PASSWORD,
    min_length=8
))

# Validate user input
try:
    clean_data = validator.validate({
        "email": "user@example.com",
        "password": "SecurePass123!"
    })
except ValidationError as e:
    print(f"Validation error: {e}")
''',
            parameters={
                'validation_rules': 'List of validation rules to apply',
                'custom_validators': 'Custom validation functions',
                'sanitization_options': 'Input sanitization configuration'
            },
            security_features=[
                'Comprehensive input validation',
                'XSS prevention through HTML escaping',
                'Pattern-based validation for common types',
                'Length and format validation',
                'Custom validation support'
            ],
            usage_examples=[
                'Web form validation',
                'API input validation',
                'User registration validation'
            ],
            best_practices=[
                'Always validate on server side',
                'Use allowlist validation when possible',
                'Sanitize all user inputs',
                'Provide clear error messages',
                'Validate data types and ranges'
            ],
            created_at=datetime.now()
        )
        
        self.templates[python_validation_template.id] = python_validation_template
    
    def _add_cryptography_templates(self) -> None:
        """Add cryptography templates."""
        python_crypto_template = CodeTemplate(
            id="python_secure_crypto",
            name="Python Secure Cryptography",
            category=TemplateCategory.CRYPTOGRAPHY,
            language=ProgrammingLanguage.PYTHON,
            description="Secure encryption, hashing, and key management",
            template_code='''import os
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecureCrypto:
    """Secure cryptography utilities with best practices."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a secure encryption key."""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Derive encryption key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Encrypt data using Fernet (AES 128 in CBC mode)."""
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Decrypt data using Fernet."""
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(encrypted_bytes)
        return decrypted_data.decode()
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple[str, bytes]:
        """Hash password using SHA-256 with salt."""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Use PBKDF2 for password hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        hash_bytes = kdf.derive(password.encode())
        hash_str = base64.urlsafe_b64encode(hash_bytes).decode()
        return hash_str, salt
    
    @staticmethod
    def verify_password(password: str, hash_str: str, salt: bytes) -> bool:
        """Verify password against hash."""
        try:
            computed_hash, _ = SecureCrypto.hash_password(password, salt)
            return secrets.compare_digest(hash_str, computed_hash)
        except Exception:
            return False
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
        """Generate RSA key pair for asymmetric encryption."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """Timing-safe string comparison."""
        return secrets.compare_digest(a, b)

# Usage examples:
# Generate and use encryption key
key = SecureCrypto.generate_key()
encrypted = SecureCrypto.encrypt_data("sensitive data", key)
decrypted = SecureCrypto.decrypt_data(encrypted, key)

# Password hashing
password_hash, salt = SecureCrypto.hash_password("user_password")
is_valid = SecureCrypto.verify_password("user_password", password_hash, salt)

# Generate secure tokens
api_token = SecureCrypto.generate_secure_token()
''',
            parameters={
                'key_size': 'RSA key size (minimum 2048)',
                'iterations': 'PBKDF2 iterations (minimum 100000)',
                'salt_length': 'Salt length in bytes'
            },
            security_features=[
                'Strong encryption using Fernet (AES)',
                'Secure password hashing with PBKDF2',
                'Cryptographically secure random generation',
                'Timing-safe string comparison',
                'Proper key derivation from passwords'
            ],
            usage_examples=[
                'Data encryption at rest',
                'Password storage and verification',
                'API token generation',
                'Secure session management'
            ],
            best_practices=[
                'Use strong, random keys',
                'Never hardcode encryption keys',
                'Use appropriate key sizes (RSA 2048+)',
                'Implement proper key rotation',
                'Use timing-safe comparisons'
            ],
            created_at=datetime.now()
        )
        
        self.templates[python_crypto_template.id] = python_crypto_template
    
    def _add_database_templates(self) -> None:
        """Add secure database access templates."""
        python_db_template = CodeTemplate(
            id="python_secure_database",
            name="Python Secure Database Access",
            category=TemplateCategory.DATABASE_ACCESS,
            language=ProgrammingLanguage.PYTHON,
            description="SQL injection prevention with parameterized queries",
            template_code='''import sqlite3
import psycopg2
from typing import Any, Dict, List, Optional, Union
import logging

class SecureDatabase:
    """Secure database access with SQL injection prevention."""
    
    def __init__(self, connection_string: str, db_type: str = 'postgresql'):
        self.connection_string = connection_string
        self.db_type = db_type
        self.logger = logging.getLogger(__name__)
    
    def get_connection(self):
        """Get database connection based on type."""
        if self.db_type == 'postgresql':
            return psycopg2.connect(self.connection_string)
        elif self.db_type == 'sqlite':
            return sqlite3.connect(self.connection_string)
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def execute_query(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Execute SELECT query with parameterized inputs."""
        if not self._is_safe_query(query):
            raise ValueError("Query contains potentially unsafe operations")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                results = []
                
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                
                self.logger.info(f"Query executed successfully: {len(results)} rows returned")
                return results
                
            except Exception as e:
                self.logger.error(f"Query execution failed: {e}")
                raise
            finally:
                cursor.close()
    
    def execute_update(self, query: str, params: tuple = None) -> int:
        """Execute INSERT/UPDATE/DELETE with parameterized inputs."""
        if not self._is_safe_query(query):
            raise ValueError("Query contains potentially unsafe operations")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                affected_rows = cursor.rowcount
                conn.commit()
                
                self.logger.info(f"Update executed successfully: {affected_rows} rows affected")
                return affected_rows
                
            except Exception as e:
                conn.rollback()
                self.logger.error(f"Update execution failed: {e}")
                raise
            finally:
                cursor.close()
    
    def _is_safe_query(self, query: str) -> bool:
        """Basic query safety validation."""
        # Convert to lowercase for checking
        query_lower = query.lower().strip()
        
        # Block potentially dangerous operations
        dangerous_patterns = [
            'drop table', 'drop database', 'truncate',
            'alter table', 'create table', 'create database',
            'grant', 'revoke', 'exec', 'execute',
            'xp_', 'sp_', '--', '/*', '*/'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in query_lower:
                self.logger.warning(f"Blocked potentially dangerous query pattern: {pattern}")
                return False
        
        return True
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Safe user lookup by ID."""
        query = "SELECT id, username, email, created_at FROM users WHERE id = %s"
        results = self.execute_query(query, (user_id,))
        return results[0] if results else None
    
    def create_user(self, username: str, email: str, password_hash: str) -> int:
        """Create new user with parameterized query."""
        query = """
        INSERT INTO users (username, email, password_hash, created_at) 
        VALUES (%s, %s, %s, NOW()) 
        RETURNING id
        """
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, (username, email, password_hash))
                user_id = cursor.fetchone()[0]
                conn.commit()
                
                self.logger.info(f"User created successfully: {user_id}")
                return user_id
                
            except Exception as e:
                conn.rollback()
                self.logger.error(f"User creation failed: {e}")
                raise
            finally:
                cursor.close()
    
    def search_users(self, search_term: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Safe user search with LIKE operator."""
        # Escape special characters in search term
        escaped_term = search_term.replace('%', '\\%').replace('_', '\\_')
        
        query = """
        SELECT id, username, email 
        FROM users 
        WHERE username ILIKE %s OR email ILIKE %s 
        LIMIT %s
        """
        
        search_pattern = f"%{escaped_term}%"
        return self.execute_query(query, (search_pattern, search_pattern, limit))

# Usage example:
db = SecureDatabase("postgresql://user:pass@localhost/mydb")

# Safe user lookup
user = db.get_user_by_id(123)

# Safe user creation
user_id = db.create_user("john_doe", "john@example.com", "hashed_password")

# Safe search
results = db.search_users("john", limit=5)
''',
            parameters={
                'connection_string': 'Database connection string',
                'db_type': 'Database type (postgresql, sqlite, etc.)',
                'query_timeout': 'Query execution timeout'
            },
            security_features=[
                'Parameterized queries prevent SQL injection',
                'Query safety validation',
                'Proper error handling and logging',
                'Connection management with context managers',
                'Input escaping for LIKE operations'
            ],
            usage_examples=[
                'User management system',
                'Content management system',
                'E-commerce applications'
            ],
            best_practices=[
                'Always use parameterized queries',
                'Validate and sanitize inputs',
                'Use least privilege database accounts',
                'Implement proper error handling',
                'Log database operations for auditing'
            ],
            created_at=datetime.now()
        )
        
        self.templates[python_db_template.id] = python_db_template
    
    def _add_api_security_templates(self) -> None:
        """Add API security templates."""
        python_api_template = CodeTemplate(
            id="python_secure_api",
            name="Python Secure REST API",
            category=TemplateCategory.API_SECURITY,
            language=ProgrammingLanguage.PYTHON,
            description="Secure Flask API with authentication, rate limiting, and CORS",
            template_code='''from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import functools
import logging
from datetime import datetime

app = Flask(__name__)

# Configure CORS securely
CORS(app, 
     origins=['https://yourdomain.com'],  # Specify allowed origins
     methods=['GET', 'POST', 'PUT', 'DELETE'],
     allow_headers=['Content-Type', 'Authorization'],
     supports_credentials=True)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "20 per minute"]
)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Request logging middleware
@app.before_request
def log_request():
    """Log all incoming requests."""
    g.start_time = datetime.now()
    logging.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def log_response(response):
    """Log response details."""
    if hasattr(g, 'start_time'):
        duration = (datetime.now() - g.start_time).total_seconds()
        logging.info(f"Response: {response.status_code} in {duration:.3f}s")
    return response

# Input validation decorator
def validate_json(*required_fields):
    """Decorator to validate required JSON fields."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Invalid JSON'}), 400
            
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                return jsonify({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Authentication decorator (assumes JWT auth from previous template)
def require_auth(f):
    """Decorator to require authentication."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Verify token (implementation depends on auth system)
        token = auth_header.split(' ')[1]
        try:
            # user = verify_jwt_token(token)  # Implement this
            # g.current_user = user
            pass
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# API Routes with security measures
@app.route('/api/health')
@limiter.limit("10 per minute")
def health_check():
    """Public health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/users', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json('username', 'email', 'password')
def create_user():
    """Create new user with validation."""
    data = request.get_json()
    
    # Additional validation
    if len(data['password']) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    try:
        # Create user (implement user creation logic)
        user_id = create_user_in_db(data)
        return jsonify({'user_id': user_id, 'message': 'User created successfully'}), 201
    
    except Exception as e:
        logging.error(f"User creation failed: {e}")
        return jsonify({'error': 'User creation failed'}), 500

@app.route('/api/users/<int:user_id>')
@require_auth
@limiter.limit("30 per minute")
def get_user(user_id):
    """Get user by ID (authenticated)."""
    try:
        # Get user from database
        user = get_user_from_db(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user)
    
    except Exception as e:
        logging.error(f"User retrieval failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
@limiter.limit("10 per minute")
@validate_json('username', 'email')
def update_user(user_id):
    """Update user (authenticated)."""
    data = request.get_json()
    
    try:
        # Update user in database
        updated = update_user_in_db(user_id, data)
        if not updated:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': 'User updated successfully'})
    
    except Exception as e:
        logging.error(f"User update failed: {e}")
        return jsonify({'error': 'Update failed'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run with HTTPS in production
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
''',
            parameters={
                'allowed_origins': 'CORS allowed origins',
                'rate_limits': 'Rate limiting configuration',
                'jwt_secret': 'JWT signing secret'
            },
            security_features=[
                'CORS configuration with specific origins',
                'Rate limiting on all endpoints',
                'Security headers (HSTS, CSP, etc.)',
                'Input validation and sanitization',
                'Authentication and authorization',
                'Comprehensive error handling',
                'Request/response logging'
            ],
            usage_examples=[
                'REST API backend',
                'Microservices architecture',
                'Mobile app backend'
            ],
            best_practices=[
                'Use HTTPS in production',
                'Implement proper CORS policies',
                'Add rate limiting to prevent abuse',
                'Validate all inputs',
                'Use security headers',
                'Log security events'
            ],
            created_at=datetime.now()
        )
        
        self.templates[python_api_template.id] = python_api_template
    
    def generate_code(self, request: GenerationRequest) -> GeneratedCode:
        """Generate secure code based on request."""
        # Find matching template
        template = self._find_best_template(request)
        
        if not template:
            return self._generate_custom_code(request)
        
        # Customize template based on request
        customized_code = self._customize_template(template, request)
        
        return GeneratedCode(
            code=customized_code,
            language=request.language,
            security_features=template.security_features,
            explanation=f"Generated from template: {template.name}. {template.description}",
            warnings=self._get_security_warnings(template, request),
            dependencies=self._extract_dependencies(template),
            test_code=self._generate_test_code(template, request)
        )
    
    def _find_best_template(self, request: GenerationRequest) -> Optional[CodeTemplate]:
        """Find the best matching template for the request."""
        matching_templates = []
        
        for template in self.templates.values():
            if (template.language == request.language and 
                template.category == request.category):
                matching_templates.append(template)
        
        if not matching_templates:
            return None
        
        # For now, return the first match
        # In a real implementation, you might score templates based on requirements
        return matching_templates[0]
    
    def _customize_template(self, template: CodeTemplate, request: GenerationRequest) -> str:
        """Customize template based on specific requirements."""
        code = template.template_code
        
        # Simple placeholder replacement
        # In a real implementation, this would be more sophisticated
        for key, value in request.context.items():
            placeholder = f"{{{key}}}"
            if placeholder in code:
                code = code.replace(placeholder, str(value))
        
        return code
    
    def _generate_custom_code(self, request: GenerationRequest) -> GeneratedCode:
        """Generate custom code when no template matches."""
        # This would integrate with an AI model in a real implementation
        basic_code = f"""
# Generated {request.language.value} code for {request.category.value}
# Description: {request.description}

# TODO: Implement secure {request.category.value} functionality
# Requirements: {', '.join(request.requirements)}

def secure_implementation():
    '''
    Implement secure {request.category.value} functionality here.
    Follow security best practices for {request.language.value}.
    '''
    pass
"""
        
        return GeneratedCode(
            code=basic_code,
            language=request.language,
            security_features=["Template-based structure"],
            explanation="Basic template generated - requires manual implementation",
            warnings=["This is a basic template that requires manual implementation"],
            dependencies=[]
        )
    
    def _get_security_warnings(self, template: CodeTemplate, request: GenerationRequest) -> List[str]:
        """Get security warnings for generated code."""
        warnings = []
        
        if template.category == TemplateCategory.AUTHENTICATION:
            warnings.append("Ensure JWT secrets are stored securely")
            warnings.append("Implement proper session management")
        
        if template.category == TemplateCategory.CRYPTOGRAPHY:
            warnings.append("Never hardcode encryption keys")
            warnings.append("Use appropriate key sizes and algorithms")
        
        if template.category == TemplateCategory.DATABASE_ACCESS:
            warnings.append("Always use parameterized queries")
            warnings.append("Implement proper access controls")
        
        return warnings
    
    def _extract_dependencies(self, template: CodeTemplate) -> List[str]:
        """Extract dependencies from template code."""
        dependencies = []
        
        # Simple dependency extraction based on imports
        import_patterns = [
            r'import\s+(\w+)',
            r'from\s+(\w+)\s+import',
            r'require\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, template.template_code)
            dependencies.extend(matches)
        
        return list(set(dependencies))
    
    def _generate_test_code(self, template: CodeTemplate, request: GenerationRequest) -> Optional[str]:
        """Generate basic test code for the template."""
        if template.language == ProgrammingLanguage.PYTHON:
            return f"""
import unittest
from unittest.mock import patch, MagicMock

class Test{template.name.replace(' ', '')}(unittest.TestCase):
    '''Test cases for {template.name}'''
    
    def setUp(self):
        '''Set up test fixtures'''
        pass
    
    def test_basic_functionality(self):
        '''Test basic functionality'''
        # TODO: Implement test cases
        pass
    
    def test_security_features(self):
        '''Test security features'''
        # TODO: Test security aspects
        pass

if __name__ == '__main__':
    unittest.main()
"""
        return None
    
    def get_template(self, template_id: str) -> Optional[CodeTemplate]:
        """Get template by ID."""
        return self.templates.get(template_id)
    
    def list_templates(self, language: Optional[ProgrammingLanguage] = None, 
                      category: Optional[TemplateCategory] = None) -> List[CodeTemplate]:
        """List available templates with optional filtering."""
        templates = list(self.templates.values())
        
        if language:
            templates = [t for t in templates if t.language == language]
        
        if category:
            templates = [t for t in templates if t.category == category]
        
        return templates
    
    def add_template(self, template: CodeTemplate) -> None:
        """Add a new template."""
        self.templates[template.id] = template
        self.logger.info(f"Added template: {template.name}")
    
    def get_template_statistics(self) -> Dict[str, Any]:
        """Get statistics about available templates."""
        stats = {
            'total_templates': len(self.templates),
            'by_language': {},
            'by_category': {}
        }
        
        for template in self.templates.values():
            # Count by language
            lang = template.language.value
            stats['by_language'][lang] = stats['by_language'].get(lang, 0) + 1
            
            # Count by category
            cat = template.category.value
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
        
        return stats


# Global code generator instance
_global_code_generator: Optional[SecureCodeGenerator] = None


def get_code_generator() -> SecureCodeGenerator:
    """Get global code generator instance."""
    global _global_code_generator
    if _global_code_generator is None:
        _global_code_generator = SecureCodeGenerator()
    return _global_code_generator


def reset_code_generator() -> None:
    """Reset global code generator (for testing)."""
    global _global_code_generator
    _global_code_generator = None