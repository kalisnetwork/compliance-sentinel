"""Authentication and authorization for MCP server with environment variable support."""

import hashlib
import secrets
import time
import os
import json
from typing import Dict, Optional, List, Set, Union, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)


def _get_auth_env_var(key: str, default: Any, var_type: type = str) -> Any:
    """Get authentication-specific environment variable."""
    env_key = f"COMPLIANCE_SENTINEL_AUTH_{key.upper()}"
    value = os.getenv(env_key)
    
    if value is None:
        return default
    
    try:
        if var_type == bool:
            return value.lower() in ('true', '1', 'yes', 'on')
        elif var_type == int:
            return int(value)
        elif var_type == float:
            return float(value)
        elif var_type == set:
            # Parse as JSON array and convert to set
            if isinstance(value, str):
                return set(json.loads(value))
            return set(value)
        elif var_type == list:
            if isinstance(value, str):
                return json.loads(value)
            return list(value)
        elif var_type == dict:
            return json.loads(value)
        else:
            return value
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid value for auth config {key}: {value}. Error: {e}")


@dataclass
class AuthConfig:
    """Authentication configuration with environment variable support."""
    jwt_secret: str = field(default_factory=lambda: _get_auth_env_var("jwt_secret", None) or secrets.token_urlsafe(32))
    jwt_algorithm: str = field(default_factory=lambda: _get_auth_env_var("jwt_algorithm", "HS256"))
    jwt_expiry_hours: int = field(default_factory=lambda: _get_auth_env_var("jwt_expiry_hours", 24, int))
    api_key_length: int = field(default_factory=lambda: _get_auth_env_var("api_key_length", 32, int))
    default_api_key_expiry_days: int = field(default_factory=lambda: _get_auth_env_var("default_api_key_expiry_days", 365, int))
    enable_default_admin_key: bool = field(default_factory=lambda: _get_auth_env_var("enable_default_admin_key", True, bool))
    password_hash_schemes: List[str] = field(default_factory=lambda: _get_auth_env_var("password_hash_schemes", ["bcrypt"], list))
    admin_api_key: Optional[str] = field(default_factory=lambda: _get_auth_env_var("admin_api_key", None))
    
    def __post_init__(self):
        """Validate authentication configuration."""
        errors = []
        
        if not self.jwt_secret:
            errors.append("JWT secret is required")
        
        if len(self.jwt_secret) < 32:
            errors.append("JWT secret must be at least 32 characters")
        
        if self.jwt_expiry_hours < 1:
            errors.append("JWT expiry hours must be at least 1")
        
        if self.api_key_length < 16:
            errors.append("API key length must be at least 16")
        
        if not self.password_hash_schemes:
            errors.append("At least one password hash scheme must be specified")
        
        if errors:
            raise ValueError(f"Authentication configuration validation failed: {'; '.join(errors)}")
    
    def get_secure_defaults(self, environment: str = "development") -> Dict[str, Any]:
        """Get secure defaults based on environment."""
        if environment == "production":
            return {
                "jwt_expiry_hours": 8,  # Shorter expiry for production
                "default_api_key_expiry_days": 90,  # Shorter API key expiry
                "enable_default_admin_key": False,  # Disable default admin key
                "password_hash_schemes": ["bcrypt", "argon2"]  # Stronger hashing
            }
        else:
            return {
                "jwt_expiry_hours": 24,
                "default_api_key_expiry_days": 365,
                "enable_default_admin_key": True,
                "password_hash_schemes": ["bcrypt"]
            }


@dataclass
class APIKey:
    """Represents an API key with metadata."""
    key_id: str
    key_hash: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0
    permissions: Set[str] = field(default_factory=set)
    rate_limit_tier: str = "normal"  # trusted, normal, limited
    is_active: bool = True
    
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def update_usage(self) -> None:
        """Update usage statistics."""
        self.last_used = datetime.utcnow()
        self.usage_count += 1


@dataclass
class JWTToken:
    """Represents a JWT token with metadata."""
    token_id: str
    user_id: str
    issued_at: datetime
    expires_at: datetime
    permissions: Set[str] = field(default_factory=set)
    is_revoked: bool = False
    
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired or revoked)."""
        return not self.is_expired() and not self.is_revoked


class AuthManager:
    """Manages authentication and authorization for the MCP server with environment-aware configuration."""
    
    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize authentication manager with configuration."""
        self.config = config or AuthConfig()
        
        # Password hashing with configurable schemes
        self.pwd_context = CryptContext(schemes=self.config.password_hash_schemes, deprecated="auto")
        
        # Storage for API keys and tokens
        self.api_keys: Dict[str, APIKey] = {}
        self.jwt_tokens: Dict[str, JWTToken] = {}
        self.revoked_tokens: Set[str] = set()
        
        # Load permissions from environment or use defaults
        self.default_permissions = _get_auth_env_var("default_permissions", {
            "read:vulnerabilities",
            "read:compliance",
            "read:cache_stats"
        }, set)
        
        self.admin_permissions = _get_auth_env_var("admin_permissions", {
            "read:vulnerabilities",
            "write:vulnerabilities", 
            "read:compliance",
            "write:compliance",
            "read:cache_stats",
            "write:cache_invalidate",
            "admin:api_keys",
            "admin:users"
        }, set)
        
        # Create default admin API key if enabled
        if self.config.enable_default_admin_key:
            self._create_default_admin_key()
        else:
            logger.info("Default admin API key creation disabled by configuration")
    
    def _create_default_admin_key(self) -> None:
        """Create a default admin API key for initial setup."""
        # Check if admin key already exists from environment
        if self.config.admin_api_key:
            # Use existing admin key from environment
            key_id = secrets.token_urlsafe(16)
            key_hash = self._hash_api_key(self.config.admin_api_key)
            
            admin_api_key = APIKey(
                key_id=key_id,
                key_hash=key_hash,
                name="admin_from_env",
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=self.config.default_api_key_expiry_days),
                permissions=self.admin_permissions,
                rate_limit_tier="trusted"
            )
            self.api_keys[key_id] = admin_api_key
            logger.info("Using admin API key from environment")
        else:
            # Generate new admin key
            admin_key = self.create_api_key(
                name="default_admin",
                permissions=self.admin_permissions,
                rate_limit_tier="trusted",
                expires_in_days=self.config.default_api_key_expiry_days
            )
            
            logger.info(f"Created default admin API key: {admin_key}")
            logger.warning("Please change the default admin API key in production!")
            
            # In production, suggest using environment variable
            environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
            if environment == "production":
                logger.warning(f"For production, set COMPLIANCE_SENTINEL_AUTH_ADMIN_API_KEY={admin_key} and disable default key creation")
    
    def create_api_key(
        self,
        name: str,
        permissions: Optional[Set[str]] = None,
        rate_limit_tier: str = "normal",
        expires_in_days: Optional[int] = None
    ) -> str:
        """
        Create a new API key.
        
        Args:
            name: Human-readable name for the key
            permissions: Set of permissions for the key
            rate_limit_tier: Rate limiting tier (trusted, normal, limited)
            expires_in_days: Expiration in days (None for no expiration)
            
        Returns:
            The generated API key string
        """
        # Generate secure API key with configurable length
        api_key = f"cs_{secrets.token_urlsafe(self.config.api_key_length)}"
        key_id = secrets.token_urlsafe(16)
        
        # Hash the key for storage
        key_hash = self._hash_api_key(api_key)
        
        # Set expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Create API key object
        api_key_obj = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            permissions=permissions or self.default_permissions.copy(),
            rate_limit_tier=rate_limit_tier
        )
        
        # Store the key
        self.api_keys[key_id] = api_key_obj
        
        logger.info(f"Created API key '{name}' with ID {key_id}")
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """
        Validate an API key and return the associated APIKey object.
        
        Args:
            api_key: The API key to validate
            
        Returns:
            APIKey object if valid, None otherwise
        """
        if not api_key or not api_key.startswith("cs_"):
            return None
        
        key_hash = self._hash_api_key(api_key)
        
        # Find matching key
        for api_key_obj in self.api_keys.values():
            if api_key_obj.key_hash == key_hash:
                # Check if key is active and not expired
                if not api_key_obj.is_active or api_key_obj.is_expired():
                    logger.warning(f"API key {api_key_obj.key_id} is inactive or expired")
                    return None
                
                # Update usage statistics
                api_key_obj.update_usage()
                
                logger.debug(f"API key {api_key_obj.key_id} validated successfully")
                return api_key_obj
        
        logger.warning("Invalid API key provided")
        return None
    
    def revoke_api_key(self, key_id: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: The key ID to revoke
            
        Returns:
            True if key was revoked, False if not found
        """
        if key_id in self.api_keys:
            self.api_keys[key_id].is_active = False
            logger.info(f"Revoked API key {key_id}")
            return True
        
        logger.warning(f"Attempted to revoke non-existent API key {key_id}")
        return False
    
    def list_api_keys(self) -> List[Dict[str, any]]:
        """List all API keys (without sensitive data)."""
        keys_info = []
        
        for api_key in self.api_keys.values():
            keys_info.append({
                "key_id": api_key.key_id,
                "name": api_key.name,
                "created_at": api_key.created_at.isoformat(),
                "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                "last_used": api_key.last_used.isoformat() if api_key.last_used else None,
                "usage_count": api_key.usage_count,
                "permissions": list(api_key.permissions),
                "rate_limit_tier": api_key.rate_limit_tier,
                "is_active": api_key.is_active,
                "is_expired": api_key.is_expired()
            })
        
        return keys_info
    
    def create_jwt_token(
        self,
        user_id: str,
        permissions: Optional[Set[str]] = None,
        expires_in_hours: Optional[int] = None
    ) -> str:
        """
        Create a JWT token.
        
        Args:
            user_id: User identifier
            permissions: Set of permissions for the token
            expires_in_hours: Token expiration in hours
            
        Returns:
            JWT token string
        """
        token_id = secrets.token_urlsafe(16)
        issued_at = datetime.utcnow()
        expires_in = expires_in_hours or self.config.jwt_expiry_hours
        expires_at = issued_at + timedelta(hours=expires_in)
        
        # Create token payload
        payload = {
            "token_id": token_id,
            "user_id": user_id,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "permissions": list(permissions or self.default_permissions)
        }
        
        # Generate JWT
        token = jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)
        
        # Store token metadata
        jwt_token_obj = JWTToken(
            token_id=token_id,
            user_id=user_id,
            issued_at=issued_at,
            expires_at=expires_at,
            permissions=permissions or self.default_permissions.copy()
        )
        
        self.jwt_tokens[token_id] = jwt_token_obj
        
        logger.info(f"Created JWT token for user {user_id} with ID {token_id}")
        return token
    
    def validate_jwt_token(self, token: str) -> Optional[JWTToken]:
        """
        Validate a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            JWTToken object if valid, None otherwise
        """
        try:
            # Decode and verify token
            payload = jwt.decode(token, self.config.jwt_secret, algorithms=[self.config.jwt_algorithm])
            
            token_id = payload.get("token_id")
            if not token_id:
                logger.warning("JWT token missing token_id")
                return None
            
            # Check if token is revoked
            if token_id in self.revoked_tokens:
                logger.warning(f"JWT token {token_id} has been revoked")
                return None
            
            # Get token metadata
            jwt_token_obj = self.jwt_tokens.get(token_id)
            if not jwt_token_obj:
                logger.warning(f"JWT token {token_id} not found in storage")
                return None
            
            # Validate token
            if not jwt_token_obj.is_valid():
                logger.warning(f"JWT token {token_id} is invalid or expired")
                return None
            
            logger.debug(f"JWT token {token_id} validated successfully")
            return jwt_token_obj
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
    
    def revoke_jwt_token(self, token_id: str) -> bool:
        """
        Revoke a JWT token.
        
        Args:
            token_id: Token ID to revoke
            
        Returns:
            True if token was revoked, False if not found
        """
        if token_id in self.jwt_tokens:
            self.jwt_tokens[token_id].is_revoked = True
            self.revoked_tokens.add(token_id)
            logger.info(f"Revoked JWT token {token_id}")
            return True
        
        logger.warning(f"Attempted to revoke non-existent JWT token {token_id}")
        return False
    
    def check_permission(
        self,
        auth_obj: Union[APIKey, JWTToken],
        required_permission: str
    ) -> bool:
        """
        Check if an authenticated entity has a required permission.
        
        Args:
            auth_obj: APIKey or JWTToken object
            required_permission: Permission to check
            
        Returns:
            True if permission is granted
        """
        if not auth_obj or not hasattr(auth_obj, 'permissions'):
            return False
        
        # Check for specific permission or admin wildcard
        has_permission = (
            required_permission in auth_obj.permissions or
            "admin:*" in auth_obj.permissions
        )
        
        if not has_permission:
            logger.warning(f"Permission denied: {required_permission} not in {auth_obj.permissions}")
        
        return has_permission
    
    def get_rate_limit_tier(self, auth_obj: Union[APIKey, JWTToken]) -> str:
        """
        Get rate limit tier for an authenticated entity.
        
        Args:
            auth_obj: APIKey or JWTToken object
            
        Returns:
            Rate limit tier string
        """
        if isinstance(auth_obj, APIKey):
            return auth_obj.rate_limit_tier
        elif isinstance(auth_obj, JWTToken):
            # JWT tokens get normal tier by default
            return "normal"
        else:
            return "limited"
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens and keys.
        
        Returns:
            Number of items cleaned up
        """
        cleaned_count = 0
        current_time = datetime.utcnow()
        
        # Clean up expired API keys
        expired_keys = [
            key_id for key_id, api_key in self.api_keys.items()
            if api_key.is_expired()
        ]
        
        for key_id in expired_keys:
            del self.api_keys[key_id]
            cleaned_count += 1
            logger.info(f"Cleaned up expired API key {key_id}")
        
        # Clean up expired JWT tokens
        expired_tokens = [
            token_id for token_id, jwt_token in self.jwt_tokens.items()
            if jwt_token.is_expired()
        ]
        
        for token_id in expired_tokens:
            del self.jwt_tokens[token_id]
            self.revoked_tokens.discard(token_id)  # Remove from revoked set too
            cleaned_count += 1
            logger.info(f"Cleaned up expired JWT token {token_id}")
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired authentication items")
        
        return cleaned_count
    
    def get_auth_statistics(self) -> Dict[str, any]:
        """Get authentication statistics."""
        current_time = datetime.utcnow()
        
        # API key statistics
        active_api_keys = sum(1 for key in self.api_keys.values() if key.is_active and not key.is_expired())
        expired_api_keys = sum(1 for key in self.api_keys.values() if key.is_expired())
        
        # JWT token statistics
        active_jwt_tokens = sum(1 for token in self.jwt_tokens.values() if token.is_valid())
        expired_jwt_tokens = sum(1 for token in self.jwt_tokens.values() if token.is_expired())
        revoked_jwt_tokens = len(self.revoked_tokens)
        
        # Usage statistics
        total_api_usage = sum(key.usage_count for key in self.api_keys.values())
        
        return {
            "api_keys": {
                "total": len(self.api_keys),
                "active": active_api_keys,
                "expired": expired_api_keys,
                "total_usage": total_api_usage
            },
            "jwt_tokens": {
                "total": len(self.jwt_tokens),
                "active": active_jwt_tokens,
                "expired": expired_jwt_tokens,
                "revoked": revoked_jwt_tokens
            },
            "permissions": {
                "default_permissions": list(self.default_permissions),
                "admin_permissions": list(self.admin_permissions)
            }
        }
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()


class PermissionManager:
    """Manages permissions and roles with environment variable support."""
    
    def __init__(self):
        """Initialize permission manager with environment-aware roles."""
        # Load roles from environment or use defaults
        default_roles = {
            "viewer": {
                "read:vulnerabilities",
                "read:compliance",
                "read:cache_stats"
            },
            "analyst": {
                "read:vulnerabilities",
                "read:compliance", 
                "read:cache_stats",
                "write:compliance"
            },
            "admin": {
                "read:vulnerabilities",
                "write:vulnerabilities",
                "read:compliance",
                "write:compliance",
                "read:cache_stats",
                "write:cache_invalidate",
                "admin:api_keys",
                "admin:users",
                "admin:*"
            }
        }
        
        # Load custom roles from environment
        custom_roles_env = _get_auth_env_var("custom_roles", None)
        if custom_roles_env:
            try:
                if isinstance(custom_roles_env, dict):
                    # Convert list permissions to sets
                    for role_name, permissions in custom_roles_env.items():
                        if isinstance(permissions, list):
                            custom_roles_env[role_name] = set(permissions)
                    default_roles.update(custom_roles_env)
                    logger.info(f"Loaded {len(custom_roles_env)} custom roles from environment")
            except Exception as e:
                logger.warning(f"Error loading custom roles from environment: {e}")
        
        self.roles = default_roles
        
        # Load environment-specific role modifications
        environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        if environment == "production":
            self._apply_production_role_restrictions()
    
    def get_role_permissions(self, role: str) -> Set[str]:
        """Get permissions for a role."""
        return self.roles.get(role, set())
    
    def add_role(self, role_name: str, permissions: Set[str]) -> None:
        """Add a new role."""
        self.roles[role_name] = permissions
        logger.info(f"Added role '{role_name}' with {len(permissions)} permissions")
    
    def update_role_permissions(self, role_name: str, permissions: Set[str]) -> bool:
        """Update permissions for an existing role."""
        if role_name not in self.roles:
            return False
        
        old_permissions = self.roles[role_name]
        self.roles[role_name] = permissions
        
        logger.info(f"Updated role '{role_name}' permissions: "
                   f"{len(old_permissions)} -> {len(permissions)}")
        return True
    
    def _apply_production_role_restrictions(self) -> None:
        """Apply production-specific role restrictions."""
        # In production, be more restrictive with admin permissions
        if "admin" in self.roles:
            # Remove wildcard admin permission in production
            self.roles["admin"].discard("admin:*")
            logger.info("Applied production restrictions to admin role")
        
        # Add read-only role for production monitoring
        self.roles["readonly"] = {
            "read:vulnerabilities",
            "read:compliance",
            "read:cache_stats"
        }
    
    def validate_permissions(self, permissions: Set[str]) -> Tuple[bool, List[str]]:
        """
        Validate a set of permissions.
        
        Returns:
            Tuple of (is_valid, list_of_invalid_permissions)
        """
        # Load valid permissions from environment or use defaults
        valid_permissions = _get_auth_env_var("valid_permissions", {
            "read:vulnerabilities",
            "write:vulnerabilities",
            "read:compliance",
            "write:compliance",
            "read:cache_stats",
            "write:cache_invalidate",
            "admin:api_keys",
            "admin:users",
            "admin:*"
        }, set)
        
        invalid_permissions = []
        for permission in permissions:
            if permission not in valid_permissions:
                invalid_permissions.append(permission)
        
        return len(invalid_permissions) == 0, invalid_permissions
    
    def get_environment_permissions(self) -> Set[str]:
        """Get all valid permissions for current environment."""
        environment = os.getenv("COMPLIANCE_SENTINEL_ENVIRONMENT", "development")
        
        base_permissions = {
            "read:vulnerabilities",
            "write:vulnerabilities",
            "read:compliance",
            "write:compliance",
            "read:cache_stats",
            "write:cache_invalidate",
            "admin:api_keys",
            "admin:users"
        }
        
        # Add admin wildcard only in development
        if environment != "production":
            base_permissions.add("admin:*")
        
        return base_permissions