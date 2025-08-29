"""Secret management configuration source for secure credential handling."""

import os
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from .dynamic_config import ConfigSource, ConfigChangeEvent

logger = logging.getLogger(__name__)


@dataclass
class SecretConfig:
    """Configuration for secret management."""
    provider: str  # aws, azure, vault, env
    region: Optional[str] = None
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    cache_ttl: int = 300  # 5 minutes
    auto_refresh: bool = True
    refresh_interval: int = 3600  # 1 hour


@dataclass
class CachedSecret:
    """Cached secret with expiration."""
    value: Any
    expires_at: datetime
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def is_expired(self) -> bool:
        """Check if secret is expired."""
        return datetime.utcnow() > self.expires_at


class SecretProvider:
    """Base class for secret providers."""
    
    async def get_secret(self, secret_name: str) -> Any:
        """Get secret value."""
        raise NotImplementedError
    
    async def list_secrets(self) -> List[str]:
        """List available secrets."""
        raise NotImplementedError


class EnvironmentSecretProvider(SecretProvider):
    """Environment variable secret provider."""
    
    def __init__(self, prefix: str = "SECRET_"):
        self.prefix = prefix
    
    async def get_secret(self, secret_name: str) -> Any:
        """Get secret from environment variable."""
        env_key = f"{self.prefix}{secret_name.upper()}"
        value = os.getenv(env_key)
        
        if value is None:
            raise KeyError(f"Secret not found: {secret_name}")
        
        # Try to parse as JSON for complex values
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    
    async def list_secrets(self) -> List[str]:
        """List available secrets from environment."""
        secrets = []
        for key in os.environ:
            if key.startswith(self.prefix):
                secret_name = key[len(self.prefix):].lower()
                secrets.append(secret_name)
        return secrets


class AWSSecretsManagerProvider(SecretProvider):
    """AWS Secrets Manager provider."""
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self._client = None
    
    async def _get_client(self):
        """Get AWS Secrets Manager client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client('secretsmanager', region_name=self.region)
            except ImportError:
                raise ImportError("boto3 is required for AWS Secrets Manager support")
        return self._client
    
    async def get_secret(self, secret_name: str) -> Any:
        """Get secret from AWS Secrets Manager."""
        try:
            client = await self._get_client()
            response = client.get_secret_value(SecretId=secret_name)
            
            secret_value = response['SecretString']
            
            # Try to parse as JSON
            try:
                return json.loads(secret_value)
            except (json.JSONDecodeError, ValueError):
                return secret_value
                
        except Exception as e:
            logger.error(f"Error getting secret from AWS: {e}")
            raise KeyError(f"Secret not found or accessible: {secret_name}")
    
    async def list_secrets(self) -> List[str]:
        """List available secrets from AWS Secrets Manager."""
        try:
            client = await self._get_client()
            response = client.list_secrets()
            return [secret['Name'] for secret in response['SecretList']]
        except Exception as e:
            logger.error(f"Error listing secrets from AWS: {e}")
            return []


class HashiCorpVaultProvider(SecretProvider):
    """HashiCorp Vault secret provider."""
    
    def __init__(self, vault_url: str, vault_token: str):
        self.vault_url = vault_url.rstrip('/')
        self.vault_token = vault_token
        self._session = None
    
    async def _get_session(self):
        """Get HTTP session for Vault API."""
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    headers={'X-Vault-Token': self.vault_token}
                )
            except ImportError:
                raise ImportError("aiohttp is required for HashiCorp Vault support")
        return self._session
    
    async def get_secret(self, secret_name: str) -> Any:
        """Get secret from HashiCorp Vault."""
        try:
            session = await self._get_session()
            url = f"{self.vault_url}/v1/secret/data/{secret_name}"
            
            async with session.get(url) as response:
                if response.status == 404:
                    raise KeyError(f"Secret not found: {secret_name}")
                elif response.status != 200:
                    raise Exception(f"Vault API error: {response.status}")
                
                data = await response.json()
                return data['data']['data']
                
        except Exception as e:
            logger.error(f"Error getting secret from Vault: {e}")
            raise KeyError(f"Secret not found or accessible: {secret_name}")
    
    async def list_secrets(self) -> List[str]:
        """List available secrets from HashiCorp Vault."""
        try:
            session = await self._get_session()
            url = f"{self.vault_url}/v1/secret/metadata"
            
            async with session.get(url) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                return list(data['data']['keys'])
                
        except Exception as e:
            logger.error(f"Error listing secrets from Vault: {e}")
            return []
    
    async def close(self):
        """Close HTTP session."""
        if self._session:
            await self._session.close()


class SecretManagerConfigSource(ConfigSource):
    """Configuration source that loads secrets from secret management systems."""
    
    def __init__(self, config: SecretConfig, secret_mappings: Dict[str, str]):
        """
        Initialize secret manager config source.
        
        Args:
            config: Secret management configuration
            secret_mappings: Mapping of config keys to secret names
                           e.g., {'database.password': 'db-password', 'api.key': 'api-key'}
        """
        self.config = config
        self.secret_mappings = secret_mappings
        self.provider = self._create_provider()
        self.secret_cache = {}
        self.watchers = []
        self.refresh_task = None
    
    def _create_provider(self) -> SecretProvider:
        """Create appropriate secret provider based on configuration."""
        if self.config.provider == "aws":
            return AWSSecretsManagerProvider(self.config.region or "us-east-1")
        elif self.config.provider == "vault":
            if not self.config.vault_url or not self.config.vault_token:
                raise ValueError("vault_url and vault_token required for Vault provider")
            return HashiCorpVaultProvider(self.config.vault_url, self.config.vault_token)
        elif self.config.provider == "env":
            return EnvironmentSecretProvider()
        else:
            raise ValueError(f"Unsupported secret provider: {self.config.provider}")
    
    async def load_config(self) -> Dict[str, Any]:
        """Load configuration from secret management system."""
        config = {}
        
        for config_key, secret_name in self.secret_mappings.items():
            try:
                # Check cache first
                if secret_name in self.secret_cache:
                    cached_secret = self.secret_cache[secret_name]
                    if not cached_secret.is_expired:
                        self._set_nested_value(config, config_key, cached_secret.value)
                        continue
                
                # Fetch from provider
                secret_value = await self.provider.get_secret(secret_name)
                
                # Cache the secret
                expires_at = datetime.utcnow() + timedelta(seconds=self.config.cache_ttl)
                self.secret_cache[secret_name] = CachedSecret(
                    value=secret_value,
                    expires_at=expires_at
                )
                
                # Set in config
                self._set_nested_value(config, config_key, secret_value)
                
                logger.debug(f"Loaded secret: {secret_name} -> {config_key}")
                
            except Exception as e:
                logger.error(f"Error loading secret {secret_name}: {e}")
                # Don't fail completely, just skip this secret
                continue
        
        return config
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """Set nested configuration value using dot notation."""
        keys = key.split('.')
        current = config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    async def watch_changes(self, callback: Callable[[ConfigChangeEvent], None]) -> None:
        """Watch for secret changes (via periodic refresh)."""
        self.watchers.append(callback)
        
        if self.config.auto_refresh and self.refresh_task is None:
            self.refresh_task = asyncio.create_task(self._periodic_refresh())
    
    async def _periodic_refresh(self) -> None:
        """Periodically refresh secrets."""
        while True:
            try:
                await asyncio.sleep(self.config.refresh_interval)
                
                # Load fresh configuration
                old_config = {}
                for config_key, secret_name in self.secret_mappings.items():
                    if secret_name in self.secret_cache:
                        cached_secret = self.secret_cache[secret_name]
                        self._set_nested_value(old_config, config_key, cached_secret.value)
                
                # Clear cache to force refresh
                self.secret_cache.clear()
                new_config = await self.load_config()
                
                # Notify watchers of changes
                for watcher in self.watchers:
                    try:
                        event = ConfigChangeEvent(
                            key="secrets",
                            old_value=old_config,
                            new_value=new_config,
                            source=self.get_source_name()
                        )
                        watcher(event)
                    except Exception as e:
                        logger.error(f"Error notifying secret watcher: {e}")
                
                logger.debug("Completed periodic secret refresh")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic secret refresh: {e}")
    
    def get_source_name(self) -> str:
        """Get the name of this configuration source."""
        return f"secrets({self.config.provider})"
    
    async def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate secret configuration."""
        errors = []
        
        # Check if we can connect to the secret provider
        try:
            available_secrets = await self.provider.list_secrets()
            
            # Check if all required secrets are available
            for config_key, secret_name in self.secret_mappings.items():
                if secret_name not in available_secrets:
                    errors.append(f"Secret not found: {secret_name} (for {config_key})")
                    
        except Exception as e:
            errors.append(f"Cannot connect to secret provider: {e}")
        
        return errors
    
    async def refresh_secrets(self) -> None:
        """Manually refresh all secrets."""
        logger.info("Manually refreshing secrets")
        self.secret_cache.clear()
        await self.load_config()
    
    async def shutdown(self) -> None:
        """Shutdown secret manager and cleanup resources."""
        if self.refresh_task:
            self.refresh_task.cancel()
            try:
                await self.refresh_task
            except asyncio.CancelledError:
                pass
        
        # Close provider connections if needed
        if hasattr(self.provider, 'close'):
            await self.provider.close()
        
        logger.debug("SecretManagerConfigSource shutdown complete")


def create_secret_config_source(
    provider: str,
    secret_mappings: Dict[str, str],
    **kwargs
) -> SecretManagerConfigSource:
    """
    Factory function to create secret configuration source.
    
    Args:
        provider: Secret provider type ('aws', 'vault', 'env')
        secret_mappings: Mapping of config keys to secret names
        **kwargs: Additional configuration options
    
    Returns:
        SecretManagerConfigSource instance
    """
    config = SecretConfig(provider=provider, **kwargs)
    return SecretManagerConfigSource(config, secret_mappings)