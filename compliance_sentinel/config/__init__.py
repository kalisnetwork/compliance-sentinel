"""Configuration module initialization."""

import asyncio
from typing import Optional
from .dynamic_config import DynamicConfigManager, EnvironmentConfigSource

# Global config manager instance
_config_manager: Optional[DynamicConfigManager] = None


def get_config_manager() -> DynamicConfigManager:
    """Get or create the global configuration manager."""
    global _config_manager
    
    if _config_manager is None:
        env_source = EnvironmentConfigSource("COMPLIANCE_SENTINEL_")
        _config_manager = DynamicConfigManager([env_source])
        
        # Initialize synchronously if we're not in an async context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're in an async context, schedule initialization
                asyncio.create_task(_config_manager.initialize())
            else:
                # We're not in an async context, run initialization
                loop.run_until_complete(_config_manager.initialize())
        except RuntimeError:
            # No event loop, create one
            asyncio.run(_config_manager.initialize())
    
    return _config_manager


async def get_config_manager_async() -> DynamicConfigManager:
    """Get or create the global configuration manager (async version)."""
    global _config_manager
    
    if _config_manager is None:
        env_source = EnvironmentConfigSource("COMPLIANCE_SENTINEL_")
        _config_manager = DynamicConfigManager([env_source])
        await _config_manager.initialize()
    
    return _config_manager


def get_config_value(key: str, default=None):
    """Get configuration value synchronously."""
    config_manager = get_config_manager()
    
    # For synchronous access, we'll use a simple approach
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're in an async context, this won't work well
            # Return default for now
            return default
        else:
            return loop.run_until_complete(config_manager.get_config(key, default))
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(config_manager.get_config(key, default))


async def get_config_value_async(key: str, default=None):
    """Get configuration value asynchronously."""
    config_manager = await get_config_manager_async()
    return await config_manager.get_config(key, default)