"""Tests for dynamic configuration management system."""

import os
import json
import tempfile
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import pytest

from compliance_sentinel.config.dynamic_config import (
    DynamicConfigManager,
    EnvironmentConfigSource,
    FileConfigSource,
    ConfigChangeEvent
)


class TestEnvironmentConfigSource:
    """Test environment variable configuration source."""
    
    def setup_method(self):
        """Set up test environment."""
        self.source = EnvironmentConfigSource("TEST_")
        # Clear any existing test environment variables
        for key in list(os.environ.keys()):
            if key.startswith("TEST_"):
                del os.environ[key]
    
    def teardown_method(self):
        """Clean up test environment."""
        for key in list(os.environ.keys()):
            if key.startswith("TEST_"):
                del os.environ[key]
    
    @pytest.mark.asyncio
    async def test_load_simple_config(self):
        """Test loading simple configuration from environment variables."""
        os.environ["TEST_HOST"] = "localhost"
        os.environ["TEST_PORT"] = "8080"
        os.environ["TEST_DEBUG"] = "true"
        
        config = await self.source.load_config()
        
        assert config["host"] == "localhost"
        assert config["port"] == 8080
        assert config["debug"] is True
    
    @pytest.mark.asyncio
    async def test_load_nested_config(self):
        """Test loading nested configuration using dot notation."""
        os.environ["TEST_DB_HOST"] = "db.example.com"
        os.environ["TEST_DB_PORT"] = "5432"
        os.environ["TEST_DB_SSL_ENABLED"] = "false"
        
        config = await self.source.load_config()
        
        assert config["db"]["host"] == "db.example.com"
        assert config["db"]["port"] == 5432
        assert config["db"]["ssl"]["enabled"] is False
    
    @pytest.mark.asyncio
    async def test_parse_json_values(self):
        """Test parsing JSON values from environment variables."""
        os.environ["TEST_SERVERS"] = '["server1", "server2", "server3"]'
        os.environ["TEST_CONFIG"] = '{"timeout": 30, "retries": 3}'
        
        config = await self.source.load_config()
        
        assert config["servers"] == ["server1", "server2", "server3"]
        assert config["config"]["timeout"] == 30
        assert config["config"]["retries"] == 3
    
    @pytest.mark.asyncio
    async def test_validation(self):
        """Test configuration validation."""
        config = {
            "mcp_server": {
                "port": 8080
            }
        }
        
        errors = await self.source.validate_config(config)
        assert len(errors) == 0
        
        # Test invalid port
        config["mcp_server"]["port"] = 99999
        errors = await self.source.validate_config(config)
        assert len(errors) == 1
        assert "Invalid port number" in errors[0]
    
    def test_get_source_name(self):
        """Test getting source name."""
        assert self.source.get_source_name() == "environment(TEST_)"


class TestFileConfigSource:
    """Test file-based configuration source."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "config.yaml"
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    @pytest.mark.asyncio
    async def test_load_yaml_config(self):
        """Test loading YAML configuration file."""
        config_data = {
            "host": "localhost",
            "port": 8080,
            "database": {
                "host": "db.example.com",
                "port": 5432
            }
        }
        
        import yaml
        with open(self.config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        source = FileConfigSource(self.config_file)
        config = await source.load_config()
        
        assert config == config_data
    
    @pytest.mark.asyncio
    async def test_load_json_config(self):
        """Test loading JSON configuration file."""
        config_file = Path(self.temp_dir) / "config.json"
        config_data = {
            "host": "localhost",
            "port": 8080,
            "features": ["auth", "logging"]
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        source = FileConfigSource(config_file)
        config = await source.load_config()
        
        assert config == config_data
    
    @pytest.mark.asyncio
    async def test_missing_file(self):
        """Test handling missing configuration file."""
        missing_file = Path(self.temp_dir) / "missing.yaml"
        source = FileConfigSource(missing_file)
        
        config = await source.load_config()
        assert config == {}
    
    @pytest.mark.asyncio
    async def test_invalid_file_format(self):
        """Test handling invalid file format."""
        invalid_file = Path(self.temp_dir) / "config.txt"
        with open(invalid_file, 'w') as f:
            f.write("invalid content")
        
        source = FileConfigSource(invalid_file)
        config = await source.load_config()
        assert config == {}
    
    @pytest.mark.asyncio
    async def test_validation(self):
        """Test file configuration validation."""
        source = FileConfigSource(self.config_file)
        
        # Valid configuration
        errors = await source.validate_config({"key": "value"})
        assert len(errors) == 0
        
        # Invalid configuration (not a dict)
        errors = await source.validate_config("invalid")
        assert len(errors) == 1
        assert "must be a dictionary" in errors[0]
    
    def test_get_source_name(self):
        """Test getting source name."""
        source = FileConfigSource(self.config_file)
        assert source.get_source_name() == f"file({self.config_file})"


class TestDynamicConfigManager:
    """Test dynamic configuration manager."""
    
    def setup_method(self):
        """Set up test environment."""
        self.env_source = Mock(spec=EnvironmentConfigSource)
        self.file_source = Mock(spec=FileConfigSource)
        
        # Set up mock methods
        self.env_source.load_config = AsyncMock()
        self.env_source.watch_changes = AsyncMock()
        self.env_source.get_source_name.return_value = "env"
        
        self.file_source.load_config = AsyncMock()
        self.file_source.watch_changes = AsyncMock()
        self.file_source.get_source_name.return_value = "file"
        
        self.manager = DynamicConfigManager([self.env_source, self.file_source])
    
    @pytest.mark.asyncio
    async def test_initialize(self):
        """Test configuration manager initialization."""
        self.env_source.load_config.return_value = {"env_key": "env_value"}
        self.file_source.load_config.return_value = {"file_key": "file_value"}
        
        await self.manager.initialize()
        
        # Verify sources were loaded
        self.env_source.load_config.assert_called_once()
        self.file_source.load_config.assert_called_once()
        
        # Verify watchers were set up
        self.env_source.watch_changes.assert_called_once()
        self.file_source.watch_changes.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_config_simple(self):
        """Test getting simple configuration value."""
        self.env_source.load_config.return_value = {"key1": "value1"}
        self.file_source.load_config.return_value = {"key2": "value2"}
        
        await self.manager.initialize()
        
        value1 = await self.manager.get_config("key1")
        value2 = await self.manager.get_config("key2")
        
        assert value1 == "value1"
        assert value2 == "value2"
    
    @pytest.mark.asyncio
    async def test_get_config_nested(self):
        """Test getting nested configuration value."""
        self.env_source.load_config.return_value = {}
        self.file_source.load_config.return_value = {
            "database": {
                "host": "localhost",
                "port": 5432
            }
        }
        
        await self.manager.initialize()
        
        host = await self.manager.get_config("database.host")
        port = await self.manager.get_config("database.port")
        
        assert host == "localhost"
        assert port == 5432
    
    @pytest.mark.asyncio
    async def test_get_config_with_default(self):
        """Test getting configuration value with default."""
        self.env_source.load_config.return_value = {}
        self.file_source.load_config.return_value = {}
        
        await self.manager.initialize()
        
        value = await self.manager.get_config("missing.key", "default_value")
        assert value == "default_value"
    
    @pytest.mark.asyncio
    async def test_config_override_order(self):
        """Test that later sources override earlier ones."""
        self.env_source.load_config.return_value = {"key": "env_value"}
        self.file_source.load_config.return_value = {"key": "file_value"}
        
        await self.manager.initialize()
        
        value = await self.manager.get_config("key")
        assert value == "file_value"  # File source should override env source
    
    @pytest.mark.asyncio
    async def test_set_config(self):
        """Test setting runtime configuration override."""
        self.env_source.load_config.return_value = {"key": "original_value"}
        self.file_source.load_config.return_value = {}
        
        await self.manager.initialize()
        
        # Set runtime override
        await self.manager.set_config("key", "override_value")
        
        value = await self.manager.get_config("key")
        assert value == "override_value"
    
    @pytest.mark.asyncio
    async def test_watch_config(self):
        """Test watching configuration changes."""
        callback = AsyncMock()
        
        await self.manager.watch_config("test.key", callback)
        
        # Simulate config change
        event = ConfigChangeEvent(
            key="test.key",
            old_value="old",
            new_value="new",
            source="test"
        )
        
        await self.manager._handle_config_change(event)
        
        # Callback should have been called
        callback.assert_called_once_with("old", "new")
    
    @pytest.mark.asyncio
    async def test_reload_config(self):
        """Test reloading configuration."""
        self.env_source.load_config.return_value = {"key": "value1"}
        self.file_source.load_config.return_value = {}
        
        await self.manager.initialize()
        
        # Change mock return value
        self.env_source.load_config.return_value = {"key": "value2"}
        
        # Reload configuration
        await self.manager.reload_config()
        
        # Should have called load_config again
        assert self.env_source.load_config.call_count == 2
    
    @pytest.mark.asyncio
    async def test_validate_all_configs(self):
        """Test validating all configuration sources."""
        self.env_source.load_config.return_value = {"valid": "config"}
        self.env_source.validate_config = AsyncMock(return_value=[])
        
        self.file_source.load_config.return_value = {"invalid": "config"}
        self.file_source.validate_config = AsyncMock(return_value=["Error message"])
        
        results = await self.manager.validate_all_configs()
        
        assert results["env"] == []
        assert results["file"] == ["Error message"]
    
    @pytest.mark.asyncio
    async def test_get_config_info(self):
        """Test getting configuration manager information."""
        await self.manager.initialize()
        
        info = await self.manager.get_config_info()
        
        assert "sources" in info
        assert "last_reload" in info
        assert "cache_size" in info
        assert len(info["sources"]) == 2
    
    @pytest.mark.asyncio
    async def test_deep_merge_dicts(self):
        """Test deep merging of dictionaries."""
        base = {
            "a": 1,
            "b": {
                "c": 2,
                "d": 3
            }
        }
        
        override = {
            "b": {
                "d": 4,
                "e": 5
            },
            "f": 6
        }
        
        result = self.manager._deep_merge_dicts(base, override)
        
        expected = {
            "a": 1,
            "b": {
                "c": 2,
                "d": 4,
                "e": 5
            },
            "f": 6
        }
        
        assert result == expected
    
    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test configuration manager shutdown."""
        # Add a source with stop_watching method
        mock_source = Mock()
        mock_source.load_config = AsyncMock(return_value={})
        mock_source.watch_changes = AsyncMock()
        mock_source.get_source_name.return_value = "mock"
        mock_source.stop_watching = Mock()
        
        manager = DynamicConfigManager([mock_source])
        await manager.initialize()
        await manager.shutdown()
        
        mock_source.stop_watching.assert_called_once()


@pytest.mark.asyncio
async def test_integration_environment_and_file():
    """Integration test with real environment and file sources."""
    # Set up environment variables
    os.environ["INTEGRATION_TEST_HOST"] = "localhost"
    os.environ["INTEGRATION_TEST_PORT"] = "8080"
    
    # Set up configuration file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        import yaml
        config_data = {
            "port": 9090,  # Should override environment
            "database": {
                "host": "db.example.com"
            }
        }
        yaml.dump(config_data, f)
        config_file = f.name
    
    try:
        # Create sources
        env_source = EnvironmentConfigSource("INTEGRATION_TEST_")
        file_source = FileConfigSource(config_file)
        
        # Create manager
        manager = DynamicConfigManager([env_source, file_source])
        await manager.initialize()
        
        # Test merged configuration
        host = await manager.get_config("host")
        port = await manager.get_config("port")
        db_host = await manager.get_config("database.host")
        
        assert host == "localhost"  # From environment
        assert port == 9090  # From file (overrides environment)
        assert db_host == "db.example.com"  # From file only
        
        await manager.shutdown()
        
    finally:
        # Clean up
        os.unlink(config_file)
        if "INTEGRATION_TEST_HOST" in os.environ:
            del os.environ["INTEGRATION_TEST_HOST"]
        if "INTEGRATION_TEST_PORT" in os.environ:
            del os.environ["INTEGRATION_TEST_PORT"]