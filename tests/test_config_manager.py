"""Tests for configuration management system."""

import pytest
import tempfile
import yaml
import json
from pathlib import Path
from datetime import datetime

from compliance_sentinel.config.config_manager import (
    ConfigManager, ProjectConfig, AnalysisRuleConfig, 
    SeverityThresholdConfig, FilePatternConfig, MCPServerConfig
)
from compliance_sentinel.config.validator import ConfigValidator


@pytest.fixture
def temp_config_dir():
    """Create temporary configuration directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def config_manager(temp_config_dir):
    """Create config manager with temporary directory."""
    return ConfigManager(temp_config_dir)


@pytest.fixture
def sample_config():
    """Create sample project configuration."""
    return ProjectConfig(
        project_name="test-project",
        version="1.0.0",
        description="Test project configuration"
    )


class TestConfigManager:
    """Test cases for ConfigManager."""
    
    def test_initialization(self, temp_config_dir):
        """Test config manager initialization."""
        manager = ConfigManager(temp_config_dir)
        
        assert manager.config_dir == temp_config_dir
        assert manager.config_dir.exists()
        assert manager.project_config_file == temp_config_dir / "config.yaml"
    
    def test_create_default_config(self, config_manager):
        """Test creating default configuration."""
        config = config_manager.create_default_config("test-project")
        
        assert config.project_name == "test-project"
        assert config.description == "Compliance Sentinel configuration for test-project"
        assert len(config.custom_rules) > 0
        assert len(config.mcp_servers) > 0
        assert isinstance(config.file_patterns, FilePatternConfig)
        assert isinstance(config.severity_thresholds, SeverityThresholdConfig)
    
    def test_save_and_load_config(self, config_manager, sample_config):
        """Test saving and loading configuration."""
        # Save configuration
        assert config_manager.save_project_config(sample_config)
        
        # Load configuration
        loaded_config = config_manager.load_project_config()
        
        assert loaded_config.project_name == sample_config.project_name
        assert loaded_config.version == sample_config.version
        assert loaded_config.description == sample_config.description
    
    def test_config_validation_on_save(self, config_manager):
        """Test that invalid configurations are rejected on save."""
        invalid_config = ProjectConfig(
            project_name="",  # Invalid: empty name
            version="1.0.0"
        )
        
        # Should fail to save invalid config
        assert not config_manager.save_project_config(invalid_config)
    
    def test_config_cascading(self, config_manager, temp_config_dir):
        """Test configuration cascading from multiple sources."""
        # Create user config
        user_config_dir = temp_config_dir / "user"
        user_config_dir.mkdir()
        user_config_file = user_config_dir / "config.yaml"
        
        user_config = {
            'project_name': 'user-project',
            'version': '2.0.0',
            'severity_thresholds': {
                'critical_threshold': 1
            }
        }
        
        with open(user_config_file, 'w') as f:
            yaml.dump(user_config, f)
        
        # Mock user config file path
        config_manager.user_config_file = user_config_file
        
        # Create project config that overrides some values
        project_config = ProjectConfig(
            project_name="project-override",
            version="3.0.0"
        )
        config_manager.save_project_config(project_config)
        
        # Load merged configuration
        loaded_config = config_manager.load_project_config()
        
        # Project config should override user config
        assert loaded_config.project_name == "project-override"
        assert loaded_config.version == "3.0.0"
        # But user config values should be preserved where not overridden
        assert loaded_config.severity_thresholds.critical_threshold == 1
    
    def test_add_custom_rule(self, config_manager, sample_config):
        """Test adding custom analysis rules."""
        config_manager.save_project_config(sample_config)
        
        rule = AnalysisRuleConfig(
            rule_id="TEST-001",
            name="Test Rule",
            description="Test rule description",
            severity="high",
            pattern=r"test_pattern",
            file_patterns=["*.py"]
        )
        
        assert config_manager.add_custom_rule(rule)
        
        # Verify rule was added
        rules = config_manager.get_custom_rules()
        rule_ids = [r.rule_id for r in rules]
        assert "TEST-001" in rule_ids
    
    def test_duplicate_rule_id_rejection(self, config_manager, sample_config):
        """Test that duplicate rule IDs are rejected."""
        config_manager.save_project_config(sample_config)
        
        rule1 = AnalysisRuleConfig(
            rule_id="DUPLICATE",
            name="First Rule",
            description="First rule",
            severity="high"
        )
        
        rule2 = AnalysisRuleConfig(
            rule_id="DUPLICATE",  # Same ID
            name="Second Rule",
            description="Second rule",
            severity="medium"
        )
        
        assert config_manager.add_custom_rule(rule1)
        assert not config_manager.add_custom_rule(rule2)  # Should fail
    
    def test_remove_custom_rule(self, config_manager, sample_config):
        """Test removing custom analysis rules."""
        config_manager.save_project_config(sample_config)
        
        rule = AnalysisRuleConfig(
            rule_id="REMOVE-ME",
            name="Rule to Remove",
            description="This rule will be removed",
            severity="low"
        )
        
        config_manager.add_custom_rule(rule)
        assert config_manager.remove_custom_rule("REMOVE-ME")
        
        # Verify rule was removed
        rules = config_manager.get_custom_rules()
        rule_ids = [r.rule_id for r in rules]
        assert "REMOVE-ME" not in rule_ids
    
    def test_add_mcp_server(self, config_manager, sample_config):
        """Test adding MCP server configuration."""
        config_manager.save_project_config(sample_config)
        
        server = MCPServerConfig(
            server_name="test-server",
            endpoint_url="https://api.example.com",
            api_key="test-key",
            timeout_seconds=45
        )
        
        assert config_manager.add_mcp_server(server)
        
        # Verify server was added
        servers = config_manager.get_mcp_servers()
        server_names = [s.server_name for s in servers]
        assert "test-server" in server_names
    
    def test_update_severity_thresholds(self, config_manager, sample_config):
        """Test updating severity thresholds."""
        config_manager.save_project_config(sample_config)
        
        new_thresholds = SeverityThresholdConfig(
            critical_threshold=2,
            high_threshold=10,
            medium_threshold=25,
            low_threshold=100
        )
        
        assert config_manager.update_severity_thresholds(new_thresholds)
        
        # Verify thresholds were updated
        loaded_thresholds = config_manager.get_effective_severity_thresholds()
        assert loaded_thresholds.critical_threshold == 2
        assert loaded_thresholds.high_threshold == 10
        assert loaded_thresholds.medium_threshold == 25
        assert loaded_thresholds.low_threshold == 100
    
    def test_export_import_config(self, config_manager, sample_config, temp_config_dir):
        """Test exporting and importing configuration."""
        config_manager.save_project_config(sample_config)
        
        # Export configuration
        export_file = temp_config_dir / "exported_config.yaml"
        assert config_manager.export_config(export_file, "yaml")
        assert export_file.exists()
        
        # Modify current config
        modified_config = ProjectConfig(
            project_name="modified-project",
            version="2.0.0"
        )
        config_manager.save_project_config(modified_config)
        
        # Import original configuration
        assert config_manager.import_config(export_file)
        
        # Verify original config was restored
        loaded_config = config_manager.load_project_config()
        assert loaded_config.project_name == sample_config.project_name
        assert loaded_config.version == sample_config.version
    
    def test_json_export_import(self, config_manager, sample_config, temp_config_dir):
        """Test JSON export and import."""
        config_manager.save_project_config(sample_config)
        
        # Export as JSON
        export_file = temp_config_dir / "config.json"
        assert config_manager.export_config(export_file, "json")
        
        # Verify JSON format
        with open(export_file, 'r') as f:
            json_data = json.load(f)
        
        assert json_data['project_name'] == sample_config.project_name
        
        # Import JSON
        assert config_manager.import_config(export_file)


class TestAnalysisRuleConfig:
    """Test cases for AnalysisRuleConfig."""
    
    def test_valid_rule_validation(self):
        """Test validation of valid rule."""
        rule = AnalysisRuleConfig(
            rule_id="VALID-001",
            name="Valid Rule",
            description="A valid rule",
            severity="high",
            pattern=r"valid_pattern"
        )
        
        errors = rule.validate()
        assert len(errors) == 0
    
    def test_invalid_rule_validation(self):
        """Test validation of invalid rule."""
        rule = AnalysisRuleConfig(
            rule_id="",  # Invalid: empty
            name="",     # Invalid: empty
            description="Test",
            severity="invalid",  # Invalid severity
            pattern="ab"         # Invalid: too short
        )
        
        errors = rule.validate()
        assert len(errors) > 0
        assert any("Rule ID is required" in error for error in errors)
        assert any("Rule name is required" in error for error in errors)
        assert any("Invalid severity" in error for error in errors)
        assert any("Pattern must be at least 3 characters" in error for error in errors)


class TestSeverityThresholdConfig:
    """Test cases for SeverityThresholdConfig."""
    
    def test_score_calculation(self):
        """Test severity score calculation."""
        thresholds = SeverityThresholdConfig()
        
        score = thresholds.calculate_score(
            critical=1, high=2, medium=3, low=4
        )
        
        expected = (1 * 100) + (2 * 25) + (3 * 5) + (4 * 1)
        assert score == expected
    
    def test_blocking_logic(self):
        """Test blocking decision logic."""
        thresholds = SeverityThresholdConfig(
            critical_threshold=0,
            high_threshold=5,
            medium_threshold=20,
            low_threshold=50,
            max_total_score=200
        )
        
        # Should block on critical issues
        assert thresholds.should_block(1, 0, 0, 0)
        
        # Should block on too many high issues
        assert thresholds.should_block(0, 6, 0, 0)
        
        # Should block on high total score
        assert thresholds.should_block(0, 0, 0, 250)  # 250 * 1 = 250 > 200
        
        # Should not block on acceptable levels
        assert not thresholds.should_block(0, 3, 10, 20)


class TestFilePatternConfig:
    """Test cases for FilePatternConfig."""
    
    def test_file_inclusion_logic(self, temp_config_dir):
        """Test file inclusion logic."""
        patterns = FilePatternConfig(
            included_patterns=["*.py", "*.js"],
            excluded_patterns=["*test*"],
            excluded_directories=[".git", "__pycache__"]
        )
        
        # Create test files
        python_file = temp_config_dir / "script.py"
        python_file.touch()
        
        js_file = temp_config_dir / "app.js"
        js_file.touch()
        
        test_file = temp_config_dir / "test_script.py"
        test_file.touch()
        
        git_file = temp_config_dir / ".git" / "config"
        git_file.parent.mkdir()
        git_file.touch()
        
        # Test inclusion logic
        assert patterns.should_include_file(python_file)
        assert patterns.should_include_file(js_file)
        assert not patterns.should_include_file(test_file)  # Excluded pattern
        assert not patterns.should_include_file(git_file)   # Excluded directory


class TestConfigValidator:
    """Test cases for ConfigValidator."""
    
    def test_valid_config_validation(self, sample_config):
        """Test validation of valid configuration."""
        validator = ConfigValidator()
        result = validator.validate_project_config(sample_config)
        
        assert result['valid']
        assert len(result['errors']) == 0
    
    def test_invalid_config_validation(self):
        """Test validation of invalid configuration."""
        invalid_config = ProjectConfig(
            project_name="",  # Invalid
            version="invalid-version"  # Warning
        )
        
        validator = ConfigValidator()
        result = validator.validate_project_config(invalid_config)
        
        assert not result['valid']
        assert len(result['errors']) > 0
        assert len(result['warnings']) > 0


if __name__ == "__main__":
    pytest.main([__file__])