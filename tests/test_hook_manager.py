"""Tests for the Hook Manager and Kiro integration."""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from compliance_sentinel.hooks.hook_manager import (
    HookManager, HookEvent, HookResult, FileWatcher
)
from compliance_sentinel.hooks.kiro_integration import (
    KiroIntegration, KiroHookConfig, install_kiro_hooks, get_kiro_hook_status
)
from compliance_sentinel.models.config import HookSettings
from compliance_sentinel.models.analysis import AnalysisResponse, SecurityIssue, IssueSeverity


class TestHookEvent:
    """Test HookEvent functionality."""
    
    def test_hook_event_creation(self):
        """Test creating a hook event."""
        event = HookEvent(
            event_id="test_123",
            event_type="file_save",
            file_path="/path/to/file.py",
            timestamp=datetime.utcnow(),
            content="print('hello')"
        )
        
        assert event.event_id == "test_123"
        assert event.event_type == "file_save"
        assert event.file_path == "/path/to/file.py"
        assert event.content == "print('hello')"
    
    def test_is_relevant_file(self):
        """Test file relevance checking."""
        event = HookEvent(
            event_id="test",
            event_type="file_save",
            file_path="/src/main.py",
            timestamp=datetime.utcnow()
        )
        
        # Test extension patterns
        assert event.is_relevant_file(["*.py"])
        assert not event.is_relevant_file(["*.js"])
        
        # Test substring patterns
        assert event.is_relevant_file(["main"])
        assert not event.is_relevant_file(["test"])
        
        # Test glob patterns
        assert event.is_relevant_file(["src/*"])
    
    def test_should_exclude(self):
        """Test exclusion checking."""
        event = HookEvent(
            event_id="test",
            event_type="file_save",
            file_path="/project/node_modules/package.js",
            timestamp=datetime.utcnow()
        )
        
        assert event.should_exclude(["node_modules"])
        assert not event.should_exclude(["src"])
        
        # Test path prefix exclusion
        event2 = HookEvent(
            event_id="test2",
            event_type="file_save",
            file_path="/project/.git/config",
            timestamp=datetime.utcnow()
        )
        
        assert event2.should_exclude([".git"])


class TestFileWatcher:
    """Test FileWatcher functionality."""
    
    def test_file_watcher_initialization(self):
        """Test file watcher initialization."""
        mock_hook_manager = Mock()
        watcher = FileWatcher(mock_hook_manager)
        
        assert watcher.hook_manager == mock_hook_manager
        assert not watcher.watching
        assert watcher.watch_thread is None
    
    def test_is_text_file(self):
        """Test text file detection."""
        mock_hook_manager = Mock()
        watcher = FileWatcher(mock_hook_manager)
        
        # Test various file types
        assert watcher._is_text_file(Path("test.py"))
        assert watcher._is_text_file(Path("test.js"))
        assert watcher._is_text_file(Path("test.java"))
        assert watcher._is_text_file(Path("README.md"))
        assert watcher._is_text_file(Path("config.json"))
        
        # Test non-text files
        assert not watcher._is_text_file(Path("image.png"))
        assert not watcher._is_text_file(Path("binary.exe"))
        assert not watcher._is_text_file(Path("archive.zip"))


class TestHookManager:
    """Test HookManager functionality."""
    
    @pytest.fixture
    def hook_settings(self):
        """Create test hook settings."""
        return HookSettings(
            enabled_file_patterns=["*.py", "*.js"],
            excluded_directories=["node_modules", ".git"],
            debounce_delay=1.0,
            async_processing=True,
            analysis_timeout=30
        )
    
    @pytest.fixture
    def hook_manager(self, hook_settings):
        """Create test hook manager."""
        return HookManager(hook_settings)
    
    def test_hook_manager_initialization(self, hook_manager):
        """Test hook manager initialization."""
        assert hook_manager.settings is not None
        assert hook_manager.analysis_coordinator is not None
        assert hook_manager.policy_engine is not None
        assert hook_manager.feedback_engine is not None
        assert not hook_manager.processing_active
    
    @pytest.mark.asyncio
    async def test_start_stop(self, hook_manager):
        """Test starting and stopping hook manager."""
        await hook_manager.start()
        assert hook_manager.processing_active
        assert hook_manager.event_loop is not None
        
        await hook_manager.stop()
        assert not hook_manager.processing_active
    
    def test_should_process_event(self, hook_manager):
        """Test event processing filtering."""
        # Relevant event
        event1 = HookEvent(
            event_id="test1",
            event_type="file_save",
            file_path="/src/main.py",
            timestamp=datetime.utcnow()
        )
        assert hook_manager._should_process_event(event1)
        
        # Irrelevant file type
        event2 = HookEvent(
            event_id="test2",
            event_type="file_save",
            file_path="/src/image.png",
            timestamp=datetime.utcnow()
        )
        assert not hook_manager._should_process_event(event2)
        
        # Excluded directory
        event3 = HookEvent(
            event_id="test3",
            event_type="file_save",
            file_path="/node_modules/package.js",
            timestamp=datetime.utcnow()
        )
        assert not hook_manager._should_process_event(event3)
        
        # Irrelevant event type
        event4 = HookEvent(
            event_id="test4",
            event_type="file_delete",
            file_path="/src/main.py",
            timestamp=datetime.utcnow()
        )
        assert not hook_manager._should_process_event(event4)
    
    def test_debouncing(self, hook_manager):
        """Test event debouncing."""
        event = HookEvent(
            event_id="test",
            event_type="file_save",
            file_path="/src/main.py",
            timestamp=datetime.utcnow()
        )
        
        # First event should not be debounced
        assert not hook_manager._is_debounced(event)
        
        # Immediate second event should be debounced
        assert hook_manager._is_debounced(event)
    
    @pytest.mark.asyncio
    async def test_process_hook_event_success(self, hook_manager):
        """Test successful hook event processing."""
        event = HookEvent(
            event_id="test",
            event_type="file_save",
            file_path="/src/main.py",
            timestamp=datetime.utcnow(),
            content="print('hello world')"
        )
        
        # Mock analysis response
        mock_response = AnalysisResponse(
            request_id="test",
            issues=[],
            scan_duration=0.5,
            files_scanned=1
        )
        
        with patch.object(hook_manager.analysis_coordinator, 'run_comprehensive_scan', 
                         return_value=mock_response):
            result = await hook_manager.process_hook_event(event)
            
            assert result.success
            assert result.event_id == "test"
            assert result.issues_found == 0
            assert "No security issues found" in result.analysis_summary
            assert not result.feedback_provided
    
    @pytest.mark.asyncio
    async def test_process_hook_event_with_issues(self, hook_manager):
        """Test hook event processing with security issues."""
        event = HookEvent(
            event_id="test",
            event_type="file_save",
            file_path="/src/main.py",
            timestamp=datetime.utcnow(),
            content="password = 'hardcoded_secret'"
        )
        
        # Mock analysis response with issues
        issue = SecurityIssue(
            rule_id="hardcoded_password",
            title="Hardcoded Password",
            description="Password found in code",
            severity=IssueSeverity.HIGH,
            file_path="/src/main.py",
            line_number=1,
            column_number=1,
            code_snippet="password = 'hardcoded_secret'",
            tool_name="bandit"
        )
        
        mock_response = AnalysisResponse(
            request_id="test",
            issues=[issue],
            scan_duration=0.5,
            files_scanned=1
        )
        
        with patch.object(hook_manager.analysis_coordinator, 'run_comprehensive_scan', 
                         return_value=mock_response):
            with patch.object(hook_manager.feedback_engine, 'format_ide_feedback', 
                             return_value="IDE feedback"):
                result = await hook_manager.process_hook_event(event)
                
                assert result.success
                assert result.issues_found == 1
                assert "1 high" in result.analysis_summary
                assert result.feedback_provided
    
    @pytest.mark.asyncio
    async def test_trigger_manual_analysis(self, hook_manager):
        """Test manual analysis trigger."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('test')")
            temp_file = f.name
        
        try:
            # Mock analysis response
            mock_response = AnalysisResponse(
                request_id="manual",
                issues=[],
                scan_duration=0.3,
                files_scanned=1
            )
            
            with patch.object(hook_manager.analysis_coordinator, 'run_comprehensive_scan', 
                             return_value=mock_response):
                result = await hook_manager.trigger_manual_analysis(temp_file)
                
                assert result.success
                assert result.issues_found == 0
                assert "manual" in result.event_id
        finally:
            Path(temp_file).unlink()
    
    def test_get_hook_statistics(self, hook_manager):
        """Test hook statistics generation."""
        # Add some mock results
        hook_manager.hook_results = [
            HookResult(
                event_id="test1",
                success=True,
                duration_ms=100.0,
                issues_found=0,
                analysis_summary="No issues",
                feedback_provided=False
            ),
            HookResult(
                event_id="test2",
                success=True,
                duration_ms=200.0,
                issues_found=2,
                analysis_summary="2 issues found",
                feedback_provided=True
            ),
            HookResult(
                event_id="test3",
                success=False,
                duration_ms=50.0,
                issues_found=0,
                analysis_summary="Failed",
                feedback_provided=False,
                error_message="Test error"
            )
        ]
        
        stats = hook_manager.get_hook_statistics()
        
        assert stats["total_events"] == 3
        assert stats["successful_events"] == 2
        assert stats["failed_events"] == 1
        assert stats["success_rate"] == 2/3
        assert stats["average_duration_ms"] == (100 + 200 + 50) / 3
        assert stats["total_issues_found"] == 2
        assert stats["feedback_provided_count"] == 1
        assert len(stats["recent_events"]) == 3


class TestKiroHookConfig:
    """Test KiroHookConfig functionality."""
    
    def test_kiro_hook_config_creation(self):
        """Test creating Kiro hook configuration."""
        config = KiroHookConfig(
            hook_name="test-hook",
            trigger_events=["file:save"],
            file_patterns=["*.py"],
            excluded_paths=["node_modules"],
            async_execution=True,
            timeout_seconds=60,
            priority=5
        )
        
        assert config.hook_name == "test-hook"
        assert config.trigger_events == ["file:save"]
        assert config.file_patterns == ["*.py"]
        assert config.excluded_paths == ["node_modules"]
        assert config.async_execution
        assert config.timeout_seconds == 60
        assert config.priority == 5
    
    def test_to_kiro_format(self):
        """Test conversion to Kiro format."""
        config = KiroHookConfig(
            hook_name="test-hook",
            trigger_events=["file:save"],
            file_patterns=["*.py"],
            excluded_paths=["node_modules"]
        )
        
        kiro_format = config.to_kiro_format()
        
        assert kiro_format["name"] == "test-hook"
        assert kiro_format["triggers"] == ["file:save"]
        assert kiro_format["patterns"] == ["*.py"]
        assert kiro_format["exclude"] == ["node_modules"]
        assert kiro_format["command"] == "compliance-sentinel hook-handler"
        assert "description" in kiro_format


class TestKiroIntegration:
    """Test KiroIntegration functionality."""
    
    @pytest.fixture
    def temp_kiro_dir(self):
        """Create temporary Kiro directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            kiro_dir = Path(temp_dir) / ".kiro"
            kiro_dir.mkdir()
            yield kiro_dir
    
    @pytest.fixture
    def kiro_integration(self, temp_kiro_dir):
        """Create KiroIntegration with temporary directory."""
        integration = KiroIntegration()
        integration.kiro_dir = temp_kiro_dir
        integration.hooks_dir = temp_kiro_dir / "hooks"
        integration.steering_dir = temp_kiro_dir / "steering"
        integration.hooks_dir.mkdir(exist_ok=True)
        integration.steering_dir.mkdir(exist_ok=True)
        return integration
    
    def test_kiro_integration_initialization(self, kiro_integration):
        """Test KiroIntegration initialization."""
        assert kiro_integration.kiro_dir.exists()
        assert kiro_integration.hooks_dir.exists()
        assert kiro_integration.steering_dir.exists()
    
    def test_create_hook_configurations(self, kiro_integration):
        """Test hook configuration creation."""
        settings = HookSettings(
            enabled_file_patterns=["*.py"],
            excluded_directories=["node_modules"],
            debounce_delay=1.0,
            async_processing=True,
            analysis_timeout=30
        )
        
        hooks = kiro_integration._create_hook_configurations(settings)
        
        assert len(hooks) == 3  # file-save, pre-commit, manual
        
        # Check file save hook
        file_save_hook = next(h for h in hooks if "file-save" in h.hook_name)
        assert "file:save" in file_save_hook.trigger_events
        assert file_save_hook.file_patterns == ["*.py"]
        assert file_save_hook.async_execution
        
        # Check pre-commit hook
        pre_commit_hook = next(h for h in hooks if "pre-commit" in h.hook_name)
        assert "git:pre-commit" in pre_commit_hook.trigger_events
        assert not pre_commit_hook.async_execution  # Synchronous for blocking
        
        # Check manual hook
        manual_hook = next(h for h in hooks if "manual" in h.hook_name)
        assert "command:compliance-check" in manual_hook.trigger_events
    
    def test_install_single_hook(self, kiro_integration):
        """Test installing a single hook."""
        hook = KiroHookConfig(
            hook_name="test-hook",
            trigger_events=["file:save"],
            file_patterns=["*.py"],
            excluded_paths=["node_modules"]
        )
        
        kiro_integration._install_single_hook(hook)
        
        hook_file = kiro_integration.hooks_dir / "test-hook.json"
        assert hook_file.exists()
        
        with open(hook_file, 'r') as f:
            hook_data = json.load(f)
            assert hook_data["name"] == "test-hook"
            assert hook_data["triggers"] == ["file:save"]
    
    def test_create_hook_handler(self, kiro_integration):
        """Test hook handler script creation."""
        kiro_integration._create_hook_handler()
        
        handler_file = kiro_integration.hooks_dir / "compliance-sentinel-handler.py"
        assert handler_file.exists()
        
        # Check if file is executable
        assert os.access(handler_file, os.X_OK)
        
        # Check content
        with open(handler_file, 'r') as f:
            content = f.read()
            assert "#!/usr/bin/env python3" in content
            assert "HookManager" in content
            assert "asyncio.run(main())" in content
    
    def test_create_steering_rules(self, kiro_integration):
        """Test steering rules creation."""
        kiro_integration.create_steering_rules()
        
        steering_file = kiro_integration.steering_dir / "compliance-sentinel.md"
        assert steering_file.exists()
        
        with open(steering_file, 'r') as f:
            content = f.read()
            assert "inclusion: always" in content
            assert "Compliance Sentinel Integration" in content
            assert "Security Analysis Context" in content
    
    def test_get_hook_status_empty(self, kiro_integration):
        """Test hook status when no hooks installed."""
        status = kiro_integration.get_hook_status()
        
        assert not status["installed"]
        assert len(status["hooks"]) == 0
        assert not status["kiro_config_exists"]
        assert not status["handler_exists"]
    
    def test_get_hook_status_with_hooks(self, kiro_integration):
        """Test hook status with installed hooks."""
        # Install a test hook
        hook = KiroHookConfig(
            hook_name="compliance-sentinel-test",
            trigger_events=["file:save"],
            file_patterns=["*.py"],
            excluded_paths=["node_modules"]
        )
        kiro_integration._install_single_hook(hook)
        kiro_integration._create_hook_handler()
        
        status = kiro_integration.get_hook_status()
        
        assert status["installed"]
        assert len(status["hooks"]) == 1
        assert status["hooks"][0]["name"] == "compliance-sentinel-test"
        assert status["handler_exists"]
    
    def test_validate_installation_no_kiro(self):
        """Test validation when not in Kiro workspace."""
        integration = KiroIntegration()
        integration.kiro_dir = Path("/nonexistent")
        
        issues = integration.validate_installation()
        
        assert len(issues) > 0
        assert any("not found" in issue for issue in issues)
    
    def test_validate_installation_valid(self, kiro_integration):
        """Test validation of valid installation."""
        # Install hooks
        hook = KiroHookConfig(
            hook_name="compliance-sentinel-test",
            trigger_events=["file:save"],
            file_patterns=["*.py"],
            excluded_paths=["node_modules"]
        )
        kiro_integration._install_single_hook(hook)
        kiro_integration._create_hook_handler()
        
        issues = kiro_integration.validate_installation()
        
        assert len(issues) == 0


class TestHookIntegrationFunctions:
    """Test integration convenience functions."""
    
    @patch('compliance_sentinel.hooks.kiro_integration.KiroIntegration')
    def test_install_kiro_hooks(self, mock_integration_class):
        """Test install_kiro_hooks function."""
        mock_integration = Mock()
        mock_integration.install_hooks.return_value = True
        mock_integration_class.return_value = mock_integration
        
        settings = HookSettings()
        result = install_kiro_hooks(settings)
        
        assert result
        mock_integration.install_hooks.assert_called_once_with(settings)
        mock_integration.create_steering_rules.assert_called_once()
    
    @patch('compliance_sentinel.hooks.kiro_integration.KiroIntegration')
    def test_get_kiro_hook_status(self, mock_integration_class):
        """Test get_kiro_hook_status function."""
        mock_integration = Mock()
        mock_status = {"installed": True, "hooks": []}
        mock_integration.get_hook_status.return_value = mock_status
        mock_integration_class.return_value = mock_integration
        
        result = get_kiro_hook_status()
        
        assert result == mock_status
        mock_integration.get_hook_status.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])