"""Tests for data synchronization functionality."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta

from compliance_sentinel.sync.data_synchronizer import DataSynchronizer, SyncResult, SyncStatus
from compliance_sentinel.providers.data_provider import DataProvider, DataRequest, DataResponse
from compliance_sentinel.utils.intelligent_cache import IntelligentCache


class MockDataProvider(DataProvider):
    """Mock data provider for testing."""
    
    def __init__(self, name: str, data: list = None, should_fail: bool = False):
        super().__init__(name)
        self.data = data or []
        self.should_fail = should_fail
        self.call_count = 0
    
    def get_supported_request_types(self) -> List[str]:
        """Return supported request types."""
        return ["sync_all", "get_data", "health_check"]
    
    async def initialize(self) -> bool:
        return not self.should_fail
    
    async def get_data(self, request: DataRequest) -> DataResponse:
        self.call_count += 1
        
        if self.should_fail:
            return DataResponse(
                success=False,
                data=None,
                error="Mock provider failure",
                provider_name=self.name
            )
        
        return DataResponse(
            success=True,
            data=self.data,
            provider_name=self.name,
            last_modified=datetime.utcnow()
        )
    
    async def health_check(self) -> bool:
        return not self.should_fail


class TestDataSynchronizer:
    """Test data synchronization functionality."""
    
    @pytest.fixture
    def cache_manager(self):
        """Create mock cache manager."""
        return MagicMock(spec=IntelligentCache)
    
    @pytest.fixture
    def mock_providers(self):
        """Create mock data providers."""
        return [
            MockDataProvider("provider1", [{"id": 1, "data": "test1"}]),
            MockDataProvider("provider2", [{"id": 2, "data": "test2"}]),
            MockDataProvider("provider3", [{"id": 3, "data": "test3"}])
        ]
    
    @pytest.fixture
    def synchronizer(self, mock_providers, cache_manager):
        """Create data synchronizer with mock providers."""
        return DataSynchronizer(
            providers=mock_providers,
            cache_manager=cache_manager,
            sync_interval=60,
            max_concurrent_syncs=2
        )
    
    @pytest.mark.asyncio
    async def test_sync_single_provider(self, synchronizer, mock_providers):
        """Test synchronizing a single provider."""
        provider = mock_providers[0]
        
        result = await synchronizer.sync_provider(provider)
        
        assert result.status == SyncStatus.SUCCESS
        assert result.provider_name == "provider1"
        assert result.records_synced == 1
        assert result.error is None
        assert provider.call_count == 1
    
    @pytest.mark.asyncio
    async def test_sync_provider_failure(self, cache_manager):
        """Test handling provider sync failure."""
        failing_provider = MockDataProvider("failing_provider", should_fail=True)
        synchronizer = DataSynchronizer([failing_provider], cache_manager)
        
        result = await synchronizer.sync_provider(failing_provider)
        
        assert result.status == SyncStatus.FAILED
        assert result.provider_name == "failing_provider"
        assert result.records_synced == 0
        assert result.error is not None
        assert "Mock provider failure" in result.error
    
    @pytest.mark.asyncio
    async def test_sync_all_providers(self, synchronizer, mock_providers):
        """Test synchronizing all providers."""
        results = await synchronizer.sync_all_providers()
        
        assert len(results) == 3
        
        for i, result in enumerate(results):
            assert result.status == SyncStatus.SUCCESS
            assert result.provider_name == f"provider{i+1}"
            assert result.records_synced == 1
            assert mock_providers[i].call_count == 1
    
    @pytest.mark.asyncio
    async def test_sync_with_mixed_results(self, cache_manager):
        """Test synchronization with mixed success/failure results."""
        providers = [
            MockDataProvider("success1", [{"id": 1}]),
            MockDataProvider("failure", should_fail=True),
            MockDataProvider("success2", [{"id": 2}, {"id": 3}])
        ]
        
        synchronizer = DataSynchronizer(providers, cache_manager)
        results = await synchronizer.sync_all_providers()
        
        assert len(results) == 3
        assert results[0].status == SyncStatus.SUCCESS
        assert results[1].status == SyncStatus.FAILED
        assert results[2].status == SyncStatus.SUCCESS
        
        # Check record counts
        assert results[0].records_synced == 1
        assert results[1].records_synced == 0
        assert results[2].records_synced == 2
    
    @pytest.mark.asyncio
    async def test_concurrent_sync_limit(self, cache_manager):
        """Test concurrent synchronization limit."""
        # Create many providers to test concurrency
        providers = [
            MockDataProvider(f"provider{i}", [{"id": i}])
            for i in range(10)
        ]
        
        synchronizer = DataSynchronizer(
            providers=providers,
            cache_manager=cache_manager,
            max_concurrent_syncs=3
        )
        
        start_time = asyncio.get_event_loop().time()
        results = await synchronizer.sync_all_providers()
        end_time = asyncio.get_event_loop().time()
        
        # All should succeed
        assert len(results) == 10
        assert all(r.status == SyncStatus.SUCCESS for r in results)
        
        # Should complete in reasonable time despite concurrency limit
        assert end_time - start_time < 5.0
    
    @pytest.mark.asyncio
    async def test_sync_with_timeout(self, cache_manager):
        """Test synchronization with timeout."""
        # Create provider that takes too long
        slow_provider = MockDataProvider("slow_provider")
        
        # Mock the get_data method to be slow
        async def slow_get_data(request):
            await asyncio.sleep(2)  # Simulate slow operation
            return DataResponse(
                success=True,
                data=[{"id": 1}],
                provider_name="slow_provider"
            )
        
        slow_provider.get_data = slow_get_data
        
        synchronizer = DataSynchronizer(
            providers=[slow_provider],
            cache_manager=cache_manager,
            sync_timeout=1  # 1 second timeout
        )
        
        result = await synchronizer.sync_provider(slow_provider)
        
        assert result.status == SyncStatus.FAILED
        assert "timeout" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_incremental_sync(self, synchronizer, mock_providers, cache_manager):
        """Test incremental synchronization."""
        # Mock cache to return last sync time
        last_sync_time = datetime.utcnow() - timedelta(hours=1)
        cache_manager.get.return_value = {
            "last_sync_time": last_sync_time.isoformat()
        }
        
        # Perform incremental sync
        results = await synchronizer.sync_all_providers(incremental=True)
        
        assert len(results) == 3
        assert all(r.status == SyncStatus.SUCCESS for r in results)
        
        # Verify cache was checked for last sync time
        assert cache_manager.get.called
    
    @pytest.mark.asyncio
    async def test_force_sync(self, synchronizer, mock_providers, cache_manager):
        """Test force synchronization (ignores cache)."""
        # Mock cache to return recent sync time
        recent_sync_time = datetime.utcnow() - timedelta(minutes=5)
        cache_manager.get.return_value = {
            "last_sync_time": recent_sync_time.isoformat()
        }
        
        # Perform force sync
        results = await synchronizer.sync_all_providers(force=True)
        
        assert len(results) == 3
        assert all(r.status == SyncStatus.SUCCESS for r in results)
        
        # All providers should have been called despite recent sync
        assert all(p.call_count == 1 for p in mock_providers)
    
    @pytest.mark.asyncio
    async def test_selective_sync(self, synchronizer, mock_providers):
        """Test selective synchronization of specific providers."""
        # Sync only specific providers
        provider_names = ["provider1", "provider3"]
        results = await synchronizer.sync_providers(provider_names)
        
        assert len(results) == 2
        assert results[0].provider_name == "provider1"
        assert results[1].provider_name == "provider3"
        
        # Only selected providers should have been called
        assert mock_providers[0].call_count == 1  # provider1
        assert mock_providers[1].call_count == 0  # provider2 (not selected)
        assert mock_providers[2].call_count == 1  # provider3
    
    @pytest.mark.asyncio
    async def test_sync_with_data_transformation(self, cache_manager):
        """Test synchronization with data transformation."""
        provider = MockDataProvider("transform_provider", [
            {"id": 1, "name": "item1"},
            {"id": 2, "name": "item2"}
        ])
        
        # Create synchronizer with transformation function
        def transform_data(data):
            return [{"id": item["id"], "transformed_name": item["name"].upper()} for item in data]
        
        synchronizer = DataSynchronizer(
            providers=[provider],
            cache_manager=cache_manager,
            data_transformer=transform_data
        )
        
        result = await synchronizer.sync_provider(provider)
        
        assert result.status == SyncStatus.SUCCESS
        assert result.records_synced == 2
        
        # Verify transformation was applied
        # (This would be verified through cache storage in real implementation)
    
    @pytest.mark.asyncio
    async def test_sync_metrics_collection(self, synchronizer, mock_providers):
        """Test that sync metrics are collected."""
        with patch('compliance_sentinel.monitoring.real_time_metrics.get_metrics') as mock_metrics:
            mock_metrics_instance = MagicMock()
            mock_metrics.return_value = mock_metrics_instance
            
            await synchronizer.sync_all_providers()
            
            # Verify metrics were recorded
            assert mock_metrics_instance.increment_counter.called
            assert mock_metrics_instance.record_timer.called
    
    @pytest.mark.asyncio
    async def test_sync_error_handling(self, cache_manager):
        """Test comprehensive error handling during sync."""
        # Create provider that raises exception
        error_provider = MockDataProvider("error_provider")
        
        async def error_get_data(request):
            raise Exception("Unexpected error")
        
        error_provider.get_data = error_get_data
        
        synchronizer = DataSynchronizer([error_provider], cache_manager)
        result = await synchronizer.sync_provider(error_provider)
        
        assert result.status == SyncStatus.FAILED
        assert "Unexpected error" in result.error
        assert result.records_synced == 0
    
    @pytest.mark.asyncio
    async def test_sync_result_caching(self, synchronizer, mock_providers, cache_manager):
        """Test that sync results are cached."""
        await synchronizer.sync_all_providers()
        
        # Verify cache was updated with sync results
        assert cache_manager.set.called
        
        # Check that sync metadata was cached
        cache_calls = cache_manager.set.call_args_list
        assert any("sync_metadata" in str(call) for call in cache_calls)
    
    @pytest.mark.asyncio
    async def test_sync_with_callback(self, synchronizer, mock_providers):
        """Test synchronization with progress callback."""
        callback_calls = []
        
        def progress_callback(provider_name: str, status: str, progress: float):
            callback_calls.append((provider_name, status, progress))
        
        synchronizer.set_progress_callback(progress_callback)
        await synchronizer.sync_all_providers()
        
        # Verify callback was called for each provider
        assert len(callback_calls) >= 3  # At least one call per provider
        
        # Check that all providers were reported
        provider_names = {call[0] for call in callback_calls}
        assert "provider1" in provider_names
        assert "provider2" in provider_names
        assert "provider3" in provider_names
    
    @pytest.mark.asyncio
    async def test_sync_scheduling(self, synchronizer):
        """Test automatic sync scheduling."""
        # Start background sync
        synchronizer.start_background_sync()
        
        # Wait a short time
        await asyncio.sleep(0.1)
        
        # Stop background sync
        synchronizer.stop_background_sync()
        
        # Verify sync was scheduled (implementation dependent)
        assert synchronizer.is_background_sync_running() is False
    
    def test_sync_result_serialization(self):
        """Test sync result serialization."""
        result = SyncResult(
            provider_name="test_provider",
            status=SyncStatus.SUCCESS,
            records_synced=10,
            sync_duration=1.5,
            last_sync_time=datetime.utcnow(),
            error=None
        )
        
        # Test to_dict method
        result_dict = result.to_dict()
        assert result_dict["provider_name"] == "test_provider"
        assert result_dict["status"] == "SUCCESS"
        assert result_dict["records_synced"] == 10
        assert result_dict["sync_duration"] == 1.5
        assert result_dict["error"] is None
        
        # Test from_dict method
        restored_result = SyncResult.from_dict(result_dict)
        assert restored_result.provider_name == result.provider_name
        assert restored_result.status == result.status
        assert restored_result.records_synced == result.records_synced
    
    @pytest.mark.asyncio
    async def test_sync_with_data_validation(self, cache_manager):
        """Test synchronization with data validation."""
        provider = MockDataProvider("validation_provider", [
            {"id": 1, "name": "valid"},
            {"id": 2},  # Missing name field
            {"name": "no_id"}  # Missing id field
        ])
        
        # Create validator function
        def validate_data(data):
            valid_items = []
            for item in data:
                if "id" in item and "name" in item:
                    valid_items.append(item)
            return valid_items
        
        synchronizer = DataSynchronizer(
            providers=[provider],
            cache_manager=cache_manager,
            data_validator=validate_data
        )
        
        result = await synchronizer.sync_provider(provider)
        
        assert result.status == SyncStatus.SUCCESS
        # Only 1 item should pass validation
        assert result.records_synced == 1
    
    @pytest.mark.asyncio
    async def test_sync_retry_mechanism(self, cache_manager):
        """Test sync retry mechanism for failed operations."""
        provider = MockDataProvider("retry_provider", should_fail=True)
        
        synchronizer = DataSynchronizer(
            providers=[provider],
            cache_manager=cache_manager,
            max_retries=3,
            retry_delay=0.1
        )
        
        result = await synchronizer.sync_provider(provider)
        
        assert result.status == SyncStatus.FAILED
        # Provider should have been called multiple times due to retries
        assert provider.call_count > 1
    
    @pytest.mark.asyncio
    async def test_sync_with_circuit_breaker(self, cache_manager):
        """Test sync with circuit breaker integration."""
        provider = MockDataProvider("circuit_provider", should_fail=True)
        
        with patch('compliance_sentinel.utils.circuit_breaker.CircuitBreakerManager') as mock_cb:
            mock_cb_instance = MagicMock()
            mock_cb.return_value = mock_cb_instance
            mock_cb_instance.is_circuit_open.return_value = True
            
            synchronizer = DataSynchronizer([provider], cache_manager)
            result = await synchronizer.sync_provider(provider)
            
            assert result.status == SyncStatus.FAILED
            assert "circuit breaker" in result.error.lower()


class TestSyncResult:
    """Test sync result functionality."""
    
    def test_sync_result_creation(self):
        """Test sync result creation."""
        result = SyncResult(
            provider_name="test_provider",
            status=SyncStatus.SUCCESS,
            records_synced=5,
            sync_duration=2.5
        )
        
        assert result.provider_name == "test_provider"
        assert result.status == SyncStatus.SUCCESS
        assert result.records_synced == 5
        assert result.sync_duration == 2.5
        assert result.error is None
        assert result.last_sync_time is not None
    
    def test_sync_result_with_error(self):
        """Test sync result with error."""
        result = SyncResult(
            provider_name="error_provider",
            status=SyncStatus.FAILED,
            records_synced=0,
            sync_duration=1.0,
            error="Connection failed"
        )
        
        assert result.status == SyncStatus.FAILED
        assert result.error == "Connection failed"
        assert result.records_synced == 0
    
    def test_sync_status_enum(self):
        """Test sync status enumeration."""
        assert SyncStatus.SUCCESS.value == "SUCCESS"
        assert SyncStatus.FAILED.value == "FAILED"
        assert SyncStatus.PARTIAL.value == "PARTIAL"
        assert SyncStatus.SKIPPED.value == "SKIPPED"


if __name__ == "__main__":
    pytest.main([__file__])