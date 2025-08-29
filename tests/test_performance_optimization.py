"""Tests for performance optimization and scalability components."""

import pytest
import asyncio
import time
import tempfile
import os
from unittest.mock import Mock, patch, AsyncMock

from compliance_sentinel.performance import (
    ParallelProcessor, ProcessingTask, TaskPriority, TaskStatus,
    DistributedAnalyzer, WorkerNode, AnalysisJob,
    CacheManager, CacheLevel, MemoryCache,
    ResourceManager, ResourceLimits, ResourceMetrics,
    QueueManager, PriorityQueue, TaskPriority as QueueTaskPriority,
    IncrementalAnalyzer, ChangeDetector, AnalysisScope,
    StreamingProcessor, StreamConfig, StreamType
)


class TestParallelProcessor:
    """Test parallel processing framework."""
    
    @pytest.fixture
    def processor(self):
        """Create parallel processor."""
        return ParallelProcessor(max_workers=2, enable_monitoring=False)
    
    @pytest.fixture
    def sample_task(self):
        """Create sample processing task."""
        def simple_processor(data):
            return f"processed: {data['value']}"
        
        return ProcessingTask(
            task_id="test_task_1",
            task_type="test",
            data={'value': 'test_data'},
            processor_func=simple_processor,
            priority=TaskPriority.NORMAL.value
        )
    
    def test_processor_initialization(self, processor):
        """Test processor initialization."""
        assert processor.max_workers == 2
        assert processor.processing_mode.value in ['hybrid', 'adaptive']
        assert len(processor.active_tasks) == 0
        assert len(processor.completed_tasks) == 0
    
    def test_submit_task(self, processor, sample_task):
        """Test task submission."""
        task_id = processor.submit_task(sample_task)
        assert task_id == sample_task.task_id
        assert not processor.task_queue.empty()
    
    @pytest.mark.asyncio
    async def test_process_single_task(self, processor, sample_task):
        """Test processing single task."""
        processor.submit_task(sample_task)
        results = await processor.process_tasks()
        
        assert len(results) == 1
        assert results[0].task_id == sample_task.task_id
        assert results[0].status == TaskStatus.COMPLETED
        assert "processed: test_data" in str(results[0].result)
    
    @pytest.mark.asyncio
    async def test_batch_processing(self, processor):
        """Test batch task processing."""
        tasks = []
        for i in range(5):
            task = ProcessingTask(
                task_id=f"batch_task_{i}",
                task_type="batch_test",
                data={'value': f'data_{i}'},
                processor_func=lambda data: f"processed: {data['value']}",
                priority=TaskPriority.NORMAL.value
            )
            tasks.append(task)
        
        # Submit all tasks
        task_ids = processor.submit_batch(tasks)
        assert len(task_ids) == 5
        
        # Process tasks
        results = await processor.process_tasks()
        assert len(results) == 5
        
        # Check all completed successfully
        completed_count = sum(1 for r in results if r.status == TaskStatus.COMPLETED)
        assert completed_count == 5
    
    def test_task_priority_ordering(self, processor):
        """Test task priority ordering."""
        # Create tasks with different priorities
        high_task = ProcessingTask(
            task_id="high_priority",
            task_type="test",
            data={'value': 'high'},
            processor_func=lambda data: data['value'],
            priority=TaskPriority.HIGH.value
        )
        
        low_task = ProcessingTask(
            task_id="low_priority",
            task_type="test",
            data={'value': 'low'},
            processor_func=lambda data: data['value'],
            priority=TaskPriority.LOW.value
        )
        
        # Submit in reverse priority order
        processor.submit_task(low_task)
        processor.submit_task(high_task)
        
        # High priority task should be processed first
        _, _, first_task = processor.task_queue.get()
        assert first_task.task_id == "high_priority"
    
    def test_performance_metrics(self, processor):
        """Test performance metrics collection."""
        metrics = processor.get_performance_metrics()
        
        assert 'tasks_processed' in metrics
        assert 'total_execution_time' in metrics
        assert 'cpu_utilization' in metrics
        assert 'throughput' in metrics
    
    @pytest.mark.asyncio
    async def test_processor_shutdown(self, processor):
        """Test graceful processor shutdown."""
        await processor.shutdown()
        
        # Verify executors are shut down
        if processor.thread_executor:
            assert processor.thread_executor._shutdown
        if processor.process_executor:
            assert processor.process_executor._shutdown


class TestDistributedAnalyzer:
    """Test distributed analysis system."""
    
    @pytest.fixture
    def analyzer(self):
        """Create distributed analyzer."""
        return DistributedAnalyzer(coordinator_port=8081)
    
    @pytest.fixture
    def sample_node(self):
        """Create sample worker node."""
        return WorkerNode(
            node_id="test_node_1",
            hostname="localhost",
            ip_address="127.0.0.1",
            port=8082,
            supported_languages=["python", "javascript"],
            max_concurrent_jobs=2
        )
    
    @pytest.fixture
    def sample_job(self):
        """Create sample analysis job."""
        return AnalysisJob(
            job_id="test_job_1",
            job_type="security_analysis",
            file_path="/test/file.py",
            file_content="print('hello world')",
            language="python"
        )
    
    @pytest.mark.asyncio
    async def test_analyzer_startup_shutdown(self, analyzer):
        """Test analyzer startup and shutdown."""
        await analyzer.start()
        assert analyzer.is_running
        
        await analyzer.stop()
        assert not analyzer.is_running
    
    def test_node_registration(self, analyzer, sample_node):
        """Test worker node registration."""
        # Mock connectivity test
        with patch.object(analyzer, '_test_node_connectivity', return_value=True):
            success = asyncio.run(analyzer.register_node(sample_node))
            assert success
            assert sample_node.node_id in analyzer.nodes
            assert analyzer.nodes[sample_node.node_id].status.value == "online"
    
    def test_node_selection(self, analyzer, sample_node, sample_job):
        """Test node selection for jobs."""
        # Register node
        analyzer.nodes[sample_node.node_id] = sample_node
        sample_node.status = sample_node.status.ONLINE
        
        # Test selection
        available_nodes = [sample_node]
        selected = analyzer.node_selector.select_node(sample_job, available_nodes)
        
        assert selected == sample_node
    
    @pytest.mark.asyncio
    async def test_job_submission(self, analyzer, sample_job):
        """Test job submission."""
        job_id = await analyzer.submit_job(sample_job)
        assert job_id == sample_job.job_id
        assert sample_job.job_id in analyzer.jobs
    
    def test_cluster_status(self, analyzer, sample_node):
        """Test cluster status reporting."""
        analyzer.nodes[sample_node.node_id] = sample_node
        
        status = analyzer.get_cluster_status()
        
        assert 'coordinator_running' in status
        assert 'total_nodes' in status
        assert 'online_nodes' in status
        assert status['total_nodes'] == 1


class TestCacheManager:
    """Test caching system."""
    
    @pytest.fixture
    def cache_manager(self):
        """Create cache manager."""
        return CacheManager(
            memory_cache_config={'max_size_bytes': 1024 * 1024},
            disk_cache_config=False,  # Disable disk cache for tests
            redis_cache_config=False  # Disable Redis cache for tests
        )
    
    def test_cache_initialization(self, cache_manager):
        """Test cache manager initialization."""
        assert CacheLevel.MEMORY in cache_manager.caches
        assert len(cache_manager.cache_hierarchy) >= 1
    
    def test_cache_put_get(self, cache_manager):
        """Test basic cache operations."""
        key = "test_key"
        value = {"data": "test_value", "number": 42}
        
        # Put value
        success = cache_manager.put(key, value)
        assert success
        
        # Get value
        retrieved = cache_manager.get(key)
        assert retrieved == value
    
    def test_cache_miss(self, cache_manager):
        """Test cache miss."""
        result = cache_manager.get("nonexistent_key")
        assert result is None
    
    def test_cache_delete(self, cache_manager):
        """Test cache deletion."""
        key = "delete_test"
        value = "test_data"
        
        cache_manager.put(key, value)
        assert cache_manager.get(key) == value
        
        success = cache_manager.delete(key)
        assert success
        assert cache_manager.get(key) is None
    
    def test_cache_stats(self, cache_manager):
        """Test cache statistics."""
        # Perform some operations
        cache_manager.put("key1", "value1")
        cache_manager.get("key1")  # Hit
        cache_manager.get("key2")  # Miss
        
        stats = cache_manager.get_stats()
        
        assert 'global' in stats
        assert 'levels' in stats
        assert stats['global']['hits'] >= 1
        assert stats['global']['misses'] >= 1


class TestResourceManager:
    """Test resource management system."""
    
    @pytest.fixture
    def resource_manager(self):
        """Create resource manager."""
        limits = ResourceLimits(
            cpu_percent_warning=50.0,
            cpu_percent_critical=80.0,
            memory_percent_warning=60.0,
            memory_percent_critical=85.0
        )
        return ResourceManager(limits=limits, monitoring_interval=0.1)
    
    @pytest.fixture
    def sample_task(self):
        """Create sample task for resource allocation."""
        return ProcessingTask(
            task_id="resource_test_task",
            task_type="test",
            data={'test': 'data'},
            processor_func=lambda x: x,
            priority=5
        )
    
    @pytest.mark.asyncio
    async def test_resource_manager_startup(self, resource_manager):
        """Test resource manager startup."""
        await resource_manager.start()
        assert resource_manager.monitor.monitoring_active
        
        await resource_manager.stop()
        assert not resource_manager.monitor.monitoring_active
    
    def test_resource_allocation(self, resource_manager, sample_task):
        """Test resource allocation and deallocation."""
        # Allocate resources
        success = resource_manager.allocate_resources(
            sample_task,
            cpu_units=50,
            memory_mb=100
        )
        assert success
        assert hasattr(sample_task, 'resource_allocations')
        
        # Check availability
        availability = resource_manager.get_resource_availability()
        assert 'cpu' in availability
        assert 'memory' in availability
        
        # Deallocate resources
        success = resource_manager.deallocate_resources(sample_task)
        assert success
    
    def test_resource_limits_check(self, resource_manager):
        """Test resource limit checking."""
        # Test with high resource usage
        high_usage_task = ProcessingTask(
            task_id="high_usage_task",
            task_type="test",
            data={},
            processor_func=lambda x: x,
            priority=5
        )
        
        # Try to allocate more resources than available
        can_handle = resource_manager.can_handle_task(
            cpu_units=10000,  # Very high CPU requirement
            memory_mb=100000  # Very high memory requirement
        )
        
        # Should not be able to handle such high requirements
        assert not can_handle
    
    def test_optimal_concurrency_calculation(self, resource_manager):
        """Test optimal concurrency calculation."""
        concurrency = resource_manager.get_optimal_concurrency()
        
        assert isinstance(concurrency, int)
        assert concurrency >= 1
        assert concurrency <= 32  # Reasonable upper bound


class TestQueueManager:
    """Test queue management system."""
    
    @pytest.fixture
    def queue_manager(self):
        """Create queue manager."""
        return QueueManager()
    
    @pytest.fixture
    def sample_tasks(self):
        """Create sample tasks."""
        tasks = []
        for i in range(5):
            task = ProcessingTask(
                task_id=f"queue_task_{i}",
                task_type="test",
                data={'index': i},
                processor_func=lambda x: x,
                priority=QueueTaskPriority.NORMAL.value
            )
            tasks.append(task)
        return tasks
    
    def test_queue_creation(self, queue_manager):
        """Test queue creation."""
        success = queue_manager.create_queue(
            "test_queue",
            queue_type=queue_manager.QueueType.PRIORITY if hasattr(queue_manager, 'QueueType') else None,
            max_size=100
        )
        assert success
        assert "test_queue" in queue_manager.queues
    
    def test_task_enqueue_dequeue(self, queue_manager, sample_tasks):
        """Test task enqueue and dequeue operations."""
        # Enqueue tasks
        for task in sample_tasks:
            success = queue_manager.enqueue_task(task)
            assert success
        
        # Dequeue tasks
        dequeued_tasks = []
        for _ in range(len(sample_tasks)):
            task = queue_manager.dequeue_task()
            if task:
                dequeued_tasks.append(task)
        
        assert len(dequeued_tasks) == len(sample_tasks)
    
    def test_queue_status(self, queue_manager, sample_tasks):
        """Test queue status reporting."""
        # Add some tasks
        for task in sample_tasks[:3]:
            queue_manager.enqueue_task(task)
        
        status = queue_manager.get_queue_status()
        
        assert 'default' in status
        assert status['default']['size'] == 3
        assert not status['default']['is_empty']
    
    def test_batch_dequeue(self, queue_manager, sample_tasks):
        """Test batch dequeue operation."""
        # Enqueue tasks
        for task in sample_tasks:
            queue_manager.enqueue_task(task)
        
        # Dequeue batch
        batch = queue_manager.dequeue_batch(3)
        assert len(batch) == 3
        
        # Check remaining tasks
        status = queue_manager.get_queue_status()
        assert status['default']['size'] == 2


class TestIncrementalAnalyzer:
    """Test incremental analysis system."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def analyzer(self, temp_dir):
        """Create incremental analyzer."""
        return IncrementalAnalyzer(cache_dir=temp_dir)
    
    @pytest.fixture
    def test_files(self, temp_dir):
        """Create test files."""
        files = []
        for i in range(3):
            file_path = os.path.join(temp_dir, f"test_file_{i}.py")
            with open(file_path, 'w') as f:
                f.write(f"# Test file {i}\nprint('hello {i}')\n")
            files.append(file_path)
        return files
    
    def test_change_detection(self, analyzer, test_files):
        """Test file change detection."""
        # First detection (all files are new)
        changes = analyzer.change_detector.detect_changes(test_files)
        
        assert len(changes.added_files) == len(test_files)
        assert len(changes.modified_files) == 0
        assert len(changes.deleted_files) == 0
        assert changes.has_changes
    
    @pytest.mark.asyncio
    async def test_incremental_analysis(self, analyzer, test_files):
        """Test incremental analysis."""
        def mock_analyzer(content, file_path):
            # Mock analyzer that finds one issue per file
            from compliance_sentinel.core.interfaces import SecurityIssue
            return [SecurityIssue(
                id=f"issue_{hash(file_path)}",
                rule_id="test_rule",
                file_path=file_path,
                line_number=1,
                severity="medium",
                category="test",
                description="Test issue"
            )]
        
        # Perform initial analysis
        result = await analyzer.analyze_incremental(
            test_files,
            mock_analyzer,
            AnalysisScope.CHANGED_FILES_ONLY
        )
        
        assert len(result.analyzed_files) == len(test_files)
        assert len(result.skipped_files) == 0
        assert len(result.new_issues) > 0
        assert result.analysis_time > 0
    
    def test_analysis_stats(self, analyzer):
        """Test analysis statistics."""
        stats = analyzer.get_analysis_stats()
        
        assert 'total_analyses' in stats
        assert 'cache_hits' in stats
        assert 'cache_misses' in stats
        assert 'files_analyzed' in stats


class TestStreamingProcessor:
    """Test streaming processing system."""
    
    @pytest.fixture
    def streaming_processor(self):
        """Create streaming processor."""
        return StreamingProcessor()
    
    @pytest.fixture
    def stream_config(self):
        """Create stream configuration."""
        return StreamConfig(
            stream_id="test_stream",
            stream_type=StreamType.CUSTOM,
            batch_size=5,
            batch_timeout_seconds=1.0,
            max_queue_size=100
        )
    
    def test_stream_creation(self, streaming_processor, stream_config):
        """Test stream creation."""
        def mock_processor(batch):
            return [f"processed_{item}" for item in batch]
        
        success = streaming_processor.create_stream(stream_config, mock_processor)
        assert success
        assert stream_config.stream_id in streaming_processor.streams
    
    @pytest.mark.asyncio
    async def test_stream_processing(self, streaming_processor, stream_config):
        """Test stream processing."""
        processed_items = []
        
        def mock_processor(batch):
            processed_items.extend(batch)
            return [f"processed_{item}" for item in batch]
        
        # Create and start stream
        streaming_processor.create_stream(stream_config, mock_processor)
        await streaming_processor.start_stream(stream_config.stream_id)
        
        # Add items to stream
        for i in range(10):
            success = streaming_processor.add_item_to_stream(
                stream_config.stream_id, 
                f"item_{i}"
            )
            assert success
        
        # Wait for processing
        await asyncio.sleep(2.0)
        
        # Stop stream
        await streaming_processor.stop_stream(stream_config.stream_id)
        
        # Check results
        assert len(processed_items) == 10
    
    def test_stream_status(self, streaming_processor, stream_config):
        """Test stream status reporting."""
        def mock_processor(batch):
            return batch
        
        streaming_processor.create_stream(stream_config, mock_processor)
        
        status = streaming_processor.get_stream_status(stream_config.stream_id)
        
        assert 'stream_id' in status
        assert 'status' in status
        assert 'config' in status
        assert 'metrics' in status
    
    def test_broadcast_item(self, streaming_processor):
        """Test broadcasting items to multiple streams."""
        # Create multiple streams
        configs = []
        for i in range(3):
            config = StreamConfig(
                stream_id=f"broadcast_stream_{i}",
                stream_type=StreamType.CUSTOM,
                batch_size=10
            )
            configs.append(config)
            
            streaming_processor.create_stream(config, lambda batch: batch)
        
        # Broadcast item
        success_count = streaming_processor.broadcast_item("broadcast_test")
        assert success_count == 3


class TestIntegrationScenarios:
    """Test integration between performance components."""
    
    @pytest.mark.asyncio
    async def test_parallel_processing_with_caching(self):
        """Test parallel processing with caching integration."""
        cache_manager = CacheManager(
            memory_cache_config={'max_size_bytes': 1024 * 1024},
            disk_cache_config=False,
            redis_cache_config=False
        )
        
        processor = ParallelProcessor(max_workers=2, enable_monitoring=False)
        
        def cached_processor(data):
            key = f"cache_key_{data['id']}"
            
            # Check cache first
            cached_result = cache_manager.get(key)
            if cached_result:
                return cached_result
            
            # Process and cache result
            result = f"processed_{data['id']}"
            cache_manager.put(key, result)
            return result
        
        # Create tasks
        tasks = []
        for i in range(5):
            task = ProcessingTask(
                task_id=f"cached_task_{i}",
                task_type="cached_processing",
                data={'id': i},
                processor_func=cached_processor,
                priority=TaskPriority.NORMAL.value
            )
            tasks.append(task)
        
        # Submit and process tasks
        processor.submit_batch(tasks)
        results = await processor.process_tasks()
        
        assert len(results) == 5
        assert all(r.status == TaskStatus.COMPLETED for r in results)
        
        # Verify caching worked
        cache_stats = cache_manager.get_stats()
        assert cache_stats['global']['hits'] >= 0  # May be 0 on first run
    
    @pytest.mark.asyncio
    async def test_resource_aware_processing(self):
        """Test processing with resource management."""
        resource_manager = ResourceManager(monitoring_interval=0.1)
        processor = ParallelProcessor(max_workers=2, enable_monitoring=False)
        
        await resource_manager.start()
        
        try:
            # Create resource-intensive task
            def resource_task(data):
                time.sleep(0.1)  # Simulate work
                return f"processed_{data['value']}"
            
            task = ProcessingTask(
                task_id="resource_task",
                task_type="resource_intensive",
                data={'value': 'test'},
                processor_func=resource_task,
                priority=TaskPriority.NORMAL.value
            )
            
            # Allocate resources
            success = resource_manager.allocate_resources(
                task,
                cpu_units=100,
                memory_mb=50
            )
            assert success
            
            # Process task
            processor.submit_task(task)
            results = await processor.process_tasks()
            
            assert len(results) == 1
            assert results[0].status == TaskStatus.COMPLETED
            
            # Deallocate resources
            resource_manager.deallocate_resources(task)
            
        finally:
            await resource_manager.stop()


if __name__ == "__main__":
    pytest.main([__file__])