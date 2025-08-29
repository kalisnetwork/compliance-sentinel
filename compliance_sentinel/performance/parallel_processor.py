"""Parallel processing framework for multi-language analysis."""

import asyncio
import concurrent.futures
from typing import List, Dict, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging
import multiprocessing
import threading
import queue
import time

from compliance_sentinel.core.interfaces import SecurityIssue
from compliance_sentinel.analyzers.languages.base import ProgrammingLanguage


logger = logging.getLogger(__name__)


@dataclass
class ProcessingConfig:
    """Configuration for parallel processing."""
    
    # Worker configuration
    max_workers: int = field(default_factory=lambda: multiprocessing.cpu_count())
    worker_type: str = "thread"  # "thread", "process", "async"
    
    # Queue configuration
    queue_size: int = 1000
    batch_size: int = 10
    
    # Timeout configuration
    task_timeout: int = 300  # seconds
    worker_timeout: int = 600  # seconds
    
    # Resource limits
    max_memory_mb: int = 1024
    max_cpu_percent: int = 80
    
    # Performance tuning
    enable_profiling: bool = False
    enable_metrics: bool = True
    
    # Error handling
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class AnalysisTask:
    """Represents an analysis task for parallel processing."""
    
    task_id: str
    file_path: str
    content: str
    language: ProgrammingLanguage
    analyzer_type: str
    
    # Metadata
    priority: int = 1  # 1=highest, 5=lowest
    created_at: datetime = field(default_factory=datetime.now)
    
    # Processing state
    attempts: int = 0
    last_error: str = ""
    
    # Results
    issues: List[SecurityIssue] = field(default_factory=list)
    processing_time: float = 0.0
    completed: bool = False


@dataclass
class ProcessingResult:
    """Result of parallel processing operation."""
    
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    total_issues: int
    
    # Timing
    start_time: datetime
    end_time: datetime
    total_duration: float
    
    # Performance metrics
    avg_task_time: float
    throughput_tasks_per_second: float
    
    # Resource usage
    peak_memory_mb: float
    avg_cpu_percent: float
    
    # Results by task
    task_results: Dict[str, AnalysisTask] = field(default_factory=dict)
    
    # Errors
    errors: List[str] = field(default_factory=list)


class ParallelAnalysisProcessor:
    """Parallel processing framework for security analysis."""
    
    def __init__(self, config: ProcessingConfig = None):
        """Initialize parallel processor."""
        self.config = config or ProcessingConfig()
        self.logger = logging.getLogger(__name__)
        
        # Processing state
        self.is_running = False
        self.task_queue = queue.Queue(maxsize=self.config.queue_size)
        self.result_queue = queue.Queue()
        
        # Workers
        self.workers = []
        self.executor = None
        
        # Metrics
        self.metrics = {
            'tasks_processed': 0,
            'tasks_failed': 0,
            'total_processing_time': 0.0,
            'start_time': None
        }
    
    async def process_files_parallel(self, 
                                   file_tasks: List[AnalysisTask],
                                   analyzer_factory: Callable) -> ProcessingResult:
        """Process multiple files in parallel."""
        
        start_time = datetime.now()
        self.metrics['start_time'] = start_time
        
        try:
            # Choose processing strategy based on configuration
            if self.config.worker_type == "async":
                result = await self._process_async(file_tasks, analyzer_factory)
            elif self.config.worker_type == "process":
                result = await self._process_multiprocessing(file_tasks, analyzer_factory)
            else:  # thread
                result = await self._process_threading(file_tasks, analyzer_factory)
            
            # Calculate final metrics
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            result.start_time = start_time
            result.end_time = end_time
            result.total_duration = total_duration
            
            if result.completed_tasks > 0:
                result.throughput_tasks_per_second = result.completed_tasks / total_duration
                result.avg_task_time = result.total_duration / result.completed_tasks
            
            return result
            
        except Exception as e:
            self.logger.error(f"Parallel processing failed: {e}")
            raise
    
    async def _process_async(self, 
                           file_tasks: List[AnalysisTask],
                           analyzer_factory: Callable) -> ProcessingResult:
        """Process files using asyncio for I/O-bound tasks."""
        
        semaphore = asyncio.Semaphore(self.config.max_workers)
        
        async def process_single_task(task: AnalysisTask) -> AnalysisTask:
            async with semaphore:
                return await self._analyze_task_async(task, analyzer_factory)
        
        # Create tasks
        async_tasks = [process_single_task(task) for task in file_tasks]
        
        # Process with timeout
        try:
            completed_tasks = await asyncio.wait_for(
                asyncio.gather(*async_tasks, return_exceptions=True),
                timeout=self.config.task_timeout
            )
        except asyncio.TimeoutError:
            self.logger.error("Async processing timed out")
            completed_tasks = []
        
        # Process results
        return self._compile_results(completed_tasks, file_tasks)
    
    async def _process_threading(self, 
                               file_tasks: List[AnalysisTask],
                               analyzer_factory: Callable) -> ProcessingResult:
        """Process files using thread pool for CPU-bound tasks."""
        
        def process_task_sync(task: AnalysisTask) -> AnalysisTask:
            return self._analyze_task_sync(task, analyzer_factory)
        
        # Use ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(process_task_sync, task): task
                for task in file_tasks
            }
            
            completed_tasks = []
            
            # Collect results with timeout
            for future in concurrent.futures.as_completed(future_to_task, timeout=self.config.task_timeout):
                try:
                    result = future.result()
                    completed_tasks.append(result)
                except Exception as e:
                    task = future_to_task[future]
                    task.last_error = str(e)
                    task.completed = False
                    completed_tasks.append(task)
                    self.logger.error(f"Task {task.task_id} failed: {e}")
        
        return self._compile_results(completed_tasks, file_tasks)
    
    async def _process_multiprocessing(self, 
                                     file_tasks: List[AnalysisTask],
                                     analyzer_factory: Callable) -> ProcessingResult:
        """Process files using multiprocessing for CPU-intensive tasks."""
        
        # Use ProcessPoolExecutor
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(self._analyze_task_process, task, analyzer_factory): task
                for task in file_tasks
            }
            
            completed_tasks = []
            
            # Collect results with timeout
            for future in concurrent.futures.as_completed(future_to_task, timeout=self.config.task_timeout):
                try:
                    result = future.result()
                    completed_tasks.append(result)
                except Exception as e:
                    task = future_to_task[future]
                    task.last_error = str(e)
                    task.completed = False
                    completed_tasks.append(task)
                    self.logger.error(f"Task {task.task_id} failed: {e}")
        
        return self._compile_results(completed_tasks, file_tasks)
    
    async def _analyze_task_async(self, task: AnalysisTask, analyzer_factory: Callable) -> AnalysisTask:
        """Analyze a single task asynchronously."""
        
        start_time = time.time()
        
        try:
            # Create analyzer
            analyzer = analyzer_factory(task.analyzer_type)
            
            # Perform analysis
            if hasattr(analyzer, 'analyze_content_async'):
                issues = await analyzer.analyze_content_async(task.content, task.file_path)
            else:
                # Fallback to sync analysis in thread pool
                loop = asyncio.get_event_loop()
                issues = await loop.run_in_executor(
                    None, 
                    analyzer.analyze_content, 
                    task.content, 
                    task.file_path
                )
            
            task.issues = issues
            task.completed = True
            
        except Exception as e:
            task.last_error = str(e)
            task.completed = False
            task.attempts += 1
            self.logger.error(f"Async analysis failed for {task.file_path}: {e}")
        
        finally:
            task.processing_time = time.time() - start_time
        
        return task
    
    def _analyze_task_sync(self, task: AnalysisTask, analyzer_factory: Callable) -> AnalysisTask:
        """Analyze a single task synchronously."""
        
        start_time = time.time()
        
        try:
            # Create analyzer
            analyzer = analyzer_factory(task.analyzer_type)
            
            # Perform analysis
            issues = analyzer.analyze_content(task.content, task.file_path)
            
            task.issues = issues
            task.completed = True
            
        except Exception as e:
            task.last_error = str(e)
            task.completed = False
            task.attempts += 1
            self.logger.error(f"Sync analysis failed for {task.file_path}: {e}")
        
        finally:
            task.processing_time = time.time() - start_time
        
        return task
    
    @staticmethod
    def _analyze_task_process(task: AnalysisTask, analyzer_factory: Callable) -> AnalysisTask:
        """Analyze a single task in separate process (must be static for pickling)."""
        
        start_time = time.time()
        
        try:
            # Create analyzer
            analyzer = analyzer_factory(task.analyzer_type)
            
            # Perform analysis
            issues = analyzer.analyze_content(task.content, task.file_path)
            
            task.issues = issues
            task.completed = True
            
        except Exception as e:
            task.last_error = str(e)
            task.completed = False
            task.attempts += 1
        
        finally:
            task.processing_time = time.time() - start_time
        
        return task
    
    def _compile_results(self, completed_tasks: List[AnalysisTask], original_tasks: List[AnalysisTask]) -> ProcessingResult:
        """Compile processing results from completed tasks."""
        
        # Handle exceptions in results
        valid_tasks = []
        for task in completed_tasks:
            if isinstance(task, Exception):
                self.logger.error(f"Task resulted in exception: {task}")
                continue
            valid_tasks.append(task)
        
        # Calculate metrics
        total_tasks = len(original_tasks)
        completed_count = len([t for t in valid_tasks if t.completed])
        failed_count = total_tasks - completed_count
        total_issues = sum(len(t.issues) for t in valid_tasks if t.completed)
        
        # Performance metrics
        processing_times = [t.processing_time for t in valid_tasks if t.processing_time > 0]
        avg_task_time = sum(processing_times) / len(processing_times) if processing_times else 0.0
        
        # Create task results mapping
        task_results = {task.task_id: task for task in valid_tasks}
        
        # Collect errors
        errors = [t.last_error for t in valid_tasks if t.last_error]
        
        return ProcessingResult(
            total_tasks=total_tasks,
            completed_tasks=completed_count,
            failed_tasks=failed_count,
            total_issues=total_issues,
            start_time=datetime.now(),  # Will be updated by caller
            end_time=datetime.now(),    # Will be updated by caller
            total_duration=0.0,         # Will be updated by caller
            avg_task_time=avg_task_time,
            throughput_tasks_per_second=0.0,  # Will be calculated by caller
            peak_memory_mb=0.0,  # Would need memory monitoring
            avg_cpu_percent=0.0,  # Would need CPU monitoring
            task_results=task_results,
            errors=errors
        )
    
    def get_optimal_worker_count(self, task_type: str = "cpu_bound") -> int:
        """Calculate optimal worker count based on system resources and task type."""
        
        cpu_count = multiprocessing.cpu_count()
        
        if task_type == "cpu_bound":
            # For CPU-bound tasks, use CPU count
            return min(cpu_count, self.config.max_workers)
        elif task_type == "io_bound":
            # For I/O-bound tasks, use more workers
            return min(cpu_count * 2, self.config.max_workers)
        elif task_type == "mixed":
            # For mixed workloads, use 1.5x CPU count
            return min(int(cpu_count * 1.5), self.config.max_workers)
        else:
            return cpu_count
    
    def estimate_processing_time(self, 
                                file_count: int,
                                avg_file_size: int,
                                complexity_factor: float = 1.0) -> float:
        """Estimate processing time based on file characteristics."""
        
        # Base processing time per file (seconds)
        base_time_per_file = 0.1
        
        # Adjust for file size (larger files take longer)
        size_factor = min(avg_file_size / 10000, 5.0)  # Cap at 5x
        
        # Adjust for complexity
        adjusted_time = base_time_per_file * size_factor * complexity_factor
        
        # Account for parallelization
        parallel_efficiency = 0.8  # 80% efficiency due to overhead
        effective_workers = self.config.max_workers * parallel_efficiency
        
        # Calculate total time
        total_sequential_time = file_count * adjusted_time
        parallel_time = total_sequential_time / effective_workers
        
        # Add overhead for coordination
        overhead_factor = 1.2
        
        return parallel_time * overhead_factor


class WorkerPool:
    """Manages a pool of analysis workers."""
    
    def __init__(self, config: ProcessingConfig):
        """Initialize worker pool."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Worker management
        self.workers = []
        self.task_queue = queue.Queue(maxsize=config.queue_size)
        self.result_queue = queue.Queue()
        
        # State management
        self.is_running = False
        self.shutdown_event = threading.Event()
        
        # Metrics
        self.worker_metrics = {}
    
    def start(self, analyzer_factory: Callable):
        """Start the worker pool."""
        
        if self.is_running:
            return
        
        self.is_running = True
        self.shutdown_event.clear()
        
        # Start workers
        for i in range(self.config.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i, analyzer_factory),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
            
            # Initialize worker metrics
            self.worker_metrics[i] = {
                'tasks_processed': 0,
                'total_time': 0.0,
                'errors': 0,
                'last_activity': datetime.now()
            }
        
        self.logger.info(f"Started worker pool with {len(self.workers)} workers")
    
    def stop(self, timeout: float = 30.0):
        """Stop the worker pool."""
        
        if not self.is_running:
            return
        
        self.logger.info("Stopping worker pool...")
        
        # Signal shutdown
        self.shutdown_event.set()
        self.is_running = False
        
        # Add poison pills to wake up workers
        for _ in self.workers:
            try:
                self.task_queue.put(None, timeout=1.0)
            except queue.Full:
                pass
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=timeout)
            if worker.is_alive():
                self.logger.warning(f"Worker {worker.name} did not shut down gracefully")
        
        self.workers.clear()
        self.logger.info("Worker pool stopped")
    
    def submit_task(self, task: AnalysisTask) -> bool:
        """Submit a task to the worker pool."""
        
        if not self.is_running:
            return False
        
        try:
            self.task_queue.put(task, timeout=1.0)
            return True
        except queue.Full:
            self.logger.warning("Task queue is full, dropping task")
            return False
    
    def get_result(self, timeout: float = 1.0) -> Optional[AnalysisTask]:
        """Get a completed task result."""
        
        try:
            return self.result_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def _worker_loop(self, worker_id: int, analyzer_factory: Callable):
        """Main worker loop."""
        
        self.logger.debug(f"Worker {worker_id} started")
        
        while not self.shutdown_event.is_set():
            try:
                # Get task from queue
                task = self.task_queue.get(timeout=1.0)
                
                # Check for poison pill (shutdown signal)
                if task is None:
                    break
                
                # Process task
                start_time = time.time()
                processed_task = self._process_task(task, analyzer_factory, worker_id)
                processing_time = time.time() - start_time
                
                # Update worker metrics
                metrics = self.worker_metrics[worker_id]
                metrics['tasks_processed'] += 1
                metrics['total_time'] += processing_time
                metrics['last_activity'] = datetime.now()
                
                if not processed_task.completed:
                    metrics['errors'] += 1
                
                # Put result
                self.result_queue.put(processed_task)
                
                # Mark task as done
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Worker {worker_id} error: {e}")
        
        self.logger.debug(f"Worker {worker_id} stopped")
    
    def _process_task(self, task: AnalysisTask, analyzer_factory: Callable, worker_id: int) -> AnalysisTask:
        """Process a single analysis task."""
        
        start_time = time.time()
        
        try:
            # Create analyzer
            analyzer = analyzer_factory(task.analyzer_type)
            
            # Perform analysis
            issues = analyzer.analyze_content(task.content, task.file_path)
            
            task.issues = issues
            task.completed = True
            
            self.logger.debug(f"Worker {worker_id} completed task {task.task_id}: {len(issues)} issues")
            
        except Exception as e:
            task.last_error = str(e)
            task.completed = False
            task.attempts += 1
            self.logger.error(f"Worker {worker_id} failed task {task.task_id}: {e}")
        
        finally:
            task.processing_time = time.time() - start_time
        
        return task
    
    def get_worker_metrics(self) -> Dict[str, Any]:
        """Get worker pool metrics."""
        
        if not self.worker_metrics:
            return {}
        
        total_tasks = sum(m['tasks_processed'] for m in self.worker_metrics.values())
        total_time = sum(m['total_time'] for m in self.worker_metrics.values())
        total_errors = sum(m['errors'] for m in self.worker_metrics.values())
        
        return {
            'total_workers': len(self.worker_metrics),
            'active_workers': len([m for m in self.worker_metrics.values() 
                                 if (datetime.now() - m['last_activity']).seconds < 60]),
            'total_tasks_processed': total_tasks,
            'total_processing_time': total_time,
            'total_errors': total_errors,
            'avg_task_time': total_time / total_tasks if total_tasks > 0 else 0.0,
            'error_rate': total_errors / total_tasks if total_tasks > 0 else 0.0,
            'worker_details': self.worker_metrics
        }