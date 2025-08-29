"""Distributed analysis system with worker node management."""

import asyncio
import aiohttp
import json
import logging
import time
import uuid
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import hashlib
import socket

from compliance_sentinel.core.interfaces import SecurityIssue, AnalysisResult


logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """Worker node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class JobStatus(Enum):
    """Analysis job status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkerNode:
    """Represents a distributed worker node."""
    
    # Node identification
    node_id: str
    hostname: str
    ip_address: str
    port: int
    
    # Capabilities
    supported_languages: List[str] = field(default_factory=list)
    max_concurrent_jobs: int = 4
    cpu_cores: int = 1
    memory_gb: float = 1.0
    
    # Status
    status: NodeStatus = NodeStatus.OFFLINE
    current_jobs: int = 0
    last_heartbeat: datetime = field(default_factory=datetime.now)
    
    # Performance metrics
    total_jobs_completed: int = 0
    total_jobs_failed: int = 0
    average_job_time: float = 0.0
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    
    # Health metrics
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    
    @property
    def endpoint_url(self) -> str:
        """Get the full endpoint URL for this node."""
        return f"http://{self.ip_address}:{self.port}"
    
    @property
    def is_available(self) -> bool:
        """Check if node is available for new jobs."""
        return (
            self.status == NodeStatus.ONLINE and
            self.current_jobs < self.max_concurrent_jobs and
            self.consecutive_failures < 3
        )
    
    @property
    def load_factor(self) -> float:
        """Calculate current load factor (0.0 to 1.0)."""
        if self.max_concurrent_jobs == 0:
            return 1.0
        return self.current_jobs / self.max_concurrent_jobs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'port': self.port,
            'supported_languages': self.supported_languages,
            'max_concurrent_jobs': self.max_concurrent_jobs,
            'cpu_cores': self.cpu_cores,
            'memory_gb': self.memory_gb,
            'status': self.status.value,
            'current_jobs': self.current_jobs,
            'last_heartbeat': self.last_heartbeat.isoformat(),
            'total_jobs_completed': self.total_jobs_completed,
            'total_jobs_failed': self.total_jobs_failed,
            'average_job_time': self.average_job_time,
            'cpu_utilization': self.cpu_utilization,
            'memory_utilization': self.memory_utilization,
            'consecutive_failures': self.consecutive_failures,
            'last_error': self.last_error,
            'is_available': self.is_available,
            'load_factor': self.load_factor
        }


@dataclass
class AnalysisJob:
    """Represents a distributed analysis job."""
    
    # Job identification
    job_id: str
    job_type: str
    
    # Job data
    file_path: str
    file_content: str
    language: str
    analyzer_config: Dict[str, Any] = field(default_factory=dict)
    
    # Job metadata
    priority: int = 5  # 1-10, higher is more priority
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3
    
    # Assignment
    assigned_node_id: Optional[str] = None
    assigned_at: Optional[datetime] = None
    
    # Execution tracking
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    result: Optional[AnalysisResult] = None
    issues: List[SecurityIssue] = field(default_factory=list)
    error: Optional[str] = None
    
    # Performance metrics
    execution_time: float = 0.0
    queue_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary."""
        return {
            'job_id': self.job_id,
            'job_type': self.job_type,
            'file_path': self.file_path,
            'language': self.language,
            'analyzer_config': self.analyzer_config,
            'priority': self.priority,
            'timeout_seconds': self.timeout_seconds,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'assigned_node_id': self.assigned_node_id,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error': self.error,
            'execution_time': self.execution_time,
            'queue_time': self.queue_time,
            'issues_count': len(self.issues)
        }


class NodeSelector:
    """Selects optimal worker nodes for job assignment."""
    
    def __init__(self):
        """Initialize node selector."""
        self.selection_strategies = {
            'round_robin': self._round_robin_selection,
            'least_loaded': self._least_loaded_selection,
            'fastest_node': self._fastest_node_selection,
            'language_affinity': self._language_affinity_selection,
            'weighted_random': self._weighted_random_selection
        }
        self.current_strategy = 'least_loaded'
        self.round_robin_index = 0
    
    def select_node(self, job: AnalysisJob, available_nodes: List[WorkerNode]) -> Optional[WorkerNode]:
        """Select the best node for a job."""
        if not available_nodes:
            return None
        
        # Filter nodes that support the required language
        compatible_nodes = [
            node for node in available_nodes
            if not node.supported_languages or job.language in node.supported_languages
        ]
        
        if not compatible_nodes:
            # Fallback to any available node
            compatible_nodes = available_nodes
        
        # Apply selection strategy
        strategy_func = self.selection_strategies.get(
            self.current_strategy, 
            self._least_loaded_selection
        )
        
        return strategy_func(job, compatible_nodes)
    
    def _round_robin_selection(self, job: AnalysisJob, nodes: List[WorkerNode]) -> WorkerNode:
        """Round-robin node selection."""
        if not nodes:
            return None
        
        selected_node = nodes[self.round_robin_index % len(nodes)]
        self.round_robin_index += 1
        return selected_node
    
    def _least_loaded_selection(self, job: AnalysisJob, nodes: List[WorkerNode]) -> WorkerNode:
        """Select node with lowest load factor."""
        return min(nodes, key=lambda node: node.load_factor)
    
    def _fastest_node_selection(self, job: AnalysisJob, nodes: List[WorkerNode]) -> WorkerNode:
        """Select node with best average job time."""
        return min(nodes, key=lambda node: node.average_job_time or float('inf'))
    
    def _language_affinity_selection(self, job: AnalysisJob, nodes: List[WorkerNode]) -> WorkerNode:
        """Select node with language affinity, then by load."""
        # Prefer nodes that explicitly support the language
        language_nodes = [
            node for node in nodes
            if job.language in node.supported_languages
        ]
        
        if language_nodes:
            return min(language_nodes, key=lambda node: node.load_factor)
        else:
            return min(nodes, key=lambda node: node.load_factor)
    
    def _weighted_random_selection(self, job: AnalysisJob, nodes: List[WorkerNode]) -> WorkerNode:
        """Weighted random selection based on inverse load factor."""
        import random
        
        # Calculate weights (inverse of load factor)
        weights = []
        for node in nodes:
            weight = 1.0 - node.load_factor
            weights.append(max(weight, 0.1))  # Minimum weight
        
        # Weighted random selection
        return random.choices(nodes, weights=weights)[0]


class DistributedAnalyzer:
    """Distributed analysis system with worker node management."""
    
    def __init__(self, 
                 coordinator_port: int = 8080,
                 heartbeat_interval: int = 30,
                 job_timeout: int = 300,
                 max_retries: int = 3):
        """Initialize distributed analyzer."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.coordinator_port = coordinator_port
        self.heartbeat_interval = heartbeat_interval
        self.job_timeout = job_timeout
        self.max_retries = max_retries
        
        # Node management
        self.nodes = {}  # node_id -> WorkerNode
        self.node_selector = NodeSelector()
        
        # Job management
        self.jobs = {}  # job_id -> AnalysisJob
        self.job_queue = asyncio.Queue()
        self.completed_jobs = {}
        
        # Coordinator state
        self.is_running = False
        self.coordinator_task = None
        self.heartbeat_task = None
        
        # HTTP session for node communication
        self.session = None
        
        # Performance metrics
        self.metrics = {
            'total_jobs': 0,
            'completed_jobs': 0,
            'failed_jobs': 0,
            'average_job_time': 0.0,
            'total_nodes': 0,
            'active_nodes': 0,
            'throughput_jobs_per_minute': 0.0
        }
    
    async def start(self):
        """Start the distributed analyzer coordinator."""
        if self.is_running:
            return
        
        self.is_running = True
        self.session = aiohttp.ClientSession()
        
        # Start coordinator tasks
        self.coordinator_task = asyncio.create_task(self._coordinator_loop())
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        self.logger.info(f"Distributed analyzer coordinator started on port {self.coordinator_port}")
    
    async def stop(self):
        """Stop the distributed analyzer coordinator."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Cancel tasks
        if self.coordinator_task:
            self.coordinator_task.cancel()
            try:
                await self.coordinator_task
            except asyncio.CancelledError:
                pass
        
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        self.logger.info("Distributed analyzer coordinator stopped")
    
    async def register_node(self, node: WorkerNode) -> bool:
        """Register a new worker node."""
        try:
            # Test node connectivity
            if await self._test_node_connectivity(node):
                self.nodes[node.node_id] = node
                node.status = NodeStatus.ONLINE
                node.last_heartbeat = datetime.now()
                
                self.logger.info(f"Registered worker node: {node.node_id} at {node.endpoint_url}")
                return True
            else:
                self.logger.error(f"Failed to connect to node: {node.node_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error registering node {node.node_id}: {e}")
            return False
    
    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a worker node."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            
            # Cancel any jobs assigned to this node
            await self._reassign_node_jobs(node_id)
            
            del self.nodes[node_id]
            self.logger.info(f"Unregistered worker node: {node_id}")
            return True
        
        return False
    
    async def submit_job(self, job: AnalysisJob) -> str:
        """Submit an analysis job for distributed processing."""
        self.jobs[job.job_id] = job
        await self.job_queue.put(job)
        
        self.metrics['total_jobs'] += 1
        self.logger.debug(f"Submitted job: {job.job_id}")
        
        return job.job_id
    
    async def submit_batch_jobs(self, jobs: List[AnalysisJob]) -> List[str]:
        """Submit multiple jobs for processing."""
        job_ids = []
        
        for job in jobs:
            job_id = await self.submit_job(job)
            job_ids.append(job_id)
        
        self.logger.info(f"Submitted batch of {len(jobs)} jobs")
        return job_ids
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific job."""
        if job_id in self.jobs:
            return self.jobs[job_id].to_dict()
        elif job_id in self.completed_jobs:
            return self.completed_jobs[job_id].to_dict()
        
        return None
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job."""
        if job_id not in self.jobs:
            return False
        
        job = self.jobs[job_id]
        
        if job.status in [JobStatus.PENDING, JobStatus.ASSIGNED]:
            job.status = JobStatus.CANCELLED
            return True
        elif job.status == JobStatus.RUNNING and job.assigned_node_id:
            # Try to cancel on the worker node
            return await self._cancel_job_on_node(job)
        
        return False
    
    async def _coordinator_loop(self):
        """Main coordinator loop for job assignment and monitoring."""
        while self.is_running:
            try:
                # Process pending jobs
                await self._process_job_queue()
                
                # Monitor running jobs
                await self._monitor_running_jobs()
                
                # Update metrics
                self._update_metrics()
                
                await asyncio.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in coordinator loop: {e}")
                await asyncio.sleep(5)
    
    async def _process_job_queue(self):
        """Process pending jobs in the queue."""
        try:
            # Get job from queue (non-blocking)
            job = await asyncio.wait_for(self.job_queue.get(), timeout=0.1)
            
            # Find available nodes
            available_nodes = [
                node for node in self.nodes.values()
                if node.is_available
            ]
            
            if not available_nodes:
                # Put job back in queue
                await self.job_queue.put(job)
                return
            
            # Select best node for the job
            selected_node = self.node_selector.select_node(job, available_nodes)
            
            if selected_node:
                # Assign job to node
                await self._assign_job_to_node(job, selected_node)
            else:
                # Put job back in queue
                await self.job_queue.put(job)
                
        except asyncio.TimeoutError:
            # No jobs in queue
            pass
        except Exception as e:
            self.logger.error(f"Error processing job queue: {e}")
    
    async def _assign_job_to_node(self, job: AnalysisJob, node: WorkerNode):
        """Assign a job to a specific worker node."""
        try:
            # Update job status
            job.status = JobStatus.ASSIGNED
            job.assigned_node_id = node.node_id
            job.assigned_at = datetime.now()
            job.queue_time = (job.assigned_at - job.created_at).total_seconds()
            
            # Update node status
            node.current_jobs += 1
            
            # Send job to node
            success = await self._send_job_to_node(job, node)
            
            if success:
                job.status = JobStatus.RUNNING
                job.started_at = datetime.now()
                self.logger.debug(f"Assigned job {job.job_id} to node {node.node_id}")
            else:
                # Assignment failed, reset job status
                job.status = JobStatus.PENDING
                job.assigned_node_id = None
                job.assigned_at = None
                node.current_jobs -= 1
                
                # Put job back in queue
                await self.job_queue.put(job)
                
        except Exception as e:
            self.logger.error(f"Error assigning job {job.job_id} to node {node.node_id}: {e}")
            
            # Reset job status on error
            job.status = JobStatus.PENDING
            job.assigned_node_id = None
            job.assigned_at = None
            if node.current_jobs > 0:
                node.current_jobs -= 1
    
    async def _send_job_to_node(self, job: AnalysisJob, node: WorkerNode) -> bool:
        """Send job to worker node for execution."""
        try:
            job_data = {
                'job_id': job.job_id,
                'job_type': job.job_type,
                'file_path': job.file_path,
                'file_content': job.file_content,
                'language': job.language,
                'analyzer_config': job.analyzer_config,
                'timeout_seconds': job.timeout_seconds
            }
            
            url = f"{node.endpoint_url}/analyze"
            
            async with self.session.post(
                url, 
                json=job_data,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return True
                else:
                    self.logger.error(f"Node {node.node_id} rejected job: {response.status}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error sending job to node {node.node_id}: {e}")
            node.consecutive_failures += 1
            node.last_error = str(e)
            
            if node.consecutive_failures >= 3:
                node.status = NodeStatus.ERROR
            
            return False
    
    async def _monitor_running_jobs(self):
        """Monitor running jobs for completion or timeout."""
        current_time = datetime.now()
        
        for job in list(self.jobs.values()):
            if job.status == JobStatus.RUNNING:
                # Check for timeout
                if job.started_at:
                    elapsed = (current_time - job.started_at).total_seconds()
                    if elapsed > job.timeout_seconds:
                        await self._handle_job_timeout(job)
                
                # Check job status on node
                elif job.assigned_node_id:
                    await self._check_job_status_on_node(job)
    
    async def _handle_job_timeout(self, job: AnalysisJob):
        """Handle job timeout."""
        self.logger.warning(f"Job {job.job_id} timed out")
        
        job.status = JobStatus.FAILED
        job.error = "Job timeout"
        job.completed_at = datetime.now()
        
        # Update node status
        if job.assigned_node_id and job.assigned_node_id in self.nodes:
            node = self.nodes[job.assigned_node_id]
            if node.current_jobs > 0:
                node.current_jobs -= 1
            node.total_jobs_failed += 1
        
        # Retry if possible
        if job.retry_count < job.max_retries:
            job.retry_count += 1
            job.status = JobStatus.PENDING
            job.assigned_node_id = None
            job.assigned_at = None
            job.started_at = None
            await self.job_queue.put(job)
        else:
            # Move to completed jobs
            self._complete_job(job)
    
    async def _check_job_status_on_node(self, job: AnalysisJob):
        """Check job status on worker node."""
        if not job.assigned_node_id or job.assigned_node_id not in self.nodes:
            return
        
        node = self.nodes[job.assigned_node_id]
        
        try:
            url = f"{node.endpoint_url}/job/{job.job_id}/status"
            
            async with self.session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    status_data = await response.json()
                    await self._update_job_from_node_status(job, status_data)
                elif response.status == 404:
                    # Job not found on node, may have completed
                    await self._fetch_job_result_from_node(job, node)
                    
        except Exception as e:
            self.logger.error(f"Error checking job status on node {node.node_id}: {e}")
    
    async def _update_job_from_node_status(self, job: AnalysisJob, status_data: Dict[str, Any]):
        """Update job status from node response."""
        node_status = status_data.get('status')
        
        if node_status == 'completed':
            await self._fetch_job_result_from_node(job, self.nodes[job.assigned_node_id])
        elif node_status == 'failed':
            job.status = JobStatus.FAILED
            job.error = status_data.get('error', 'Unknown error')
            job.completed_at = datetime.now()
            self._complete_job(job)
    
    async def _fetch_job_result_from_node(self, job: AnalysisJob, node: WorkerNode):
        """Fetch job result from worker node."""
        try:
            url = f"{node.endpoint_url}/job/{job.job_id}/result"
            
            async with self.session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    result_data = await response.json()
                    
                    # Update job with results
                    job.status = JobStatus.COMPLETED
                    job.completed_at = datetime.now()
                    job.execution_time = result_data.get('execution_time', 0.0)
                    
                    # Parse issues
                    issues_data = result_data.get('issues', [])
                    job.issues = [self._parse_security_issue(issue_data) for issue_data in issues_data]
                    
                    # Update node metrics
                    node.current_jobs = max(0, node.current_jobs - 1)
                    node.total_jobs_completed += 1
                    node.consecutive_failures = 0
                    
                    # Update average job time
                    if node.total_jobs_completed > 0:
                        total_time = node.average_job_time * (node.total_jobs_completed - 1) + job.execution_time
                        node.average_job_time = total_time / node.total_jobs_completed
                    
                    self._complete_job(job)
                    self.logger.debug(f"Job {job.job_id} completed successfully")
                    
                else:
                    self.logger.error(f"Failed to fetch job result: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Error fetching job result from node {node.node_id}: {e}")
    
    def _parse_security_issue(self, issue_data: Dict[str, Any]) -> SecurityIssue:
        """Parse security issue from node response."""
        # This would need to match the SecurityIssue structure
        return SecurityIssue(
            id=issue_data.get('id', ''),
            rule_id=issue_data.get('rule_id', ''),
            file_path=issue_data.get('file_path', ''),
            line_number=issue_data.get('line_number', 0),
            severity=issue_data.get('severity', 'medium'),
            category=issue_data.get('category', ''),
            description=issue_data.get('description', ''),
            created_at=datetime.now()
        )
    
    def _complete_job(self, job: AnalysisJob):
        """Move job to completed jobs."""
        if job.job_id in self.jobs:
            del self.jobs[job.job_id]
        
        self.completed_jobs[job.job_id] = job
        
        # Update metrics
        if job.status == JobStatus.COMPLETED:
            self.metrics['completed_jobs'] += 1
        else:
            self.metrics['failed_jobs'] += 1
    
    async def _heartbeat_loop(self):
        """Heartbeat loop to monitor node health."""
        while self.is_running:
            try:
                await self._check_node_health()
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                self.logger.error(f"Error in heartbeat loop: {e}")
                await asyncio.sleep(10)
    
    async def _check_node_health(self):
        """Check health of all registered nodes."""
        current_time = datetime.now()
        
        for node in list(self.nodes.values()):
            try:
                # Check if node is responsive
                if await self._test_node_connectivity(node):
                    node.last_heartbeat = current_time
                    node.consecutive_failures = 0
                    
                    if node.status == NodeStatus.ERROR:
                        node.status = NodeStatus.ONLINE
                        self.logger.info(f"Node {node.node_id} recovered")
                else:
                    # Node is not responsive
                    time_since_heartbeat = (current_time - node.last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > self.heartbeat_interval * 3:
                        node.status = NodeStatus.OFFLINE
                        self.logger.warning(f"Node {node.node_id} is offline")
                        
                        # Reassign jobs from offline node
                        await self._reassign_node_jobs(node.node_id)
                        
            except Exception as e:
                self.logger.error(f"Error checking health of node {node.node_id}: {e}")
    
    async def _test_node_connectivity(self, node: WorkerNode) -> bool:
        """Test connectivity to a worker node."""
        try:
            url = f"{node.endpoint_url}/health"
            
            async with self.session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    health_data = await response.json()
                    
                    # Update node metrics from health data
                    node.cpu_utilization = health_data.get('cpu_utilization', 0.0)
                    node.memory_utilization = health_data.get('memory_utilization', 0.0)
                    node.current_jobs = health_data.get('current_jobs', 0)
                    
                    return True
                    
        except Exception:
            pass
        
        return False
    
    async def _reassign_node_jobs(self, node_id: str):
        """Reassign jobs from a failed or offline node."""
        reassigned_count = 0
        
        for job in list(self.jobs.values()):
            if job.assigned_node_id == node_id and job.status in [JobStatus.ASSIGNED, JobStatus.RUNNING]:
                # Reset job for reassignment
                job.status = JobStatus.PENDING
                job.assigned_node_id = None
                job.assigned_at = None
                job.started_at = None
                job.retry_count += 1
                
                if job.retry_count <= job.max_retries:
                    await self.job_queue.put(job)
                    reassigned_count += 1
                else:
                    # Max retries exceeded
                    job.status = JobStatus.FAILED
                    job.error = "Max retries exceeded due to node failures"
                    job.completed_at = datetime.now()
                    self._complete_job(job)
        
        if reassigned_count > 0:
            self.logger.info(f"Reassigned {reassigned_count} jobs from node {node_id}")
    
    async def _cancel_job_on_node(self, job: AnalysisJob) -> bool:
        """Cancel a running job on worker node."""
        if not job.assigned_node_id or job.assigned_node_id not in self.nodes:
            return False
        
        node = self.nodes[job.assigned_node_id]
        
        try:
            url = f"{node.endpoint_url}/job/{job.job_id}/cancel"
            
            async with self.session.post(
                url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    job.status = JobStatus.CANCELLED
                    job.completed_at = datetime.now()
                    
                    # Update node status
                    node.current_jobs = max(0, node.current_jobs - 1)
                    
                    self._complete_job(job)
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error cancelling job on node {node.node_id}: {e}")
        
        return False
    
    def _update_metrics(self):
        """Update performance metrics."""
        self.metrics['total_nodes'] = len(self.nodes)
        self.metrics['active_nodes'] = len([
            node for node in self.nodes.values()
            if node.status == NodeStatus.ONLINE
        ])
        
        # Calculate average job time
        completed_jobs = list(self.completed_jobs.values())
        if completed_jobs:
            total_time = sum(job.execution_time for job in completed_jobs if job.execution_time > 0)
            job_count = len([job for job in completed_jobs if job.execution_time > 0])
            
            if job_count > 0:
                self.metrics['average_job_time'] = total_time / job_count
        
        # Calculate throughput (jobs per minute)
        if completed_jobs:
            time_span = (datetime.now() - min(job.created_at for job in completed_jobs)).total_seconds()
            if time_span > 0:
                self.metrics['throughput_jobs_per_minute'] = (len(completed_jobs) * 60) / time_span
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get overall cluster status."""
        return {
            'coordinator_running': self.is_running,
            'total_nodes': len(self.nodes),
            'online_nodes': len([n for n in self.nodes.values() if n.status == NodeStatus.ONLINE]),
            'offline_nodes': len([n for n in self.nodes.values() if n.status == NodeStatus.OFFLINE]),
            'error_nodes': len([n for n in self.nodes.values() if n.status == NodeStatus.ERROR]),
            'total_jobs': len(self.jobs) + len(self.completed_jobs),
            'pending_jobs': len([j for j in self.jobs.values() if j.status == JobStatus.PENDING]),
            'running_jobs': len([j for j in self.jobs.values() if j.status == JobStatus.RUNNING]),
            'completed_jobs': len(self.completed_jobs),
            'queue_size': self.job_queue.qsize(),
            'metrics': self.metrics
        }
    
    def get_node_status(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific node."""
        if node_id in self.nodes:
            return self.nodes[node_id].to_dict()
        return None
    
    def get_all_nodes_status(self) -> List[Dict[str, Any]]:
        """Get status of all nodes."""
        return [node.to_dict() for node in self.nodes.values()]


# Utility functions for creating distributed analysis jobs

def create_file_analysis_job(file_path: str, file_content: str, language: str,
                           job_type: str = "security_analysis",
                           priority: int = 5,
                           timeout_seconds: int = 300,
                           analyzer_config: Dict[str, Any] = None) -> AnalysisJob:
    """Create a file analysis job for distributed processing."""
    
    job_id = f"{job_type}_{hashlib.md5(file_path.encode()).hexdigest()[:8]}_{int(time.time())}"
    
    return AnalysisJob(
        job_id=job_id,
        job_type=job_type,
        file_path=file_path,
        file_content=file_content,
        language=language,
        analyzer_config=analyzer_config or {},
        priority=priority,
        timeout_seconds=timeout_seconds
    )


def create_batch_analysis_jobs(files_data: List[Dict[str, Any]],
                             job_type: str = "security_analysis",
                             priority: int = 5,
                             timeout_seconds: int = 300) -> List[AnalysisJob]:
    """Create multiple analysis jobs for batch processing."""
    
    jobs = []
    
    for file_data in files_data:
        job = create_file_analysis_job(
            file_path=file_data['file_path'],
            file_content=file_data['content'],
            language=file_data['language'],
            job_type=job_type,
            priority=priority,
            timeout_seconds=timeout_seconds,
            analyzer_config=file_data.get('analyzer_config')
        )
        jobs.append(job)
    
    return jobs