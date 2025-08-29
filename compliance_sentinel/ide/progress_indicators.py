"""Progress indicators for long-running analysis operations."""

import asyncio
import time
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime, timedelta


logger = logging.getLogger(__name__)


class ProgressType(Enum):
    """Types of progress indicators."""
    DETERMINATE = "determinate"      # Known total steps
    INDETERMINATE = "indeterminate"  # Unknown total steps
    SPINNER = "spinner"              # Simple spinner
    PULSE = "pulse"                  # Pulsing indicator


class ProgressState(Enum):
    """Progress indicator states."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class ProgressStep:
    """Individual step in a progress sequence."""
    id: str
    name: str
    description: str
    weight: float = 1.0  # Relative weight for progress calculation
    estimated_duration: Optional[float] = None  # Seconds
    completed: bool = False
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class ProgressInfo:
    """Progress information for display."""
    id: str
    title: str
    description: str
    progress_type: ProgressType
    state: ProgressState
    current_step: int = 0
    total_steps: int = 0
    percentage: float = 0.0
    current_step_name: str = ""
    current_step_description: str = ""
    elapsed_time: float = 0.0
    estimated_remaining: Optional[float] = None
    steps: List[ProgressStep] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


class ProgressTracker:
    """Tracks progress of long-running operations."""
    
    def __init__(self, progress_id: str, title: str, description: str = "", 
                 progress_type: ProgressType = ProgressType.DETERMINATE):
        """Initialize progress tracker."""
        self.progress_info = ProgressInfo(
            id=progress_id,
            title=title,
            description=description,
            progress_type=progress_type,
            state=ProgressState.NOT_STARTED
        )
        
        self.start_time: Optional[float] = None
        self.callbacks: List[Callable[[ProgressInfo], None]] = []
        self.update_interval = 0.1  # Update every 100ms
        self.last_update = 0.0
        
    def add_steps(self, steps: List[ProgressStep]) -> None:
        """Add steps to the progress tracker."""
        self.progress_info.steps.extend(steps)
        self.progress_info.total_steps = len(self.progress_info.steps)
        self._notify_update()
    
    def add_step(self, step_id: str, name: str, description: str = "", 
                 weight: float = 1.0, estimated_duration: Optional[float] = None) -> None:
        """Add a single step to the progress tracker."""
        step = ProgressStep(
            id=step_id,
            name=name,
            description=description,
            weight=weight,
            estimated_duration=estimated_duration
        )
        self.progress_info.steps.append(step)
        self.progress_info.total_steps = len(self.progress_info.steps)
        self._notify_update()
    
    def start(self) -> None:
        """Start progress tracking."""
        self.start_time = time.time()
        self.progress_info.state = ProgressState.RUNNING
        self.progress_info.created_at = datetime.utcnow()
        self._notify_update()
    
    def start_step(self, step_id: str) -> None:
        """Start a specific step."""
        step = self._find_step(step_id)
        if step:
            step.started_at = datetime.utcnow()
            self.progress_info.current_step = self._get_step_index(step_id) + 1
            self.progress_info.current_step_name = step.name
            self.progress_info.current_step_description = step.description
            self._update_progress()
            self._notify_update()
    
    def complete_step(self, step_id: str, error: Optional[str] = None) -> None:
        """Complete a specific step."""
        step = self._find_step(step_id)
        if step:
            step.completed = True
            step.completed_at = datetime.utcnow()
            if error:
                step.error = error
                self.progress_info.state = ProgressState.ERROR
            
            self._update_progress()
            self._notify_update()
    
    def update_step_description(self, step_id: str, description: str) -> None:
        """Update step description."""
        step = self._find_step(step_id)
        if step:
            step.description = description
            if self.progress_info.current_step_name == step.name:
                self.progress_info.current_step_description = description
            self._notify_update()
    
    def set_progress(self, percentage: float, message: str = "") -> None:
        """Set progress percentage directly (for indeterminate progress)."""
        self.progress_info.percentage = max(0.0, min(100.0, percentage))
        if message:
            self.progress_info.current_step_description = message
        self._notify_update()
    
    def complete(self) -> None:
        """Mark progress as completed."""
        self.progress_info.state = ProgressState.COMPLETED
        self.progress_info.percentage = 100.0
        self._update_progress()
        self._notify_update()
    
    def cancel(self) -> None:
        """Cancel the progress."""
        self.progress_info.state = ProgressState.CANCELLED
        self._notify_update()
    
    def error(self, error_message: str) -> None:
        """Mark progress as error."""
        self.progress_info.state = ProgressState.ERROR
        self.progress_info.metadata['error'] = error_message
        self._notify_update()
    
    def pause(self) -> None:
        """Pause the progress."""
        self.progress_info.state = ProgressState.PAUSED
        self._notify_update()
    
    def resume(self) -> None:
        """Resume the progress."""
        self.progress_info.state = ProgressState.RUNNING
        self._notify_update()
    
    def add_callback(self, callback: Callable[[ProgressInfo], None]) -> None:
        """Add progress update callback."""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[ProgressInfo], None]) -> None:
        """Remove progress update callback."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def get_progress_info(self) -> ProgressInfo:
        """Get current progress information."""
        self._update_progress()
        return self.progress_info
    
    def _find_step(self, step_id: str) -> Optional[ProgressStep]:
        """Find step by ID."""
        for step in self.progress_info.steps:
            if step.id == step_id:
                return step
        return None
    
    def _get_step_index(self, step_id: str) -> int:
        """Get step index by ID."""
        for i, step in enumerate(self.progress_info.steps):
            if step.id == step_id:
                return i
        return -1
    
    def _update_progress(self) -> None:
        """Update progress calculations."""
        if self.start_time:
            self.progress_info.elapsed_time = time.time() - self.start_time
        
        if self.progress_info.progress_type == ProgressType.DETERMINATE and self.progress_info.steps:
            # Calculate weighted progress
            total_weight = sum(step.weight for step in self.progress_info.steps)
            completed_weight = sum(step.weight for step in self.progress_info.steps if step.completed)
            
            if total_weight > 0:
                self.progress_info.percentage = (completed_weight / total_weight) * 100
            
            # Estimate remaining time
            if completed_weight > 0 and self.progress_info.elapsed_time > 0:
                rate = completed_weight / self.progress_info.elapsed_time
                remaining_weight = total_weight - completed_weight
                self.progress_info.estimated_remaining = remaining_weight / rate if rate > 0 else None
        
        self.progress_info.updated_at = datetime.utcnow()
    
    def _notify_update(self) -> None:
        """Notify callbacks of progress update."""
        current_time = time.time()
        if current_time - self.last_update >= self.update_interval:
            self.last_update = current_time
            for callback in self.callbacks:
                try:
                    callback(self.progress_info)
                except Exception as e:
                    logger.error(f"Error in progress callback: {e}")


class ProgressManager:
    """Manages multiple progress trackers."""
    
    def __init__(self):
        """Initialize progress manager."""
        self.trackers: Dict[str, ProgressTracker] = {}
        self.global_callbacks: List[Callable[[str, ProgressInfo], None]] = []
    
    def create_tracker(self, progress_id: str, title: str, description: str = "",
                      progress_type: ProgressType = ProgressType.DETERMINATE) -> ProgressTracker:
        """Create a new progress tracker."""
        tracker = ProgressTracker(progress_id, title, description, progress_type)
        tracker.add_callback(lambda info: self._notify_global_callbacks(progress_id, info))
        self.trackers[progress_id] = tracker
        return tracker
    
    def get_tracker(self, progress_id: str) -> Optional[ProgressTracker]:
        """Get existing progress tracker."""
        return self.trackers.get(progress_id)
    
    def remove_tracker(self, progress_id: str) -> None:
        """Remove progress tracker."""
        if progress_id in self.trackers:
            del self.trackers[progress_id]
    
    def get_all_progress(self) -> Dict[str, ProgressInfo]:
        """Get progress info for all trackers."""
        return {pid: tracker.get_progress_info() for pid, tracker in self.trackers.items()}
    
    def get_active_progress(self) -> Dict[str, ProgressInfo]:
        """Get progress info for active trackers."""
        active = {}
        for pid, tracker in self.trackers.items():
            info = tracker.get_progress_info()
            if info.state in [ProgressState.RUNNING, ProgressState.PAUSED]:
                active[pid] = info
        return active
    
    def add_global_callback(self, callback: Callable[[str, ProgressInfo], None]) -> None:
        """Add global progress callback."""
        self.global_callbacks.append(callback)
    
    def remove_global_callback(self, callback: Callable[[str, ProgressInfo], None]) -> None:
        """Remove global progress callback."""
        if callback in self.global_callbacks:
            self.global_callbacks.remove(callback)
    
    def cleanup_completed(self, max_age_hours: int = 24) -> None:
        """Clean up completed trackers older than max_age_hours."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        to_remove = []
        
        for pid, tracker in self.trackers.items():
            info = tracker.get_progress_info()
            if (info.state in [ProgressState.COMPLETED, ProgressState.CANCELLED, ProgressState.ERROR] and
                info.updated_at < cutoff_time):
                to_remove.append(pid)
        
        for pid in to_remove:
            self.remove_tracker(pid)
    
    def _notify_global_callbacks(self, progress_id: str, info: ProgressInfo) -> None:
        """Notify global callbacks."""
        for callback in self.global_callbacks:
            try:
                callback(progress_id, info)
            except Exception as e:
                logger.error(f"Error in global progress callback: {e}")


class AnalysisProgressTracker:
    """Specialized progress tracker for security analysis operations."""
    
    def __init__(self, progress_manager: ProgressManager):
        """Initialize analysis progress tracker."""
        self.progress_manager = progress_manager
    
    def create_file_analysis_progress(self, analysis_id: str, file_paths: List[str]) -> ProgressTracker:
        """Create progress tracker for file analysis."""
        tracker = self.progress_manager.create_tracker(
            progress_id=analysis_id,
            title="Security Analysis",
            description=f"Analyzing {len(file_paths)} files for security issues",
            progress_type=ProgressType.DETERMINATE
        )
        
        # Add analysis steps
        steps = [
            ProgressStep("init", "Initialization", "Setting up analysis environment", weight=0.5),
            ProgressStep("sast", "SAST Analysis", "Running static analysis security testing", weight=3.0),
            ProgressStep("deps", "Dependency Scan", "Scanning dependencies for vulnerabilities", weight=2.0),
            ProgressStep("policy", "Policy Check", "Applying security policies", weight=1.0),
            ProgressStep("report", "Report Generation", "Generating analysis report", weight=0.5)
        ]
        
        tracker.add_steps(steps)
        return tracker
    
    def create_project_analysis_progress(self, analysis_id: str, total_files: int) -> ProgressTracker:
        """Create progress tracker for project analysis."""
        tracker = self.progress_manager.create_tracker(
            progress_id=analysis_id,
            title="Project Security Analysis",
            description=f"Comprehensive security analysis of {total_files} files",
            progress_type=ProgressType.DETERMINATE
        )
        
        # Add project analysis steps
        steps = [
            ProgressStep("discovery", "File Discovery", "Discovering files to analyze", weight=0.5),
            ProgressStep("filtering", "File Filtering", "Applying file filters and exclusions", weight=0.5),
            ProgressStep("analysis", "Security Analysis", "Running comprehensive security analysis", weight=8.0),
            ProgressStep("aggregation", "Result Aggregation", "Aggregating and deduplicating results", weight=0.5),
            ProgressStep("feedback", "Feedback Generation", "Generating IDE feedback and reports", weight=0.5)
        ]
        
        tracker.add_steps(steps)
        return tracker
    
    def create_hook_analysis_progress(self, analysis_id: str, file_path: str) -> ProgressTracker:
        """Create progress tracker for hook-triggered analysis."""
        tracker = self.progress_manager.create_tracker(
            progress_id=analysis_id,
            title="Real-time Analysis",
            description=f"Analyzing {file_path} for security issues",
            progress_type=ProgressType.INDETERMINATE
        )
        
        return tracker


# Global progress manager instance
_global_progress_manager = ProgressManager()


def get_global_progress_manager() -> ProgressManager:
    """Get the global progress manager instance."""
    return _global_progress_manager


def create_analysis_progress_tracker() -> AnalysisProgressTracker:
    """Create analysis progress tracker with global manager."""
    return AnalysisProgressTracker(_global_progress_manager)


# IDE-specific progress formatters
class IDEProgressFormatter:
    """Formats progress information for different IDEs."""
    
    @staticmethod
    def format_vscode_progress(info: ProgressInfo) -> Dict[str, Any]:
        """Format progress for VS Code."""
        return {
            "title": info.title,
            "message": info.current_step_description or info.description,
            "increment": info.percentage if info.progress_type == ProgressType.DETERMINATE else None,
            "cancellable": info.state == ProgressState.RUNNING,
            "location": "Notification" if info.progress_type == ProgressType.INDETERMINATE else "Window"
        }
    
    @staticmethod
    def format_kiro_progress(info: ProgressInfo) -> Dict[str, Any]:
        """Format progress for Kiro IDE."""
        return {
            "id": info.id,
            "title": info.title,
            "description": info.description,
            "type": info.progress_type.value,
            "state": info.state.value,
            "progress": {
                "current": info.current_step,
                "total": info.total_steps,
                "percentage": info.percentage
            },
            "currentStep": {
                "name": info.current_step_name,
                "description": info.current_step_description
            },
            "timing": {
                "elapsed": info.elapsed_time,
                "estimated_remaining": info.estimated_remaining
            },
            "steps": [
                {
                    "id": step.id,
                    "name": step.name,
                    "description": step.description,
                    "completed": step.completed,
                    "error": step.error
                }
                for step in info.steps
            ],
            "metadata": info.metadata
        }
    
    @staticmethod
    def format_generic_progress(info: ProgressInfo) -> Dict[str, Any]:
        """Format progress for generic IDE."""
        return {
            "title": info.title,
            "message": info.current_step_description or info.description,
            "progress": info.percentage,
            "state": info.state.value
        }