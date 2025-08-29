"""Incremental analysis for large codebases with change detection."""

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import sqlite3
import threading
from pathlib import Path

from compliance_sentinel.core.interfaces import SecurityIssue, AnalysisResult
from compliance_sentinel.performance.parallel_processor import ProcessingTask


logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of file changes."""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    UNCHANGED = "unchanged"


class AnalysisScope(Enum):
    """Scope of incremental analysis."""
    CHANGED_FILES_ONLY = "changed_files_only"
    CHANGED_AND_DEPENDENCIES = "changed_and_dependencies"
    FULL_REANALYSIS = "full_reanalysis"


@dataclass
class FileMetadata:
    """Metadata for tracked files."""
    
    file_path: str
    file_hash: str
    size_bytes: int
    last_modified: datetime
    last_analyzed: Optional[datetime] = None
    
    # Analysis results
    issues_count: int = 0
    analysis_time: float = 0.0
    analyzer_version: str = ""
    
    # Dependencies
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'file_path': self.file_path,
            'file_hash': self.file_hash,
            'size_bytes': self.size_bytes,
            'last_modified': self.last_modified.isoformat(),
            'last_analyzed': self.last_analyzed.isoformat() if self.last_analyzed else None,
            'issues_count': self.issues_count,
            'analysis_time': self.analysis_time,
            'analyzer_version': self.analyzer_version,
            'dependencies': list(self.dependencies),
            'dependents': list(self.dependents)
        }


@dataclass
class ChangeDetectionResult:
    """Result of change detection."""
    
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    renamed_files: List[Tuple[str, str]] = field(default_factory=list)
    unchanged_files: List[str] = field(default_factory=list)
    
    @property
    def total_changes(self) -> int:
        """Get total number of changes."""
        return (len(self.added_files) + len(self.modified_files) + 
                len(self.deleted_files) + len(self.renamed_files))
    
    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return self.total_changes > 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'added_files': self.added_files,
            'modified_files': self.modified_files,
            'deleted_files': self.deleted_files,
            'renamed_files': self.renamed_files,
            'unchanged_files': self.unchanged_files,
            'total_changes': self.total_changes,
            'has_changes': self.has_changes
        }


@dataclass
class DeltaAnalysis:
    """Result of incremental analysis."""
    
    # Files analyzed
    analyzed_files: List[str] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    
    # Issues found
    new_issues: List[SecurityIssue] = field(default_factory=list)
    resolved_issues: List[SecurityIssue] = field(default_factory=list)
    existing_issues: List[SecurityIssue] = field(default_factory=list)
    
    # Performance metrics
    analysis_time: float = 0.0
    files_per_second: float = 0.0
    cache_hit_rate: float = 0.0
    
    # Change summary
    change_detection: Optional[ChangeDetectionResult] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'analyzed_files': self.analyzed_files,
            'skipped_files': self.skipped_files,
            'new_issues_count': len(self.new_issues),
            'resolved_issues_count': len(self.resolved_issues),
            'existing_issues_count': len(self.existing_issues),
            'analysis_time': self.analysis_time,
            'files_per_second': self.files_per_second,
            'cache_hit_rate': self.cache_hit_rate,
            'change_detection': self.change_detection.to_dict() if self.change_detection else None
        }


class ChangeDetector:
    """Detects changes in codebase for incremental analysis."""
    
    def __init__(self, 
                 cache_dir: str = "/tmp/compliance_cache",
                 track_dependencies: bool = True):
        """Initialize change detector."""
        self.cache_dir = cache_dir
        self.track_dependencies = track_dependencies
        
        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize database
        self.db_path = os.path.join(cache_dir, "file_metadata.db")
        self._init_database()
        
        # File metadata cache
        self.metadata_cache = {}
        self.lock = threading.RLock()
    
    def _init_database(self):
        """Initialize SQLite database for file metadata."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_metadata (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT,
                    size_bytes INTEGER,
                    last_modified TIMESTAMP,
                    last_analyzed TIMESTAMP,
                    issues_count INTEGER DEFAULT 0,
                    analysis_time REAL DEFAULT 0.0,
                    analyzer_version TEXT DEFAULT '',
                    dependencies TEXT DEFAULT '[]',
                    dependents TEXT DEFAULT '[]'
                )
            """)
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_metadata(file_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_modified ON file_metadata(last_modified)")
    
    def detect_changes(self, 
                      file_paths: List[str],
                      base_directory: str = "") -> ChangeDetectionResult:
        """Detect changes in specified files."""
        with self.lock:
            result = ChangeDetectionResult()
            
            # Load existing metadata
            existing_metadata = self._load_metadata()
            existing_paths = set(existing_metadata.keys())
            current_paths = set(file_paths)
            
            # Detect added files
            result.added_files = list(current_paths - existing_paths)
            
            # Detect deleted files
            result.deleted_files = list(existing_paths - current_paths)
            
            # Check existing files for modifications
            for file_path in current_paths & existing_paths:
                try:
                    current_metadata = self._get_file_metadata(file_path)
                    existing = existing_metadata[file_path]
                    
                    if current_metadata.file_hash != existing.file_hash:
                        result.modified_files.append(file_path)
                    else:
                        result.unchanged_files.append(file_path)
                        
                except Exception as e:
                    logger.error(f"Error checking file {file_path}: {e}")
                    result.modified_files.append(file_path)  # Assume modified on error
            
            # Detect renamed files (simple heuristic based on hash matching)
            if result.added_files and result.deleted_files:
                result.renamed_files = self._detect_renames(
                    result.added_files, 
                    result.deleted_files,
                    existing_metadata
                )
                
                # Remove renamed files from added/deleted lists
                for old_path, new_path in result.renamed_files:
                    if old_path in result.deleted_files:
                        result.deleted_files.remove(old_path)
                    if new_path in result.added_files:
                        result.added_files.remove(new_path)
            
            return result
    
    def _detect_renames(self, 
                       added_files: List[str],
                       deleted_files: List[str],
                       existing_metadata: Dict[str, FileMetadata]) -> List[Tuple[str, str]]:
        """Detect renamed files by matching hashes."""
        renames = []
        
        # Create hash map for deleted files
        deleted_hashes = {}
        for file_path in deleted_files:
            if file_path in existing_metadata:
                file_hash = existing_metadata[file_path].file_hash
                deleted_hashes[file_hash] = file_path
        
        # Check added files for matching hashes
        for added_file in added_files:
            try:
                current_metadata = self._get_file_metadata(added_file)
                if current_metadata.file_hash in deleted_hashes:
                    old_path = deleted_hashes[current_metadata.file_hash]
                    renames.append((old_path, added_file))
            except Exception:
                continue
        
        return renames
    
    def _get_file_metadata(self, file_path: str) -> FileMetadata:
        """Get metadata for a file."""
        try:
            stat = os.stat(file_path)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            return FileMetadata(
                file_path=file_path,
                file_hash=file_hash,
                size_bytes=stat.st_size,
                last_modified=datetime.fromtimestamp(stat.st_mtime)
            )
            
        except Exception as e:
            logger.error(f"Error getting metadata for {file_path}: {e}")
            raise
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file content."""
        hasher = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _load_metadata(self) -> Dict[str, FileMetadata]:
        """Load file metadata from database."""
        metadata = {}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT * FROM file_metadata")
                
                for row in cursor.fetchall():
                    dependencies = json.loads(row['dependencies'] or '[]')
                    dependents = json.loads(row['dependents'] or '[]')
                    
                    metadata[row['file_path']] = FileMetadata(
                        file_path=row['file_path'],
                        file_hash=row['file_hash'],
                        size_bytes=row['size_bytes'],
                        last_modified=datetime.fromisoformat(row['last_modified']),
                        last_analyzed=datetime.fromisoformat(row['last_analyzed']) if row['last_analyzed'] else None,
                        issues_count=row['issues_count'],
                        analysis_time=row['analysis_time'],
                        analyzer_version=row['analyzer_version'],
                        dependencies=set(dependencies),
                        dependents=set(dependents)
                    )
        
        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
        
        return metadata
    
    def update_metadata(self, 
                       file_path: str,
                       issues_count: int = 0,
                       analysis_time: float = 0.0,
                       analyzer_version: str = "",
                       dependencies: Set[str] = None):
        """Update metadata for a file after analysis."""
        with self.lock:
            try:
                # Get current file metadata
                metadata = self._get_file_metadata(file_path)
                metadata.last_analyzed = datetime.now()
                metadata.issues_count = issues_count
                metadata.analysis_time = analysis_time
                metadata.analyzer_version = analyzer_version
                
                if dependencies is not None:
                    metadata.dependencies = dependencies
                
                # Save to database
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO file_metadata 
                        (file_path, file_hash, size_bytes, last_modified, last_analyzed,
                         issues_count, analysis_time, analyzer_version, dependencies, dependents)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        metadata.file_path,
                        metadata.file_hash,
                        metadata.size_bytes,
                        metadata.last_modified.isoformat(),
                        metadata.last_analyzed.isoformat(),
                        metadata.issues_count,
                        metadata.analysis_time,
                        metadata.analyzer_version,
                        json.dumps(list(metadata.dependencies)),
                        json.dumps(list(metadata.dependents))
                    ))
                
                # Update cache
                self.metadata_cache[file_path] = metadata
                
            except Exception as e:
                logger.error(f"Error updating metadata for {file_path}: {e}")
    
    def get_dependencies(self, file_path: str) -> Set[str]:
        """Get dependencies for a file."""
        if file_path in self.metadata_cache:
            return self.metadata_cache[file_path].dependencies
        
        # Load from database
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT dependencies FROM file_metadata WHERE file_path = ?",
                    (file_path,)
                )
                
                row = cursor.fetchone()
                if row:
                    dependencies = json.loads(row[0] or '[]')
                    return set(dependencies)
        
        except Exception as e:
            logger.error(f"Error getting dependencies for {file_path}: {e}")
        
        return set()
    
    def get_dependents(self, file_path: str) -> Set[str]:
        """Get files that depend on this file."""
        if file_path in self.metadata_cache:
            return self.metadata_cache[file_path].dependents
        
        # Load from database
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT dependents FROM file_metadata WHERE file_path = ?",
                    (file_path,)
                )
                
                row = cursor.fetchone()
                if row:
                    dependents = json.loads(row[0] or '[]')
                    return set(dependents)
        
        except Exception as e:
            logger.error(f"Error getting dependents for {file_path}: {e}")
        
        return set()


class IncrementalAnalyzer:
    """Performs incremental security analysis on codebases."""
    
    def __init__(self, 
                 cache_dir: str = "/tmp/compliance_cache",
                 analyzer_version: str = "1.0.0"):
        """Initialize incremental analyzer."""
        self.cache_dir = cache_dir
        self.analyzer_version = analyzer_version
        
        # Change detection
        self.change_detector = ChangeDetector(cache_dir)
        
        # Results cache
        self.results_cache = {}
        
        # Analysis statistics
        self.stats = {
            'total_analyses': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'files_analyzed': 0,
            'files_skipped': 0,
            'total_time': 0.0
        }
    
    async def analyze_incremental(self, 
                                 file_paths: List[str],
                                 analyzer_func: Callable,
                                 scope: AnalysisScope = AnalysisScope.CHANGED_FILES_ONLY,
                                 force_reanalysis: bool = False) -> DeltaAnalysis:
        """Perform incremental analysis on files."""
        start_time = time.time()
        
        try:
            # Detect changes
            changes = self.change_detector.detect_changes(file_paths)
            
            # Determine files to analyze
            files_to_analyze = self._determine_analysis_scope(changes, scope)
            
            if force_reanalysis:
                files_to_analyze = file_paths
            
            # Perform analysis
            result = await self._analyze_files(files_to_analyze, analyzer_func, changes)
            
            # Update statistics
            analysis_time = time.time() - start_time
            result.analysis_time = analysis_time
            
            if len(result.analyzed_files) > 0:
                result.files_per_second = len(result.analyzed_files) / analysis_time
            
            total_files = len(result.analyzed_files) + len(result.skipped_files)
            if total_files > 0:
                result.cache_hit_rate = len(result.skipped_files) / total_files
            
            # Update global stats
            self.stats['total_analyses'] += 1
            self.stats['files_analyzed'] += len(result.analyzed_files)
            self.stats['files_skipped'] += len(result.skipped_files)
            self.stats['total_time'] += analysis_time
            
            if len(result.skipped_files) > 0:
                self.stats['cache_hits'] += len(result.skipped_files)
            if len(result.analyzed_files) > 0:
                self.stats['cache_misses'] += len(result.analyzed_files)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in incremental analysis: {e}")
            raise
    
    def _determine_analysis_scope(self, 
                                 changes: ChangeDetectionResult,
                                 scope: AnalysisScope) -> List[str]:
        """Determine which files need analysis based on scope."""
        files_to_analyze = []
        
        if scope == AnalysisScope.CHANGED_FILES_ONLY:
            files_to_analyze.extend(changes.added_files)
            files_to_analyze.extend(changes.modified_files)
            
            # Handle renames
            for old_path, new_path in changes.renamed_files:
                files_to_analyze.append(new_path)
        
        elif scope == AnalysisScope.CHANGED_AND_DEPENDENCIES:
            # Start with changed files
            changed_files = set(changes.added_files + changes.modified_files)
            
            # Add renamed files
            for old_path, new_path in changes.renamed_files:
                changed_files.add(new_path)
            
            # Add dependencies and dependents
            all_affected = set(changed_files)
            
            for file_path in changed_files:
                # Add files that depend on this file
                dependents = self.change_detector.get_dependents(file_path)
                all_affected.update(dependents)
                
                # Add files this file depends on (if they might be affected)
                dependencies = self.change_detector.get_dependencies(file_path)
                all_affected.update(dependencies)
            
            files_to_analyze = list(all_affected)
        
        elif scope == AnalysisScope.FULL_REANALYSIS:
            # Analyze all files
            files_to_analyze = (changes.added_files + changes.modified_files + 
                              changes.unchanged_files)
            
            # Add renamed files
            for old_path, new_path in changes.renamed_files:
                files_to_analyze.append(new_path)
        
        return files_to_analyze
    
    async def _analyze_files(self, 
                           files_to_analyze: List[str],
                           analyzer_func: Callable,
                           changes: ChangeDetectionResult) -> DeltaAnalysis:
        """Analyze specified files."""
        result = DeltaAnalysis(change_detection=changes)
        
        # Load previous results for comparison
        previous_results = self._load_previous_results(files_to_analyze)
        
        for file_path in files_to_analyze:
            try:
                # Check if we can skip analysis
                if self._can_skip_analysis(file_path):
                    result.skipped_files.append(file_path)
                    
                    # Add existing issues to result
                    if file_path in previous_results:
                        result.existing_issues.extend(previous_results[file_path])
                    
                    continue
                
                # Perform analysis
                file_start_time = time.time()
                
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Analyze file
                if asyncio.iscoroutinefunction(analyzer_func):
                    issues = await analyzer_func(content, file_path)
                else:
                    issues = analyzer_func(content, file_path)
                
                file_analysis_time = time.time() - file_start_time
                
                # Update metadata
                dependencies = self._extract_dependencies(content, file_path)
                self.change_detector.update_metadata(
                    file_path,
                    issues_count=len(issues),
                    analysis_time=file_analysis_time,
                    analyzer_version=self.analyzer_version,
                    dependencies=dependencies
                )
                
                # Compare with previous results
                previous_issues = previous_results.get(file_path, [])
                new_issues, resolved_issues = self._compare_issues(issues, previous_issues)
                
                result.analyzed_files.append(file_path)
                result.new_issues.extend(new_issues)
                result.resolved_issues.extend(resolved_issues)
                
                # Cache results
                self.results_cache[file_path] = issues
                
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
                continue
        
        return result
    
    def _can_skip_analysis(self, file_path: str) -> bool:
        """Check if file analysis can be skipped."""
        try:
            # Load metadata from database
            with sqlite3.connect(self.change_detector.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT file_hash, last_analyzed, analyzer_version 
                    FROM file_metadata 
                    WHERE file_path = ?
                """, (file_path,))
                
                row = cursor.fetchone()
                if not row:
                    return False
                
                stored_hash, last_analyzed, stored_version = row
                
                # Check if file has changed
                current_metadata = self.change_detector._get_file_metadata(file_path)
                if current_metadata.file_hash != stored_hash:
                    return False
                
                # Check if analyzer version has changed
                if stored_version != self.analyzer_version:
                    return False
                
                # Check if analysis is recent enough
                if last_analyzed:
                    last_analyzed_dt = datetime.fromisoformat(last_analyzed)
                    age = datetime.now() - last_analyzed_dt
                    
                    # Skip if analyzed within last 24 hours
                    if age < timedelta(hours=24):
                        return True
                
                return False
                
        except Exception as e:
            logger.error(f"Error checking skip condition for {file_path}: {e}")
            return False
    
    def _load_previous_results(self, file_paths: List[str]) -> Dict[str, List[SecurityIssue]]:
        """Load previous analysis results for comparison."""
        # This would typically load from a results database
        # For now, return empty results
        return {}
    
    def _compare_issues(self, 
                       current_issues: List[SecurityIssue],
                       previous_issues: List[SecurityIssue]) -> Tuple[List[SecurityIssue], List[SecurityIssue]]:
        """Compare current and previous issues to find new and resolved ones."""
        # Create sets for comparison (using rule_id and line_number as key)
        current_set = {(issue.rule_id, issue.line_number, issue.description) for issue in current_issues}
        previous_set = {(issue.rule_id, issue.line_number, issue.description) for issue in previous_issues}
        
        # Find new and resolved issue keys
        new_keys = current_set - previous_set
        resolved_keys = previous_set - current_set
        
        # Convert back to issue objects
        new_issues = [issue for issue in current_issues 
                     if (issue.rule_id, issue.line_number, issue.description) in new_keys]
        
        resolved_issues = [issue for issue in previous_issues 
                          if (issue.rule_id, issue.line_number, issue.description) in resolved_keys]
        
        return new_issues, resolved_issues
    
    def _extract_dependencies(self, content: str, file_path: str) -> Set[str]:
        """Extract file dependencies from content."""
        dependencies = set()
        
        # Simple dependency extraction (can be enhanced for specific languages)
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Python imports
            if line.startswith('import ') or line.startswith('from '):
                # Extract module name (simplified)
                if 'import ' in line:
                    parts = line.split('import ')
                    if len(parts) > 1:
                        module = parts[1].split()[0].split('.')[0]
                        dependencies.add(module)
            
            # JavaScript/TypeScript imports
            elif line.startswith('import ') and ' from ' in line:
                parts = line.split(' from ')
                if len(parts) > 1:
                    module = parts[1].strip().strip('\'"')
                    dependencies.add(module)
            
            # Include statements (C/C++)
            elif line.startswith('#include'):
                if '"' in line:
                    start = line.find('"') + 1
                    end = line.find('"', start)
                    if end > start:
                        header = line[start:end]
                        dependencies.add(header)
        
        return dependencies
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        stats = self.stats.copy()
        
        # Calculate derived metrics
        if stats['total_analyses'] > 0:
            stats['average_analysis_time'] = stats['total_time'] / stats['total_analyses']
        
        total_files = stats['files_analyzed'] + stats['files_skipped']
        if total_files > 0:
            stats['cache_hit_rate'] = stats['files_skipped'] / total_files
            stats['cache_miss_rate'] = stats['files_analyzed'] / total_files
        
        return stats
    
    def clear_cache(self):
        """Clear analysis cache."""
        self.results_cache.clear()
        
        # Clear database
        try:
            with sqlite3.connect(self.change_detector.db_path) as conn:
                conn.execute("DELETE FROM file_metadata")
            
            logger.info("Analysis cache cleared")
            
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information."""
        try:
            with sqlite3.connect(self.change_detector.db_path) as conn:
                cursor = conn.cursor()
                
                # Get total files in cache
                cursor.execute("SELECT COUNT(*) FROM file_metadata")
                total_files = cursor.fetchone()[0]
                
                # Get cache size
                cursor.execute("SELECT SUM(size_bytes) FROM file_metadata")
                total_size = cursor.fetchone()[0] or 0
                
                # Get last analysis time
                cursor.execute("SELECT MAX(last_analyzed) FROM file_metadata")
                last_analysis = cursor.fetchone()[0]
                
                return {
                    'total_files': total_files,
                    'total_size_bytes': total_size,
                    'last_analysis': last_analysis,
                    'cache_directory': self.cache_dir,
                    'analyzer_version': self.analyzer_version
                }
                
        except Exception as e:
            logger.error(f"Error getting cache info: {e}")
            return {}


# Utility functions for incremental analysis

def create_incremental_analysis_task(file_paths: List[str],
                                   analyzer_func: Callable,
                                   scope: AnalysisScope = AnalysisScope.CHANGED_FILES_ONLY,
                                   priority: int = 5) -> ProcessingTask:
    """Create an incremental analysis task."""
    
    task_id = f"incremental_analysis_{hashlib.md5(str(file_paths).encode()).hexdigest()[:8]}_{int(time.time())}"
    
    return ProcessingTask(
        task_id=task_id,
        task_type="incremental_analysis",
        data={
            'file_paths': file_paths,
            'analyzer_func': analyzer_func,
            'scope': scope
        },
        processor_func=lambda data: asyncio.run(
            IncrementalAnalyzer().analyze_incremental(
                data['file_paths'],
                data['analyzer_func'],
                data['scope']
            )
        ),
        priority=priority
    )


def estimate_incremental_savings(file_paths: List[str], 
                                cache_dir: str = "/tmp/compliance_cache") -> Dict[str, Any]:
    """Estimate time savings from incremental analysis."""
    
    detector = ChangeDetector(cache_dir)
    changes = detector.detect_changes(file_paths)
    
    total_files = len(file_paths)
    changed_files = changes.total_changes
    unchanged_files = len(changes.unchanged_files)
    
    # Estimate savings (assuming unchanged files can be skipped)
    if total_files > 0:
        savings_percent = (unchanged_files / total_files) * 100
    else:
        savings_percent = 0
    
    return {
        'total_files': total_files,
        'changed_files': changed_files,
        'unchanged_files': unchanged_files,
        'estimated_savings_percent': savings_percent,
        'changes': changes.to_dict()
    }