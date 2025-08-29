"""Analysis coordinator that orchestrates multiple security analysis tools."""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

from compliance_sentinel.core.interfaces import (
    SecurityAnalyzer,
    SecurityIssue,
    Severity,
    SecurityCategory
)
from compliance_sentinel.analyzers.bandit_analyzer import BanditAnalyzer, BanditConfig
from compliance_sentinel.analyzers.semgrep_analyzer import SemgrepAnalyzer, SemgrepConfig
from compliance_sentinel.models.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    AnalysisStatus,
    AnalysisType
)
from compliance_sentinel.utils.error_handler import (
    get_global_error_handler,
    async_safe_execute,
    RetryStrategy
)
from compliance_sentinel.utils.cache import get_global_cache
from compliance_sentinel.engines.policy_engine import PolicyEngine


logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Result from a single analyzer."""
    analyzer_name: str
    issues: List[SecurityIssue]
    duration_seconds: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class CoordinatorConfig:
    """Configuration for the analysis coordinator."""
    max_concurrent_analyses: int = 5
    enable_bandit: bool = True
    enable_semgrep: bool = True
    enable_policy_engine: bool = True
    timeout_seconds: int = 300
    deduplicate_issues: bool = True
    merge_similar_issues: bool = True
    confidence_threshold: float = 0.3
    severity_weights: Dict[str, float] = field(default_factory=lambda: {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.6,
        "low": 0.4
    })


class AnalysisCoordinator:
    """Coordinates multiple security analysis tools for comprehensive scanning."""
    
    def __init__(self, config: Optional[CoordinatorConfig] = None):
        """Initialize the analysis coordinator."""
        self.config = config or CoordinatorConfig()
        self.cache = get_global_cache()
        self.error_handler = get_global_error_handler()
        
        # Initialize analyzers
        self.analyzers: Dict[str, SecurityAnalyzer] = {}
        self._initialize_analyzers()
        
        # Initialize policy engine
        self.policy_engine = PolicyEngine() if self.config.enable_policy_engine else None
        
        # Thread pool for parallel analysis
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_analyses)
        
        logger.info(f"Initialized analysis coordinator with {len(self.analyzers)} analyzers")
    
    def _initialize_analyzers(self) -> None:
        """Initialize all configured analyzers."""
        try:
            # Always initialize built-in analyzer
            from compliance_sentinel.analyzers.builtin_analyzer import BuiltinSecurityAnalyzer
            self.analyzers['builtin'] = BuiltinSecurityAnalyzer()
            logger.info("Built-in security analyzer initialized")
            
            if self.config.enable_bandit:
                bandit_config = BanditConfig(
                    confidence_level="low",
                    severity_level="low"
                )
                self.analyzers["bandit"] = BanditAnalyzer(bandit_config)
                logger.info("Initialized Bandit analyzer")
        except Exception as e:
            logger.warning(f"Failed to initialize Bandit analyzer: {e}")
        
        try:
            if self.config.enable_semgrep:
                semgrep_config = SemgrepConfig(
                    rulesets=["auto", "security"],
                    timeout=60
                )
                self.analyzers["semgrep"] = SemgrepAnalyzer(semgrep_config)
                logger.info("Initialized Semgrep analyzer")
        except Exception as e:
            logger.warning(f"Failed to initialize Semgrep analyzer: {e}")
    
    async def run_comprehensive_scan(self, request: AnalysisRequest) -> AnalysisResponse:
        """Run comprehensive security scan using all available analyzers."""
        start_time = datetime.utcnow()
        
        try:
            # Validate request
            self._validate_analysis_request(request)
            
            # Check cache for recent results
            cache_key = self._generate_cache_key(request)
            cached_response = self.cache.get(cache_key)
            if cached_response:
                logger.info(f"Using cached analysis results for request {request.request_id}")
                return cached_response
            
            # Run analysis on all files
            all_results = await self._analyze_files_parallel(request)
            
            # Aggregate results
            aggregated_issues = self._aggregate_analysis_results(all_results)
            
            # Apply post-processing
            processed_issues = self._post_process_issues(aggregated_issues, request)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(processed_issues)
            
            # Create response
            response = AnalysisResponse(
                request_id=request.request_id,
                status=AnalysisStatus.COMPLETED,
                started_at=start_time,
                completed_at=datetime.utcnow(),
                issues=processed_issues,
                total_files_analyzed=len(request.file_paths),
                tools_used=list(self.analyzers.keys()),
                recommendations=recommendations
            )
            
            # Cache response
            self.cache.set(cache_key, response, ttl=1800)  # Cache for 30 minutes
            
            logger.info(f"Comprehensive scan completed for request {request.request_id}: "
                       f"{len(processed_issues)} issues found")
            
            return response
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed for request {request.request_id}: {e}")
            self.error_handler.handle_analysis_error(e, f"comprehensive_scan:{request.request_id}")
            
            return AnalysisResponse(
                request_id=request.request_id,
                status=AnalysisStatus.FAILED,
                started_at=start_time,
                completed_at=datetime.utcnow(),
                error_message=str(e)
            )
    
    async def _analyze_files_parallel(self, request: AnalysisRequest) -> List[AnalysisResult]:
        """Analyze files in parallel using all available analyzers."""
        all_results = []
        
        # Create analysis tasks for each file and analyzer combination
        tasks = []
        
        for file_path in request.file_paths:
            # Policy engine analysis
            if self.policy_engine:
                task = self._create_policy_analysis_task(file_path)
                tasks.append(task)
            
            # Tool-based analysis
            for analyzer_name, analyzer in self.analyzers.items():
                task = self._create_analyzer_task(analyzer_name, analyzer, file_path)
                tasks.append(task)
        
        # Execute tasks with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=request.timeout_seconds
            )
            
            # Process results
            for result in results:
                if isinstance(result, AnalysisResult):
                    all_results.append(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Analysis task failed: {result}")
                    
        except asyncio.TimeoutError:
            logger.warning(f"Analysis timed out after {request.timeout_seconds} seconds")
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
        
        return all_results
    
    async def _create_analyzer_task(self, analyzer_name: str, analyzer: SecurityAnalyzer, file_path: str) -> AnalysisResult:
        """Create an async task for analyzer execution."""
        start_time = datetime.utcnow()
        
        try:
            # Check if analyzer supports this file type
            file_ext = Path(file_path).suffix
            if not self._analyzer_supports_file(analyzer, file_ext):
                return AnalysisResult(
                    analyzer_name=analyzer_name,
                    issues=[],
                    duration_seconds=0.0,
                    success=True
                )
            
            # Run analysis directly (it's already async)
            issues = await analyzer.analyze_file(file_path)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return AnalysisResult(
                analyzer_name=analyzer_name,
                issues=issues,
                duration_seconds=duration,
                success=True
            )
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Analyzer {analyzer_name} failed for {file_path}: {e}")
            
            return AnalysisResult(
                analyzer_name=analyzer_name,
                issues=[],
                duration_seconds=duration,
                success=False,
                error_message=str(e)
            )
    
    async def _create_policy_analysis_task(self, file_path: str) -> AnalysisResult:
        """Create an async task for policy engine analysis."""
        start_time = datetime.utcnow()
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Run policy analysis in thread pool
            loop = asyncio.get_event_loop()
            file_ext = Path(file_path).suffix
            issues = await loop.run_in_executor(
                self.executor,
                self.policy_engine.apply_policies_to_content,
                content,
                file_path,
                file_ext
            )
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return AnalysisResult(
                analyzer_name="policy_engine",
                issues=issues,
                duration_seconds=duration,
                success=True
            )
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Policy engine failed for {file_path}: {e}")
            
            return AnalysisResult(
                analyzer_name="policy_engine",
                issues=[],
                duration_seconds=duration,
                success=False,
                error_message=str(e)
            )
    
    def _analyzer_supports_file(self, analyzer: SecurityAnalyzer, file_ext: str) -> bool:
        """Check if analyzer supports the given file extension."""
        try:
            supported_types = analyzer.get_supported_file_types()
            return file_ext in supported_types
        except Exception:
            return True  # Assume support if we can't determine
    
    def _aggregate_analysis_results(self, results: List[AnalysisResult]) -> List[SecurityIssue]:
        """Aggregate issues from all analysis results."""
        all_issues = []
        
        for result in results:
            if result.success:
                all_issues.extend(result.issues)
            else:
                logger.warning(f"Analyzer {result.analyzer_name} failed: {result.error_message}")
        
        logger.info(f"Aggregated {len(all_issues)} issues from {len(results)} analysis results")
        return all_issues
    
    def _post_process_issues(self, issues: List[SecurityIssue], request: AnalysisRequest) -> List[SecurityIssue]:
        """Post-process issues with deduplication, filtering, and prioritization."""
        processed_issues = issues.copy()
        
        # Filter by confidence threshold
        processed_issues = [
            issue for issue in processed_issues
            if issue.confidence >= self.config.confidence_threshold
        ]
        
        # Filter by severity threshold if specified
        if hasattr(request, 'severity_threshold'):
            severity_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
            min_level = severity_order.get(request.severity_threshold, 1)
            processed_issues = [
                issue for issue in processed_issues
                if severity_order.get(issue.severity, 1) >= min_level
            ]
        
        # Deduplicate issues if enabled
        if self.config.deduplicate_issues:
            processed_issues = self._deduplicate_issues(processed_issues)
        
        # Merge similar issues if enabled
        if self.config.merge_similar_issues:
            processed_issues = self._merge_similar_issues(processed_issues)
        
        # Sort by priority (severity, confidence, line number)
        processed_issues = self.prioritize_issues(processed_issues)
        
        logger.info(f"Post-processing reduced {len(issues)} issues to {len(processed_issues)}")
        return processed_issues
    
    def _deduplicate_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Remove duplicate issues based on file path, line number, and rule ID."""
        seen = set()
        deduplicated = []
        
        for issue in issues:
            # Create a key for deduplication
            key = (issue.file_path, issue.line_number, issue.rule_id)
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(issue)
            else:
                # Keep the issue with higher confidence
                existing_issue = next(
                    (i for i in deduplicated if (i.file_path, i.line_number, i.rule_id) == key),
                    None
                )
                if existing_issue and issue.confidence > existing_issue.confidence:
                    deduplicated.remove(existing_issue)
                    deduplicated.append(issue)
        
        logger.debug(f"Deduplication removed {len(issues) - len(deduplicated)} duplicate issues")
        return deduplicated
    
    def _merge_similar_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Merge similar issues in the same file."""
        merged = []
        issue_groups = {}
        
        # Group issues by file, category, and rule
        for issue in issues:
            key = (issue.file_path, issue.category, issue.rule_id)
            if key not in issue_groups:
                issue_groups[key] = []
            issue_groups[key].append(issue)
        
        # Merge groups with multiple issues
        for key, group in issue_groups.items():
            if len(group) == 1:
                merged.extend(group)
            else:
                # Create merged issue
                primary_issue = max(group, key=lambda x: x.confidence)
                line_numbers = sorted(set(issue.line_number for issue in group))
                
                # Update description to include line range
                if len(line_numbers) > 1:
                    line_range = f"lines {min(line_numbers)}-{max(line_numbers)}"
                    primary_issue.description = f"{primary_issue.description} (found on {line_range})"
                
                # Combine remediation suggestions
                all_suggestions = []
                for issue in group:
                    all_suggestions.extend(issue.remediation_suggestions)
                primary_issue.remediation_suggestions = list(dict.fromkeys(all_suggestions))[:3]
                
                merged.append(primary_issue)
        
        logger.debug(f"Merging reduced {len(issues)} issues to {len(merged)}")
        return merged
    
    def prioritize_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Prioritize issues by severity, confidence, and other factors."""
        def priority_score(issue: SecurityIssue) -> Tuple[int, float, int]:
            # Severity weight (higher is more important)
            severity_weight = self.config.severity_weights.get(issue.severity.value, 0.5)
            
            # Confidence score
            confidence_score = issue.confidence
            
            # Line number (earlier lines first)
            line_number = issue.line_number
            
            return (-severity_weight, -confidence_score, line_number)
        
        return sorted(issues, key=priority_score)
    
    def _generate_recommendations(self, issues: List[SecurityIssue]) -> List[str]:
        """Generate high-level recommendations based on found issues."""
        recommendations = []
        
        if not issues:
            recommendations.append("✅ No security issues found. Great job!")
            return recommendations
        
        # Count issues by category and severity
        category_counts = {}
        severity_counts = {}
        
        for issue in issues:
            category = issue.category.value
            severity = issue.severity.value
            
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Generate severity-based recommendations
        if severity_counts.get('critical', 0) > 0:
            recommendations.append(
                f"🚨 {severity_counts['critical']} critical issues found - immediate action required"
            )
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append(
                f"⚠️ {severity_counts['high']} high severity issues should be addressed soon"
            )
        
        # Generate category-specific recommendations
        if category_counts.get('hardcoded_secrets', 0) > 0:
            recommendations.append(
                "🔐 Implement secure secret management to eliminate hardcoded credentials"
            )
        
        if category_counts.get('sql_injection', 0) > 0:
            recommendations.append(
                "💉 Use parameterized queries to prevent SQL injection attacks"
            )
        
        if category_counts.get('insecure_crypto', 0) > 0:
            recommendations.append(
                "🔒 Update cryptographic implementations to use secure algorithms"
            )
        
        # General recommendations
        total_issues = len(issues)
        if total_issues > 10:
            recommendations.append(
                f"📊 {total_issues} total issues found - consider implementing automated security scanning"
            )
        
        recommendations.append(
            "📚 Review OWASP Top 10 guidelines for comprehensive security best practices"
        )
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _validate_analysis_request(self, request: AnalysisRequest) -> None:
        """Validate analysis request parameters."""
        if not request.file_paths:
            raise ValueError("Analysis request must include at least one file path")
        
        for file_path in request.file_paths:
            if not Path(file_path).exists():
                raise FileNotFoundError(f"File not found: {file_path}")
        
        if request.timeout_seconds < 30:
            raise ValueError("Timeout must be at least 30 seconds")
    
    def _generate_cache_key(self, request: AnalysisRequest) -> str:
        """Generate cache key for analysis request."""
        # Include file paths, modification times, and analysis type
        key_parts = [
            request.analysis_type.value,
            str(request.severity_threshold.value if hasattr(request, 'severity_threshold') else 'medium'),
        ]
        
        for file_path in sorted(request.file_paths):
            try:
                mtime = Path(file_path).stat().st_mtime
                key_parts.append(f"{file_path}:{mtime}")
            except Exception:
                key_parts.append(file_path)
        
        return f"comprehensive_analysis:{'|'.join(key_parts)}"
    
    def get_analyzer_status(self) -> Dict[str, Any]:
        """Get status information for all analyzers."""
        status = {
            "total_analyzers": len(self.analyzers),
            "policy_engine_enabled": self.policy_engine is not None,
            "analyzers": {}
        }
        
        for name, analyzer in self.analyzers.items():
            try:
                analyzer_info = analyzer.get_analyzer_info()
                status["analyzers"][name] = {
                    "status": "available",
                    "info": analyzer_info
                }
            except Exception as e:
                status["analyzers"][name] = {
                    "status": "error",
                    "error": str(e)
                }
        
        return status
    
    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)