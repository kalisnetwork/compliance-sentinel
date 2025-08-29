"""Main Compliance Agent that orchestrates comprehensive security analysis workflow."""

import asyncio
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import logging

from compliance_sentinel.models.analysis import (
    AnalysisRequest, AnalysisResponse, AnalysisType, AnalysisStatus, SecurityIssue
)
from compliance_sentinel.models.config import SystemConfiguration
from compliance_sentinel.analyzers.coordinator import AnalysisCoordinator
from compliance_sentinel.engines.policy_engine import PolicyEngine
from compliance_sentinel.engines.feedback_engine import FeedbackEngine
from compliance_sentinel.hooks.hook_manager import HookManager
from compliance_sentinel.scanners.dependency_scanner import DependencyScanner
from compliance_sentinel.utils.error_handler import get_global_error_handler
from compliance_sentinel.utils.cache import get_global_cache
from compliance_sentinel.utils.performance import get_performance_monitor
from compliance_sentinel.utils.async_utils import get_async_task_manager
from compliance_sentinel.utils.config_loader import ConfigLoader


logger = logging.getLogger(__name__)


@dataclass
class AnalysisWorkflowResult:
    """Result of a comprehensive analysis workflow."""
    request_id: str
    file_paths: List[str]
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    policy_violations: int
    dependency_vulnerabilities: int
    analysis_duration_ms: float
    feedback_generated: bool
    success: bool
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of issues by severity."""
        return {
            'critical': self.critical_issues,
            'high': self.high_issues,
            'medium': self.medium_issues,
            'low': self.low_issues
        }
    
    @property
    def has_blocking_issues(self) -> bool:
        """Check if there are issues that should block commits."""
        return self.critical_issues > 0 or self.high_issues > 0


@dataclass
class WorkflowMetrics:
    """Metrics for workflow performance tracking."""
    total_analyses: int = 0
    successful_analyses: int = 0
    failed_analyses: int = 0
    average_duration_ms: float = 0.0
    total_issues_found: int = 0
    total_files_analyzed: int = 0
    cache_hit_rate: float = 0.0
    
    def update_with_result(self, result: AnalysisWorkflowResult) -> None:
        """Update metrics with a new analysis result."""
        self.total_analyses += 1
        self.total_files_analyzed += len(result.file_paths)
        self.total_issues_found += result.total_issues
        
        if result.success:
            self.successful_analyses += 1
        else:
            self.failed_analyses += 1
        
        # Update average duration
        total_duration = self.average_duration_ms * (self.total_analyses - 1)
        self.average_duration_ms = (total_duration + result.analysis_duration_ms) / self.total_analyses


class ComplianceAgent:
    """Main agent that orchestrates comprehensive security analysis workflow."""
    
    def __init__(self, config: Optional[SystemConfiguration] = None):
        """Initialize the compliance agent."""
        self.config = config or SystemConfiguration()
        self.config_loader = ConfigLoader()
        
        # Initialize core components
        self.error_handler = get_global_error_handler()
        self.cache = get_global_cache()
        self.performance_monitor = get_performance_monitor()
        self.task_manager = get_async_task_manager()
        
        # Initialize analysis components
        self.analysis_coordinator = AnalysisCoordinator()
        self.policy_engine = PolicyEngine()
        self.feedback_engine = FeedbackEngine()
        self.dependency_scanner = DependencyScanner()
        
        # Initialize hook manager
        self.hook_manager = None
        if self.config.hooks_enabled:
            hook_settings = self.config_loader.load_hook_settings()
            self.hook_manager = HookManager(hook_settings)
        
        # Workflow state
        self.is_running = False
        self.workflow_metrics = WorkflowMetrics()
        self.active_analyses: Dict[str, asyncio.Task] = {}
        
        logger.info("Compliance Agent initialized")
    
    async def start(self) -> None:
        """Start the compliance agent and all its components."""
        if self.is_running:
            logger.warning("Compliance Agent is already running")
            return
        
        try:
            self.is_running = True
            
            # Start hook manager if enabled
            if self.hook_manager:
                await self.hook_manager.start()
                logger.info("Hook manager started")
            
            # Initialize policy engine
            await self.policy_engine.initialize()
            logger.info("Policy engine initialized")
            
            logger.info("Compliance Agent started successfully")
            
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start Compliance Agent: {e}")
            self.error_handler.handle_system_error(e, "agent_startup")
            raise
    
    async def stop(self) -> None:
        """Stop the compliance agent and cleanup resources."""
        if not self.is_running:
            return
        
        try:
            self.is_running = False
            
            # Cancel active analyses
            for request_id, task in self.active_analyses.items():
                if not task.done():
                    task.cancel()
                    logger.info(f"Cancelled active analysis: {request_id}")
            
            # Wait for tasks to complete
            if self.active_analyses:
                await asyncio.gather(*self.active_analyses.values(), return_exceptions=True)
            
            # Stop hook manager
            if self.hook_manager:
                await self.hook_manager.stop()
                logger.info("Hook manager stopped")
            
            logger.info("Compliance Agent stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping Compliance Agent: {e}")
            self.error_handler.handle_system_error(e, "agent_shutdown")
    
    async def analyze_files(
        self,
        file_paths: List[str],
        analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE,
        request_id: Optional[str] = None
    ) -> AnalysisWorkflowResult:
        """Run comprehensive analysis workflow on specified files."""
        if not self.is_running:
            raise RuntimeError("Compliance Agent is not running")
        
        start_time = time.time()
        request_id = request_id or f"analysis_{int(time.time() * 1000)}"
        
        try:
            logger.info(f"Starting analysis workflow {request_id} for {len(file_paths)} files")
            
            # Create analysis request
            analysis_request = AnalysisRequest(
                file_paths=file_paths,
                analysis_type=analysis_type,
                timeout_seconds=self.config.analysis_timeout
            )
            
            # Run the comprehensive workflow
            result = await self._run_comprehensive_workflow(request_id, analysis_request)
            
            # Update metrics
            self.workflow_metrics.update_with_result(result)
            
            logger.info(
                f"Analysis workflow {request_id} completed: "
                f"{result.total_issues} issues found in {result.analysis_duration_ms:.2f}ms"
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Analysis workflow {request_id} failed: {e}")
            self.error_handler.handle_analysis_error(e, request_id)
            
            return AnalysisWorkflowResult(
                request_id=request_id,
                file_paths=file_paths,
                total_issues=0,
                critical_issues=0,
                high_issues=0,
                medium_issues=0,
                low_issues=0,
                policy_violations=0,
                dependency_vulnerabilities=0,
                analysis_duration_ms=duration_ms,
                feedback_generated=False,
                success=False,
                error_message=str(e)
            )
        finally:
            # Remove from active analyses
            self.active_analyses.pop(request_id, None)
    
    async def _run_comprehensive_workflow(
        self,
        request_id: str,
        analysis_request: AnalysisRequest
    ) -> AnalysisWorkflowResult:
        """Run the comprehensive analysis workflow."""
        start_time = time.time()
        
        # Track this analysis
        workflow_task = asyncio.current_task()
        if workflow_task:
            self.active_analyses[request_id] = workflow_task
        
        try:
            # Step 1: Run SAST analysis
            logger.debug(f"Running SAST analysis for {request_id}")
            sast_response = await self.analysis_coordinator.run_comprehensive_scan(analysis_request)
            
            # Step 2: Run dependency analysis if applicable
            dependency_issues = []
            if self._should_run_dependency_analysis(analysis_request.file_paths):
                logger.debug(f"Running dependency analysis for {request_id}")
                dependency_issues = await self._run_dependency_analysis(analysis_request.file_paths)
            
            # Step 3: Apply policy rules
            logger.debug(f"Applying policy rules for {request_id}")
            all_issues = sast_response.issues + dependency_issues
            policy_violations = await self._apply_policy_rules(all_issues, analysis_request.file_paths)
            
            # Step 4: Aggregate and categorize results
            logger.debug(f"Aggregating results for {request_id}")
            aggregated_issues = self._aggregate_issues(all_issues, policy_violations)
            
            # Step 5: Generate feedback
            logger.debug(f"Generating feedback for {request_id}")
            feedback_generated = await self._generate_feedback(aggregated_issues, analysis_request.file_paths)
            
            # Step 6: Create workflow result
            duration_ms = (time.time() - start_time) * 1000
            result = self._create_workflow_result(
                request_id=request_id,
                file_paths=analysis_request.file_paths,
                issues=aggregated_issues,
                policy_violations=policy_violations,
                dependency_issues=dependency_issues,
                duration_ms=duration_ms,
                feedback_generated=feedback_generated
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error in comprehensive workflow {request_id}: {e}")
            raise
    
    def _should_run_dependency_analysis(self, file_paths: List[str]) -> bool:
        """Determine if dependency analysis should be run."""
        dependency_files = {
            'requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile',
            'package.json', 'yarn.lock', 'pom.xml', 'build.gradle',
            'Gemfile', 'composer.json', 'go.mod', 'Cargo.toml'
        }
        
        for file_path in file_paths:
            file_name = Path(file_path).name
            if file_name in dependency_files:
                return True
        
        return False
    
    async def _run_dependency_analysis(self, file_paths: List[str]) -> List[SecurityIssue]:
        """Run dependency vulnerability analysis."""
        try:
            # Find dependency files
            dependency_files = []
            for file_path in file_paths:
                if self._is_dependency_file(file_path):
                    dependency_files.append(file_path)
            
            if not dependency_files:
                return []
            
            # Run dependency scanner
            vulnerabilities = await self.dependency_scanner.scan_dependencies(dependency_files)
            
            # Convert to SecurityIssue objects
            issues = []
            for vuln in vulnerabilities:
                issue = SecurityIssue(
                    rule_id=f"dependency_{vuln.cve_id or vuln.vulnerability_id}",
                    title=f"Vulnerable dependency: {vuln.package_name}",
                    description=vuln.description,
                    severity=vuln.severity,
                    file_path=vuln.file_path,
                    line_number=1,
                    column_number=1,
                    code_snippet=f"{vuln.package_name}=={vuln.current_version}",
                    remediation=f"Upgrade to version {vuln.fixed_version}" if vuln.fixed_version else "Review and update dependency",
                    references=[vuln.advisory_url] if vuln.advisory_url else [],
                    cwe_id=vuln.cwe_id,
                    confidence="high"
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            logger.error(f"Error in dependency analysis: {e}")
            self.error_handler.handle_analysis_error(e, "dependency_analysis")
            return []
    
    def _is_dependency_file(self, file_path: str) -> bool:
        """Check if file is a dependency file."""
        dependency_files = {
            'requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile',
            'package.json', 'yarn.lock', 'pom.xml', 'build.gradle',
            'Gemfile', 'composer.json', 'go.mod', 'Cargo.toml'
        }
        
        file_name = Path(file_path).name
        return file_name in dependency_files
    
    async def _apply_policy_rules(
        self,
        issues: List[SecurityIssue],
        file_paths: List[str]
    ) -> List[SecurityIssue]:
        """Apply policy rules to found issues and generate policy violations."""
        try:
            # Load and apply policies
            policy_violations = []
            
            for file_path in file_paths:
                # Apply file-specific policies
                file_violations = await self.policy_engine.apply_policies_to_file(file_path, issues)
                policy_violations.extend(file_violations)
            
            # Apply global policies
            global_violations = await self.policy_engine.apply_global_policies(issues)
            policy_violations.extend(global_violations)
            
            return policy_violations
            
        except Exception as e:
            logger.error(f"Error applying policy rules: {e}")
            self.error_handler.handle_analysis_error(e, "policy_application")
            return []
    
    def _aggregate_issues(
        self,
        sast_issues: List[SecurityIssue],
        policy_violations: List[SecurityIssue]
    ) -> List[SecurityIssue]:
        """Aggregate and deduplicate issues from different sources."""
        all_issues = sast_issues + policy_violations
        
        # Deduplicate issues based on file, line, and rule
        seen_issues = set()
        unique_issues = []
        
        for issue in all_issues:
            issue_key = (issue.file_path, issue.line_number, issue.rule_id)
            if issue_key not in seen_issues:
                seen_issues.add(issue_key)
                unique_issues.append(issue)
        
        # Sort by severity and file path
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        unique_issues.sort(
            key=lambda x: (severity_order.get(x.severity.value, 5), x.file_path, x.line_number)
        )
        
        return unique_issues
    
    async def _generate_feedback(
        self,
        issues: List[SecurityIssue],
        file_paths: List[str]
    ) -> bool:
        """Generate and deliver feedback for found issues."""
        try:
            if not issues:
                logger.debug("No issues found, skipping feedback generation")
                return False
            
            # Generate different types of feedback
            feedback_tasks = []
            
            # IDE feedback for inline annotations
            if self.config.ide_feedback_enabled:
                ide_feedback_task = self.feedback_engine.format_ide_feedback(issues)
                feedback_tasks.append(ide_feedback_task)
            
            # Summary report
            if self.config.summary_reports_enabled:
                # Create a mock analysis result for the report
                from compliance_sentinel.models.analysis import AnalysisResponse
                analysis_result = AnalysisResponse(
                    request_id=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    status=AnalysisStatus.COMPLETED,
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                    issues=issues,
                    total_files_analyzed=len(file_paths)
                )
                # Generate report synchronously (it's not async)
                report = self.feedback_engine.generate_report(analysis_result)
                logger.debug(f"Generated feedback report: {len(report)} characters")
            
            return True
            
        except Exception as e:
            logger.error(f"Error generating feedback: {e}")
            self.error_handler.handle_analysis_error(e, "feedback_generation")
            return False
    
    def _create_workflow_result(
        self,
        request_id: str,
        file_paths: List[str],
        issues: List[SecurityIssue],
        policy_violations: List[SecurityIssue],
        dependency_issues: List[SecurityIssue],
        duration_ms: float,
        feedback_generated: bool
    ) -> AnalysisWorkflowResult:
        """Create workflow result from analysis data."""
        # Count issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in issues:
            severity = issue.severity.value
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return AnalysisWorkflowResult(
            request_id=request_id,
            file_paths=file_paths,
            total_issues=len(issues),
            critical_issues=severity_counts['critical'],
            high_issues=severity_counts['high'],
            medium_issues=severity_counts['medium'],
            low_issues=severity_counts['low'],
            policy_violations=len(policy_violations),
            dependency_vulnerabilities=len(dependency_issues),
            analysis_duration_ms=duration_ms,
            feedback_generated=feedback_generated,
            success=True
        )
    
    async def analyze_project(self, project_path: str = ".") -> AnalysisWorkflowResult:
        """Run comprehensive analysis on entire project."""
        project_path_obj = Path(project_path)
        
        # Find all relevant files
        file_patterns = self.config.file_patterns or ['*.py', '*.js', '*.ts', '*.java']
        excluded_dirs = self.config.excluded_directories or ['node_modules', '.git', '__pycache__']
        
        relevant_files = []
        for pattern in file_patterns:
            for file_path in project_path_obj.rglob(pattern):
                # Check if file should be excluded
                should_exclude = False
                for excluded_dir in excluded_dirs:
                    if excluded_dir in file_path.parts:
                        should_exclude = True
                        break
                
                if not should_exclude and file_path.is_file():
                    relevant_files.append(str(file_path))
        
        logger.info(f"Found {len(relevant_files)} files to analyze in project")
        
        return await self.analyze_files(
            file_paths=relevant_files,
            analysis_type=AnalysisType.COMPREHENSIVE
        )
    
    def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get workflow performance metrics."""
        return {
            'total_analyses': self.workflow_metrics.total_analyses,
            'successful_analyses': self.workflow_metrics.successful_analyses,
            'failed_analyses': self.workflow_metrics.failed_analyses,
            'success_rate': (
                self.workflow_metrics.successful_analyses / self.workflow_metrics.total_analyses
                if self.workflow_metrics.total_analyses > 0 else 0
            ),
            'average_duration_ms': self.workflow_metrics.average_duration_ms,
            'total_issues_found': self.workflow_metrics.total_issues_found,
            'total_files_analyzed': self.workflow_metrics.total_files_analyzed,
            'cache_hit_rate': self.workflow_metrics.cache_hit_rate,
            'active_analyses': len(self.active_analyses),
            'is_running': self.is_running
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        status = {
            'agent_running': self.is_running,
            'components': {
                'analysis_coordinator': self.analysis_coordinator is not None,
                'policy_engine': self.policy_engine is not None,
                'feedback_engine': self.feedback_engine is not None,
                'dependency_scanner': self.dependency_scanner is not None,
                'hook_manager': self.hook_manager is not None and self.hook_manager.processing_active
            },
            'metrics': self.get_workflow_metrics(),
            'configuration': {
                'hooks_enabled': self.config.hooks_enabled,
                'ide_feedback_enabled': self.config.ide_feedback_enabled,
                'summary_reports_enabled': self.config.summary_reports_enabled,
                'analysis_timeout': self.config.analysis_timeout
            }
        }
        
        # Add hook manager status if available
        if self.hook_manager:
            status['hook_statistics'] = self.hook_manager.get_hook_statistics()
        
        return status
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()