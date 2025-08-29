"""Git hooks for pre-commit and pre-push security validation."""

import os
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import logging
from pathlib import Path
import tempfile

from compliance_sentinel.core.interfaces import SecurityIssue, Severity


logger = logging.getLogger(__name__)


class HookType(Enum):
    """Types of Git hooks."""
    PRE_COMMIT = "pre-commit"
    PRE_PUSH = "pre-push"
    POST_COMMIT = "post-commit"
    PRE_RECEIVE = "pre-receive"
    POST_RECEIVE = "post-receive"


class HookResult(Enum):
    """Result of hook execution."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"


@dataclass
class GitFile:
    """Represents a file in Git."""
    path: str
    status: str  # A=added, M=modified, D=deleted, R=renamed
    content: Optional[str] = None
    old_path: Optional[str] = None  # For renamed files


@dataclass
class HookExecutionResult:
    """Result of Git hook execution."""
    hook_type: HookType
    result: HookResult
    issues_found: int
    critical_issues: int
    high_issues: int
    execution_time: float
    message: str
    details: List[str]
    files_analyzed: List[str]
    executed_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'hook_type': self.hook_type.value,
            'result': self.result.value,
            'issues_found': self.issues_found,
            'critical_issues': self.critical_issues,
            'high_issues': self.high_issues,
            'execution_time': self.execution_time,
            'message': self.message,
            'details': self.details,
            'files_analyzed': self.files_analyzed,
            'executed_at': self.executed_at.isoformat()
        }


class GitHooks:
    """Git hooks manager for security validation."""
    
    def __init__(self, repo_path: str = "."):
        """Initialize Git hooks manager."""
        self.repo_path = Path(repo_path).resolve()
        self.git_dir = self.repo_path / ".git"
        self.hooks_dir = self.git_dir / "hooks"
        self.logger = logging.getLogger(f"{__name__}.git_hooks")
        
        # Hook configuration
        self.config = self._load_hook_config()
        
        # Ensure hooks directory exists
        self.hooks_dir.mkdir(exist_ok=True)
    
    def _load_hook_config(self) -> Dict[str, Any]:
        """Load hook configuration."""
        config_path = self.repo_path / ".compliance-sentinel" / "hooks.json"
        default_config = {
            "enabled": True,
            "severity_threshold": "medium",
            "fail_on_critical": True,
            "fail_on_high": False,
            "max_issues": 10,
            "exclude_patterns": ["*.min.js", "node_modules/**", "vendor/**"],
            "include_patterns": ["*.py", "*.js", "*.ts", "*.java", "*.cs", "*.go", "*.rs", "*.php"],
            "frameworks": ["soc2", "pci_dss"],
            "auto_fix": False,
            "generate_report": True
        }
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
        except Exception as e:
            self.logger.warning(f"Failed to load hook config: {e}")
        
        return default_config
    
    def install_hooks(self, hook_types: List[HookType] = None) -> Dict[HookType, bool]:
        """Install Git hooks."""
        if hook_types is None:
            hook_types = [HookType.PRE_COMMIT, HookType.PRE_PUSH]
        
        results = {}
        
        for hook_type in hook_types:
            try:
                hook_path = self.hooks_dir / hook_type.value
                hook_content = self._generate_hook_script(hook_type)
                
                # Write hook script
                with open(hook_path, 'w') as f:
                    f.write(hook_content)
                
                # Make executable
                os.chmod(hook_path, 0o755)
                
                results[hook_type] = True
                self.logger.info(f"Installed {hook_type.value} hook")
            
            except Exception as e:
                self.logger.error(f"Failed to install {hook_type.value} hook: {e}")
                results[hook_type] = False
        
        return results
    
    def _generate_hook_script(self, hook_type: HookType) -> str:
        """Generate hook script content."""
        python_path = subprocess.check_output(["which", "python3"], text=True).strip()
        
        if hook_type == HookType.PRE_COMMIT:
            return f"""#!/bin/bash
# Compliance Sentinel Pre-Commit Hook
# Auto-generated - do not edit manually

set -e

echo "🔍 Running Compliance Sentinel security analysis..."

# Run security analysis on staged files
{python_path} -c "
import sys
sys.path.insert(0, '{self.repo_path}')
from compliance_sentinel.git_integration.git_hooks import GitHooks
hooks = GitHooks('{self.repo_path}')
result = hooks.execute_pre_commit_hook()
sys.exit(0 if result.result in ['pass', 'warning'] else 1)
"

exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "❌ Security issues found. Commit blocked."
    echo "Run 'git commit --no-verify' to bypass (not recommended)"
    exit 1
fi

echo "✅ Security analysis passed"
exit 0
"""
        
        elif hook_type == HookType.PRE_PUSH:
            return f"""#!/bin/bash
# Compliance Sentinel Pre-Push Hook
# Auto-generated - do not edit manually

set -e

echo "🔍 Running Compliance Sentinel security analysis for push..."

# Run security analysis on commits being pushed
{python_path} -c "
import sys
sys.path.insert(0, '{self.repo_path}')
from compliance_sentinel.git_integration.git_hooks import GitHooks
hooks = GitHooks('{self.repo_path}')
result = hooks.execute_pre_push_hook()
sys.exit(0 if result.result in ['pass', 'warning'] else 1)
"

exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "❌ Security issues found. Push blocked."
    echo "Run 'git push --no-verify' to bypass (not recommended)"
    exit 1
fi

echo "✅ Security analysis passed"
exit 0
"""
        
        return ""
    
    def execute_pre_commit_hook(self) -> HookExecutionResult:
        """Execute pre-commit security validation."""
        start_time = datetime.now()
        
        try:
            # Get staged files
            staged_files = self._get_staged_files()
            
            if not staged_files:
                return HookExecutionResult(
                    hook_type=HookType.PRE_COMMIT,
                    result=HookResult.SKIP,
                    issues_found=0,
                    critical_issues=0,
                    high_issues=0,
                    execution_time=0.0,
                    message="No staged files to analyze",
                    details=[],
                    files_analyzed=[],
                    executed_at=start_time
                )
            
            # Filter files based on patterns
            filtered_files = self._filter_files(staged_files)
            
            # Analyze files
            all_issues = []
            analyzed_files = []
            
            for git_file in filtered_files:
                if git_file.status != 'D':  # Skip deleted files
                    issues = self._analyze_file(git_file)
                    all_issues.extend(issues)
                    analyzed_files.append(git_file.path)
            
            # Calculate metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            critical_count = sum(1 for issue in all_issues if issue.severity == Severity.CRITICAL)
            high_count = sum(1 for issue in all_issues if issue.severity == Severity.HIGH)
            
            # Determine result
            result = self._determine_hook_result(all_issues, critical_count, high_count)
            
            # Generate message and details
            message, details = self._generate_hook_message(result, all_issues, analyzed_files)
            
            hook_result = HookExecutionResult(
                hook_type=HookType.PRE_COMMIT,
                result=result,
                issues_found=len(all_issues),
                critical_issues=critical_count,
                high_issues=high_count,
                execution_time=execution_time,
                message=message,
                details=details,
                files_analyzed=analyzed_files,
                executed_at=start_time
            )
            
            # Generate report if configured
            if self.config.get("generate_report", True):
                self._generate_hook_report(hook_result, all_issues)
            
            return hook_result
        
        except Exception as e:
            self.logger.error(f"Pre-commit hook execution failed: {e}")
            return HookExecutionResult(
                hook_type=HookType.PRE_COMMIT,
                result=HookResult.FAIL,
                issues_found=0,
                critical_issues=0,
                high_issues=0,
                execution_time=(datetime.now() - start_time).total_seconds(),
                message=f"Hook execution failed: {str(e)}",
                details=[],
                files_analyzed=[],
                executed_at=start_time
            )
    
    def execute_pre_push_hook(self) -> HookExecutionResult:
        """Execute pre-push security validation."""
        start_time = datetime.now()
        
        try:
            # Get commits being pushed
            commits = self._get_push_commits()
            
            if not commits:
                return HookExecutionResult(
                    hook_type=HookType.PRE_PUSH,
                    result=HookResult.SKIP,
                    issues_found=0,
                    critical_issues=0,
                    high_issues=0,
                    execution_time=0.0,
                    message="No new commits to analyze",
                    details=[],
                    files_analyzed=[],
                    executed_at=start_time
                )
            
            # Get changed files from commits
            changed_files = self._get_changed_files_from_commits(commits)
            filtered_files = self._filter_files(changed_files)
            
            # Analyze files
            all_issues = []
            analyzed_files = []
            
            for git_file in filtered_files:
                if git_file.status != 'D':  # Skip deleted files
                    issues = self._analyze_file(git_file)
                    all_issues.extend(issues)
                    analyzed_files.append(git_file.path)
            
            # Calculate metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            critical_count = sum(1 for issue in all_issues if issue.severity == Severity.CRITICAL)
            high_count = sum(1 for issue in all_issues if issue.severity == Severity.HIGH)
            
            # Determine result
            result = self._determine_hook_result(all_issues, critical_count, high_count)
            
            # Generate message and details
            message, details = self._generate_hook_message(result, all_issues, analyzed_files)
            
            return HookExecutionResult(
                hook_type=HookType.PRE_PUSH,
                result=result,
                issues_found=len(all_issues),
                critical_issues=critical_count,
                high_issues=high_count,
                execution_time=execution_time,
                message=message,
                details=details,
                files_analyzed=analyzed_files,
                executed_at=start_time
            )
        
        except Exception as e:
            self.logger.error(f"Pre-push hook execution failed: {e}")
            return HookExecutionResult(
                hook_type=HookType.PRE_PUSH,
                result=HookResult.FAIL,
                issues_found=0,
                critical_issues=0,
                high_issues=0,
                execution_time=(datetime.now() - start_time).total_seconds(),
                message=f"Hook execution failed: {str(e)}",
                details=[],
                files_analyzed=[],
                executed_at=start_time
            )
    
    def _get_staged_files(self) -> List[GitFile]:
        """Get list of staged files."""
        try:
            # Get staged files with status
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-status"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            files = []
            for line in result.stdout.strip().split('\\n'):
                if line:
                    parts = line.split('\\t')
                    if len(parts) >= 2:
                        status = parts[0]
                        path = parts[1]
                        
                        # Get file content for non-deleted files
                        content = None
                        if status != 'D':
                            content = self._get_staged_file_content(path)
                        
                        files.append(GitFile(
                            path=path,
                            status=status,
                            content=content
                        ))
            
            return files
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get staged files: {e}")
            return []
    
    def _get_staged_file_content(self, file_path: str) -> Optional[str]:
        """Get content of staged file."""
        try:
            result = subprocess.run(
                ["git", "show", f":{file_path}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError:
            # File might be new, try reading from working directory
            try:
                full_path = self.repo_path / file_path
                if full_path.exists():
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()
            except Exception:
                pass
            return None
    
    def _get_push_commits(self) -> List[str]:
        """Get list of commits being pushed."""
        try:
            # Get commits that are ahead of origin
            result = subprocess.run(
                ["git", "rev-list", "HEAD", "^origin/HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = [line.strip() for line in result.stdout.strip().split('\\n') if line.strip()]
            return commits
        
        except subprocess.CalledProcessError:
            # Fallback: get last few commits
            try:
                result = subprocess.run(
                    ["git", "rev-list", "-n", "5", "HEAD"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                commits = [line.strip() for line in result.stdout.strip().split('\\n') if line.strip()]
                return commits
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to get push commits: {e}")
                return []
    
    def _get_changed_files_from_commits(self, commits: List[str]) -> List[GitFile]:
        """Get changed files from list of commits."""
        files = []
        
        for commit in commits:
            try:
                result = subprocess.run(
                    ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                for line in result.stdout.strip().split('\\n'):
                    if line:
                        parts = line.split('\\t')
                        if len(parts) >= 2:
                            status = parts[0]
                            path = parts[1]
                            
                            # Get current file content
                            content = None
                            if status != 'D':
                                try:
                                    full_path = self.repo_path / path
                                    if full_path.exists():
                                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            content = f.read()
                                except Exception:
                                    pass
                            
                            files.append(GitFile(
                                path=path,
                                status=status,
                                content=content
                            ))
            
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to get files for commit {commit}: {e}")
        
        return files
    
    def _filter_files(self, files: List[GitFile]) -> List[GitFile]:
        """Filter files based on include/exclude patterns."""
        import fnmatch
        
        include_patterns = self.config.get("include_patterns", [])
        exclude_patterns = self.config.get("exclude_patterns", [])
        
        filtered = []
        
        for file in files:
            # Check exclude patterns first
            excluded = False
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(file.path, pattern):
                    excluded = True
                    break
            
            if excluded:
                continue
            
            # Check include patterns
            if include_patterns:
                included = False
                for pattern in include_patterns:
                    if fnmatch.fnmatch(file.path, pattern):
                        included = True
                        break
                
                if not included:
                    continue
            
            filtered.append(file)
        
        return filtered
    
    def _analyze_file(self, git_file: GitFile) -> List[SecurityIssue]:
        """Analyze a single file for security issues."""
        if not git_file.content:
            return []
        
        # Mock analysis for demo - in real implementation, this would use the full analyzer
        issues = []
        lines = git_file.content.split('\\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for hardcoded secrets
            if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']) and ('=' in line or ':' in line):
                if '"' in line or "'" in line:
                    issues.append(SecurityIssue(
                        id=f"git_hook_{git_file.path}_{line_num}",
                        severity=Severity.HIGH,
                        category=None,  # Would be set by real analyzer
                        file_path=git_file.path,
                        line_number=line_num,
                        description=f"Hardcoded secret detected in {git_file.path}",
                        rule_id="hardcoded_secrets",
                        confidence=0.8,
                        remediation_suggestions=["Use environment variables for secrets"],
                        created_at=datetime.now()
                    ))
            
            # Check for SQL injection patterns
            if 'execute' in line.lower() and ('f"' in line or "f'" in line or '+' in line):
                issues.append(SecurityIssue(
                    id=f"git_hook_sql_{git_file.path}_{line_num}",
                    severity=Severity.CRITICAL,
                    category=None,
                    file_path=git_file.path,
                    line_number=line_num,
                    description=f"Potential SQL injection in {git_file.path}",
                    rule_id="sql_injection",
                    confidence=0.7,
                    remediation_suggestions=["Use parameterized queries"],
                    created_at=datetime.now()
                ))
        
        return issues
    
    def _determine_hook_result(self, issues: List[SecurityIssue], critical_count: int, high_count: int) -> HookResult:
        """Determine hook execution result based on issues found."""
        max_issues = self.config.get("max_issues", 10)
        fail_on_critical = self.config.get("fail_on_critical", True)
        fail_on_high = self.config.get("fail_on_high", False)
        
        # Check if we should fail
        if fail_on_critical and critical_count > 0:
            return HookResult.FAIL
        
        if fail_on_high and high_count > 0:
            return HookResult.FAIL
        
        if len(issues) > max_issues:
            return HookResult.FAIL
        
        # Check for warnings
        if critical_count > 0 or high_count > 0 or len(issues) > 0:
            return HookResult.WARNING
        
        return HookResult.PASS
    
    def _generate_hook_message(self, result: HookResult, issues: List[SecurityIssue], files: List[str]) -> Tuple[str, List[str]]:
        """Generate hook result message and details."""
        if result == HookResult.PASS:
            message = f"✅ Security analysis passed - {len(files)} files analyzed, no issues found"
            details = [f"Analyzed files: {', '.join(files[:5])}" + ("..." if len(files) > 5 else "")]
        
        elif result == HookResult.WARNING:
            message = f"⚠️  Security issues found - {len(issues)} issues in {len(files)} files"
            details = []
            
            # Group issues by severity
            critical_issues = [i for i in issues if i.severity == Severity.CRITICAL]
            high_issues = [i for i in issues if i.severity == Severity.HIGH]
            
            if critical_issues:
                details.append(f"Critical issues: {len(critical_issues)}")
                for issue in critical_issues[:3]:  # Show first 3
                    details.append(f"  - {issue.file_path}:{issue.line_number} - {issue.description}")
            
            if high_issues:
                details.append(f"High severity issues: {len(high_issues)}")
                for issue in high_issues[:3]:  # Show first 3
                    details.append(f"  - {issue.file_path}:{issue.line_number} - {issue.description}")
        
        elif result == HookResult.FAIL:
            message = f"❌ Security analysis failed - {len(issues)} issues found, commit/push blocked"
            details = []
            
            # Show critical issues first
            critical_issues = [i for i in issues if i.severity == Severity.CRITICAL]
            if critical_issues:
                details.append(f"Critical issues ({len(critical_issues)}):")
                for issue in critical_issues[:5]:  # Show first 5
                    details.append(f"  - {issue.file_path}:{issue.line_number} - {issue.description}")
            
            details.append("Fix these issues before committing/pushing")
        
        else:  # SKIP
            message = "ℹ️  Security analysis skipped - no relevant files to analyze"
            details = []
        
        return message, details
    
    def _generate_hook_report(self, result: HookExecutionResult, issues: List[SecurityIssue]) -> None:
        """Generate detailed hook execution report."""
        try:
            report_dir = self.repo_path / ".compliance-sentinel" / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = result.executed_at.strftime("%Y%m%d_%H%M%S")
            report_file = report_dir / f"hook_{result.hook_type.value}_{timestamp}.json"
            
            report_data = {
                "execution_result": result.to_dict(),
                "issues": [
                    {
                        "id": issue.id,
                        "severity": issue.severity.value if issue.severity else "unknown",
                        "file_path": issue.file_path,
                        "line_number": issue.line_number,
                        "description": issue.description,
                        "rule_id": issue.rule_id,
                        "confidence": issue.confidence
                    }
                    for issue in issues
                ],
                "summary": {
                    "total_issues": len(issues),
                    "by_severity": {
                        "critical": sum(1 for i in issues if i.severity == Severity.CRITICAL),
                        "high": sum(1 for i in issues if i.severity == Severity.HIGH),
                        "medium": sum(1 for i in issues if i.severity == Severity.MEDIUM),
                        "low": sum(1 for i in issues if i.severity == Severity.LOW)
                    }
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Generated hook report: {report_file}")
        
        except Exception as e:
            self.logger.error(f"Failed to generate hook report: {e}")
    
    def uninstall_hooks(self, hook_types: List[HookType] = None) -> Dict[HookType, bool]:
        """Uninstall Git hooks."""
        if hook_types is None:
            hook_types = [HookType.PRE_COMMIT, HookType.PRE_PUSH]
        
        results = {}
        
        for hook_type in hook_types:
            try:
                hook_path = self.hooks_dir / hook_type.value
                if hook_path.exists():
                    hook_path.unlink()
                    results[hook_type] = True
                    self.logger.info(f"Uninstalled {hook_type.value} hook")
                else:
                    results[hook_type] = True  # Already uninstalled
            
            except Exception as e:
                self.logger.error(f"Failed to uninstall {hook_type.value} hook: {e}")
                results[hook_type] = False
        
        return results
    
    def get_hook_status(self) -> Dict[HookType, bool]:
        """Get installation status of hooks."""
        status = {}
        
        for hook_type in HookType:
            hook_path = self.hooks_dir / hook_type.value
            status[hook_type] = hook_path.exists() and os.access(hook_path, os.X_OK)
        
        return status
    
    def update_config(self, config_updates: Dict[str, Any]) -> None:
        """Update hook configuration."""
        self.config.update(config_updates)
        
        # Save to file
        config_dir = self.repo_path / ".compliance-sentinel"
        config_dir.mkdir(exist_ok=True)
        
        config_path = config_dir / "hooks.json"
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        self.logger.info("Updated hook configuration")


# Global Git hooks instance
_global_git_hooks: Optional[GitHooks] = None


def get_git_hooks(repo_path: str = ".") -> GitHooks:
    """Get global Git hooks instance."""
    global _global_git_hooks
    if _global_git_hooks is None:
        _global_git_hooks = GitHooks(repo_path)
    return _global_git_hooks


def reset_git_hooks() -> None:
    """Reset global Git hooks (for testing)."""
    global _global_git_hooks
    _global_git_hooks = None