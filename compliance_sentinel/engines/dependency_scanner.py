"""Dependency security scanner for detecting vulnerabilities in project dependencies."""

import json
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import hashlib

from compliance_sentinel.core.interfaces import (
    VulnerabilityScanner,
    VulnerabilityReport,
    SecurityIssue,
    SecurityCategory,
    Severity
)
from compliance_sentinel.utils.error_handler import (
    get_global_error_handler,
    retry_with_backoff,
    RetryStrategy
)
from compliance_sentinel.utils.cache import get_global_cache, VulnerabilityCacheManager
from compliance_sentinel.core.validation import InputSanitizer


logger = logging.getLogger(__name__)


@dataclass
class DependencyInfo:
    """Information about a project dependency."""
    name: str
    version: str
    file_path: str
    line_number: int
    ecosystem: str  # pip, npm, maven, etc.
    is_dev_dependency: bool = False
    is_transitive: bool = False
    parent_dependency: Optional[str] = None


@dataclass
class ScannerConfig:
    """Configuration for dependency scanner."""
    enable_safety: bool = True
    enable_pip_audit: bool = True
    enable_osv_scanner: bool = False  # Optional OSV scanner
    safety_db_update: bool = True
    include_dev_dependencies: bool = False
    severity_threshold: Severity = Severity.LOW
    max_age_days: int = 30  # Max age for vulnerability data
    timeout_seconds: int = 120
    cache_ttl: int = 3600  # 1 hour cache
    
    # File patterns to scan
    dependency_files: Dict[str, str] = field(default_factory=lambda: {
        "requirements.txt": "pip",
        "requirements-dev.txt": "pip",
        "Pipfile": "pip",
        "Pipfile.lock": "pip",
        "pyproject.toml": "pip",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "Gemfile": "gem",
        "Gemfile.lock": "gem",
        "composer.json": "composer",
        "composer.lock": "composer",
        "go.mod": "go",
        "go.sum": "go"
    })


class DependencyParser:
    """Parses dependency files to extract package information."""
    
    @staticmethod
    def parse_requirements_txt(file_path: str) -> List[DependencyInfo]:
        """Parse requirements.txt file."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                
                # Parse package specification
                dep_info = DependencyParser._parse_pip_requirement(line, file_path, line_num)
                if dep_info:
                    dependencies.append(dep_info)
                    
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    @staticmethod
    def _parse_pip_requirement(requirement: str, file_path: str, line_num: int) -> Optional[DependencyInfo]:
        """Parse a single pip requirement line."""
        # Remove inline comments
        requirement = requirement.split('#')[0].strip()
        
        if not requirement:
            return None
        
        # Handle different requirement formats
        # package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
        match = re.match(r'^([a-zA-Z0-9_.-]+)([><=!~]+)([0-9a-zA-Z.-]+)', requirement)
        if match:
            name = match.group(1)
            operator = match.group(2)
            version = match.group(3)
            
            # For exact versions, use as-is; for ranges, use the specified version
            if operator == '==':
                exact_version = version
            else:
                # For version ranges, we'll use the specified version as a reference
                exact_version = version
            
            return DependencyInfo(
                name=name,
                version=exact_version,
                file_path=file_path,
                line_number=line_num,
                ecosystem="pip",
                is_dev_dependency="dev" in Path(file_path).name.lower()
            )
        
        # Handle package names without version specifiers
        match = re.match(r'^([a-zA-Z0-9_.-]+)$', requirement)
        if match:
            name = match.group(1)
            return DependencyInfo(
                name=name,
                version="latest",  # Will need to resolve actual version
                file_path=file_path,
                line_number=line_num,
                ecosystem="pip",
                is_dev_dependency="dev" in Path(file_path).name.lower()
            )
        
        return None
    
    @staticmethod
    def parse_package_json(file_path: str) -> List[DependencyInfo]:
        """Parse package.json file."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse regular dependencies
            deps = data.get('dependencies', {})
            for name, version in deps.items():
                clean_version = DependencyParser._clean_npm_version(version)
                dependencies.append(DependencyInfo(
                    name=name,
                    version=clean_version,
                    file_path=file_path,
                    line_number=1,  # JSON doesn't have meaningful line numbers
                    ecosystem="npm",
                    is_dev_dependency=False
                ))
            
            # Parse dev dependencies
            dev_deps = data.get('devDependencies', {})
            for name, version in dev_deps.items():
                clean_version = DependencyParser._clean_npm_version(version)
                dependencies.append(DependencyInfo(
                    name=name,
                    version=clean_version,
                    file_path=file_path,
                    line_number=1,
                    ecosystem="npm",
                    is_dev_dependency=True
                ))
                
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    @staticmethod
    def _clean_npm_version(version: str) -> str:
        """Clean npm version string to extract actual version."""
        # Remove npm version prefixes like ^, ~, >=, etc.
        version = re.sub(r'^[~^>=<]+', '', version)
        
        # Extract version number
        match = re.match(r'^([0-9]+\.[0-9]+\.[0-9]+)', version)
        if match:
            return match.group(1)
        
        return version
    
    @staticmethod
    def parse_pyproject_toml(file_path: str) -> List[DependencyInfo]:
        """Parse pyproject.toml file."""
        dependencies = []
        
        try:
            import tomli
            
            with open(file_path, 'rb') as f:
                data = tomli.load(f)
            
            # Parse project dependencies
            project_deps = data.get('project', {}).get('dependencies', [])
            for dep in project_deps:
                dep_info = DependencyParser._parse_pip_requirement(dep, file_path, 1)
                if dep_info:
                    dependencies.append(dep_info)
            
            # Parse optional dependencies
            optional_deps = data.get('project', {}).get('optional-dependencies', {})
            for group_name, deps in optional_deps.items():
                for dep in deps:
                    dep_info = DependencyParser._parse_pip_requirement(dep, file_path, 1)
                    if dep_info:
                        dep_info.is_dev_dependency = group_name in ['dev', 'test', 'docs']
                        dependencies.append(dep_info)
                        
        except ImportError:
            logger.warning("tomli not available, cannot parse pyproject.toml")
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
        
        return dependencies


class SafetyScanner:
    """Scanner using Safety tool for Python dependencies."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.cache = get_global_cache()
        
        # Verify Safety is available
        self._verify_safety_installation()
    
    def _verify_safety_installation(self) -> None:
        """Verify that Safety is installed and accessible."""
        try:
            result = subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Safety version: {result.stdout.strip()}")
            else:
                raise RuntimeError("Safety not properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError) as e:
            logger.error(f"Safety installation check failed: {e}")
            raise RuntimeError(
                "Safety is not installed or not accessible. "
                "Please install it with: pip install safety"
            )
    
    @retry_with_backoff(
        strategy=RetryStrategy(max_attempts=2, base_delay=2.0),
        exceptions=(subprocess.TimeoutExpired, subprocess.CalledProcessError)
    )
    def scan_dependencies(self, dependencies: List[DependencyInfo]) -> List[VulnerabilityReport]:
        """Scan dependencies using Safety."""
        if not dependencies:
            return []
        
        # Filter to Python dependencies only
        python_deps = [dep for dep in dependencies if dep.ecosystem == "pip"]
        if not python_deps:
            return []
        
        try:
            # Update Safety database if configured
            if self.config.safety_db_update:
                self._update_safety_db()
            
            # Create temporary requirements file
            temp_requirements = self._create_temp_requirements(python_deps)
            
            # Run Safety scan
            vulnerabilities = self._run_safety_scan(temp_requirements)
            
            # Clean up
            if temp_requirements.exists():
                temp_requirements.unlink()
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Safety scan failed: {e}")
            return []
    
    def _update_safety_db(self) -> None:
        """Update Safety vulnerability database."""
        try:
            result = subprocess.run(
                ["safety", "check", "--db", "--update"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                logger.info("Safety database updated successfully")
            else:
                logger.warning(f"Safety database update failed: {result.stderr}")
        except Exception as e:
            logger.warning(f"Failed to update Safety database: {e}")
    
    def _create_temp_requirements(self, dependencies: List[DependencyInfo]) -> Path:
        """Create temporary requirements file for Safety scan."""
        import tempfile
        
        temp_file = Path(tempfile.mktemp(suffix='.txt'))
        
        with open(temp_file, 'w') as f:
            for dep in dependencies:
                if dep.version and dep.version != "latest":
                    f.write(f"{dep.name}=={dep.version}\n")
                else:
                    f.write(f"{dep.name}\n")
        
        return temp_file
    
    def _run_safety_scan(self, requirements_file: Path) -> List[VulnerabilityReport]:
        """Run Safety scan on requirements file."""
        cmd = [
            "safety", "check",
            "--requirements", str(requirements_file),
            "--json",
            "--output", "json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds
            )
            
            # Safety returns non-zero exit code when vulnerabilities are found
            if result.returncode > 1:
                logger.error(f"Safety scan failed: {result.stderr}")
                return []
            
            # Parse JSON output
            if result.stdout.strip():
                vulnerabilities_data = json.loads(result.stdout)
                return self._parse_safety_output(vulnerabilities_data)
            else:
                return []
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Safety JSON output: {e}")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("Safety scan timed out")
            return []
    
    def _parse_safety_output(self, safety_data: List[Dict[str, Any]]) -> List[VulnerabilityReport]:
        """Parse Safety JSON output into VulnerabilityReport objects."""
        vulnerabilities = []
        
        for vuln_data in safety_data:
            try:
                # Extract vulnerability information
                package_name = vuln_data.get('package', 'unknown')
                installed_version = vuln_data.get('installed_version', 'unknown')
                vulnerability_id = vuln_data.get('vulnerability_id', 'unknown')
                advisory = vuln_data.get('advisory', 'No description available')
                
                # Safety doesn't always provide CVE IDs
                cve_id = vulnerability_id if vulnerability_id.startswith('CVE-') else f"SAFETY-{vulnerability_id}"
                
                # Extract affected versions
                affected_versions = vuln_data.get('affected_versions', [installed_version])
                if isinstance(affected_versions, str):
                    affected_versions = [affected_versions]
                
                # Determine severity (Safety doesn't provide CVSS scores)
                severity_score = self._estimate_severity_score(advisory, vulnerability_id)
                
                # Check for remediation
                remediation_available = 'fixed_versions' in vuln_data and vuln_data['fixed_versions']
                upgrade_path = None
                if remediation_available:
                    fixed_versions = vuln_data.get('fixed_versions', [])
                    if fixed_versions:
                        # Recommend the latest fixed version
                        upgrade_path = max(fixed_versions) if isinstance(fixed_versions, list) else str(fixed_versions)
                
                vulnerability = VulnerabilityReport(
                    cve_id=cve_id,
                    package_name=package_name,
                    affected_versions=affected_versions,
                    severity_score=severity_score,
                    description=advisory,
                    remediation_available=remediation_available,
                    upgrade_path=upgrade_path
                )
                
                vulnerabilities.append(vulnerability)
                
            except Exception as e:
                logger.warning(f"Error parsing Safety vulnerability: {e}")
                continue
        
        return vulnerabilities
    
    def _estimate_severity_score(self, advisory: str, vuln_id: str) -> float:
        """Estimate severity score based on advisory text."""
        advisory_lower = advisory.lower()
        
        # High severity indicators
        if any(keyword in advisory_lower for keyword in [
            'remote code execution', 'rce', 'arbitrary code',
            'sql injection', 'command injection', 'deserialization'
        ]):
            return 9.0
        
        # Medium-high severity
        if any(keyword in advisory_lower for keyword in [
            'cross-site scripting', 'xss', 'csrf', 'authentication bypass',
            'privilege escalation', 'directory traversal'
        ]):
            return 7.0
        
        # Medium severity
        if any(keyword in advisory_lower for keyword in [
            'denial of service', 'dos', 'information disclosure',
            'weak cryptography', 'insecure'
        ]):
            return 5.0
        
        # Default to medium-low
        return 4.0


class PipAuditScanner:
    """Scanner using pip-audit tool for Python dependencies."""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.cache = get_global_cache()
        
        # Verify pip-audit is available
        self._verify_pip_audit_installation()
    
    def _verify_pip_audit_installation(self) -> None:
        """Verify that pip-audit is installed and accessible."""
        try:
            result = subprocess.run(
                ["pip-audit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"pip-audit version: {result.stdout.strip()}")
            else:
                raise RuntimeError("pip-audit not properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError) as e:
            logger.error(f"pip-audit installation check failed: {e}")
            raise RuntimeError(
                "pip-audit is not installed or not accessible. "
                "Please install it with: pip install pip-audit"
            )
    
    @retry_with_backoff(
        strategy=RetryStrategy(max_attempts=2, base_delay=2.0),
        exceptions=(subprocess.TimeoutExpired, subprocess.CalledProcessError)
    )
    def scan_requirements_file(self, requirements_file: str) -> List[VulnerabilityReport]:
        """Scan requirements file using pip-audit."""
        try:
            cmd = [
                "pip-audit",
                "--requirement", requirements_file,
                "--format", "json",
                "--no-deps"  # Only check direct dependencies
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds
            )
            
            # pip-audit returns non-zero exit code when vulnerabilities are found
            if result.returncode > 1:
                logger.error(f"pip-audit scan failed: {result.stderr}")
                return []
            
            # Parse JSON output
            if result.stdout.strip():
                vulnerabilities_data = json.loads(result.stdout)
                return self._parse_pip_audit_output(vulnerabilities_data)
            else:
                return []
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse pip-audit JSON output: {e}")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit scan timed out")
            return []
    
    def _parse_pip_audit_output(self, audit_data: Dict[str, Any]) -> List[VulnerabilityReport]:
        """Parse pip-audit JSON output into VulnerabilityReport objects."""
        vulnerabilities = []
        
        dependencies = audit_data.get('dependencies', [])
        
        for dep_data in dependencies:
            package_name = dep_data.get('name', 'unknown')
            version = dep_data.get('version', 'unknown')
            vulns = dep_data.get('vulns', [])
            
            for vuln in vulns:
                try:
                    cve_id = vuln.get('id', 'unknown')
                    description = vuln.get('description', 'No description available')
                    
                    # Extract affected versions
                    affected_versions = [version]  # Current version is affected
                    
                    # Get severity score from CVSS if available
                    severity_score = 5.0  # Default
                    if 'severity' in vuln:
                        severity_score = float(vuln['severity'])
                    
                    # Check for fix information
                    fix_versions = vuln.get('fix_versions', [])
                    remediation_available = bool(fix_versions)
                    upgrade_path = min(fix_versions) if fix_versions else None
                    
                    vulnerability = VulnerabilityReport(
                        cve_id=cve_id,
                        package_name=package_name,
                        affected_versions=affected_versions,
                        severity_score=severity_score,
                        description=description,
                        remediation_available=remediation_available,
                        upgrade_path=upgrade_path
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
                except Exception as e:
                    logger.warning(f"Error parsing pip-audit vulnerability: {e}")
                    continue
        
        return vulnerabilities


class DependencyScanner(VulnerabilityScanner):
    """Main dependency security scanner that coordinates multiple scanning tools."""
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize dependency scanner with configuration."""
        self.config = config or ScannerConfig()
        self.cache = get_global_cache()
        self.vuln_cache = VulnerabilityCacheManager(self.cache)
        self.error_handler = get_global_error_handler()
        
        # Initialize scanners
        self.scanners = {}
        self._initialize_scanners()
        
        logger.info(f"Initialized dependency scanner with {len(self.scanners)} tools")
    
    def _initialize_scanners(self) -> None:
        """Initialize available scanning tools."""
        if self.config.enable_safety:
            try:
                self.scanners['safety'] = SafetyScanner(self.config)
                logger.info("Initialized Safety scanner")
            except Exception as e:
                logger.warning(f"Failed to initialize Safety scanner: {e}")
        
        if self.config.enable_pip_audit:
            try:
                self.scanners['pip-audit'] = PipAuditScanner(self.config)
                logger.info("Initialized pip-audit scanner")
            except Exception as e:
                logger.warning(f"Failed to initialize pip-audit scanner: {e}")
    
    def scan_dependencies(self, requirements_file: str) -> List[VulnerabilityReport]:
        """Scan dependencies from a requirements file."""
        if not Path(requirements_file).exists():
            raise FileNotFoundError(f"Requirements file not found: {requirements_file}")
        
        # Check cache first
        cache_key = f"dep_scan:{requirements_file}:{Path(requirements_file).stat().st_mtime}"
        cached_result = self.vuln_cache.get_vulnerability_scan("file", cache_key)
        if cached_result:
            logger.info(f"Using cached dependency scan results for {requirements_file}")
            return cached_result
        
        try:
            # Parse dependencies from file
            dependencies = self._parse_dependency_file(requirements_file)
            
            if not dependencies:
                logger.warning(f"No dependencies found in {requirements_file}")
                return []
            
            # Run scans with all available tools
            all_vulnerabilities = []
            
            for scanner_name, scanner in self.scanners.items():
                try:
                    if scanner_name == 'safety' and hasattr(scanner, 'scan_dependencies'):
                        vulns = scanner.scan_dependencies(dependencies)
                    elif scanner_name == 'pip-audit' and hasattr(scanner, 'scan_requirements_file'):
                        vulns = scanner.scan_requirements_file(requirements_file)
                    else:
                        continue
                    
                    all_vulnerabilities.extend(vulns)
                    logger.info(f"{scanner_name} found {len(vulns)} vulnerabilities")
                    
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    self.error_handler.handle_analysis_error(e, f"dependency_scan:{scanner_name}")
            
            # Deduplicate vulnerabilities
            deduplicated_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)
            
            # Filter by severity threshold
            filtered_vulns = self._filter_by_severity(deduplicated_vulns)
            
            # Cache results
            self.vuln_cache.cache_vulnerability_scan("file", cache_key, filtered_vulns)
            
            logger.info(f"Dependency scan completed for {requirements_file}: "
                       f"{len(filtered_vulns)} vulnerabilities found")
            
            return filtered_vulns
            
        except Exception as e:
            logger.error(f"Dependency scan failed for {requirements_file}: {e}")
            self.error_handler.handle_analysis_error(e, f"dependency_scan:{requirements_file}")
            return []
    
    def check_package_vulnerability(self, package: str, version: str) -> Optional[VulnerabilityReport]:
        """Check a specific package version for vulnerabilities."""
        # Check cache first
        cached_result = self.vuln_cache.get_vulnerability_scan(package, version)
        if cached_result:
            return cached_result[0] if cached_result else None
        
        try:
            # Create temporary dependency info
            temp_dep = DependencyInfo(
                name=package,
                version=version,
                file_path="<direct_check>",
                line_number=1,
                ecosystem="pip"
            )
            
            # Scan with available tools
            vulnerabilities = []
            
            for scanner_name, scanner in self.scanners.items():
                try:
                    if scanner_name == 'safety' and hasattr(scanner, 'scan_dependencies'):
                        vulns = scanner.scan_dependencies([temp_dep])
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    logger.warning(f"Scanner {scanner_name} failed for {package}:{version}: {e}")
            
            # Find vulnerability for this specific package
            package_vulns = [v for v in vulnerabilities if v.package_name.lower() == package.lower()]
            
            # Cache result
            self.vuln_cache.cache_vulnerability_scan(package, version, package_vulns)
            
            return package_vulns[0] if package_vulns else None
            
        except Exception as e:
            logger.error(f"Package vulnerability check failed for {package}:{version}: {e}")
            return None
    
    def _parse_dependency_file(self, file_path: str) -> List[DependencyInfo]:
        """Parse dependency file based on its type."""
        file_name = Path(file_path).name.lower()
        
        if file_name in ['requirements.txt', 'requirements-dev.txt']:
            return DependencyParser.parse_requirements_txt(file_path)
        elif file_name == 'package.json':
            return DependencyParser.parse_package_json(file_path)
        elif file_name == 'pyproject.toml':
            return DependencyParser.parse_pyproject_toml(file_path)
        else:
            logger.warning(f"Unsupported dependency file format: {file_name}")
            return []
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Remove duplicate vulnerabilities from multiple scanners."""
        seen = set()
        deduplicated = []
        
        for vuln in vulnerabilities:
            # Create key for deduplication
            key = (vuln.package_name.lower(), vuln.cve_id)
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(vuln)
            else:
                # Keep the vulnerability with more information
                existing = next(v for v in deduplicated if (v.package_name.lower(), v.cve_id) == key)
                if len(vuln.description) > len(existing.description):
                    deduplicated.remove(existing)
                    deduplicated.append(vuln)
        
        logger.debug(f"Deduplication reduced {len(vulnerabilities)} to {len(deduplicated)} vulnerabilities")
        return deduplicated
    
    def _filter_by_severity(self, vulnerabilities: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Filter vulnerabilities by severity threshold."""
        severity_thresholds = {
            Severity.LOW: 0.0,
            Severity.MEDIUM: 4.0,
            Severity.HIGH: 7.0,
            Severity.CRITICAL: 9.0
        }
        
        min_score = severity_thresholds.get(self.config.severity_threshold, 0.0)
        filtered = [v for v in vulnerabilities if v.severity_score >= min_score]
        
        logger.debug(f"Severity filtering reduced {len(vulnerabilities)} to {len(filtered)} vulnerabilities")
        return filtered
    
    def scan_project_dependencies(self, project_path: str) -> Dict[str, List[VulnerabilityReport]]:
        """Scan all dependency files in a project."""
        project_dir = Path(project_path)
        if not project_dir.exists():
            raise FileNotFoundError(f"Project directory not found: {project_path}")
        
        results = {}
        
        # Find all dependency files
        for file_pattern, ecosystem in self.config.dependency_files.items():
            for dep_file in project_dir.glob(file_pattern):
                if dep_file.is_file():
                    try:
                        vulnerabilities = self.scan_dependencies(str(dep_file))
                        if vulnerabilities:
                            results[str(dep_file)] = vulnerabilities
                    except Exception as e:
                        logger.error(f"Failed to scan {dep_file}: {e}")
        
        return results
    
    def generate_upgrade_recommendations(self, vulnerabilities: List[VulnerabilityReport]) -> List[str]:
        """Generate upgrade recommendations based on vulnerabilities."""
        recommendations = []
        
        # Group by package
        by_package = {}
        for vuln in vulnerabilities:
            package = vuln.package_name
            if package not in by_package:
                by_package[package] = []
            by_package[package].append(vuln)
        
        # Generate recommendations per package
        for package, package_vulns in by_package.items():
            # Find the best upgrade path
            upgrade_versions = set()
            for vuln in package_vulns:
                if vuln.upgrade_path:
                    upgrade_versions.add(vuln.upgrade_path)
            
            if upgrade_versions:
                # Recommend the highest version
                recommended_version = max(upgrade_versions)
                vuln_count = len(package_vulns)
                recommendations.append(
                    f"Upgrade {package} to {recommended_version} "
                    f"(fixes {vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'})"
                )
            else:
                # No upgrade path available
                critical_vulns = [v for v in package_vulns if v.severity_score >= 9.0]
                if critical_vulns:
                    recommendations.append(
                        f"⚠️  {package} has {len(critical_vulns)} critical vulnerabilities with no available fix"
                    )
        
        return recommendations
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get information about available scanners."""
        info = {
            "available_scanners": list(self.scanners.keys()),
            "supported_ecosystems": ["pip", "npm", "maven", "gradle", "gem", "composer", "go"],
            "supported_files": list(self.config.dependency_files.keys()),
            "configuration": {
                "severity_threshold": self.config.severity_threshold.value,
                "include_dev_dependencies": self.config.include_dev_dependencies,
                "timeout_seconds": self.config.timeout_seconds
            }
        }
        
        # Get version info for each scanner
        for scanner_name in self.scanners.keys():
            try:
                if scanner_name == 'safety':
                    result = subprocess.run(["safety", "--version"], capture_output=True, text=True, timeout=5)
                    info[f"{scanner_name}_version"] = result.stdout.strip() if result.returncode == 0 else "unknown"
                elif scanner_name == 'pip-audit':
                    result = subprocess.run(["pip-audit", "--version"], capture_output=True, text=True, timeout=5)
                    info[f"{scanner_name}_version"] = result.stdout.strip() if result.returncode == 0 else "unknown"
            except Exception:
                info[f"{scanner_name}_version"] = "unknown"
        
        return info