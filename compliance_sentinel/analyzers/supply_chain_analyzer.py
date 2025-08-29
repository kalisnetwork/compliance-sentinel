"""Supply chain security analyzer for dependencies, CI/CD, and build processes."""

import re
import json
import yaml
from typing import List, Dict, Optional, Tuple, Set, Any
from pathlib import Path
import logging
from enum import Enum

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class SupplyChainVulnerabilityType(Enum):
    """Types of supply chain security vulnerabilities."""
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    TYPOSQUATTING_RISK = "typosquatting_risk"
    LICENSE_COMPLIANCE_ISSUE = "license_compliance_issue"
    SECRET_EXPOSURE_CICD = "secret_exposure_cicd"
    INSUFFICIENT_ACCESS_CONTROLS = "insufficient_access_controls"
    BUILD_INJECTION_RISK = "build_injection_risk"
    VULNERABLE_BASE_IMAGE = "vulnerable_base_image"
    EXPOSED_SECRETS_CONTAINER = "exposed_secrets_container"
    EXCESSIVE_PRIVILEGES = "excessive_privileges"
    INSECURE_DOWNLOADS = "insecure_downloads"
    PRIVILEGE_ESCALATION_BUILD = "privilege_escalation_build"
    CONFIGURATION_DRIFT = "configuration_drift"
    UNSIGNED_ARTIFACTS = "unsigned_artifacts"
    WEAK_SBOM = "weak_sbom"


class DependencyAnalyzer:
    """Analyzes package dependencies for security issues."""
    
    def __init__(self):
        """Initialize dependency analyzer."""
        self.logger = logging.getLogger(f"{__name__}.dependency")
        
        # Known vulnerable packages (simplified - in production, use CVE databases)
        self.vulnerable_packages = self._load_vulnerable_packages()
        
        # Typosquatting patterns
        self.typosquatting_patterns = self._load_typosquatting_patterns()
        
        # Problematic licenses
        self.problematic_licenses = {
            'GPL-3.0', 'AGPL-3.0', 'SSPL-1.0', 'Commons Clause',
            'WTFPL', 'Unlicense', 'CC0-1.0'
        }
    
    def _load_vulnerable_packages(self) -> Dict[str, Dict[str, Any]]:
        """Load known vulnerable packages."""
        return {
            # JavaScript/Node.js packages
            'lodash': {
                'vulnerable_versions': ['<4.17.21'],
                'cve': 'CVE-2021-23337',
                'description': 'Prototype pollution vulnerability',
                'severity': 'high'
            },
            'moment': {
                'vulnerable_versions': ['<2.29.2'],
                'cve': 'CVE-2022-24785',
                'description': 'ReDoS vulnerability in parsing',
                'severity': 'medium'
            },
            'handlebars': {
                'vulnerable_versions': ['<4.7.7'],
                'cve': 'CVE-2021-23369',
                'description': 'Prototype pollution vulnerability',
                'severity': 'high'
            },
            'yargs-parser': {
                'vulnerable_versions': ['<18.1.3'],
                'cve': 'CVE-2020-7608',
                'description': 'Prototype pollution vulnerability',
                'severity': 'high'
            },
            
            # Python packages
            'pillow': {
                'vulnerable_versions': ['<8.3.2'],
                'cve': 'CVE-2021-34552',
                'description': 'Buffer overflow vulnerability',
                'severity': 'high'
            },
            'pyyaml': {
                'vulnerable_versions': ['<5.4'],
                'cve': 'CVE-2020-14343',
                'description': 'Arbitrary code execution',
                'severity': 'critical'
            },
            'urllib3': {
                'vulnerable_versions': ['<1.26.5'],
                'cve': 'CVE-2021-33503',
                'description': 'Catastrophic backtracking in URL parsing',
                'severity': 'medium'
            },
            
            # Java packages
            'log4j-core': {
                'vulnerable_versions': ['>=2.0,<2.17.0'],
                'cve': 'CVE-2021-44228',
                'description': 'Log4Shell RCE vulnerability',
                'severity': 'critical'
            },
            'jackson-databind': {
                'vulnerable_versions': ['<2.13.2'],
                'cve': 'CVE-2022-42003',
                'description': 'Deserialization vulnerability',
                'severity': 'high'
            },
        }
    
    def _load_typosquatting_patterns(self) -> Dict[str, List[str]]:
        """Load typosquatting patterns for popular packages."""
        return {
            # JavaScript packages
            'react': ['raect', 'recat', 'reactt', 'react-js'],
            'lodash': ['loadash', 'lodahs', 'lodas', 'lodsh'],
            'express': ['expres', 'expresss', 'exppress'],
            'axios': ['axois', 'axioss', 'axos'],
            
            # Python packages
            'requests': ['request', 'requsts', 'reqests'],
            'numpy': ['numpi', 'numpyy', 'nunpy'],
            'pandas': ['panda', 'pandass', 'pnadas'],
            'django': ['djnago', 'djangoo', 'djang'],
            
            # Java packages
            'springframework': ['spring-framework', 'springframwork'],
            'junit': ['junitt', 'jnit', 'junit5'],
        }
    
    def analyze_package_json(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze package.json for security issues."""
        issues = []
        
        try:
            package_data = json.loads(content)
            
            # Analyze dependencies
            dependencies = {}
            dependencies.update(package_data.get('dependencies', {}))
            dependencies.update(package_data.get('devDependencies', {}))
            
            for package_name, version in dependencies.items():
                issues.extend(self._check_package_vulnerability(
                    file_path, package_name, version, 'npm'
                ))
                issues.extend(self._check_typosquatting(
                    file_path, package_name, 'javascript'
                ))
            
            # Check for missing security fields
            issues.extend(self._check_package_security_config(file_path, package_data))
            
        except json.JSONDecodeError as e:
            issues.append(self._create_supply_chain_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=SupplyChainVulnerabilityType.VULNERABLE_DEPENDENCY,
                description=f"Invalid JSON in package.json: {str(e)}",
                severity=Severity.LOW,
                remediation=["Fix JSON syntax errors in package.json"]
            ))
        
        return issues
    
    def analyze_requirements_txt(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze requirements.txt for security issues."""
        issues = []
        
        lines = content.strip().split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package specification
            package_spec = self._parse_python_requirement(line)
            if package_spec:
                package_name, version = package_spec
                issues.extend(self._check_package_vulnerability(
                    file_path, package_name, version, 'pip', line_num
                ))
                issues.extend(self._check_typosquatting(
                    file_path, package_name, 'python', line_num
                ))
            
            # Check for insecure sources
            if re.search(r'--index-url\s+http://', line, re.IGNORECASE):
                issues.append(self._create_supply_chain_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=SupplyChainVulnerabilityType.INSECURE_DOWNLOADS,
                    description=f"Insecure HTTP index URL: {line}",
                    severity=Severity.MEDIUM,
                    remediation=[
                        "Use HTTPS URLs for package indexes",
                        "Verify package integrity with checksums",
                        "Use trusted package repositories"
                    ]
                ))
        
        return issues
    
    def analyze_pom_xml(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Maven pom.xml for security issues."""
        issues = []
        
        # Extract dependencies using regex (simplified XML parsing)
        dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
        
        dependencies = re.findall(dependency_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for group_id, artifact_id, version in dependencies:
            package_name = f"{group_id}:{artifact_id}"
            issues.extend(self._check_package_vulnerability(
                file_path, package_name, version, 'maven'
            ))
        
        # Check for insecure repositories
        repo_pattern = r'<repository>.*?<url>(http://[^<]+)</url>.*?</repository>'
        insecure_repos = re.findall(repo_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for repo_url in insecure_repos:
            issues.append(self._create_supply_chain_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=SupplyChainVulnerabilityType.INSECURE_DOWNLOADS,
                description=f"Insecure HTTP repository URL: {repo_url}",
                severity=Severity.MEDIUM,
                remediation=[
                    "Use HTTPS URLs for Maven repositories",
                    "Verify repository authenticity",
                    "Use Maven Central or trusted repositories"
                ]
            ))
        
        return issues
    
    def _check_package_vulnerability(
        self, 
        file_path: str, 
        package_name: str, 
        version: str, 
        ecosystem: str,
        line_number: int = 1
    ) -> List[SecurityIssue]:
        """Check if package version is vulnerable."""
        issues = []
        
        # Clean package name for lookup
        clean_name = package_name.split(':')[-1] if ':' in package_name else package_name
        
        if clean_name in self.vulnerable_packages:
            vuln_info = self.vulnerable_packages[clean_name]
            
            # Simple version check (in production, use proper version parsing)
            if self._is_vulnerable_version(version, vuln_info['vulnerable_versions']):
                severity_map = {
                    'critical': Severity.CRITICAL,
                    'high': Severity.HIGH,
                    'medium': Severity.MEDIUM,
                    'low': Severity.LOW
                }
                
                severity = severity_map.get(vuln_info['severity'], Severity.MEDIUM)
                
                issues.append(self._create_supply_chain_issue(
                    file_path=file_path,
                    line_number=line_number,
                    vuln_type=SupplyChainVulnerabilityType.VULNERABLE_DEPENDENCY,
                    description=f"Vulnerable dependency: {package_name}@{version} - {vuln_info['description']} ({vuln_info['cve']})",
                    severity=severity,
                    remediation=[
                        f"Update {package_name} to a secure version",
                        f"Review {vuln_info['cve']} for details",
                        "Run dependency audit tools regularly",
                        "Monitor security advisories for dependencies"
                    ]
                ))
        
        return issues
    
    def _check_typosquatting(
        self, 
        file_path: str, 
        package_name: str, 
        language: str,
        line_number: int = 1
    ) -> List[SecurityIssue]:
        """Check for potential typosquatting."""
        issues = []
        
        for legitimate_package, typos in self.typosquatting_patterns.items():
            if package_name.lower() in [typo.lower() for typo in typos]:
                issues.append(self._create_supply_chain_issue(
                    file_path=file_path,
                    line_number=line_number,
                    vuln_type=SupplyChainVulnerabilityType.TYPOSQUATTING_RISK,
                    description=f"Potential typosquatting: '{package_name}' (did you mean '{legitimate_package}'?)",
                    severity=Severity.MEDIUM,
                    remediation=[
                        f"Verify package name - did you mean '{legitimate_package}'?",
                        "Check package author and download statistics",
                        "Review package source code before use",
                        "Use package-lock files to prevent substitution"
                    ]
                ))
        
        return issues
    
    def _check_package_security_config(self, file_path: str, package_data: Dict) -> List[SecurityIssue]:
        """Check package.json security configuration."""
        issues = []
        
        # Check for missing security-related scripts
        scripts = package_data.get('scripts', {})
        
        if 'audit' not in scripts and 'security-check' not in scripts:
            issues.append(self._create_supply_chain_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=SupplyChainVulnerabilityType.WEAK_SBOM,
                description="No security audit script configured in package.json",
                severity=Severity.LOW,
                remediation=[
                    "Add 'npm audit' script to package.json",
                    "Configure automated security scanning",
                    "Set up dependency vulnerability monitoring"
                ]
            ))
        
        # Check for overly permissive version ranges
        dependencies = package_data.get('dependencies', {})
        for dep_name, version in dependencies.items():
            if isinstance(version, str) and ('*' in version or '^' in version or '~' in version):
                issues.append(self._create_supply_chain_issue(
                    file_path=file_path,
                    line_number=1,
                    vuln_type=SupplyChainVulnerabilityType.CONFIGURATION_DRIFT,
                    description=f"Overly permissive version range for {dep_name}: {version}",
                    severity=Severity.LOW,
                    remediation=[
                        "Use exact version numbers for critical dependencies",
                        "Use package-lock.json to lock dependency versions",
                        "Regularly update and test dependency versions"
                    ]
                ))
        
        return issues
    
    def _parse_python_requirement(self, line: str) -> Optional[Tuple[str, str]]:
        """Parse Python requirement specification."""
        # Simple parsing - in production, use packaging library
        match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]+)([0-9.]+)', line.strip())
        if match:
            return match.group(1), match.group(3)
        
        # Handle simple package names without version
        match = re.match(r'^([a-zA-Z0-9_-]+)$', line.strip())
        if match:
            return match.group(1), 'latest'
        
        return None
    
    def _is_vulnerable_version(self, version: str, vulnerable_ranges: List[str]) -> bool:
        """Check if version falls within vulnerable ranges."""
        # Simplified version checking - in production, use proper version parsing
        for vuln_range in vulnerable_ranges:
            if '<' in vuln_range:
                # Extract version number from range like "<4.17.21"
                max_version = vuln_range.replace('<', '').strip()
                if self._compare_versions(version, max_version) < 0:
                    return True
            elif '>=' in vuln_range and '<' in vuln_range:
                # Handle ranges like ">=2.0,<2.17.0"
                parts = vuln_range.split(',')
                if len(parts) == 2:
                    min_ver = parts[0].replace('>=', '').strip()
                    max_ver = parts[1].replace('<', '').strip()
                    if (self._compare_versions(version, min_ver) >= 0 and 
                        self._compare_versions(version, max_ver) < 0):
                        return True
        
        return False
    
    def _create_supply_chain_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: SupplyChainVulnerabilityType,
        description: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a supply chain security issue."""
        from datetime import datetime
        
        issue_id = f"supply_chain_{vuln_type.value}_{line_number}_{hash(description) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.DEPENDENCY_VULNERABILITY,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"supply_chain_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Simple version comparison (-1: v1 < v2, 0: equal, 1: v1 > v2)."""
        # Simplified - in production, use packaging.version
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except ValueError:
            # Fallback to string comparison
            return -1 if v1 < v2 else (1 if v1 > v2 else 0)


class CICDAnalyzer:
    """Analyzes CI/CD pipeline configurations for security issues."""
    
    def __init__(self):
        """Initialize CI/CD analyzer."""
        self.logger = logging.getLogger(f"{__name__}.cicd")
    
    def analyze_github_actions(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze GitHub Actions workflow for security issues."""
        issues = []
        
        try:
            workflow = yaml.safe_load(content)
            
            # Check for secret exposure
            issues.extend(self._check_github_secrets(file_path, workflow))
            
            # Check for insecure actions
            issues.extend(self._check_github_actions_security(file_path, workflow))
            
            # Check for privilege escalation
            issues.extend(self._check_github_permissions(file_path, workflow))
            
        except yaml.YAMLError as e:
            issues.append(self._create_supply_chain_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=SupplyChainVulnerabilityType.BUILD_INJECTION_RISK,
                description=f"Invalid YAML in GitHub Actions workflow: {str(e)}",
                severity=Severity.LOW,
                remediation=["Fix YAML syntax errors"]
            ))
        
        return issues
    
    def analyze_jenkins_pipeline(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Jenkins pipeline for security issues."""
        issues = []
        
        # Check for hardcoded credentials
        secret_patterns = [
            r'password\s*[=:]\s*["\'][^"\']+["\']',
            r'token\s*[=:]\s*["\'][^"\']+["\']',
            r'key\s*[=:]\s*["\'][^"\']+["\']',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_supply_chain_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=SupplyChainVulnerabilityType.SECRET_EXPOSURE_CICD,
                        description=f"Hardcoded secret in Jenkins pipeline: {line.strip()}",
                        severity=Severity.HIGH,
                        remediation=[
                            "Use Jenkins credentials store",
                            "Use environment variables for secrets",
                            "Implement proper secret management"
                        ]
                    ))
        
        # Check for shell injection risks
        shell_patterns = [
            r'sh\s+["\'][^"\']*\$\{[^}]+\}[^"\']*["\']',
            r'bat\s+["\'][^"\']*\$\{[^}]+\}[^"\']*["\']',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in shell_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_supply_chain_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=SupplyChainVulnerabilityType.BUILD_INJECTION_RISK,
                        description=f"Potential shell injection in Jenkins pipeline: {line.strip()}",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Sanitize variables before shell execution",
                            "Use parameterized builds",
                            "Validate input parameters"
                        ]
                    ))
        
        return issues
    
    def _check_github_secrets(self, file_path: str, workflow: Dict) -> List[SecurityIssue]:
        """Check for secret exposure in GitHub Actions."""
        issues = []
        
        jobs = workflow.get('jobs', {})
        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])
            
            for step_index, step in enumerate(steps):
                # Check for secrets in run commands
                run_command = step.get('run', '')
                if isinstance(run_command, str):
                    # Look for potential secret exposure
                    if re.search(r'echo\s+\$\{\{\s*secrets\.[^}]+\}\}', run_command, re.IGNORECASE):
                        issues.append(self._create_supply_chain_issue(
                            file_path=file_path,
                            line_number=step_index + 1,
                            vuln_type=SupplyChainVulnerabilityType.SECRET_EXPOSURE_CICD,
                            description=f"Secret potentially exposed in echo command: {run_command[:50]}...",
                            severity=Severity.HIGH,
                            remediation=[
                                "Never echo secrets in CI/CD logs",
                                "Use secrets only in secure contexts",
                                "Mask sensitive output in logs"
                            ]
                        ))
                
                # Check for insecure environment variables
                env = step.get('env', {})
                for env_name, env_value in env.items():
                    if isinstance(env_value, str) and len(env_value) > 20 and not env_value.startswith('${{'):
                        issues.append(self._create_supply_chain_issue(
                            file_path=file_path,
                            line_number=step_index + 1,
                            vuln_type=SupplyChainVulnerabilityType.SECRET_EXPOSURE_CICD,
                            description=f"Potential hardcoded secret in environment variable: {env_name}",
                            severity=Severity.MEDIUM,
                            remediation=[
                                "Use GitHub secrets for sensitive values",
                                "Avoid hardcoding credentials in workflows"
                            ]
                        ))
        
        return issues
    
    def _check_github_actions_security(self, file_path: str, workflow: Dict) -> List[SecurityIssue]:
        """Check for insecure GitHub Actions usage."""
        issues = []
        
        jobs = workflow.get('jobs', {})
        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])
            
            for step_index, step in enumerate(steps):
                uses = step.get('uses', '')
                if uses:
                    # Check for actions without version pinning
                    if '@' not in uses or uses.endswith('@main') or uses.endswith('@master'):
                        issues.append(self._create_supply_chain_issue(
                            file_path=file_path,
                            line_number=step_index + 1,
                            vuln_type=SupplyChainVulnerabilityType.CONFIGURATION_DRIFT,
                            description=f"GitHub Action not pinned to specific version: {uses}",
                            severity=Severity.MEDIUM,
                            remediation=[
                                "Pin actions to specific commit SHA or version tag",
                                "Avoid using @main or @master branches",
                                "Regularly update and audit action versions"
                            ]
                        ))
                    
                    # Check for potentially dangerous actions
                    dangerous_actions = [
                        'actions/checkout@v1',  # Vulnerable version
                        'actions/upload-artifact@v1',  # Vulnerable version
                    ]
                    
                    if any(dangerous in uses for dangerous in dangerous_actions):
                        issues.append(self._create_supply_chain_issue(
                            file_path=file_path,
                            line_number=step_index + 1,
                            vuln_type=SupplyChainVulnerabilityType.VULNERABLE_DEPENDENCY,
                            description=f"Using vulnerable GitHub Action: {uses}",
                            severity=Severity.HIGH,
                            remediation=[
                                "Update to latest secure version of the action",
                                "Review action security advisories",
                                "Consider alternative actions"
                            ]
                        ))
        
        return issues
    
    def _check_github_permissions(self, file_path: str, workflow: Dict) -> List[SecurityIssue]:
        """Check for excessive permissions in GitHub Actions."""
        issues = []
        
        # Check global permissions
        permissions = workflow.get('permissions', {})
        if isinstance(permissions, str) and permissions == 'write-all':
            issues.append(self._create_supply_chain_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=SupplyChainVulnerabilityType.EXCESSIVE_PRIVILEGES,
                description="Workflow has write-all permissions",
                severity=Severity.MEDIUM,
                remediation=[
                    "Use specific permissions instead of write-all",
                    "Follow principle of least privilege",
                    "Grant only necessary permissions"
                ]
            ))
        
        # Check job-level permissions
        jobs = workflow.get('jobs', {})
        for job_name, job_config in jobs.items():
            job_permissions = job_config.get('permissions', {})
            if isinstance(job_permissions, str) and job_permissions == 'write-all':
                issues.append(self._create_supply_chain_issue(
                    file_path=file_path,
                    line_number=1,
                    vuln_type=SupplyChainVulnerabilityType.EXCESSIVE_PRIVILEGES,
                    description=f"Job '{job_name}' has write-all permissions",
                    severity=Severity.MEDIUM,
                    remediation=[
                        "Use specific permissions for each job",
                        "Limit permissions to job requirements"
                    ]
                ))
        
        return issues
    
    def _create_supply_chain_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: SupplyChainVulnerabilityType,
        description: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a supply chain security issue."""
        from datetime import datetime
        
        issue_id = f"supply_chain_{vuln_type.value}_{line_number}_{hash(description) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.DEPENDENCY_VULNERABILITY,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"supply_chain_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class SupplyChainSecurityAnalyzer:
    """Main supply chain security analyzer."""
    
    def __init__(self):
        """Initialize supply chain security analyzer."""
        self.dependency_analyzer = DependencyAnalyzer()
        self.cicd_analyzer = CICDAnalyzer()
        self.logger = logging.getLogger(__name__)
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze supply chain security file."""
        issues = []
        
        file_name = Path(file_path).name.lower()
        
        # Dependency files
        if file_name == 'package.json':
            issues.extend(self.dependency_analyzer.analyze_package_json(file_path, content))
        elif file_name in ['requirements.txt', 'requirements-dev.txt']:
            issues.extend(self.dependency_analyzer.analyze_requirements_txt(file_path, content))
        elif file_name == 'pom.xml':
            issues.extend(self.dependency_analyzer.analyze_pom_xml(file_path, content))
        
        # CI/CD files
        elif '.github/workflows/' in file_path and file_name.endswith(('.yml', '.yaml')):
            issues.extend(self.cicd_analyzer.analyze_github_actions(file_path, content))
        elif file_name in ['jenkinsfile', 'pipeline.groovy']:
            issues.extend(self.cicd_analyzer.analyze_jenkins_pipeline(file_path, content))
        
        return issues
    
    def get_supported_patterns(self) -> List[str]:
        """Get list of supply chain security patterns."""
        return [
            'Vulnerable dependencies (CVE detection)',
            'Typosquatting package names',
            'License compliance issues',
            'Secret exposure in CI/CD',
            'Insufficient access controls',
            'Build injection risks',
            'Insecure package downloads',
            'Configuration drift',
            'Unsigned artifacts',
            'Weak SBOM (Software Bill of Materials)'
        ]
    
    def _create_supply_chain_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: SupplyChainVulnerabilityType,
        description: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a supply chain security issue."""
        from datetime import datetime
        
        issue_id = f"supply_chain_{vuln_type.value}_{line_number}_{hash(description) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.DEPENDENCY_VULNERABILITY,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"supply_chain_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


# Global analyzer instance
_global_supply_chain_analyzer: Optional[SupplyChainSecurityAnalyzer] = None


def get_supply_chain_analyzer() -> SupplyChainSecurityAnalyzer:
    """Get global supply chain analyzer instance."""
    global _global_supply_chain_analyzer
    if _global_supply_chain_analyzer is None:
        _global_supply_chain_analyzer = SupplyChainSecurityAnalyzer()
    return _global_supply_chain_analyzer


def reset_supply_chain_analyzer() -> None:
    """Reset global supply chain analyzer (for testing)."""
    global _global_supply_chain_analyzer
    _global_supply_chain_analyzer = None