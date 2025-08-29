"""Cloud security analyzer for infrastructure-as-code."""

import re
import json
import yaml
from typing import List, Dict, Optional, Tuple, Set, Any
from pathlib import Path
import logging
from enum import Enum

from compliance_sentinel.core.interfaces import SecurityIssue, SecurityCategory, Severity


logger = logging.getLogger(__name__)


class CloudPlatform(Enum):
    """Supported cloud platforms."""
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    AWS_CLOUDFORMATION = "aws_cloudformation"
    AZURE_ARM = "azure_arm"
    GOOGLE_DEPLOYMENT_MANAGER = "google_deployment_manager"


class CloudVulnerabilityType(Enum):
    """Types of cloud security vulnerabilities."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SECRET_EXPOSURE = "secret_exposure"
    INSECURE_BASE_IMAGE = "insecure_base_image"
    NETWORK_MISCONFIGURATION = "network_misconfiguration"
    MISSING_ENCRYPTION = "missing_encryption"
    OVERLY_PERMISSIVE_IAM = "overly_permissive_iam"
    EXPOSED_PORTS = "exposed_ports"
    VOLUME_MOUNT_VULNERABILITY = "volume_mount_vulnerability"
    INSECURE_DEFAULTS = "insecure_defaults"
    MISSING_SECURITY_CONTEXT = "missing_security_context"


class DockerfileAnalyzer:
    """Analyzes Dockerfile for security issues."""
    
    def __init__(self):
        """Initialize Dockerfile analyzer."""
        self.logger = logging.getLogger(f"{__name__}.dockerfile")
        
        # Insecure base images
        self.insecure_base_images = {
            'ubuntu:latest', 'debian:latest', 'centos:latest', 'alpine:latest',
            'node:latest', 'python:latest', 'java:latest', 'nginx:latest'
        }
        
        # Vulnerable base image patterns
        self.vulnerable_patterns = [
            r'FROM\s+ubuntu:(?:14\.04|16\.04|18\.04)(?:\s|$)',  # EOL versions
            r'FROM\s+centos:[1-6](?:\s|$)',  # EOL versions
            r'FROM\s+debian:[1-8](?:\s|$)',  # EOL versions
        ]
    
    def analyze(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Dockerfile for security issues."""
        issues = []
        
        issues.extend(self._check_base_image_security(file_path, content))
        issues.extend(self._check_privilege_escalation(file_path, content))
        issues.extend(self._check_secret_exposure(file_path, content))
        issues.extend(self._check_user_configuration(file_path, content))
        issues.extend(self._check_exposed_ports(file_path, content))
        issues.extend(self._check_package_management(file_path, content))
        issues.extend(self._check_file_permissions(file_path, content))
        
        return issues
    
    def _check_base_image_security(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for insecure base images."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for latest tags
            if re.match(r'FROM\s+\w+:latest', line, re.IGNORECASE):
                base_image = re.search(r'FROM\s+(\S+)', line, re.IGNORECASE).group(1)
                if base_image.lower() in [img.lower() for img in self.insecure_base_images]:
                    issues.append(self._create_docker_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CloudVulnerabilityType.INSECURE_BASE_IMAGE,
                        description=f"Using 'latest' tag for base image: {base_image}",
                        match=line,
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Use specific version tags instead of 'latest'",
                            "Pin to specific, secure versions",
                            "Regularly update to latest secure versions",
                            "Use minimal base images like Alpine when possible"
                        ]
                    ))
            
            # Check for vulnerable versions
            for pattern in self.vulnerable_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_docker_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CloudVulnerabilityType.INSECURE_BASE_IMAGE,
                        description=f"Using vulnerable/EOL base image: {line}",
                        match=line,
                        severity=Severity.HIGH,
                        remediation=[
                            "Update to supported, non-EOL base image versions",
                            "Use security-focused base images",
                            "Regularly scan base images for vulnerabilities"
                        ]
                    ))
        
        return issues
    
    def _check_privilege_escalation(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for privilege escalation risks."""
        issues = []
        lines = content.split('\n')
        
        running_as_root = True  # Default assumption
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for USER directive
            if re.match(r'USER\s+', line, re.IGNORECASE):
                user = re.search(r'USER\s+(\S+)', line, re.IGNORECASE).group(1)
                if user.lower() in ['root', '0']:
                    issues.append(self._create_docker_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                        description=f"Explicitly running as root user: {line}",
                        match=line,
                        severity=Severity.HIGH,
                        remediation=[
                            "Create and use a non-root user",
                            "Use USER directive with non-privileged user",
                            "Follow principle of least privilege"
                        ]
                    ))
                else:
                    running_as_root = False
            
            # Check for sudo usage
            if re.search(r'(sudo|su\s)', line, re.IGNORECASE):
                issues.append(self._create_docker_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                    description=f"Using sudo/su in container: {line}",
                    match=line,
                    severity=Severity.MEDIUM,
                    remediation=[
                        "Avoid sudo/su in containers",
                        "Use multi-stage builds for privilege separation",
                        "Install packages in earlier build stages"
                    ]
                ))
        
        # Check if no USER directive found (running as root by default)
        if running_as_root and not any('USER' in line.upper() for line in lines):
            issues.append(self._create_docker_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                description="No USER directive found - container runs as root by default",
                match="",
                severity=Severity.MEDIUM,
                remediation=[
                    "Add USER directive with non-root user",
                    "Create dedicated user for application",
                    "Use --user flag when running container"
                ]
            ))
        
        return issues
    
    def _check_secret_exposure(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for exposed secrets in Dockerfile."""
        issues = []
        lines = content.split('\n')
        
        secret_patterns = [
            r'(password|pwd|secret|key|token)\s*[=:]\s*["\'][^"\']{3,}["\']',
            r'ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\s*[=\s]\s*["\']?[^"\'\s]{3,}',
            r'ARG\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\s*[=\s]\s*["\']?[^"\'\s]{3,}',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_docker_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CloudVulnerabilityType.SECRET_EXPOSURE,
                        description=f"Potential secret exposed in Dockerfile: {line[:50]}...",
                        match=line,
                        severity=Severity.HIGH,
                        remediation=[
                            "Use Docker secrets or external secret management",
                            "Pass secrets via environment variables at runtime",
                            "Use multi-stage builds to avoid secret persistence",
                            "Never hardcode secrets in Dockerfile"
                        ]
                    ))
        
        return issues
    
    def _check_user_configuration(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check user configuration security."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for insecure user creation
            if re.search(r'useradd.*--uid\s+0', line, re.IGNORECASE):
                issues.append(self._create_docker_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                    description=f"Creating user with UID 0 (root): {line}",
                    match=line,
                    severity=Severity.HIGH,
                    remediation=[
                        "Use non-zero UID for application user",
                        "Avoid creating users with root privileges"
                    ]
                ))
        
        return issues
    
    def _check_exposed_ports(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check for exposed ports security."""
        issues = []
        lines = content.split('\n')
        
        dangerous_ports = {
            '22': 'SSH',
            '23': 'Telnet',
            '21': 'FTP',
            '3389': 'RDP',
            '5432': 'PostgreSQL',
            '3306': 'MySQL',
            '27017': 'MongoDB',
            '6379': 'Redis'
        }
        
        for line_num, line in enumerate(lines, 1):
            if re.match(r'EXPOSE\s+', line, re.IGNORECASE):
                ports = re.findall(r'\d+', line)
                for port in ports:
                    if port in dangerous_ports:
                        service = dangerous_ports[port]
                        issues.append(self._create_docker_issue(
                            file_path=file_path,
                            line_number=line_num,
                            vuln_type=CloudVulnerabilityType.EXPOSED_PORTS,
                            description=f"Exposing potentially dangerous port {port} ({service}): {line}",
                            match=line,
                            severity=Severity.MEDIUM,
                            remediation=[
                                f"Avoid exposing {service} port {port} directly",
                                "Use reverse proxy or load balancer",
                                "Implement proper authentication and encryption",
                                "Consider using non-standard ports"
                            ]
                        ))
        
        return issues
    
    def _check_package_management(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check package management security."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for missing package cache cleanup
            if re.search(r'(apt-get|yum|apk)\s+install', line, re.IGNORECASE):
                # Look for cleanup in same line or next few lines
                cleanup_found = False
                for check_line in lines[line_num-1:min(line_num+3, len(lines))]:
                    if re.search(r'(rm\s+-rf\s+/var/lib/apt/lists|yum\s+clean|apk\s+del)', check_line, re.IGNORECASE):
                        cleanup_found = True
                        break
                
                if not cleanup_found:
                    issues.append(self._create_docker_issue(
                        file_path=file_path,
                        line_number=line_num,
                        vuln_type=CloudVulnerabilityType.INSECURE_DEFAULTS,
                        description=f"Package installation without cache cleanup: {line}",
                        match=line,
                        severity=Severity.LOW,
                        remediation=[
                            "Clean package manager cache after installation",
                            "Use && to chain commands in single RUN directive",
                            "Remove unnecessary files to reduce image size"
                        ]
                    ))
        
        return issues
    
    def _check_file_permissions(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Check file permission security."""
        issues = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for overly permissive file permissions
            if re.search(r'chmod\s+[0-9]*[7][7][7]', line):
                issues.append(self._create_docker_issue(
                    file_path=file_path,
                    line_number=line_num,
                    vuln_type=CloudVulnerabilityType.INSECURE_DEFAULTS,
                    description=f"Overly permissive file permissions (777): {line}",
                    match=line,
                    severity=Severity.MEDIUM,
                    remediation=[
                        "Use least privilege file permissions",
                        "Avoid 777 permissions",
                        "Set specific permissions based on requirements"
                    ]
                ))
        
        return issues
    
    def _create_docker_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: CloudVulnerabilityType,
        description: str,
        match: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a Docker security issue."""
        from datetime import datetime
        
        issue_id = f"docker_{vuln_type.value}_{line_number}_{hash(match) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,  # Cloud security category
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"docker_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class KubernetesAnalyzer:
    """Analyzes Kubernetes manifests for security issues."""
    
    def __init__(self):
        """Initialize Kubernetes analyzer."""
        self.logger = logging.getLogger(f"{__name__}.kubernetes")
    
    def analyze(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Kubernetes manifest for security issues."""
        issues = []
        
        try:
            # Parse YAML content
            docs = list(yaml.safe_load_all(content))
            
            for doc_index, doc in enumerate(docs):
                if not doc or not isinstance(doc, dict):
                    continue
                
                issues.extend(self._check_security_context(file_path, doc, doc_index))
                issues.extend(self._check_network_policies(file_path, doc, doc_index))
                issues.extend(self._check_rbac_configuration(file_path, doc, doc_index))
                issues.extend(self._check_resource_limits(file_path, doc, doc_index))
                issues.extend(self._check_secrets_management(file_path, doc, doc_index))
        
        except yaml.YAMLError as e:
            issues.append(self._create_k8s_issue(
                file_path=file_path,
                line_number=1,
                vuln_type=CloudVulnerabilityType.INSECURE_DEFAULTS,
                description=f"Invalid YAML syntax: {str(e)}",
                severity=Severity.LOW,
                remediation=["Fix YAML syntax errors"]
            ))
        
        return issues
    
    def _check_security_context(self, file_path: str, doc: Dict, doc_index: int) -> List[SecurityIssue]:
        """Check security context configuration."""
        issues = []
        
        if doc.get('kind') in ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet']:
            spec = doc.get('spec', {})
            
            # For Deployment/StatefulSet, check template spec
            if 'template' in spec:
                spec = spec['template'].get('spec', {})
            
            security_context = spec.get('securityContext', {})
            
            # Check if running as root
            if security_context.get('runAsUser') == 0:
                issues.append(self._create_k8s_issue(
                    file_path=file_path,
                    line_number=doc_index + 1,
                    vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                    description="Pod configured to run as root user (runAsUser: 0)",
                    severity=Severity.HIGH,
                    remediation=[
                        "Set runAsUser to non-zero value",
                        "Use runAsNonRoot: true",
                        "Follow principle of least privilege"
                    ]
                ))
            
            # Check for privileged containers
            containers = spec.get('containers', [])
            for container in containers:
                container_security = container.get('securityContext', {})
                if container_security.get('privileged'):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                        description=f"Container '{container.get('name', 'unknown')}' runs in privileged mode",
                        severity=Severity.CRITICAL,
                        remediation=[
                            "Remove privileged: true",
                            "Use specific capabilities instead",
                            "Implement proper security context"
                        ]
                    ))
                
                # Check for allowPrivilegeEscalation
                if container_security.get('allowPrivilegeEscalation', True):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.PRIVILEGE_ESCALATION,
                        description=f"Container '{container.get('name', 'unknown')}' allows privilege escalation",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Set allowPrivilegeEscalation: false",
                            "Implement proper security controls"
                        ]
                    ))
        
        return issues
    
    def _check_network_policies(self, file_path: str, doc: Dict, doc_index: int) -> List[SecurityIssue]:
        """Check network policy configuration."""
        issues = []
        
        if doc.get('kind') == 'NetworkPolicy':
            spec = doc.get('spec', {})
            
            # Check for overly permissive policies
            ingress = spec.get('ingress', [])
            egress = spec.get('egress', [])
            
            for rule in ingress:
                if not rule.get('from'):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.NETWORK_MISCONFIGURATION,
                        description="NetworkPolicy ingress rule allows traffic from all sources",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Specify explicit source selectors",
                            "Use namespaceSelector or podSelector",
                            "Implement least privilege network access"
                        ]
                    ))
            
            for rule in egress:
                if not rule.get('to'):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.NETWORK_MISCONFIGURATION,
                        description="NetworkPolicy egress rule allows traffic to all destinations",
                        severity=Severity.MEDIUM,
                        remediation=[
                            "Specify explicit destination selectors",
                            "Limit egress to required services only",
                            "Implement network segmentation"
                        ]
                    ))
        
        return issues
    
    def _check_rbac_configuration(self, file_path: str, doc: Dict, doc_index: int) -> List[SecurityIssue]:
        """Check RBAC configuration."""
        issues = []
        
        if doc.get('kind') == 'ClusterRole':
            rules = doc.get('rules', [])
            
            for rule in rules:
                # Check for wildcard permissions
                if '*' in rule.get('resources', []) or '*' in rule.get('verbs', []):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.OVERLY_PERMISSIVE_IAM,
                        description="ClusterRole grants wildcard permissions (*)",
                        severity=Severity.HIGH,
                        remediation=[
                            "Use specific resource names and verbs",
                            "Follow principle of least privilege",
                            "Avoid wildcard permissions"
                        ]
                    ))
                
                # Check for dangerous permissions
                dangerous_verbs = ['*', 'create', 'delete', 'deletecollection']
                dangerous_resources = ['secrets', 'configmaps', 'pods/exec']
                
                if any(verb in dangerous_verbs for verb in rule.get('verbs', [])) and \
                   any(resource in dangerous_resources for resource in rule.get('resources', [])):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.OVERLY_PERMISSIVE_IAM,
                        description="ClusterRole grants dangerous permissions on sensitive resources",
                        severity=Severity.HIGH,
                        remediation=[
                            "Limit permissions to specific use cases",
                            "Use Role instead of ClusterRole when possible",
                            "Regular audit of RBAC permissions"
                        ]
                    ))
        
        return issues
    
    def _check_resource_limits(self, file_path: str, doc: Dict, doc_index: int) -> List[SecurityIssue]:
        """Check resource limits configuration."""
        issues = []
        
        if doc.get('kind') in ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet']:
            spec = doc.get('spec', {})
            
            # For Deployment/StatefulSet, check template spec
            if 'template' in spec:
                spec = spec['template'].get('spec', {})
            
            containers = spec.get('containers', [])
            
            for container in containers:
                resources = container.get('resources', {})
                
                # Check for missing resource limits
                if not resources.get('limits'):
                    issues.append(self._create_k8s_issue(
                        file_path=file_path,
                        line_number=doc_index + 1,
                        vuln_type=CloudVulnerabilityType.INSECURE_DEFAULTS,
                        description=f"Container '{container.get('name', 'unknown')}' has no resource limits",
                        severity=Severity.LOW,
                        remediation=[
                            "Set CPU and memory limits",
                            "Prevent resource exhaustion attacks",
                            "Use ResourceQuota for namespace limits"
                        ]
                    ))
        
        return issues
    
    def _check_secrets_management(self, file_path: str, doc: Dict, doc_index: int) -> List[SecurityIssue]:
        """Check secrets management."""
        issues = []
        
        if doc.get('kind') == 'Secret':
            data = doc.get('data', {})
            
            # Check for base64-encoded secrets that might be weak
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 0:
                    try:
                        import base64
                        decoded = base64.b64decode(value).decode('utf-8')
                        
                        # Check for common weak secrets
                        if decoded.lower() in ['password', 'secret', '123456', 'admin']:
                            issues.append(self._create_k8s_issue(
                                file_path=file_path,
                                line_number=doc_index + 1,
                                vuln_type=CloudVulnerabilityType.SECRET_EXPOSURE,
                                description=f"Secret '{key}' contains weak/default value",
                                severity=Severity.MEDIUM,
                                remediation=[
                                    "Use strong, randomly generated secrets",
                                    "Rotate secrets regularly",
                                    "Use external secret management systems"
                                ]
                            ))
                    except:
                        pass  # Invalid base64, skip
        
        return issues
    
    def _create_k8s_issue(
        self,
        file_path: str,
        line_number: int,
        vuln_type: CloudVulnerabilityType,
        description: str,
        severity: Severity,
        remediation: List[str]
    ) -> SecurityIssue:
        """Create a Kubernetes security issue."""
        from datetime import datetime
        
        issue_id = f"k8s_{vuln_type.value}_{line_number}_{hash(description) % 10000}"
        
        return SecurityIssue(
            id=issue_id,
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id=f"k8s_{vuln_type.value}",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


class CloudSecurityAnalyzer:
    """Main cloud security analyzer that coordinates different cloud analyzers."""
    
    def __init__(self):
        """Initialize cloud security analyzer."""
        self.dockerfile_analyzer = DockerfileAnalyzer()
        self.kubernetes_analyzer = KubernetesAnalyzer()
        self.logger = logging.getLogger(__name__)
    
    def analyze_file(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze cloud configuration file for security issues."""
        issues = []
        
        file_path_lower = file_path.lower()
        
        # Determine file type and analyze accordingly
        if self._is_dockerfile(file_path, content):
            issues.extend(self.dockerfile_analyzer.analyze(file_path, content))
        elif self._is_kubernetes_manifest(file_path, content):
            issues.extend(self.kubernetes_analyzer.analyze(file_path, content))
        elif self._is_docker_compose(file_path, content):
            issues.extend(self._analyze_docker_compose(file_path, content))
        elif self._is_terraform(file_path, content):
            issues.extend(self._analyze_terraform(file_path, content))
        
        return issues
    
    def _is_dockerfile(self, file_path: str, content: str) -> bool:
        """Check if file is a Dockerfile."""
        file_name = Path(file_path).name.lower()
        return (file_name == 'dockerfile' or 
                file_name.startswith('dockerfile.') or
                content.strip().startswith('FROM '))
    
    def _is_kubernetes_manifest(self, file_path: str, content: str) -> bool:
        """Check if file is a Kubernetes manifest."""
        if not (file_path.endswith('.yaml') or file_path.endswith('.yml')):
            return False
        
        try:
            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if isinstance(doc, dict) and 'apiVersion' in doc and 'kind' in doc:
                    return True
        except:
            pass
        
        return False
    
    def _is_docker_compose(self, file_path: str, content: str) -> bool:
        """Check if file is a Docker Compose file."""
        file_name = Path(file_path).name.lower()
        return ('docker-compose' in file_name or 
                'compose' in file_name) and file_name.endswith(('.yml', '.yaml'))
    
    def _is_terraform(self, file_path: str, content: str) -> bool:
        """Check if file is a Terraform configuration."""
        return file_path.endswith('.tf') or file_path.endswith('.hcl')
    
    def _analyze_docker_compose(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Docker Compose file (simplified implementation)."""
        issues = []
        
        try:
            compose_data = yaml.safe_load(content)
            services = compose_data.get('services', {})
            
            for service_name, service_config in services.items():
                # Check for privileged containers
                if service_config.get('privileged'):
                    issues.append(self._create_compose_issue(
                        file_path=file_path,
                        description=f"Service '{service_name}' runs in privileged mode",
                        severity=Severity.HIGH,
                        remediation=["Remove privileged: true", "Use specific capabilities"]
                    ))
                
                # Check for exposed ports
                ports = service_config.get('ports', [])
                for port in ports:
                    if isinstance(port, str) and ':22:' in port:
                        issues.append(self._create_compose_issue(
                            file_path=file_path,
                            description=f"Service '{service_name}' exposes SSH port 22",
                            severity=Severity.MEDIUM,
                            remediation=["Avoid exposing SSH ports", "Use secure alternatives"]
                        ))
        
        except yaml.YAMLError:
            pass
        
        return issues
    
    def _analyze_terraform(self, file_path: str, content: str) -> List[SecurityIssue]:
        """Analyze Terraform configuration (simplified implementation)."""
        issues = []
        
        # Simple regex-based analysis for common Terraform security issues
        terraform_patterns = [
            (r'source\s*=\s*"[^"]*\*[^"]*"', "Wildcard in Terraform source", Severity.MEDIUM),
            (r'public_read\s*=\s*true', "S3 bucket with public read access", Severity.HIGH),
            (r'acl\s*=\s*"public-read"', "S3 bucket with public ACL", Severity.HIGH),
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern, description, severity in terraform_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_terraform_issue(
                        file_path=file_path,
                        line_number=line_num,
                        description=description,
                        severity=severity,
                        remediation=["Review and secure Terraform configuration"]
                    ))
        
        return issues
    
    def _create_compose_issue(self, file_path: str, description: str, severity: Severity, remediation: List[str]) -> SecurityIssue:
        """Create Docker Compose security issue."""
        from datetime import datetime
        
        return SecurityIssue(
            id=f"compose_{hash(description) % 10000}",
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=1,
            description=description,
            rule_id="docker_compose_security",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )
    
    def _create_terraform_issue(self, file_path: str, line_number: int, description: str, severity: Severity, remediation: List[str]) -> SecurityIssue:
        """Create Terraform security issue."""
        from datetime import datetime
        
        return SecurityIssue(
            id=f"terraform_{line_number}_{hash(description) % 10000}",
            severity=severity,
            category=SecurityCategory.AUTHENTICATION,
            file_path=file_path,
            line_number=line_number,
            description=description,
            rule_id="terraform_security",
            confidence=0.8,
            remediation_suggestions=remediation,
            created_at=datetime.now()
        )


# Global analyzer instance
_global_cloud_analyzer: Optional[CloudSecurityAnalyzer] = None


def get_cloud_analyzer() -> CloudSecurityAnalyzer:
    """Get global cloud analyzer instance."""
    global _global_cloud_analyzer
    if _global_cloud_analyzer is None:
        _global_cloud_analyzer = CloudSecurityAnalyzer()
    return _global_cloud_analyzer


def reset_cloud_analyzer() -> None:
    """Reset global cloud analyzer (for testing)."""
    global _global_cloud_analyzer
    _global_cloud_analyzer = None