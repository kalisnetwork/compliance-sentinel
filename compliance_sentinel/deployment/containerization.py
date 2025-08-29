"""Containerized deployment system with Docker and Kubernetes."""

import logging
import yaml
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


logger = logging.getLogger(__name__)


class ContainerRuntime(Enum):
    """Container runtime types."""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    PODMAN = "podman"


@dataclass
class ContainerConfig:
    """Container configuration."""
    
    image_name: str
    tag: str = "latest"
    
    # Resource limits
    cpu_limit: str = "1000m"
    memory_limit: str = "1Gi"
    cpu_request: str = "100m"
    memory_request: str = "256Mi"
    
    # Environment
    environment_vars: Dict[str, str] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    
    # Networking
    ports: List[int] = field(default_factory=lambda: [8080])
    
    # Health checks
    health_check_path: str = "/health"
    readiness_probe_path: str = "/ready"
    
    # Security
    run_as_non_root: bool = True
    read_only_root_filesystem: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'image_name': self.image_name,
            'tag': self.tag,
            'cpu_limit': self.cpu_limit,
            'memory_limit': self.memory_limit,
            'cpu_request': self.cpu_request,
            'memory_request': self.memory_request,
            'environment_vars': self.environment_vars,
            'ports': self.ports,
            'health_check_path': self.health_check_path,
            'readiness_probe_path': self.readiness_probe_path,
            'run_as_non_root': self.run_as_non_root,
            'read_only_root_filesystem': self.read_only_root_filesystem
        }


class DockerBuilder:
    """Builds Docker containers for Compliance Sentinel."""
    
    def __init__(self):
        """Initialize Docker builder."""
        self.logger = logging.getLogger(__name__)
    
    def generate_dockerfile(self, config: ContainerConfig) -> str:
        """Generate optimized Dockerfile."""
        
        dockerfile = f"""# Multi-stage build for Compliance Sentinel
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser . .

# Security settings
{"USER appuser" if config.run_as_non_root else ""}

# Expose ports
{chr(10).join(f"EXPOSE {port}" for port in config.ports)}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:{config.ports[0]}{config.health_check_path} || exit 1

# Start application
CMD ["python", "-m", "compliance_sentinel.main"]
"""
        
        return dockerfile
    
    def generate_dockerignore(self) -> str:
        """Generate .dockerignore file."""
        
        return """# Version control
.git
.gitignore

# Python
__pycache__
*.pyc
*.pyo
*.pyd
.Python
env
pip-log.txt
pip-delete-this-directory.txt
.tox
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.log
.git
.mypy_cache
.pytest_cache
.hypothesis

# Documentation
docs/_build

# IDE
.vscode
.idea
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Testing
.pytest_cache
.coverage
htmlcov/

# Build artifacts
build/
dist/
*.egg-info/

# Deployment
deployment/
k8s/
terraform/
"""
    
    def build_image(self, config: ContainerConfig, build_context: str = ".") -> bool:
        """Build Docker image."""
        
        try:
            # Generate Dockerfile
            dockerfile_content = self.generate_dockerfile(config)
            dockerfile_path = Path(build_context) / "Dockerfile"
            
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            
            # Generate .dockerignore
            dockerignore_content = self.generate_dockerignore()
            dockerignore_path = Path(build_context) / ".dockerignore"
            
            with open(dockerignore_path, 'w') as f:
                f.write(dockerignore_content)
            
            self.logger.info(f"Generated Docker build files for {config.image_name}:{config.tag}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error building Docker image: {e}")
            return False


class KubernetesDeployer:
    """Deploys applications to Kubernetes."""
    
    def __init__(self):
        """Initialize Kubernetes deployer."""
        self.logger = logging.getLogger(__name__)
    
    def generate_deployment_manifest(self, config: ContainerConfig, app_name: str = "compliance-sentinel") -> Dict[str, Any]:
        """Generate Kubernetes deployment manifest."""
        
        return {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': app_name,
                'labels': {
                    'app': app_name,
                    'version': config.tag
                }
            },
            'spec': {
                'replicas': 3,
                'selector': {
                    'matchLabels': {
                        'app': app_name
                    }
                },
                'template': {
                    'metadata': {
                        'labels': {
                            'app': app_name,
                            'version': config.tag
                        }
                    },
                    'spec': {
                        'securityContext': {
                            'runAsNonRoot': config.run_as_non_root,
                            'runAsUser': 1000,
                            'fsGroup': 2000
                        },
                        'containers': [{
                            'name': app_name,
                            'image': f"{config.image_name}:{config.tag}",
                            'ports': [{'containerPort': port} for port in config.ports],
                            'env': [
                                {'name': k, 'value': v} 
                                for k, v in config.environment_vars.items()
                            ],
                            'resources': {
                                'limits': {
                                    'cpu': config.cpu_limit,
                                    'memory': config.memory_limit
                                },
                                'requests': {
                                    'cpu': config.cpu_request,
                                    'memory': config.memory_request
                                }
                            },
                            'livenessProbe': {
                                'httpGet': {
                                    'path': config.health_check_path,
                                    'port': config.ports[0]
                                },
                                'initialDelaySeconds': 30,
                                'periodSeconds': 10
                            },
                            'readinessProbe': {
                                'httpGet': {
                                    'path': config.readiness_probe_path,
                                    'port': config.ports[0]
                                },
                                'initialDelaySeconds': 5,
                                'periodSeconds': 5
                            },
                            'securityContext': {
                                'allowPrivilegeEscalation': False,
                                'readOnlyRootFilesystem': config.read_only_root_filesystem,
                                'capabilities': {
                                    'drop': ['ALL']
                                }
                            }
                        }]
                    }
                }
            }
        }
    
    def generate_service_manifest(self, config: ContainerConfig, app_name: str = "compliance-sentinel") -> Dict[str, Any]:
        """Generate Kubernetes service manifest."""
        
        return {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': f"{app_name}-service",
                'labels': {
                    'app': app_name
                }
            },
            'spec': {
                'selector': {
                    'app': app_name
                },
                'ports': [
                    {
                        'port': 80,
                        'targetPort': config.ports[0],
                        'protocol': 'TCP'
                    }
                ],
                'type': 'ClusterIP'
            }
        }
    
    def generate_ingress_manifest(self, config: ContainerConfig, 
                                 app_name: str = "compliance-sentinel",
                                 hostname: str = "compliance-sentinel.example.com") -> Dict[str, Any]:
        """Generate Kubernetes ingress manifest."""
        
        return {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'metadata': {
                'name': f"{app_name}-ingress",
                'annotations': {
                    'kubernetes.io/ingress.class': 'nginx',
                    'cert-manager.io/cluster-issuer': 'letsencrypt-prod',
                    'nginx.ingress.kubernetes.io/ssl-redirect': 'true'
                }
            },
            'spec': {
                'tls': [{
                    'hosts': [hostname],
                    'secretName': f"{app_name}-tls"
                }],
                'rules': [{
                    'host': hostname,
                    'http': {
                        'paths': [{
                            'path': '/',
                            'pathType': 'Prefix',
                            'backend': {
                                'service': {
                                    'name': f"{app_name}-service",
                                    'port': {
                                        'number': 80
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }
    
    def generate_configmap_manifest(self, config: ContainerConfig, app_name: str = "compliance-sentinel") -> Dict[str, Any]:
        """Generate Kubernetes ConfigMap manifest."""
        
        return {
            'apiVersion': 'v1',
            'kind': 'ConfigMap',
            'metadata': {
                'name': f"{app_name}-config"
            },
            'data': config.environment_vars
        }
    
    def deploy_to_kubernetes(self, config: ContainerConfig, 
                           namespace: str = "default",
                           app_name: str = "compliance-sentinel") -> bool:
        """Deploy application to Kubernetes."""
        
        try:
            manifests = {
                'deployment': self.generate_deployment_manifest(config, app_name),
                'service': self.generate_service_manifest(config, app_name),
                'configmap': self.generate_configmap_manifest(config, app_name),
                'ingress': self.generate_ingress_manifest(config, app_name)
            }
            
            # Write manifests to files
            k8s_dir = Path("k8s")
            k8s_dir.mkdir(exist_ok=True)
            
            for manifest_type, manifest in manifests.items():
                manifest_file = k8s_dir / f"{manifest_type}.yaml"
                with open(manifest_file, 'w') as f:
                    yaml.dump(manifest, f, default_flow_style=False)
            
            self.logger.info(f"Generated Kubernetes manifests for {app_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deploying to Kubernetes: {e}")
            return False


class DockerCompose:
    """Docker Compose configuration generator."""
    
    def __init__(self):
        """Initialize Docker Compose generator."""
        self.logger = logging.getLogger(__name__)
    
    def generate_compose_file(self, config: ContainerConfig) -> Dict[str, Any]:
        """Generate docker-compose.yml configuration."""
        
        return {
            'version': '3.8',
            'services': {
                'compliance-sentinel': {
                    'build': {
                        'context': '.',
                        'dockerfile': 'Dockerfile'
                    },
                    'image': f"{config.image_name}:{config.tag}",
                    'ports': [f"{port}:{port}" for port in config.ports],
                    'environment': config.environment_vars,
                    'restart': 'unless-stopped',
                    'healthcheck': {
                        'test': f"curl -f http://localhost:{config.ports[0]}{config.health_check_path} || exit 1",
                        'interval': '30s',
                        'timeout': '10s',
                        'retries': 3,
                        'start_period': '40s'
                    },
                    'deploy': {
                        'resources': {
                            'limits': {
                                'cpus': config.cpu_limit.rstrip('m'),
                                'memory': config.memory_limit
                            },
                            'reservations': {
                                'cpus': config.cpu_request.rstrip('m'),
                                'memory': config.memory_request
                            }
                        }
                    }
                },
                'redis': {
                    'image': 'redis:7-alpine',
                    'ports': ['6379:6379'],
                    'restart': 'unless-stopped',
                    'command': 'redis-server --appendonly yes',
                    'volumes': ['redis_data:/data']
                },
                'postgres': {
                    'image': 'postgres:15-alpine',
                    'environment': {
                        'POSTGRES_DB': 'compliance_sentinel',
                        'POSTGRES_USER': 'cs_user',
                        'POSTGRES_PASSWORD': 'secure_password'
                    },
                    'ports': ['5432:5432'],
                    'restart': 'unless-stopped',
                    'volumes': ['postgres_data:/var/lib/postgresql/data']
                }
            },
            'volumes': {
                'redis_data': {},
                'postgres_data': {}
            },
            'networks': {
                'default': {
                    'driver': 'bridge'
                }
            }
        }


class HelmChart:
    """Helm chart generator for Kubernetes deployments."""
    
    def __init__(self):
        """Initialize Helm chart generator."""
        self.logger = logging.getLogger(__name__)
    
    def generate_chart_yaml(self, app_name: str = "compliance-sentinel", version: str = "1.0.0") -> Dict[str, Any]:
        """Generate Chart.yaml file."""
        
        return {
            'apiVersion': 'v2',
            'name': app_name,
            'description': 'A Helm chart for Compliance Sentinel',
            'type': 'application',
            'version': version,
            'appVersion': version,
            'keywords': ['security', 'compliance', 'analysis'],
            'maintainers': [
                {
                    'name': 'Compliance Sentinel Team',
                    'email': 'team@compliance-sentinel.com'
                }
            ]
        }
    
    def generate_values_yaml(self, config: ContainerConfig) -> Dict[str, Any]:
        """Generate values.yaml file."""
        
        return {
            'replicaCount': 3,
            'image': {
                'repository': config.image_name,
                'tag': config.tag,
                'pullPolicy': 'IfNotPresent'
            },
            'service': {
                'type': 'ClusterIP',
                'port': 80,
                'targetPort': config.ports[0]
            },
            'ingress': {
                'enabled': True,
                'className': 'nginx',
                'annotations': {
                    'cert-manager.io/cluster-issuer': 'letsencrypt-prod'
                },
                'hosts': [
                    {
                        'host': 'compliance-sentinel.example.com',
                        'paths': [
                            {
                                'path': '/',
                                'pathType': 'Prefix'
                            }
                        ]
                    }
                ],
                'tls': [
                    {
                        'secretName': 'compliance-sentinel-tls',
                        'hosts': ['compliance-sentinel.example.com']
                    }
                ]
            },
            'resources': {
                'limits': {
                    'cpu': config.cpu_limit,
                    'memory': config.memory_limit
                },
                'requests': {
                    'cpu': config.cpu_request,
                    'memory': config.memory_request
                }
            },
            'autoscaling': {
                'enabled': True,
                'minReplicas': 2,
                'maxReplicas': 10,
                'targetCPUUtilizationPercentage': 80
            },
            'securityContext': {
                'runAsNonRoot': config.run_as_non_root,
                'runAsUser': 1000,
                'fsGroup': 2000
            },
            'env': config.environment_vars
        }
    
    def create_helm_chart(self, config: ContainerConfig, 
                         chart_name: str = "compliance-sentinel",
                         output_dir: str = "helm") -> bool:
        """Create complete Helm chart."""
        
        try:
            chart_dir = Path(output_dir) / chart_name
            chart_dir.mkdir(parents=True, exist_ok=True)
            
            # Create templates directory
            templates_dir = chart_dir / "templates"
            templates_dir.mkdir(exist_ok=True)
            
            # Generate Chart.yaml
            chart_yaml = self.generate_chart_yaml(chart_name)
            with open(chart_dir / "Chart.yaml", 'w') as f:
                yaml.dump(chart_yaml, f, default_flow_style=False)
            
            # Generate values.yaml
            values_yaml = self.generate_values_yaml(config)
            with open(chart_dir / "values.yaml", 'w') as f:
                yaml.dump(values_yaml, f, default_flow_style=False)
            
            # Generate template files
            k8s_deployer = KubernetesDeployer()
            
            templates = {
                'deployment.yaml': k8s_deployer.generate_deployment_manifest(config, chart_name),
                'service.yaml': k8s_deployer.generate_service_manifest(config, chart_name),
                'ingress.yaml': k8s_deployer.generate_ingress_manifest(config, chart_name),
                'configmap.yaml': k8s_deployer.generate_configmap_manifest(config, chart_name)
            }
            
            for template_name, template_content in templates.items():
                with open(templates_dir / template_name, 'w') as f:
                    yaml.dump(template_content, f, default_flow_style=False)
            
            self.logger.info(f"Created Helm chart: {chart_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating Helm chart: {e}")
            return False


# Utility functions

def create_default_container_config() -> ContainerConfig:
    """Create default container configuration."""
    
    return ContainerConfig(
        image_name="compliance-sentinel/app",
        tag="latest",
        environment_vars={
            'ENVIRONMENT': 'production',
            'LOG_LEVEL': 'INFO',
            'REDIS_URL': 'redis://redis:6379',
            'DATABASE_URL': 'postgresql://cs_user:secure_password@postgres:5432/compliance_sentinel'
        },
        ports=[8080],
        health_check_path="/health",
        readiness_probe_path="/ready"
    )


def deploy_complete_stack(config: Optional[ContainerConfig] = None) -> bool:
    """Deploy complete Compliance Sentinel stack."""
    
    if config is None:
        config = create_default_container_config()
    
    try:
        # Build Docker image
        docker_builder = DockerBuilder()
        docker_builder.build_image(config)
        
        # Generate Kubernetes manifests
        k8s_deployer = KubernetesDeployer()
        k8s_deployer.deploy_to_kubernetes(config)
        
        # Generate Docker Compose
        compose = DockerCompose()
        compose_config = compose.generate_compose_file(config)
        
        with open("docker-compose.yml", 'w') as f:
            yaml.dump(compose_config, f, default_flow_style=False)
        
        # Generate Helm chart
        helm = HelmChart()
        helm.create_helm_chart(config)
        
        return True
        
    except Exception as e:
        logger.error(f"Error deploying complete stack: {e}")
        return False