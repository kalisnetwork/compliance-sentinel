"""Infrastructure-as-code templates for cloud deployment."""

import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITAL_OCEAN = "digitalocean"


@dataclass
class InfrastructureConfig:
    """Infrastructure configuration."""
    
    provider: CloudProvider
    region: str
    environment: str = "production"
    
    # Compute resources
    instance_type: str = "t3.medium"
    min_instances: int = 2
    max_instances: int = 10
    
    # Storage
    storage_size_gb: int = 100
    backup_retention_days: int = 30
    
    # Networking
    vpc_cidr: str = "10.0.0.0/16"
    enable_nat_gateway: bool = True
    
    # Security
    enable_encryption: bool = True
    enable_monitoring: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'provider': self.provider.value,
            'region': self.region,
            'environment': self.environment,
            'instance_type': self.instance_type,
            'min_instances': self.min_instances,
            'max_instances': self.max_instances,
            'storage_size_gb': self.storage_size_gb,
            'backup_retention_days': self.backup_retention_days,
            'vpc_cidr': self.vpc_cidr,
            'enable_nat_gateway': self.enable_nat_gateway,
            'enable_encryption': self.enable_encryption,
            'enable_monitoring': self.enable_monitoring
        }


class TerraformManager:
    """Manages Terraform infrastructure templates."""
    
    def __init__(self):
        """Initialize Terraform manager."""
        self.logger = logging.getLogger(__name__)
    
    def generate_main_tf(self, config: InfrastructureConfig) -> str:
        """Generate main Terraform configuration."""
        
        if config.provider == CloudProvider.AWS:
            return self._generate_aws_main_tf(config)
        elif config.provider == CloudProvider.AZURE:
            return self._generate_azure_main_tf(config)
        elif config.provider == CloudProvider.GCP:
            return self._generate_gcp_main_tf(config)
        else:
            raise ValueError(f"Unsupported provider: {config.provider}")
    
    def _generate_aws_main_tf(self, config: InfrastructureConfig) -> str:
        """Generate AWS Terraform configuration."""
        
        return f'''
terraform {{
  required_version = ">= 1.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{config.region}"
}}

# VPC
resource "aws_vpc" "main" {{
  cidr_block           = "{config.vpc_cidr}"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {{
    Name        = "compliance-sentinel-vpc"
    Environment = "{config.environment}"
  }}
}}

# Internet Gateway
resource "aws_internet_gateway" "main" {{
  vpc_id = aws_vpc.main.id

  tags = {{
    Name = "compliance-sentinel-igw"
  }}
}}

# Public Subnets
resource "aws_subnet" "public" {{
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = {{
    Name = "compliance-sentinel-public-${{count.index + 1}}"
    Type = "public"
  }}
}}

# Private Subnets
resource "aws_subnet" "private" {{
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {{
    Name = "compliance-sentinel-private-${{count.index + 1}}"
    Type = "private"
  }}
}}

# EKS Cluster
resource "aws_eks_cluster" "main" {{
  name     = "compliance-sentinel-cluster"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.27"

  vpc_config {{
    subnet_ids              = concat(aws_subnet.public[*].id, aws_subnet.private[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
  }}

  encryption_config {{
    provider {{
      key_arn = aws_kms_key.eks.arn
    }}
    resources = ["secrets"]
  }}

  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
  ]

  tags = {{
    Environment = "{config.environment}"
  }}
}}

# RDS Instance
resource "aws_db_instance" "main" {{
  identifier = "compliance-sentinel-db"
  
  engine         = "postgres"
  engine_version = "15.3"
  instance_class = "db.t3.micro"
  
  allocated_storage     = {config.storage_size_gb}
  max_allocated_storage = {config.storage_size_gb * 2}
  
  db_name  = "compliance_sentinel"
  username = "cs_admin"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = {config.backup_retention_days}
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  storage_encrypted = {str(config.enable_encryption).lower()}
  kms_key_id       = aws_kms_key.rds.arn
  
  skip_final_snapshot = false
  final_snapshot_identifier = "compliance-sentinel-final-snapshot"
  
  tags = {{
    Name        = "compliance-sentinel-db"
    Environment = "{config.environment}"
  }}
}}
'''
    
    def _generate_azure_main_tf(self, config: InfrastructureConfig) -> str:
        """Generate Azure Terraform configuration."""
        
        return f'''
terraform {{
  required_providers {{
    azurerm = {{
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }}
  }}
}}

provider "azurerm" {{
  features {{}}
}}

# Resource Group
resource "azurerm_resource_group" "main" {{
  name     = "compliance-sentinel-rg"
  location = "{config.region}"

  tags = {{
    Environment = "{config.environment}"
  }}
}}

# Virtual Network
resource "azurerm_virtual_network" "main" {{
  name                = "compliance-sentinel-vnet"
  address_space       = ["{config.vpc_cidr}"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {{
    Environment = "{config.environment}"
  }}
}}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {{
  name                = "compliance-sentinel-aks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "compliance-sentinel"

  default_node_pool {{
    name       = "default"
    node_count = {config.min_instances}
    vm_size    = "Standard_D2_v2"
  }}

  identity {{
    type = "SystemAssigned"
  }}

  tags = {{
    Environment = "{config.environment}"
  }}
}}

# PostgreSQL Database
resource "azurerm_postgresql_server" "main" {{
  name                = "compliance-sentinel-db"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  administrator_login          = "cs_admin"
  administrator_login_password = var.db_password

  sku_name   = "B_Gen5_2"
  version    = "11"
  storage_mb = {config.storage_size_gb * 1024}

  backup_retention_days        = {config.backup_retention_days}
  geo_redundant_backup_enabled = false
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"

  tags = {{
    Environment = "{config.environment}"
  }}
}}
'''
    
    def _generate_gcp_main_tf(self, config: InfrastructureConfig) -> str:
        """Generate GCP Terraform configuration."""
        
        return f'''
terraform {{
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 4.0"
    }}
  }}
}}

provider "google" {{
  project = var.project_id
  region  = "{config.region}"
}}

# VPC Network
resource "google_compute_network" "main" {{
  name                    = "compliance-sentinel-vpc"
  auto_create_subnetworks = false
}}

# Subnet
resource "google_compute_subnetwork" "main" {{
  name          = "compliance-sentinel-subnet"
  ip_cidr_range = "{config.vpc_cidr}"
  region        = "{config.region}"
  network       = google_compute_network.main.id
}}

# GKE Cluster
resource "google_container_cluster" "main" {{
  name     = "compliance-sentinel-cluster"
  location = "{config.region}"
  
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main.name
  subnetwork = google_compute_subnetwork.main.name

  workload_identity_config {{
    workload_pool = "${{var.project_id}}.svc.id.goog"
  }}
}}

# GKE Node Pool
resource "google_container_node_pool" "main" {{
  name       = "main-pool"
  location   = "{config.region}"
  cluster    = google_container_cluster.main.name
  node_count = {config.min_instances}

  node_config {{
    preemptible  = false
    machine_type = "e2-medium"

    service_account = google_service_account.main.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }}
}}

# Cloud SQL Instance
resource "google_sql_database_instance" "main" {{
  name             = "compliance-sentinel-db"
  database_version = "POSTGRES_15"
  region           = "{config.region}"

  settings {{
    tier = "db-f1-micro"
    
    backup_configuration {{
      enabled    = true
      start_time = "03:00"
    }}
    
    ip_configuration {{
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }}
  }}

  deletion_protection = true
}}
'''
    
    def create_terraform_project(self, config: InfrastructureConfig, output_dir: str = "terraform") -> bool:
        """Create complete Terraform project."""
        
        try:
            tf_dir = Path(output_dir)
            tf_dir.mkdir(exist_ok=True)
            
            # Generate main.tf
            main_tf = self.generate_main_tf(config)
            with open(tf_dir / "main.tf", 'w') as f:
                f.write(main_tf)
            
            # Generate variables.tf
            variables_tf = self._generate_variables_tf(config)
            with open(tf_dir / "variables.tf", 'w') as f:
                f.write(variables_tf)
            
            # Generate outputs.tf
            outputs_tf = self._generate_outputs_tf(config)
            with open(tf_dir / "outputs.tf", 'w') as f:
                f.write(outputs_tf)
            
            # Generate terraform.tfvars.example
            tfvars_example = self._generate_tfvars_example(config)
            with open(tf_dir / "terraform.tfvars.example", 'w') as f:
                f.write(tfvars_example)
            
            self.logger.info(f"Created Terraform project: {tf_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating Terraform project: {e}")
            return False
    
    def _generate_variables_tf(self, config: InfrastructureConfig) -> str:
        """Generate variables.tf file."""
        
        return '''
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "region" {
  description = "Cloud region"
  type        = string
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "Instance type for compute resources"
  type        = string
  default     = "t3.medium"
}

variable "min_instances" {
  description = "Minimum number of instances"
  type        = number
  default     = 2
}

variable "max_instances" {
  description = "Maximum number of instances"
  type        = number
  default     = 10
}
'''
    
    def _generate_outputs_tf(self, config: InfrastructureConfig) -> str:
        """Generate outputs.tf file."""
        
        if config.provider == CloudProvider.AWS:
            return '''
output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.main.name
}

output "database_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}
'''
        else:
            return '''
output "cluster_name" {
  description = "Kubernetes cluster name"
  value       = "compliance-sentinel-cluster"
}
'''
    
    def _generate_tfvars_example(self, config: InfrastructureConfig) -> str:
        """Generate terraform.tfvars.example file."""
        
        return f'''
# Example Terraform variables file
# Copy to terraform.tfvars and customize

environment = "{config.environment}"
region = "{config.region}"
db_password = "change-this-secure-password"
instance_type = "{config.instance_type}"
min_instances = {config.min_instances}
max_instances = {config.max_instances}
'''


class InfrastructureManager:
    """Main infrastructure management system."""
    
    def __init__(self):
        """Initialize infrastructure manager."""
        self.logger = logging.getLogger(__name__)
        self.terraform_manager = TerraformManager()
    
    def create_infrastructure_project(self, 
                                    config: InfrastructureConfig,
                                    output_dir: str = "infrastructure") -> bool:
        """Create complete infrastructure project."""
        
        try:
            # Create Terraform configuration
            terraform_success = self.terraform_manager.create_terraform_project(
                config, 
                str(Path(output_dir) / "terraform")
            )
            
            # Create deployment scripts
            scripts_success = self._create_deployment_scripts(config, output_dir)
            
            # Create monitoring configuration
            monitoring_success = self._create_monitoring_config(config, output_dir)
            
            return terraform_success and scripts_success and monitoring_success
            
        except Exception as e:
            self.logger.error(f"Error creating infrastructure project: {e}")
            return False
    
    def _create_deployment_scripts(self, config: InfrastructureConfig, output_dir: str) -> bool:
        """Create deployment scripts."""
        
        try:
            scripts_dir = Path(output_dir) / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            
            # Deploy script
            deploy_script = f'''#!/bin/bash
set -e

echo "Deploying Compliance Sentinel infrastructure..."

# Initialize Terraform
cd terraform
terraform init

# Plan deployment
terraform plan -var-file="../config/{config.environment}.tfvars"

# Apply deployment
terraform apply -var-file="../config/{config.environment}.tfvars" -auto-approve

echo "Infrastructure deployment completed!"
'''
            
            with open(scripts_dir / "deploy.sh", 'w') as f:
                f.write(deploy_script)
            
            # Destroy script
            destroy_script = '''#!/bin/bash
set -e

echo "Destroying Compliance Sentinel infrastructure..."

cd terraform
terraform destroy -auto-approve

echo "Infrastructure destroyed!"
'''
            
            with open(scripts_dir / "destroy.sh", 'w') as f:
                f.write(destroy_script)
            
            # Make scripts executable
            import stat
            for script_file in scripts_dir.glob("*.sh"):
                script_file.chmod(script_file.stat().st_mode | stat.S_IEXEC)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating deployment scripts: {e}")
            return False
    
    def _create_monitoring_config(self, config: InfrastructureConfig, output_dir: str) -> bool:
        """Create monitoring configuration."""
        
        try:
            monitoring_dir = Path(output_dir) / "monitoring"
            monitoring_dir.mkdir(parents=True, exist_ok=True)
            
            # Prometheus configuration
            prometheus_config = {
                'global': {
                    'scrape_interval': '15s',
                    'evaluation_interval': '15s'
                },
                'scrape_configs': [
                    {
                        'job_name': 'compliance-sentinel',
                        'static_configs': [
                            {
                                'targets': ['compliance-sentinel:8080']
                            }
                        ],
                        'metrics_path': '/metrics',
                        'scrape_interval': '30s'
                    }
                ]
            }
            
            with open(monitoring_dir / "prometheus.yml", 'w') as f:
                yaml.dump(prometheus_config, f, default_flow_style=False)
            
            # Grafana dashboard
            dashboard_config = {
                'dashboard': {
                    'title': 'Compliance Sentinel Metrics',
                    'panels': [
                        {
                            'title': 'Security Scans',
                            'type': 'graph',
                            'targets': [
                                {
                                    'expr': 'compliance_sentinel_scans_total',
                                    'legendFormat': 'Total Scans'
                                }
                            ]
                        },
                        {
                            'title': 'Issues Found',
                            'type': 'graph',
                            'targets': [
                                {
                                    'expr': 'compliance_sentinel_issues_total',
                                    'legendFormat': 'Total Issues'
                                }
                            ]
                        }
                    ]
                }
            }
            
            with open(monitoring_dir / "dashboard.json", 'w') as f:
                json.dump(dashboard_config, f, indent=2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating monitoring config: {e}")
            return False


# Specialized infrastructure classes

class AWSInfrastructure(InfrastructureManager):
    """AWS-specific infrastructure management."""
    
    def create_eks_cluster_config(self, config: InfrastructureConfig) -> Dict[str, Any]:
        """Create EKS cluster configuration."""
        
        return {
            'cluster_name': 'compliance-sentinel-cluster',
            'kubernetes_version': '1.27',
            'node_groups': [
                {
                    'name': 'main-nodes',
                    'instance_types': [config.instance_type],
                    'min_size': config.min_instances,
                    'max_size': config.max_instances,
                    'desired_size': config.min_instances
                }
            ],
            'addons': [
                'vpc-cni',
                'coredns',
                'kube-proxy',
                'aws-load-balancer-controller'
            ]
        }


class AzureInfrastructure(InfrastructureManager):
    """Azure-specific infrastructure management."""
    
    def create_aks_cluster_config(self, config: InfrastructureConfig) -> Dict[str, Any]:
        """Create AKS cluster configuration."""
        
        return {
            'cluster_name': 'compliance-sentinel-aks',
            'kubernetes_version': '1.27',
            'node_pools': [
                {
                    'name': 'default',
                    'vm_size': 'Standard_D2_v2',
                    'node_count': config.min_instances,
                    'min_count': config.min_instances,
                    'max_count': config.max_instances,
                    'enable_auto_scaling': True
                }
            ]
        }


class GCPInfrastructure(InfrastructureManager):
    """GCP-specific infrastructure management."""
    
    def create_gke_cluster_config(self, config: InfrastructureConfig) -> Dict[str, Any]:
        """Create GKE cluster configuration."""
        
        return {
            'cluster_name': 'compliance-sentinel-cluster',
            'kubernetes_version': '1.27',
            'node_pools': [
                {
                    'name': 'default-pool',
                    'machine_type': 'e2-medium',
                    'initial_node_count': config.min_instances,
                    'min_node_count': config.min_instances,
                    'max_node_count': config.max_instances,
                    'autoscaling': True
                }
            ],
            'addons': [
                'http_load_balancing',
                'horizontal_pod_autoscaling',
                'network_policy'
            ]
        }


# Utility functions

def create_aws_config(region: str = "us-west-2") -> InfrastructureConfig:
    """Create AWS infrastructure configuration."""
    
    return InfrastructureConfig(
        provider=CloudProvider.AWS,
        region=region,
        instance_type="t3.medium",
        min_instances=2,
        max_instances=10
    )


def create_azure_config(region: str = "East US") -> InfrastructureConfig:
    """Create Azure infrastructure configuration."""
    
    return InfrastructureConfig(
        provider=CloudProvider.AZURE,
        region=region,
        instance_type="Standard_D2_v2",
        min_instances=2,
        max_instances=10
    )


def create_gcp_config(region: str = "us-central1") -> InfrastructureConfig:
    """Create GCP infrastructure configuration."""
    
    return InfrastructureConfig(
        provider=CloudProvider.GCP,
        region=region,
        instance_type="e2-medium",
        min_instances=2,
        max_instances=10
    )