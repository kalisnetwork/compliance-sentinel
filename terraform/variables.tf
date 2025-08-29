# Variables for Compliance Sentinel infrastructure

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "cluster_version" {
  description = "Kubernetes cluster version"
  type        = string
  default     = "1.28"
}

variable "node_groups" {
  description = "EKS node group configurations"
  type = map(object({
    instance_types = list(string)
    capacity_type  = string
    min_size      = number
    max_size      = number
    desired_size  = number
    disk_size     = number
    labels        = map(string)
    taints        = list(object({
      key    = string
      value  = string
      effect = string
    }))
  }))
  
  default = {
    general = {
      instance_types = ["t3.medium", "t3.large"]
      capacity_type  = "ON_DEMAND"
      min_size      = 2
      max_size      = 10
      desired_size  = 3
      disk_size     = 50
      labels = {
        role = "general"
      }
      taints = []
    }
    
    compute = {
      instance_types = ["c5.large", "c5.xlarge"]
      capacity_type  = "SPOT"
      min_size      = 0
      max_size      = 20
      desired_size  = 2
      disk_size     = 100
      labels = {
        role = "compute"
      }
      taints = [{
        key    = "compute"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

variable "database_config" {
  description = "RDS database configuration"
  type = object({
    engine_version    = string
    instance_class    = string
    allocated_storage = number
    max_allocated_storage = number
    backup_retention_period = number
    backup_window     = string
    maintenance_window = string
    multi_az          = bool
    deletion_protection = bool
  })
  
  default = {
    engine_version    = "15.4"
    instance_class    = "db.t3.medium"
    allocated_storage = 100
    max_allocated_storage = 1000
    backup_retention_period = 7
    backup_window     = "03:00-04:00"
    maintenance_window = "sun:04:00-sun:05:00"
    multi_az          = true
    deletion_protection = true
  }
}

variable "redis_config" {
  description = "ElastiCache Redis configuration"
  type = object({
    node_type               = string
    num_cache_nodes        = number
    parameter_group_name   = string
    port                   = number
    maintenance_window     = string
    snapshot_retention_limit = number
    snapshot_window        = string
    automatic_failover_enabled = bool
    multi_az_enabled       = bool
  })
  
  default = {
    node_type               = "cache.t3.micro"
    num_cache_nodes        = 2
    parameter_group_name   = "default.redis7"
    port                   = 6379
    maintenance_window     = "sun:05:00-sun:06:00"
    snapshot_retention_limit = 5
    snapshot_window        = "03:00-05:00"
    automatic_failover_enabled = true
    multi_az_enabled       = true
  }
}

variable "monitoring_config" {
  description = "Monitoring and logging configuration"
  type = object({
    enable_cloudwatch_logs = bool
    log_retention_days     = number
    enable_prometheus      = bool
    enable_grafana         = bool
    enable_alertmanager    = bool
  })
  
  default = {
    enable_cloudwatch_logs = true
    log_retention_days     = 30
    enable_prometheus      = true
    enable_grafana         = true
    enable_alertmanager    = true
  }
}

variable "security_config" {
  description = "Security configuration"
  type = object({
    enable_waf             = bool
    enable_shield_advanced = bool
    enable_guardduty       = bool
    enable_security_hub    = bool
    enable_config          = bool
  })
  
  default = {
    enable_waf             = true
    enable_shield_advanced = false
    enable_guardduty       = true
    enable_security_hub    = true
    enable_config          = true
  }
}

variable "backup_config" {
  description = "Backup and disaster recovery configuration"
  type = object({
    enable_backup_vault    = bool
    backup_retention_days  = number
    enable_cross_region_backup = bool
    backup_region          = string
  })
  
  default = {
    enable_backup_vault    = true
    backup_retention_days  = 30
    enable_cross_region_backup = true
    backup_region          = "us-east-1"
  }
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "compliance-sentinel.example.com"
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  type        = string
  default     = ""
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}