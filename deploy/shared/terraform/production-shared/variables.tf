variable "aws_region" {
  description = "AWS region where the production shared-services stack is provisioned."
  type        = string
}

variable "deployment_id" {
  description = "Environment identifier used to make shared-service names unique."
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for production shared-service resources."
  type        = string
  default     = "intents-juno-shared"
}

variable "vpc_id" {
  description = "VPC that hosts the production shared-services stack."
  type        = string
}

variable "shared_subnet_ids" {
  description = "At least two subnet IDs in distinct AZs for Aurora, MSK, ECS, and the IPFS NLB."
  type        = list(string)

  validation {
    condition     = length(var.shared_subnet_ids) >= 2
    error_message = "shared_subnet_ids must contain at least two subnets."
  }
}

variable "shared_service_client_cidr_blocks" {
  description = "Additional client CIDR blocks that may reach Aurora and MSK from operator environments."
  type        = list(string)
  default     = []
}

variable "shared_ipfs_client_cidr_blocks" {
  description = "Additional client CIDR blocks that may reach the internal IPFS API."
  type        = list(string)
  default     = []
}

variable "shared_postgres_user" {
  description = "Aurora Postgres username for shared services."
  type        = string
  default     = "postgres"
}

variable "shared_postgres_password" {
  description = "Aurora Postgres password for shared services. This is required and must be supplied out-of-band."
  type        = string
  sensitive   = true
}

variable "shared_postgres_db" {
  description = "Aurora Postgres database name for shared services."
  type        = string
  default     = "intents"
}

variable "shared_postgres_port" {
  description = "Aurora Postgres port."
  type        = number
  default     = 5432

  validation {
    condition     = var.shared_postgres_port >= 1 && var.shared_postgres_port <= 65535
    error_message = "shared_postgres_port must be in the range [1, 65535]."
  }
}

variable "shared_postgres_backup_retention_days" {
  description = "Backup retention for the Aurora cluster."
  type        = number
  default     = 14

  validation {
    condition     = var.shared_postgres_backup_retention_days >= 7
    error_message = "shared_postgres_backup_retention_days must be at least 7 days."
  }
}

variable "shared_postgres_preferred_backup_window" {
  description = "Preferred Aurora backup window."
  type        = string
  default     = "07:00-09:00"
}

variable "shared_postgres_final_snapshot_identifier" {
  description = "Optional final snapshot identifier to override the default production snapshot name."
  type        = string
  default     = ""
}

variable "shared_aurora_instance_class" {
  description = "Aurora instance class for production shared services."
  type        = string
  default     = "db.t4g.medium"
}

variable "shared_kafka_port" {
  description = "MSK SASL/IAM bootstrap port exposed to clients."
  type        = number
  default     = 9098

  validation {
    condition     = var.shared_kafka_port == 9098
    error_message = "shared_kafka_port must be 9098 for MSK IAM bootstrap brokers."
  }
}

variable "shared_msk_kafka_version" {
  description = "Kafka version for the production MSK cluster."
  type        = string
  default     = "3.6.0"
}

variable "shared_msk_broker_instance_type" {
  description = "MSK broker instance type."
  type        = string
  default     = "kafka.t3.small"
}

variable "shared_msk_broker_ebs_volume_size_gb" {
  description = "MSK broker EBS volume size in GiB."
  type        = number
  default     = 100

  validation {
    condition     = var.shared_msk_broker_ebs_volume_size_gb >= 20
    error_message = "shared_msk_broker_ebs_volume_size_gb must be at least 20 GiB."
  }
}

variable "shared_ecs_desired_count" {
  description = "Desired task count for each shared proof service. Defaults to 0 so the base shared stack provisions idle ECS services; live rollout injects the full runtime contract later."
  type        = number
  default     = 0

  validation {
    condition     = var.shared_ecs_desired_count >= 0
    error_message = "shared_ecs_desired_count must be >= 0."
  }
}

variable "shared_ecs_task_cpu" {
  description = "Fargate CPU units for each proof-service task."
  type        = number
  default     = 2048
}

variable "shared_ecs_task_memory" {
  description = "Fargate memory in MiB for each proof-service task."
  type        = number
  default     = 8192
}

variable "shared_ecs_assign_public_ip" {
  description = "Whether proof-service tasks receive public IPs."
  type        = bool
  default     = false
}

variable "shared_proof_service_image" {
  description = "Container image used by proof-requestor and proof-funder. If empty, the Terraform-managed ECR repository is used with :latest."
  type        = string
  default     = ""
}

variable "shared_proof_service_image_ecr_repository_arn" {
  description = "Optional ECR repository ARN backing shared_proof_service_image when it points at an explicit ECR image. Leave empty when using the Terraform-managed default image or a non-ECR image."
  type        = string
  default     = ""
}

variable "shared_sp1_requestor_secret_arn" {
  description = "Secrets Manager ARN containing the proof-requestor private key."
  type        = string
}

variable "shared_sp1_funder_secret_arn" {
  description = "Secrets Manager ARN containing the proof-funder private key."
  type        = string
}

variable "shared_log_retention_days" {
  description = "CloudWatch log retention in days for shared proof services."
  type        = number
  default     = 30
}

variable "shared_ipfs_instance_type" {
  description = "EC2 instance type for the shared IPFS pinning nodes."
  type        = string
  default     = "c7i.large"
}

variable "shared_ipfs_ami_id" {
  description = "Optional custom AMI ID for shared IPFS instances."
  type        = string
  default     = ""
}

variable "shared_ipfs_root_volume_size_gb" {
  description = "Root EBS size for the IPFS instances."
  type        = number
  default     = 40

  validation {
    condition     = var.shared_ipfs_root_volume_size_gb >= 20
    error_message = "shared_ipfs_root_volume_size_gb must be at least 20 GiB."
  }
}

variable "shared_ipfs_min_size" {
  description = "Minimum size of the IPFS autoscaling group."
  type        = number
  default     = 2
}

variable "shared_ipfs_max_size" {
  description = "Maximum size of the IPFS autoscaling group."
  type        = number
  default     = 3
}

variable "shared_ipfs_desired_capacity" {
  description = "Desired size of the IPFS autoscaling group."
  type        = number
  default     = 2
}

variable "shared_ipfs_api_port" {
  description = "TCP port exposed through the internal IPFS NLB."
  type        = number
  default     = 5001

  validation {
    condition     = var.shared_ipfs_api_port >= 1 && var.shared_ipfs_api_port <= 65535
    error_message = "shared_ipfs_api_port must be in the range [1, 65535]."
  }
}

variable "shared_ipfs_assign_public_ip" {
  description = "Whether the IPFS instances should receive public IPs."
  type        = bool
  default     = false
}

variable "shared_ipfs_container_image" {
  description = "Container image used for the shared IPFS nodes."
  type        = string
  default     = "ipfs/kubo:v0.32.1"
}
