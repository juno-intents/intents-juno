variable "aws_region" {
  description = "AWS region where the live e2e runner instance is created."
  type        = string
}

variable "deployment_id" {
  description = "Unique deployment identifier used to avoid naming collisions."
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for AWS resources."
  type        = string
  default     = "juno-live-e2e"
}

variable "instance_type" {
  description = "EC2 instance type for the live e2e runner."
  type        = string
  default     = "c7i.4xlarge"
}

variable "runner_ami_id" {
  description = "Optional custom AMI ID for the runner instance (for pre-baked/synced images)."
  type        = string
  default     = ""
}

variable "root_volume_size_gb" {
  description = "Root EBS size in GiB."
  type        = number
  default     = 200
}

variable "operator_instance_count" {
  description = "Number of dedicated operator EC2 instances."
  type        = number
  default     = 5

  validation {
    condition     = var.operator_instance_count >= 1
    error_message = "operator_instance_count must be >= 1."
  }
}

variable "operator_instance_type" {
  description = "EC2 instance type for each dedicated operator host."
  type        = string
  default     = "c7i.large"
}

variable "operator_ami_id" {
  description = "Optional custom AMI ID for operator instances (for pre-baked/synced images)."
  type        = string
  default     = ""
}

variable "operator_root_volume_size_gb" {
  description = "Root EBS size in GiB for each dedicated operator host."
  type        = number
  default     = 100

  validation {
    condition     = var.operator_root_volume_size_gb >= 20
    error_message = "operator_root_volume_size_gb must be >= 20."
  }
}

variable "operator_base_port" {
  description = "First operator gRPC TCP port used for distributed DKG."
  type        = number
  default     = 18443

  validation {
    condition     = var.operator_base_port >= 1 && var.operator_base_port <= 65535
    error_message = "operator_base_port must be in the range [1, 65535]."
  }
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH to the runner instance."
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key material used for instance access."
  type        = string
}

variable "vpc_id" {
  description = "Optional VPC ID for the runner. If empty, a VPC is inferred from the selected subnet."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Optional subnet ID for the runner. If empty, the first subnet in the selected VPC is used."
  type        = string
  default     = ""
}

variable "shared_subnet_ids" {
  description = "Optional subnet IDs used by shared Aurora/MSK/ECS/IPFS resources. If empty, the first two subnets in the selected VPC are used."
  type        = list(string)
  default     = []
}

variable "runner_associate_public_ip_address" {
  description = "Whether to associate a public IPv4 address to the runner EC2 instance."
  type        = bool
  default     = false
}

variable "operator_associate_public_ip_address" {
  description = "Whether to associate public IPv4 addresses to operator EC2 instances."
  type        = bool
  default     = false
}

variable "iam_instance_profile" {
  description = "Optional IAM instance profile name attached to runner/operator/shared hosts."
  type        = string
  default     = ""
}

variable "provision_shared_services" {
  description = "Whether to provision managed shared services (Aurora + MSK + ECS + IPFS)."
  type        = bool
  default     = true
}

variable "shared_instance_type" {
  description = "EC2 instance type for IPFS pinning nodes in the shared ASG."
  type        = string
  default     = "c7i.large"
}

variable "shared_ami_id" {
  description = "Optional custom AMI ID for the IPFS pinning ASG instances."
  type        = string
  default     = ""
}

variable "shared_root_volume_size_gb" {
  description = "Root EBS size in GiB for IPFS pinning ASG instances."
  type        = number
  default     = 100

  validation {
    condition     = var.shared_root_volume_size_gb >= 20
    error_message = "shared_root_volume_size_gb must be >= 20."
  }
}

variable "shared_postgres_user" {
  description = "Aurora Postgres username for shared e2e validation."
  type        = string
  default     = "postgres"
}

variable "shared_postgres_password" {
  description = "Aurora Postgres password for shared e2e validation."
  type        = string
  default     = "postgres"
  sensitive   = true
}

variable "shared_postgres_db" {
  description = "Aurora Postgres database name for shared e2e validation."
  type        = string
  default     = "intents_e2e"
}

variable "shared_postgres_port" {
  description = "Aurora Postgres TCP port exposed to the runner."
  type        = number
  default     = 5432

  validation {
    condition     = var.shared_postgres_port >= 1 && var.shared_postgres_port <= 65535
    error_message = "shared_postgres_port must be in the range [1, 65535]."
  }
}

variable "shared_aurora_instance_class" {
  description = "Aurora cluster instance class for live e2e shared services."
  type        = string
  default     = "db.t4g.medium"
}

variable "shared_kafka_port" {
  description = "MSK TLS bootstrap TCP port exposed to the runner."
  type        = number
  default     = 9094

  validation {
    condition     = var.shared_kafka_port == 9094
    error_message = "shared_kafka_port must be 9094 for MSK TLS bootstrap brokers."
  }
}

variable "shared_msk_kafka_version" {
  description = "MSK Kafka version for live e2e shared services."
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
    condition     = var.shared_msk_broker_ebs_volume_size_gb >= 1
    error_message = "shared_msk_broker_ebs_volume_size_gb must be >= 1."
  }
}

variable "shared_ecs_desired_count" {
  description = "Desired task count for each shared proof service ECS service (proof-requestor and proof-funder)."
  type        = number
  default     = 0

  validation {
    condition     = var.shared_ecs_desired_count >= 0
    error_message = "shared_ecs_desired_count must be >= 0."
  }
}

variable "shared_ecs_task_cpu" {
  description = "Fargate CPU units for each shared proof-service task definition."
  type        = number
  default     = 256
}

variable "shared_ecs_task_memory" {
  description = "Fargate memory (MiB) for each shared proof-service task definition."
  type        = number
  default     = 512
}

variable "shared_ecs_assign_public_ip" {
  description = "Whether shared ECS proof services should receive public IPv4 addresses."
  type        = bool
  default     = false
}

variable "shared_proof_service_image" {
  description = "Container image URI for shared proof services (proof-requestor/proof-funder). If empty, use the Terraform-managed ECR repo with :latest."
  type        = string
  default     = ""
}

variable "shared_boundless_requestor_secret_arn" {
  description = "Secrets Manager ARN containing the Boundless requestor private key used by shared proof-requestor/proof-funder ECS services."
  type        = string
  default     = ""
}

variable "shared_ipfs_min_size" {
  description = "Minimum size for the shared IPFS pinning autoscaling group."
  type        = number
  default     = 1
}

variable "shared_ipfs_max_size" {
  description = "Maximum size for the shared IPFS pinning autoscaling group."
  type        = number
  default     = 1
}

variable "shared_ipfs_desired_capacity" {
  description = "Desired capacity for the shared IPFS pinning autoscaling group."
  type        = number
  default     = 1
}

variable "shared_ipfs_api_port" {
  description = "TCP port exposed for shared IPFS API access through the internal NLB."
  type        = number
  default     = 5001

  validation {
    condition     = var.shared_ipfs_api_port >= 1 && var.shared_ipfs_api_port <= 65535
    error_message = "shared_ipfs_api_port must be in the range [1, 65535]."
  }
}

variable "dkg_s3_key_prefix" {
  description = "S3 key prefix used for operator DKG key-package exports."
  type        = string
  default     = "dkg/keypackages"
}
