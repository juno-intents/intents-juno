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
  description = "Optional subnet ID for the runner. If empty, the first public subnet is selected."
  type        = string
  default     = ""
}

variable "iam_instance_profile" {
  description = "Optional IAM instance profile name attached to the runner."
  type        = string
  default     = ""
}

variable "provision_shared_services" {
  description = "Whether to provision a shared services EC2 host for Postgres+Kafka."
  type        = bool
  default     = true
}

variable "shared_instance_type" {
  description = "EC2 instance type for the shared services host."
  type        = string
  default     = "c7i.large"
}

variable "shared_root_volume_size_gb" {
  description = "Root EBS size in GiB for the shared services host."
  type        = number
  default     = 100
}

variable "shared_postgres_user" {
  description = "Postgres username on shared services host."
  type        = string
  default     = "postgres"
}

variable "shared_postgres_password" {
  description = "Postgres password on shared services host."
  type        = string
  default     = "postgres"
  sensitive   = true
}

variable "shared_postgres_db" {
  description = "Postgres database name on shared services host."
  type        = string
  default     = "intents_e2e"
}

variable "shared_postgres_port" {
  description = "Postgres TCP port exposed by the shared services host."
  type        = number
  default     = 5432
}

variable "shared_kafka_port" {
  description = "Kafka TCP port exposed by the shared services host."
  type        = number
  default     = 9092
}
