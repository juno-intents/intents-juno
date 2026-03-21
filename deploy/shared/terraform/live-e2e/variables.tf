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
  default     = "c7i.2xlarge"
}

variable "runner_ami_id" {
  description = "Optional custom AMI ID for the runner instance (for pre-baked/synced images)."
  type        = string
  default     = ""
}

variable "root_volume_size_gb" {
  description = "Root EBS size in GiB."
  type        = number
  default     = 60
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
  default     = 40

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
  description = "Optional subnet IDs used by shared Aurora/MSK/ECS/IPFS resources. If empty, the first two private subnets in distinct AZs in the selected VPC are used."
  type        = list(string)
  default     = []
}

variable "runner_associate_public_ip_address" {
  description = "Whether to associate a public IPv4 address to the runner EC2 instance."
  type        = bool
  default     = true
}

variable "operator_associate_public_ip_address" {
  description = "Whether to associate public IPv4 addresses to operator EC2 instances."
  type        = bool
  default     = true
}

variable "operator_client_security_group_ids" {
  description = "Additional security group IDs allowed to reach operator gRPC, health, base-relayer, and Juno RPC ports."
  type        = list(string)
  default     = []
}

variable "iam_instance_profile" {
  description = "Optional IAM instance profile name attached to runner/operator/shared hosts."
  type        = string
  default     = ""
}

variable "allowed_checkpoint_signer_kms_key_arns" {
  description = "KMS key ARNs that the Terraform-managed live e2e instance role may use for checkpoint signing. Ignored when iam_instance_profile is set."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.allowed_checkpoint_signer_kms_key_arns :
      trimspace(arn) != "" && can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$", trimspace(arn)))
    ])
    error_message = "allowed_checkpoint_signer_kms_key_arns must contain only non-empty AWS KMS key ARNs."
  }
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
  default     = 40

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
  description = "MSK SASL/IAM bootstrap port exposed to clients."
  type        = number
  default     = 9098

  validation {
    condition     = var.shared_kafka_port == 9098
    error_message = "shared_kafka_port must be 9098 for MSK IAM bootstrap brokers."
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
  default     = "kafka.m5.large"
}

variable "shared_msk_broker_ebs_volume_size_gb" {
  description = "MSK broker EBS volume size in GiB."
  type        = number
  default     = 20

  validation {
    condition     = var.shared_msk_broker_ebs_volume_size_gb >= 1
    error_message = "shared_msk_broker_ebs_volume_size_gb must be >= 1."
  }
}

variable "shared_ecs_desired_count" {
  description = "Desired task count for each shared proof service ECS service (proof-requestor and proof-funder)."
  type        = number
  default     = 1

  validation {
    condition     = var.shared_ecs_desired_count >= 0
    error_message = "shared_ecs_desired_count must be >= 0."
  }
}

variable "shared_ecs_task_cpu" {
  description = "Fargate CPU units for each shared proof-service task definition."
  type        = number
  default     = 2048
}

variable "shared_ecs_task_memory" {
  description = "Fargate memory (MiB) for each shared proof-service task definition."
  type        = number
  default     = 8192
}

variable "shared_ecs_assign_public_ip" {
  description = "Whether shared ECS proof services should receive public IPv4 addresses."
  type        = bool
  default     = false
}

variable "shared_proof_service_image" {
  description = "Container image URI for shared proof services (proof-requestor/proof-funder). Required when provision_shared_services is true."
  type        = string
  default     = ""
}

variable "shared_sp1_requestor_secret_arn" {
  description = "Secrets Manager ARN containing the SP1 requestor private key used by shared proof-requestor/proof-funder ECS services."
  type        = string
  default     = ""
}

variable "shared_sp1_funder_secret_arn" {
  description = "Secrets Manager ARN containing the SP1 funder private key used by shared proof-funder ECS services."
  type        = string
  default     = ""
}

variable "shared_sp1_requestor_address" {
  description = "EVM address for the shared SP1 requestor key. Required when shared_ecs_desired_count > 0."
  type        = string
  default     = ""
}

variable "shared_base_chain_id" {
  description = "Base/EVM chain id used by shared proof-requestor request IDs. Required when shared_ecs_desired_count > 0."
  type        = number
  default     = 0
}

variable "shared_deposit_image_id" {
  description = "Deposit guest image id (bytes32 hex) used to derive the shared proof-requestor deposit guest program URL. Required when shared_ecs_desired_count > 0."
  type        = string
  default     = ""
}

variable "shared_withdraw_image_id" {
  description = "Withdraw guest image id (bytes32 hex) used to derive the shared proof-requestor withdraw guest program URL. Required when shared_ecs_desired_count > 0."
  type        = string
  default     = ""
}

variable "shared_bridge_guest_release_tag" {
  description = "GitHub release tag used to derive shared SP1 guest program URLs from guest image ids."
  type        = string
  default     = "bridge-guests-latest"
}

variable "shared_sp1_rpc_url" {
  description = "Succinct SP1 network RPC URL used by the shared proof services."
  type        = string
  default     = "https://rpc.mainnet.succinct.xyz"
}

variable "shared_sp1_max_price_per_pgu" {
  description = "Maximum SP1 auction price per PGU used by the shared proof-requestor and proof-funder credit guardrail."
  type        = number
  default     = 2000000000
}

variable "shared_sp1_deposit_pgu_estimate" {
  description = "Deposit PGU estimate used to compute shared proof-funder credit guardrails."
  type        = number
  default     = 50000000
}

variable "shared_sp1_withdraw_pgu_estimate" {
  description = "Withdraw PGU estimate used to compute shared proof-funder credit guardrails."
  type        = number
  default     = 50000000
}

variable "shared_sp1_groth16_base_fee_wei" {
  description = "Groth16 base fee used to compute shared proof-funder credit guardrails."
  type        = number
  default     = 200000000000000000
}

variable "shared_sp1_min_auction_period" {
  description = "Minimum SP1 auction period in seconds for the shared proof-requestor."
  type        = number
  default     = 85
}

variable "shared_sp1_auction_timeout_seconds" {
  description = "SP1 auction timeout in seconds for the shared proof-requestor."
  type        = number
  default     = 625
}

variable "shared_sp1_request_timeout_seconds" {
  description = "SP1 request timeout in seconds for the shared proof-requestor."
  type        = number
  default     = 1500
}

variable "shared_postgres_dr_region" {
  description = "AWS region that receives copied Aurora backups for disaster recovery."
  type        = string
  default     = "us-west-2"

  validation {
    condition     = trimspace(var.shared_postgres_dr_region) != ""
    error_message = "shared_postgres_dr_region must be non-empty."
  }
}

variable "shared_postgres_backup_schedule_expression" {
  description = "AWS Backup schedule expression for Aurora cross-region backups."
  type        = string
  default     = "cron(0 6 * * ? *)"
}

variable "shared_postgres_backup_delete_after_days" {
  description = "Retention in days for copied Aurora backups in AWS Backup vaults."
  type        = number
  default     = 14

  validation {
    condition     = var.shared_postgres_backup_delete_after_days >= 7
    error_message = "shared_postgres_backup_delete_after_days must be at least 7 days."
  }
}

variable "shared_ipfs_min_size" {
  description = "Minimum size for the shared IPFS pinning autoscaling group."
  type        = number
  default     = 1
}

variable "shared_ipfs_data_volume_size_gb" {
  description = "Dedicated EBS data volume size for persisted shared IPFS content."
  type        = number
  default     = 80

  validation {
    condition     = var.shared_ipfs_data_volume_size_gb >= 20
    error_message = "shared_ipfs_data_volume_size_gb must be at least 20 GiB."
  }
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

variable "shared_wireguard_enabled" {
  description = "Whether the live-e2e shared stack should provision a dedicated WireGuard gateway for backoffice access."
  type        = bool
  default     = false
}

variable "shared_wireguard_public_subnet_id" {
  description = "Optional public subnet ID used by the dedicated WireGuard gateway when shared_wireguard_enabled=true. If empty, the first discovered public subnet is used."
  type        = string
  default     = ""
}

variable "shared_wireguard_instance_type" {
  description = "EC2 instance type for the dedicated WireGuard gateway."
  type        = string
  default     = "t3.small"
}

variable "shared_wireguard_listen_port" {
  description = "UDP port exposed by the dedicated WireGuard gateway."
  type        = number
  default     = 51820

  validation {
    condition     = var.shared_wireguard_listen_port >= 1 && var.shared_wireguard_listen_port <= 65535
    error_message = "shared_wireguard_listen_port must be in the range [1, 65535]."
  }
}

variable "shared_wireguard_network_cidr" {
  description = "Tunnel network CIDR assigned to the dedicated WireGuard gateway and its generated client."
  type        = string
  default     = "10.66.0.0/24"
}

variable "shared_wireguard_backoffice_hostname" {
  description = "Backoffice hostname resolved over the dedicated WireGuard gateway when shared_wireguard_enabled=true."
  type        = string
  default     = ""
}

variable "shared_wireguard_backoffice_private_endpoint" {
  description = "Optional private IPv4 address of the app host reached through the dedicated WireGuard gateway when shared_wireguard_enabled=true. If empty, the runner private IP is used."
  type        = string
  default     = ""
}

variable "dkg_s3_key_prefix" {
  description = "S3 key prefix used for operator DKG key-package exports."
  type        = string
  default     = "dkg/keypackages"
}

variable "alarm_actions" {
  description = "Optional CloudWatch alarm action ARNs."
  type        = list(string)
  default     = []
}
