output "runner_instance_id" {
  description = "Runner EC2 instance ID."
  value       = aws_instance.runner.id
}

output "runner_ami_id" {
  description = "Runner AMI ID."
  value       = aws_instance.runner.ami
}

output "runner_public_ip" {
  description = "Runner public IPv4 address."
  value       = aws_instance.runner.public_ip
}

output "runner_public_dns" {
  description = "Runner public DNS hostname."
  value       = aws_instance.runner.public_dns
}

output "runner_ssh_user" {
  description = "SSH username for Ubuntu image."
  value       = "ubuntu"
}

output "shared_services_enabled" {
  description = "Whether managed shared services are provisioned."
  value       = var.provision_shared_services
}

output "shared_postgres_endpoint" {
  description = "Aurora Postgres writer endpoint hostname."
  value       = try(aws_rds_cluster.shared[0].endpoint, null)
}

output "shared_postgres_reader_endpoint" {
  description = "Aurora Postgres reader endpoint hostname."
  value       = try(aws_rds_cluster.shared[0].reader_endpoint, null)
}

output "shared_postgres_port" {
  description = "Aurora Postgres TCP port."
  value       = var.shared_postgres_port
}

output "shared_kafka_port" {
  description = "MSK SASL/IAM Kafka port."
  value       = var.shared_kafka_port
}

output "shared_kafka_bootstrap_brokers" {
  description = "MSK bootstrap brokers for SASL/IAM clients."
  value       = try(aws_msk_cluster.shared[0].bootstrap_brokers_sasl_iam, null)
}

output "shared_ecs_cluster_arn" {
  description = "Shared ECS cluster ARN."
  value       = try(aws_ecs_cluster.shared[0].arn, null)
}

output "shared_proof_requestor_service_name" {
  description = "Shared proof-requestor ECS service name."
  value       = try(aws_ecs_service.proof_requestor[0].name, null)
}

output "shared_proof_funder_service_name" {
  description = "Shared proof-funder ECS service name."
  value       = try(aws_ecs_service.proof_funder[0].name, null)
}

output "shared_sp1_requestor_address" {
  description = "EVM address used by the shared SP1 proof-requestor."
  value       = trimspace(var.shared_sp1_requestor_address)
}

output "shared_sp1_rpc_url" {
  description = "Succinct prover network RPC used by shared proof services."
  value       = trimspace(var.shared_sp1_rpc_url)
}

output "shared_proof_services_ecr_repository_url" {
  description = "ECR repository URL that stores the shared proof-services image."
  value       = try(aws_ecr_repository.proof_services[0].repository_url, null)
}

output "shared_ipfs_nlb_dns" {
  description = "Internal NLB DNS name fronting the IPFS pinning ASG."
  value       = try(aws_lb.ipfs[0].dns_name, null)
}

output "shared_ipfs_api_url" {
  description = "IPFS API URL exposed by the internal NLB."
  value       = try("http://${aws_lb.ipfs[0].dns_name}:${var.shared_ipfs_api_port}", null)
}

output "shared_ipfs_api_auth_secret_arn" {
  description = "Secrets Manager ARN containing the shared IPFS API bearer token."
  value       = try(aws_secretsmanager_secret.shared_ipfs_api_bearer_token[0].arn, null)
  sensitive   = true
}

output "shared_kafka_critical_hmac_secret_arn" {
  description = "Secrets Manager ARN containing the shared Kafka critical-topic HMAC key."
  value       = try(aws_secretsmanager_secret.shared_kafka_critical_hmac_key[0].arn, null)
  sensitive   = true
}

output "shared_wireguard_gateway_private_ip" {
  description = "Private IPv4 address of the dedicated WireGuard gateway."
  value       = try(aws_instance.wireguard_gateway[0].private_ip, null)
}

output "shared_wireguard_endpoint_host" {
  description = "Public endpoint host used by the generated WireGuard client config."
  value       = try(aws_eip.wireguard_gateway[0].public_ip, null)
}

output "shared_wireguard_listen_port" {
  description = "UDP port exposed by the dedicated WireGuard gateway."
  value       = local.wireguard_enabled ? var.shared_wireguard_listen_port : null
}

output "shared_wireguard_network_cidr" {
  description = "Tunnel CIDR assigned to the dedicated WireGuard gateway."
  value       = local.wireguard_enabled ? var.shared_wireguard_network_cidr : null
}

output "shared_wireguard_client_address_cidr" {
  description = "Client tunnel address generated for the dedicated backoffice WireGuard profile."
  value       = local.wireguard_enabled ? local.wireguard_client_address_cidr : null
}

output "shared_wireguard_client_config_secret_arn" {
  description = "Secrets Manager ARN containing the generated backoffice WireGuard client config."
  value       = try(aws_secretsmanager_secret.shared_wireguard_client_config[0].arn, null)
  sensitive   = true
}

output "operator_instance_ids" {
  description = "Operator EC2 instance IDs."
  value       = data.aws_instance.operator[*].id
}

output "operator_ami_ids" {
  description = "Operator AMI IDs."
  value       = data.aws_instance.operator[*].ami
}

output "operator_public_ips" {
  description = "Operator public IPv4 addresses."
  value       = data.aws_instance.operator[*].public_ip
}

output "operator_private_ips" {
  description = "Operator private IPv4 addresses."
  value       = data.aws_instance.operator[*].private_ip
}

output "effective_instance_profile" {
  description = "IAM instance profile attached to runner/operator/ipfs hosts."
  value       = aws_instance.runner.iam_instance_profile
}

output "dkg_kms_key_arn" {
  description = "KMS key ARN used for DKG key-package exports."
  value       = aws_kms_key.dkg.arn
}

output "dkg_kms_alias" {
  description = "KMS alias used for DKG key-package exports."
  value       = aws_kms_alias.dkg.name
}

output "dkg_s3_bucket" {
  description = "S3 bucket used for DKG key-package exports."
  value       = aws_s3_bucket.dkg_keypackages.bucket
}

output "dkg_s3_key_prefix" {
  description = "S3 prefix for DKG key-package exports."
  value       = var.dkg_s3_key_prefix
}
