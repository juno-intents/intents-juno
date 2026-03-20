output "shared_postgres_endpoint" {
  description = "Aurora Postgres writer endpoint hostname."
  value       = aws_rds_cluster.shared.endpoint
}

output "shared_postgres_cluster_arn" {
  description = "Aurora Postgres cluster ARN."
  value       = aws_rds_cluster.shared.arn
}

output "shared_postgres_reader_endpoint" {
  description = "Aurora Postgres reader endpoint hostname."
  value       = aws_rds_cluster.shared.reader_endpoint
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
  value       = aws_msk_cluster.shared.bootstrap_brokers_sasl_iam
}

output "shared_kafka_cluster_arn" {
  description = "MSK cluster ARN."
  value       = aws_msk_cluster.shared.arn
}

output "shared_kafka_bootstrap_brokers_tls" {
  description = "MSK bootstrap brokers for TLS-only clients."
  value       = aws_msk_cluster.shared.bootstrap_brokers_tls
}

output "shared_sp1_requestor_address" {
  description = "Shared SP1 requestor address used by proof services."
  value       = var.shared_sp1_requestor_address
}

output "shared_sp1_rpc_url" {
  description = "Shared SP1 RPC URL used by proof services."
  value       = var.shared_sp1_rpc_url
}

output "shared_proof_services_ecr_repository_url" {
  description = "ECR repository URL that stores the proof-services image."
  value       = aws_ecr_repository.proof_services.repository_url
}

output "shared_proof_role_asg_name" {
  description = "Autoscaling group name for the shared proof-role foundation."
  value       = aws_autoscaling_group.proof_role.name
}

output "shared_proof_role" {
  description = "Structured proof-role contract for deployment handoffs."
  value = {
    asg = aws_autoscaling_group.proof_role.name
    launch_template = {
      id      = aws_launch_template.proof_role.id
      version = tostring(aws_launch_template.proof_role.latest_version)
    }
    requestor_address = var.shared_sp1_requestor_address
    rpc_url           = var.shared_sp1_rpc_url
  }
}

output "shared_proof_role_launch_template_id" {
  description = "Launch template ID for the shared proof-role foundation."
  value       = aws_launch_template.proof_role.id
}

output "shared_proof_requestor_secret_arn" {
  description = "Secrets Manager ARN bound to proof-requestor."
  value       = var.shared_sp1_requestor_secret_arn
  sensitive   = true
}

output "shared_proof_funder_secret_arn" {
  description = "Secrets Manager ARN bound to proof-funder."
  value       = var.shared_sp1_funder_secret_arn
  sensitive   = true
}

output "shared_postgres_dsn_secret_arn" {
  description = "Secrets Manager ARN containing the shared services Postgres DSN."
  value       = aws_secretsmanager_secret.shared_postgres_dsn.arn
  sensitive   = true
}

output "shared_ipfs_nlb_dns" {
  description = "Internal NLB DNS name fronting the IPFS ASG."
  value       = aws_lb.ipfs.dns_name
}

output "shared_ipfs_api_url" {
  description = "IPFS API URL exposed by the internal NLB."
  value       = "http://${aws_lb.ipfs.dns_name}:${var.shared_ipfs_api_port}"
}

output "shared_ipfs_api_auth_secret_arn" {
  description = "Secrets Manager ARN containing the shared IPFS API bearer token."
  value       = aws_secretsmanager_secret.shared_ipfs_api_bearer_token.arn
  sensitive   = true
}

output "shared_kafka_critical_hmac_secret_arn" {
  description = "Secrets Manager ARN containing the shared Kafka critical-topic HMAC key."
  value       = aws_secretsmanager_secret.shared_kafka_critical_hmac_key.arn
  sensitive   = true
}

output "shared_ipfs_target_group_arn" {
  description = "IPFS API target group ARN."
  value       = aws_lb_target_group.ipfs_api.arn
}

output "shared_ipfs_instance_profile" {
  description = "IAM instance profile attached to the shared IPFS nodes."
  value       = aws_iam_instance_profile.ipfs.name
}

output "shared_wireguard_role_asg_name" {
  description = "Autoscaling group name for the WireGuard gateway role foundation."
  value       = var.shared_wireguard_enabled ? aws_autoscaling_group.wireguard_role[0].name : null
}

output "shared_wireguard_role" {
  description = "Structured wireguard role contract for deployment handoffs."
  value = var.shared_wireguard_enabled ? {
    asg = aws_autoscaling_group.wireguard_role[0].name
    launch_template = {
      id      = aws_launch_template.wireguard_role[0].id
      version = tostring(aws_launch_template.wireguard_role[0].latest_version)
    }
    endpoint_host                   = aws_lb.wireguard[0].dns_name
    listen_port                     = var.shared_wireguard_listen_port
    network_cidr                    = var.shared_wireguard_network_cidr
    source_cidrs                    = var.shared_wireguard_source_cidrs
    server_key_secret_arn           = aws_secretsmanager_secret.shared_wireguard_server_key[0].arn
    peer_roster_secret_arns         = [for secret in values(aws_secretsmanager_secret.shared_wireguard_peer_config) : secret.arn]
    peer_config_secret_arns         = { for name, secret in aws_secretsmanager_secret.shared_wireguard_peer_config : name => secret.arn }
    backoffice_private_endpoint_ips = local.shared_wireguard_backoffice_private_endpoint_ips
  } : {
    asg               = null
    launch_template   = { id = null, version = null }
    endpoint_host     = null
    listen_port       = null
    network_cidr      = null
    source_cidrs      = []
    server_key_secret_arn           = null
    peer_roster_secret_arns         = []
    peer_config_secret_arns         = {}
    backoffice_private_endpoint_ips = []
  }
  sensitive = true
}

output "shared_wireguard_role_launch_template_id" {
  description = "Launch template ID for the WireGuard gateway role foundation."
  value       = var.shared_wireguard_enabled ? aws_launch_template.wireguard_role[0].id : null
}

output "shared_wireguard_nlb_dns_name" {
  description = "Public DNS name for the WireGuard UDP network load balancer."
  value       = var.shared_wireguard_enabled ? aws_lb.wireguard[0].dns_name : null
}

output "shared_wireguard_listen_port" {
  description = "UDP port exposed by the dedicated WireGuard gateway."
  value       = var.shared_wireguard_enabled ? var.shared_wireguard_listen_port : null
}

output "shared_wireguard_network_cidr" {
  description = "Tunnel CIDR assigned to the dedicated WireGuard gateway."
  value       = var.shared_wireguard_enabled ? var.shared_wireguard_network_cidr : null
}

output "shared_wireguard_server_key_secret_arn" {
  description = "Secrets Manager ARN containing the shared WireGuard server private key."
  value       = var.shared_wireguard_enabled ? aws_secretsmanager_secret.shared_wireguard_server_key[0].arn : null
  sensitive   = true
}

output "shared_wireguard_peer_config_secret_arns" {
  description = "Secrets Manager ARNs reserved for named WireGuard peer configs."
  value       = { for name, secret in aws_secretsmanager_secret.shared_wireguard_peer_config : name => secret.arn }
  sensitive   = true
}

output "shared_wireguard_backoffice_private_endpoint_ips" {
  description = "Private IPv4 addresses for the internal backoffice load balancer routed over WireGuard."
  value       = local.shared_wireguard_backoffice_private_endpoint_ips
}
