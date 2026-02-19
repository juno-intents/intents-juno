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
  description = "Whether shared services host is provisioned."
  value       = var.provision_shared_services
}

output "shared_instance_id" {
  description = "Shared services EC2 instance ID."
  value       = try(aws_instance.shared[0].id, null)
}

output "shared_ami_id" {
  description = "Shared services AMI ID."
  value       = try(aws_instance.shared[0].ami, null)
}

output "shared_public_ip" {
  description = "Shared services public IPv4 address."
  value       = try(aws_instance.shared[0].public_ip, null)
}

output "shared_private_ip" {
  description = "Shared services private IPv4 address."
  value       = try(aws_instance.shared[0].private_ip, null)
}

output "shared_postgres_port" {
  description = "Shared Postgres TCP port."
  value       = var.shared_postgres_port
}

output "shared_kafka_port" {
  description = "Shared Kafka TCP port."
  value       = var.shared_kafka_port
}

output "operator_instance_ids" {
  description = "Operator EC2 instance IDs."
  value       = aws_instance.operator[*].id
}

output "operator_ami_ids" {
  description = "Operator AMI IDs."
  value       = aws_instance.operator[*].ami
}

output "operator_public_ips" {
  description = "Operator public IPv4 addresses."
  value       = aws_instance.operator[*].public_ip
}

output "operator_private_ips" {
  description = "Operator private IPv4 addresses."
  value       = aws_instance.operator[*].private_ip
}

output "effective_instance_profile" {
  description = "IAM instance profile attached to runner/operator/shared hosts."
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
