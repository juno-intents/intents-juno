output "runner_instance_id" {
  description = "Runner EC2 instance ID."
  value       = aws_instance.runner.id
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

output "operator_public_ips" {
  description = "Operator public IPv4 addresses."
  value       = aws_instance.operator[*].public_ip
}

output "operator_private_ips" {
  description = "Operator private IPv4 addresses."
  value       = aws_instance.operator[*].private_ip
}
