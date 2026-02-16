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

