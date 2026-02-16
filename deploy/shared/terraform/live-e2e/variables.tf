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
