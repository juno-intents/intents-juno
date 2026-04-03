variable "aws_region" {
  description = "AWS region for app runtime resources."
  type        = string
}

variable "deployment_id" {
  description = "Deployment identifier used in resource names and tags."
  type        = string
}

variable "vpc_id" {
  description = "VPC identifier for the app runtime stack."
  type        = string
}

variable "public_subnet_ids" {
  description = "At least two public subnet IDs across AZs for the public bridge load balancer."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "At least two public subnet IDs across AZs for the public bridge load balancer."
  }
}

variable "private_subnet_ids" {
  description = "At least two private subnet IDs across AZs for the app autoscaling group."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two private subnet IDs across AZs for the app autoscaling group."
  }
}

variable "app_ami_id" {
  description = "AMI id for the immutable app instances."
  type        = string
}

variable "app_instance_profile_name" {
  description = "IAM instance profile name attached to app instances."
  type        = string
}

variable "app_instance_type" {
  description = "EC2 instance type for the app autoscaling group."
  type        = string
  default     = "t3.large"
}

variable "app_min_size" {
  description = "Minimum app autoscaling group size."
  type        = number
  default     = 2
}

variable "app_desired_capacity" {
  description = "Desired app autoscaling group size."
  type        = number
  default     = 2
}

variable "app_max_size" {
  description = "Maximum app autoscaling group size."
  type        = number
  default     = 4
}

variable "app_https_port" {
  description = "HTTPS port exposed by the instance-local proxy on app instances."
  type        = number
  default     = 443
}

variable "bridge_health_check_path" {
  description = "Health check path for the public bridge target group."
  type        = string
  default     = "/healthz"
}

variable "backoffice_health_check_path" {
  description = "Health check path for the internal backoffice target group."
  type        = string
  default     = "/healthz"
}

variable "public_bridge_certificate_arn" {
  description = "ACM certificate ARN for the public bridge load balancer listener."
  type        = string
}

variable "public_bridge_additional_certificate_arns" {
  description = "Additional ACM certificate ARNs attached to the public bridge load balancer listener."
  type        = list(string)
  default     = []
}

variable "internal_backoffice_certificate_arn" {
  description = "ACM certificate ARN for the internal backoffice load balancer listener."
  type        = string
}

variable "root_volume_size_gb" {
  description = "Root EBS volume size for app instances."
  type        = number
  default     = 50
}

variable "user_data" {
  description = "Raw cloud-init or shell bootstrap user data for app instances."
  type        = string
  default     = ""
}

variable "alarm_actions" {
  description = "CloudWatch action ARNs used for app runtime alarms."
  type        = list(string)

  validation {
    condition     = length(var.alarm_actions) > 0
    error_message = "alarm_actions must include at least one CloudWatch action ARN."
  }
}

variable "tags" {
  description = "Additional tags applied to app runtime resources."
  type        = map(string)
  default     = {}
}
