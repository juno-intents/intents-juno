variable "aws_region" {
  type = string
}

variable "deployment_id" {
  type = string
}

variable "zone_id" {
  type = string
  default = ""
}

variable "manage_dns_records" {
  type    = bool
  default = true

  validation {
    condition     = var.manage_dns_records || var.viewer_certificate_arn != ""
    error_message = "viewer_certificate_arn must be set when manage_dns_records is false."
  }
}

variable "bridge_record_name" {
  type = string
}

variable "origin_record_name" {
  type = string
}

variable "public_lb_dns_name" {
  type = string
}

variable "origin_http_port" {
  type    = number
  default = 443
}

variable "security_group_id" {
  type    = string
  default = ""
}

variable "viewer_certificate_arn" {
  type    = string
  default = ""
}

variable "rate_limit" {
  type    = number
  default = 2000
}

variable "enable_shield_advanced" {
  type    = bool
  default = false
}

variable "alarm_actions" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.alarm_actions) > 0
    error_message = "alarm_actions must include at least one CloudWatch action ARN."
  }
}
