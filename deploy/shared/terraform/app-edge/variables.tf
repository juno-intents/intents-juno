variable "aws_region" {
  type = string
}

variable "deployment_id" {
  type = string
}

variable "zone_id" {
  type = string
}

variable "bridge_record_name" {
  type = string
}

variable "backoffice_record_name" {
  type = string
}

variable "origin_record_name" {
  type = string
}

variable "origin_endpoint" {
  type = string
}

variable "origin_http_port" {
  type    = number
  default = 80
}

variable "security_group_id" {
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
}
