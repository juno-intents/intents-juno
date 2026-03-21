output "app_role" {
  description = "Structured app role contract for deployment handoffs."
  value = {
    asg = aws_autoscaling_group.app.name
    app_security_group_id = aws_security_group.app.id
    launch_template = {
      id      = aws_launch_template.app.id
      version = tostring(aws_launch_template.app.latest_version)
    }
    public_lb = {
      dns_name          = aws_lb.public_bridge.dns_name
      zone_id           = aws_lb.public_bridge.zone_id
      security_group_id = aws_security_group.public_bridge_lb.id
      target_group_arn  = aws_lb_target_group.bridge.arn
    }
    internal_lb = {
      dns_name          = aws_lb.internal_backoffice.dns_name
      zone_id           = aws_lb.internal_backoffice.zone_id
      security_group_id = aws_security_group.internal_backoffice_lb.id
      target_group_arn  = aws_lb_target_group.backoffice.arn
    }
  }
}

output "app_role_asg_name" {
  description = "App autoscaling group name."
  value       = aws_autoscaling_group.app.name
}

output "app_security_group_id" {
  description = "Security group id attached to app instances."
  value       = aws_security_group.app.id
}

output "app_role_launch_template_id" {
  description = "App launch template id."
  value       = aws_launch_template.app.id
}

output "app_role_launch_template_latest_version" {
  description = "Latest app launch template version."
  value       = aws_launch_template.app.latest_version
}

output "public_bridge_lb_dns_name" {
  description = "Public bridge load balancer DNS name."
  value       = aws_lb.public_bridge.dns_name
}

output "public_bridge_lb_zone_id" {
  description = "Public bridge load balancer hosted zone id."
  value       = aws_lb.public_bridge.zone_id
}

output "public_bridge_lb_security_group_id" {
  description = "Security group id attached to the public bridge load balancer."
  value       = aws_security_group.public_bridge_lb.id
}

output "internal_backoffice_lb_dns_name" {
  description = "Internal backoffice load balancer DNS name."
  value       = aws_lb.internal_backoffice.dns_name
}

output "internal_backoffice_lb_zone_id" {
  description = "Internal backoffice load balancer hosted zone id."
  value       = aws_lb.internal_backoffice.zone_id
}

output "internal_backoffice_lb_security_group_id" {
  description = "Security group id attached to the internal backoffice load balancer."
  value       = aws_security_group.internal_backoffice_lb.id
}
