#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
source "$REPO_ROOT/deploy/production/tests/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

main() {
  local main_tf variables_tf outputs_tf versions_tf app_asg app_lt public_lb internal_lb

  main_tf="$(cat "$SCRIPT_DIR/main.tf")"
  variables_tf="$(cat "$SCRIPT_DIR/variables.tf")"
  outputs_tf="$(cat "$SCRIPT_DIR/outputs.tf")"
  versions_tf="$(cat "$SCRIPT_DIR/versions.tf")"
  app_asg="$(awk '
    /resource "aws_autoscaling_group" "app" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  app_lt="$(awk '
    /resource "aws_launch_template" "app" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  public_lb="$(awk '
    /resource "aws_lb" "public_bridge" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  internal_lb="$(awk '
    /resource "aws_lb" "internal_backoffice" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"

  assert_contains "$main_tf" 'resource "aws_launch_template" "app"' "app-runtime provisions an app launch template"
  assert_contains "$main_tf" 'resource "aws_autoscaling_group" "app"' "app-runtime provisions an app autoscaling group"
  assert_contains "$main_tf" 'resource "aws_lb" "public_bridge"' "app-runtime provisions a public bridge load balancer"
  assert_contains "$main_tf" 'resource "aws_lb" "internal_backoffice"' "app-runtime provisions an internal backoffice load balancer"
  assert_contains "$main_tf" 'resource "aws_lb_target_group" "bridge"' "app-runtime provisions a public bridge target group"
  assert_contains "$main_tf" 'resource "aws_lb_target_group" "backoffice"' "app-runtime provisions an internal backoffice target group"
  assert_contains "$main_tf" 'resource "aws_lb_listener" "public_bridge_https"' "app-runtime provisions a public bridge HTTPS listener"
  assert_contains "$main_tf" 'resource "aws_lb_listener_certificate" "public_bridge_additional"' "app-runtime can attach additional TLS certificates to the public bridge listener"
  assert_contains "$main_tf" 'resource "aws_lb_listener" "internal_backoffice_https"' "app-runtime provisions an internal backoffice HTTPS listener"
  assert_contains "$main_tf" 'resource "aws_security_group" "app"' "app-runtime provisions an app instance security group"
  assert_contains "$main_tf" 'resource "aws_security_group" "public_bridge_lb"' "app-runtime provisions a public bridge load balancer security group"
  assert_contains "$main_tf" 'resource "aws_security_group" "internal_backoffice_lb"' "app-runtime provisions an internal backoffice load balancer security group"
  assert_contains "$main_tf" 'public_bridge_alb_name        = trimsuffix(substr("${local.resource_slug}-bridge", 0, 32), "-")' "app-runtime trims trailing hyphens from public ALB names"
  assert_contains "$main_tf" 'public_bridge_targetgrp_name  = trimsuffix(substr("${local.resource_slug}-bridge-tg", 0, 32), "-")' "app-runtime trims trailing hyphens from public target group names"
  assert_contains "$main_tf" 'internal_backoffice_tg_name   = trimsuffix(substr("${local.resource_slug}-backoffice-tg", 0, 32), "-")' "app-runtime trims trailing hyphens from backoffice target group names"
  assert_contains "$main_tf" 'resource "aws_cloudwatch_metric_alarm" "app_in_service"' "app-runtime alarms on autoscaling in-service capacity"
  assert_contains "$main_tf" 'resource "aws_cloudwatch_metric_alarm" "public_bridge_5xx"' "app-runtime alarms on public bridge 5xxs"
  assert_contains "$main_tf" 'resource "aws_cloudwatch_metric_alarm" "internal_backoffice_unhealthy_hosts"' "app-runtime alarms on unhealthy backoffice targets"

  assert_contains "$app_lt" 'base64encode(var.user_data)' "app-runtime launch template base64-encodes user data"
  assert_contains "$app_lt" 'vpc_security_group_ids = [aws_security_group.app.id]' "app-runtime launch template binds the app security group"
  assert_contains "$app_asg" 'desired_capacity          = var.app_desired_capacity' "app-runtime keeps desired app capacity configurable"
  assert_contains "$app_asg" 'min_size                  = var.app_min_size' "app-runtime keeps app minimum capacity configurable"
  assert_contains "$app_asg" 'max_size                  = var.app_max_size' "app-runtime keeps app maximum capacity configurable"
  assert_contains "$app_asg" 'force_delete              = true' "app-runtime force-deletes stale preview asg members during teardown"
  assert_contains "$app_asg" 'health_check_type         = "ELB"' "app-runtime uses load balancer health checks for app instances"
  assert_contains "$app_asg" 'vpc_zone_identifier       = var.private_subnet_ids' "app-runtime keeps app instances on private subnets"
  assert_contains "$app_asg" 'target_group_arns         = [aws_lb_target_group.bridge.arn, aws_lb_target_group.backoffice.arn]' "app-runtime registers app instances behind both target groups"
  assert_contains "$main_tf" 'strategy = "Rolling"' "app-runtime uses rolling instance refresh"
  assert_contains "$main_tf" 'triggers = ["launch_template"]' "app-runtime refreshes instances on launch template changes"

  assert_contains "$public_lb" 'internal                         = false' "public bridge load balancer stays internet-facing"
  assert_contains "$public_lb" 'load_balancer_type               = "application"' "public bridge load balancer uses ALB semantics"
  assert_contains "$public_lb" 'enable_cross_zone_load_balancing = true' "public bridge load balancer keeps cross-zone balancing enabled"
  assert_contains "$internal_lb" 'internal                         = true' "internal backoffice load balancer stays private"
  assert_contains "$internal_lb" 'enable_cross_zone_load_balancing = true' "internal backoffice load balancer keeps cross-zone balancing enabled"

  assert_contains "$main_tf" 'data "aws_vpc" "selected"' "app-runtime resolves the selected vpc for internal backoffice ingress"
  assert_contains "$main_tf" 'cidr_blocks = [data.aws_vpc.selected.cidr_block]' "internal backoffice ingress is limited to the VPC CIDR"
  assert_contains "$main_tf" 'security_groups = [aws_security_group.public_bridge_lb.id]' "app bridge ingress only trusts the public load balancer security group"
  assert_contains "$main_tf" 'security_groups = [aws_security_group.internal_backoffice_lb.id]' "app backoffice ingress only trusts the internal load balancer security group"

  assert_contains "$variables_tf" 'variable "app_ami_id"' "app-runtime requires an app AMI input"
  assert_contains "$variables_tf" 'variable "public_bridge_additional_certificate_arns"' "app-runtime accepts additional public bridge listener certificates"
  assert_contains "$variables_tf" 'variable "private_subnet_ids"' "app-runtime requires private app subnets"
  assert_contains "$variables_tf" 'variable "public_subnet_ids"' "app-runtime requires public bridge load balancer subnets"
  assert_not_contains "$variables_tf" 'variable "wireguard_cidr_blocks"' "app-runtime no longer requires WireGuard CIDR allowlisting"
  assert_contains "$variables_tf" 'alarm_actions must include at least one CloudWatch action ARN.' "app-runtime requires CloudWatch alarm actions"
  assert_contains "$variables_tf" 'At least two private subnet IDs across AZs for the app autoscaling group.' "app-runtime documents the private subnet requirement"
  assert_contains "$variables_tf" 'At least two public subnet IDs across AZs for the public bridge load balancer.' "app-runtime documents the public subnet requirement"
  assert_contains "$versions_tf" 'backend "s3" {}' "app-runtime declares an s3 backend block for coordinator bootstrap"

  assert_contains "$outputs_tf" 'output "app_role"' "app-runtime exports a structured app role object"
  assert_contains "$outputs_tf" 'asg = aws_autoscaling_group.app.name' "app-runtime structured output includes the app autoscaling group name"
  assert_contains "$outputs_tf" 'app_security_group_id = aws_security_group.app.id' "app-runtime structured output includes the app instance security group id"
  assert_contains "$outputs_tf" 'public_lb = {' "app-runtime structured output includes the public load balancer contract"
  assert_contains "$outputs_tf" 'internal_lb = {' "app-runtime structured output includes the internal load balancer contract"
  assert_contains "$outputs_tf" 'target_group_arn  = aws_lb_target_group.bridge.arn' "app-runtime structured output includes the public bridge target group arn"
  assert_contains "$outputs_tf" 'target_group_arn  = aws_lb_target_group.backoffice.arn' "app-runtime structured output includes the internal backoffice target group arn"
  assert_contains "$outputs_tf" 'output "app_role_asg_name"' "app-runtime exports the app autoscaling group name"
  assert_contains "$outputs_tf" 'output "app_security_group_id"' "app-runtime exports the app instance security group id"
  assert_contains "$outputs_tf" 'output "app_role_launch_template_id"' "app-runtime exports the app launch template id"
  assert_contains "$outputs_tf" 'output "app_role_launch_template_latest_version"' "app-runtime exports the app launch template version"
  assert_contains "$outputs_tf" 'output "public_bridge_lb_dns_name"' "app-runtime exports the public bridge load balancer DNS name"
  assert_contains "$outputs_tf" 'output "public_bridge_lb_zone_id"' "app-runtime exports the public bridge load balancer hosted zone id"
  assert_contains "$outputs_tf" 'output "internal_backoffice_lb_dns_name"' "app-runtime exports the internal backoffice load balancer DNS name"
  assert_contains "$outputs_tf" 'output "internal_backoffice_lb_zone_id"' "app-runtime exports the internal backoffice load balancer hosted zone id"
  assert_contains "$outputs_tf" 'output "public_bridge_lb_security_group_id"' "app-runtime exports the public bridge load balancer security group id"
  assert_contains "$outputs_tf" 'output "internal_backoffice_lb_security_group_id"' "app-runtime exports the internal backoffice load balancer security group id"

  printf 'app_runtime package_a_snapshot_test: PASS\n'
}

main "$@"
