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
  local main_tf variables_tf bridge_a bridge_aaaa origin_cname viewer_validation origin_port_block

  main_tf="$(cat "$SCRIPT_DIR/main.tf")"
  variables_tf="$(cat "$SCRIPT_DIR/variables.tf")"
  bridge_a="$(awk '
    /resource "aws_route53_record" "bridge_alias_a" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  bridge_aaaa="$(awk '
    /resource "aws_route53_record" "bridge_alias_aaaa" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  origin_cname="$(awk '
    /resource "aws_route53_record" "origin_cname" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  viewer_validation="$(awk '
    /resource "aws_route53_record" "viewer_validation" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  origin_port_block="$(awk '
    /variable "origin_http_port" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/variables.tf")"

  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_a"' "bridge A record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_aaaa"' "bridge AAAA record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "origin_cname"' "origin CNAME record exists for the app load balancer"
  assert_not_contains "$main_tf" 'resource "aws_route53_record" "origin_a"' "app-edge no longer aliases the origin directly to an instance IPv4"
  assert_not_contains "$main_tf" 'aws_cloudfront_distribution.backoffice' "backoffice no longer rides the public edge"
  assert_not_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_a"' "backoffice A alias removed from app-edge"
  assert_not_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_aaaa"' "backoffice AAAA alias removed from app-edge"
  assert_not_contains "$variables_tf" 'variable "backoffice_record_name"' "app-edge no longer accepts a backoffice hostname"
  assert_not_contains "$variables_tf" 'variable "origin_endpoint"' "app-edge no longer accepts a mutable instance endpoint"
  assert_contains "$variables_tf" 'variable "public_lb_dns_name"' "app-edge accepts the public app load balancer DNS name"
  assert_contains "$origin_cname" 'records = [var.public_lb_dns_name]' "origin CNAME points at the public app load balancer"
  assert_contains "$origin_cname" 'allow_overwrite = true' "origin CNAME allows overwrite for replay-safe preview deploys"
  assert_contains "$viewer_validation" 'allow_overwrite = true' "viewer certificate validation CNAMEs allow overwrite for replay-safe preview deploys"

  assert_contains "$bridge_a" 'allow_overwrite = true' "bridge A record allows overwrite for replay-safe preview deploys"
  assert_contains "$bridge_aaaa" 'allow_overwrite = true' "bridge AAAA record allows overwrite for replay-safe preview deploys"
  assert_contains "$main_tf" 'origin_protocol_policy = "https-only"' "CloudFront uses TLS on the origin leg"
  assert_not_contains "$main_tf" 'origin_path = "/bridge"' "CloudFront does not prefix origin requests with /bridge"
  assert_contains "$main_tf" 'http_port              = 80' "CloudFront keeps the origin HTTP port pinned away from app TLS"
  assert_contains "$main_tf" 'https_port             = var.origin_http_port' "CloudFront origin HTTPS port stays configurable"
  assert_contains "$main_tf" 'description       = "CloudFront origin HTTPS"' "origin ingress rule is scoped to HTTPS"
  assert_contains "$origin_port_block" 'default = 443' "app-edge defaults origin HTTPS to 443 for the app load balancer"
  assert_contains "$variables_tf" 'alarm_actions must include at least one CloudWatch action ARN.' "app-edge requires alarm actions"

  printf 'app_edge package_a_snapshot_test: PASS\n'
}

main "$@"
