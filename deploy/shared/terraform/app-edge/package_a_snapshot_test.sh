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
  local main_tf variables_tf bridge_a bridge_aaaa

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

  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_a"' "bridge A record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_aaaa"' "bridge AAAA record exists"
  assert_not_contains "$main_tf" 'aws_cloudfront_distribution.backoffice' "backoffice no longer rides the public edge"
  assert_not_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_a"' "backoffice A alias removed from app-edge"
  assert_not_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_aaaa"' "backoffice AAAA alias removed from app-edge"
  assert_not_contains "$variables_tf" 'variable "backoffice_record_name"' "app-edge no longer accepts a backoffice hostname"

  assert_contains "$bridge_a" 'allow_overwrite = true' "bridge A record allows overwrite for replay-safe preview deploys"
  assert_contains "$bridge_aaaa" 'allow_overwrite = true' "bridge AAAA record allows overwrite for replay-safe preview deploys"
  assert_contains "$main_tf" 'origin_protocol_policy = "https-only"' "CloudFront uses TLS on the origin leg"
  assert_contains "$main_tf" 'description       = "CloudFront origin HTTPS"' "origin ingress rule is scoped to HTTPS"
  assert_contains "$variables_tf" 'alarm_actions must include at least one CloudWatch action ARN.' "app-edge requires alarm actions"

  printf 'app_edge package_a_snapshot_test: PASS\n'
}

main "$@"
