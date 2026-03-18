#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
source "$REPO_ROOT/deploy/production/tests/common_test.sh"

main() {
  local main_tf variables_tf bridge_a bridge_aaaa backoffice_a backoffice_aaaa

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
  backoffice_a="$(awk '
    /resource "aws_route53_record" "backoffice_alias_a" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"
  backoffice_aaaa="$(awk '
    /resource "aws_route53_record" "backoffice_alias_aaaa" \{/ { in_block = 1 }
    in_block { print }
    in_block && /^\}/ { exit }
  ' "$SCRIPT_DIR/main.tf")"

  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_a"' "bridge A record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "bridge_alias_aaaa"' "bridge AAAA record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_a"' "backoffice A record exists"
  assert_contains "$main_tf" 'resource "aws_route53_record" "backoffice_alias_aaaa"' "backoffice AAAA record exists"

  assert_contains "$bridge_a" 'allow_overwrite = true' "bridge A record allows overwrite for replay-safe preview deploys"
  assert_contains "$bridge_aaaa" 'allow_overwrite = true' "bridge AAAA record allows overwrite for replay-safe preview deploys"
  assert_contains "$backoffice_a" 'allow_overwrite = true' "backoffice A record allows overwrite for replay-safe preview deploys"
  assert_contains "$backoffice_aaaa" 'allow_overwrite = true' "backoffice AAAA record allows overwrite for replay-safe preview deploys"
  assert_contains "$main_tf" 'origin_protocol_policy = "https-only"' "CloudFront uses TLS on the origin leg"
  assert_contains "$main_tf" 'description       = "CloudFront origin HTTPS"' "origin ingress rule is scoped to HTTPS"
  assert_contains "$variables_tf" 'alarm_actions must include at least one CloudWatch action ARN.' "app-edge requires alarm actions"

  printf 'app_edge package_a_snapshot_test: PASS\n'
}

main "$@"
