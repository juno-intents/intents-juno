#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: unexpected=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

main() {
  local main_tf
  main_tf="$(cat "$REPO_ROOT/deploy/shared/terraform/live-e2e/main.tf")"

  assert_not_contains "$main_tf" "map-public-ip-on-launch" "no hard public-subnet discovery dependency"
  assert_not_contains "$main_tf" "associate_public_ip_address = true" "instance public IP association should be configurable"
  assert_not_contains "$main_tf" "assign_public_ip = true" "ecs public IP assignment should be configurable"
  assert_not_contains "$main_tf" "unauthenticated = true" "msk unauthenticated mode disabled"
  assert_not_contains "$main_tf" "TLS_PLAINTEXT" "msk plaintext client broker disabled"
  assert_contains "$main_tf" "client_broker = \"TLS\"" "msk client transport is tls-only"
}

main "$@"
