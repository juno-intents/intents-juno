#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
TARGET_TERRAFORM="$REPO_ROOT/deploy/shared/terraform/live-e2e/main.tf"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

main() {
  local terraform_text
  terraform_text="$(cat "$TARGET_TERRAFORM")"

  assert_contains "$terraform_text" "AllowSharedECSServiceRollout" "runner role includes explicit ecs rollout permissions for shared proof services"
  assert_contains "$terraform_text" "\"ecs:DescribeServices\"" "runner role can describe shared ecs services"
  assert_contains "$terraform_text" "\"ecs:DescribeTaskDefinition\"" "runner role can describe shared ecs task definitions"
  assert_contains "$terraform_text" "\"ecs:RegisterTaskDefinition\"" "runner role can register updated shared ecs task definitions"
  assert_contains "$terraform_text" "\"ecs:UpdateService\"" "runner role can update shared ecs services"
  assert_contains "$terraform_text" "AllowPassSharedECSTaskExecutionRole" "runner role includes passrole statement for ecs task execution role"
  assert_contains "$terraform_text" "\"iam:PassRole\"" "runner role can pass task execution role for ecs rollout"
  assert_contains "$terraform_text" "iam:PassedToService" "passrole statement constrains target service"
  assert_contains "$terraform_text" "\"ecs-tasks.amazonaws.com\"" "passrole statement targets ecs tasks service principal"
  assert_contains "$terraform_text" "AllowSharedECSLogTail" "runner role includes cloudwatch logs permissions for shared proof service tails"
  assert_contains "$terraform_text" "\"logs:FilterLogEvents\"" "runner role can tail shared proof service logs"
}

main "$@"
