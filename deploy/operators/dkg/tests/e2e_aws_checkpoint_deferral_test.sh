#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
TARGET_SCRIPT="$REPO_ROOT/deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh"

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
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "staging hydrator config and restarting operator stack services on op" "wrapper stages hydrator config across operators"
  assert_contains "$script_text" "checkpoint-signer/checkpoint-aggregator restart deferred until bridge config is staged by remote e2e" "wrapper logs checkpoint restart deferral"
  assert_not_contains "$script_text" "sudo systemctl restart checkpoint-signer.service checkpoint-aggregator.service" "wrapper does not restart checkpoint services before bridge deployment config"
}

main "$@"
