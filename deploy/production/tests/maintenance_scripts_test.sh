#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
# shellcheck source=./common_test.sh
source "$SCRIPT_DIR/common_test.sh"

test_upgrade_operator_requires_known_hosts() {
  local tmp bin_dir
  tmp="$(mktemp -d)"
  bin_dir="$tmp/bin"
  mkdir -p "$bin_dir"
  printf 'binary\n' >"$bin_dir/checkpoint-signer"

  if (
    cd "$REPO_ROOT"
    deploy/production/upgrade-operator.sh \
      --operator-host operator.example \
      --binary-dir "$bin_dir" \
      --dry-run
  ) >/dev/null 2>&1; then
    printf 'expected upgrade-operator to require known-hosts\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

test_update_deposit_scanner_requires_known_hosts() {
  if (
    cd "$REPO_ROOT"
    deploy/production/update-deposit-scanner.sh \
      --operator-host operator.example \
      --juno-scan-url http://127.0.0.1:8080 \
      --juno-scan-wallet-id wallet-op1 \
      --juno-rpc-url http://127.0.0.1:18232 \
      --dry-run
  ) >/dev/null 2>&1; then
    printf 'expected update-deposit-scanner to require known-hosts\n' >&2
    exit 1
  fi
}

main() {
  test_upgrade_operator_requires_known_hosts
  test_update_deposit_scanner_requires_known_hosts
}

main "$@"
