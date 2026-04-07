#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

main() {
  local workflow_text
  workflow_text="$(cat "$REPO_ROOT/.github/workflows/release-app-binaries.yml")"

  assert_contains "$workflow_text" 'go build -o .ci/out/bridge-deploy_linux_amd64 ./cmd/bridge-deploy' "release workflow builds bridge-deploy"
  assert_contains "$workflow_text" 'go build -o .ci/out/deposit-relayer_linux_amd64 ./cmd/deposit-relayer' "release workflow builds deposit-relayer"
  assert_contains "$workflow_text" 'go build -o .ci/out/withdraw-coordinator_linux_amd64 ./cmd/withdraw-coordinator' "release workflow builds withdraw-coordinator"
  assert_contains "$workflow_text" 'go build -o .ci/out/withdraw-finalizer_linux_amd64 ./cmd/withdraw-finalizer' "release workflow builds withdraw-finalizer"
  assert_contains "$workflow_text" 'go build -o .ci/out/base-event-scanner_linux_amd64 ./cmd/base-event-scanner' "release workflow builds base-event-scanner"
  assert_contains "$workflow_text" 'sha256sum bridge-deploy_linux_amd64 > bridge-deploy_linux_amd64.sha256' "release workflow hashes bridge-deploy"
  assert_contains "$workflow_text" 'sha256sum deposit-relayer_linux_amd64 > deposit-relayer_linux_amd64.sha256' "release workflow hashes deposit-relayer"
  assert_contains "$workflow_text" 'sha256sum withdraw-coordinator_linux_amd64 > withdraw-coordinator_linux_amd64.sha256' "release workflow hashes withdraw-coordinator"
  assert_contains "$workflow_text" 'sha256sum withdraw-finalizer_linux_amd64 > withdraw-finalizer_linux_amd64.sha256' "release workflow hashes withdraw-finalizer"
  assert_contains "$workflow_text" 'sha256sum base-event-scanner_linux_amd64 > base-event-scanner_linux_amd64.sha256' "release workflow hashes base-event-scanner"
  assert_contains "$workflow_text" '.ci/out/bridge-deploy_linux_amd64' "release workflow uploads bridge-deploy"
  assert_contains "$workflow_text" '.ci/out/deposit-relayer_linux_amd64' "release workflow uploads deposit-relayer"
  assert_contains "$workflow_text" '.ci/out/withdraw-coordinator_linux_amd64' "release workflow uploads withdraw-coordinator"
  assert_contains "$workflow_text" '.ci/out/withdraw-finalizer_linux_amd64' "release workflow uploads withdraw-finalizer"
  assert_contains "$workflow_text" '.ci/out/base-event-scanner_linux_amd64' "release workflow uploads base-event-scanner"
  assert_contains "$workflow_text" 'FRONTEND_WALLETCONNECT_PROJECT_ID' "release workflow requires walletconnect build input"
  assert_contains "$workflow_text" 'VITE_BASE_CHAIN_ID=' "release workflow sets frontend base chain id by release tier"
}

main "$@"
