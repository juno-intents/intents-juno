#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

main() {
  local -a role_trace_paths=(
    "deploy/production/lib.sh"
    "deploy/production/deploy-operator.sh"
    "deploy/production/deploy-coordinator.sh"
    "deploy/production/canary-operator-boot.sh"
    "deploy/production/refresh-app-runtime.sh"
    "deploy/production/canary-app-host.sh"
    "deploy/production/update-deposit-scanner.sh"
    "deploy/production/package-mainnet-release.sh"
    "deploy/production/prepare-operator-handoff.sh"
    "deploy/production/run-operator-rollout.sh"
    "deploy/production/run-operator-local-canary.sh"
    "deploy/production/upgrade-operator.sh"
    "deploy/production/rotate-operator-key.sh"
    "deploy/production/schema/operator-deploy.example.json"
    "deploy/shared/runbooks/build-operator-stack-ami.sh"
    "deploy/production/tests/runtime_material_refs_test.sh"
    "deploy/production/tests/deploy_operator_live_test.sh"
    "deploy/production/tests/canary_operator_boot_live_test.sh"
    "deploy/production/tests/prepare_operator_handoff_test.sh"
    "deploy/production/tests/package_mainnet_release_live_test.sh"
    "deploy/production/tests/build_operator_stack_ami_test.sh"
  )
  local -a transport_paths=(
    "deploy/production/deploy-operator.sh"
    "deploy/production/deploy-coordinator.sh"
    "deploy/production/canary-operator-boot.sh"
    "deploy/production/refresh-app-runtime.sh"
    "deploy/production/canary-app-host.sh"
    "deploy/production/update-deposit-scanner.sh"
  )
  local -a schema_paths=(
    "deploy/production/schema/deployment-inventory.example.json"
    "deploy/production/schema/app-deploy.example.json"
    "deploy/production/schema/operator-deploy.example.json"
  )
  local -a disallowed_patterns=(
    "external de""ployer"
    "operator-""owned"
    "third-""party rollout"
  )
  local pattern matches

  cd "$REPO_ROOT"
  for pattern in "${disallowed_patterns[@]}"; do
    matches="$(git grep -n --fixed-strings -- "$pattern" -- "${role_trace_paths[@]}" || true)"
    if [[ -n "$matches" ]]; then
      printf 'disallowed role-trace pattern found: %s\n%s\n' "$pattern" "$matches" >&2
      exit 1
    fi
  done

  matches="$(git grep -nE '\bssh\b|\bscp\b' -- "${transport_paths[@]}" || true)"
  if [[ -n "$matches" ]]; then
    printf 'disallowed transport command found in hardened production entrypoints:\n%s\n' "$matches" >&2
    exit 1
  fi

  for pattern in "known_hosts_file" "secret_contract_file" "dkg_backup_zip"; do
    matches="$(git grep -n --fixed-strings -- "$pattern" -- "${schema_paths[@]}" || true)"
    if [[ -n "$matches" ]]; then
      printf 'legacy manifest field still present in hardened schema examples: %s\n%s\n' "$pattern" "$matches" >&2
      exit 1
    fi
  done

  matches="$(git grep -n --fixed-strings -- 'PRODUCTION_PREPARE_OPERATOR_HANDOFF_PRIVATE_KEY' -- deploy/production/prepare-operator-handoff.sh || true)"
  if [[ -n "$matches" ]]; then
    printf 'caller-supplied operator handoff private key path must not remain:\n%s\n' "$matches" >&2
    exit 1
  fi
}

main "$@"
