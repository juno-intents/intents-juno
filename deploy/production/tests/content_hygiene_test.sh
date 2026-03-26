#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

main() {
  local -a scan_paths=(
    "deploy/production/lib.sh"
    "deploy/production/deploy-operator.sh"
    "deploy/production/canary-operator-boot.sh"
    "deploy/production/package-mainnet-release.sh"
    "deploy/production/prepare-runtime-materials.sh"
    "deploy/production/run-operator-rollout.sh"
    "deploy/production/run-operator-local-canary.sh"
    "deploy/production/schema/operator-deploy.example.json"
    "deploy/shared/runbooks/build-operator-stack-ami.sh"
    "deploy/production/tests/runtime_material_refs_test.sh"
    "deploy/production/tests/deploy_operator_live_test.sh"
    "deploy/production/tests/canary_operator_boot_live_test.sh"
    "deploy/production/tests/prepare_runtime_materials_test.sh"
    "deploy/production/tests/package_mainnet_release_live_test.sh"
    "deploy/production/tests/build_operator_stack_ami_test.sh"
  )
  local -a disallowed_patterns=(
    "de""ployer"
    "external de""ployer"
    "operator-""owned"
    "third-""party rollout"
  )
  local pattern matches

  cd "$REPO_ROOT"
  for pattern in "${disallowed_patterns[@]}"; do
    matches="$(git grep -n --fixed-strings -- "$pattern" -- "${scan_paths[@]}" || true)"
    if [[ -n "$matches" ]]; then
      printf 'disallowed role-trace pattern found: %s\n%s\n' "$pattern" "$matches" >&2
      exit 1
    fi
  done
}

main "$@"
