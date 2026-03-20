#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

main() {
  local preview_workflow reset_preview_workflow mainnet_workflow
  preview_workflow="$(cat "$REPO_ROOT/.github/workflows/deploy-preview-role-runtime.yml")"
  reset_preview_workflow="$(cat "$REPO_ROOT/.github/workflows/reset-preview-role-runtime.yml")"
  mainnet_workflow="$(cat "$REPO_ROOT/.github/workflows/deploy-mainnet-role-runtime.yml")"

  assert_contains "$preview_workflow" 'app_binaries_release_tag' "preview deploy workflow requires the app-binaries release tag"
  assert_contains "$preview_workflow" 'app_runtime_ami_release_tag' "preview deploy workflow requires the app runtime ami release tag"
  assert_contains "$preview_workflow" 'shared_proof_services_image_release_tag' "preview deploy workflow requires the shared proof image release tag"
  assert_contains "$preview_workflow" 'wireguard_role_ami_release_tag' "preview deploy workflow requires the wireguard ami release tag"
  assert_contains "$preview_workflow" 'operator_stack_ami_release_tag' "preview deploy workflow accepts the operator stack ami tag"
  assert_contains "$preview_workflow" 'resolve-role-runtime-release-inputs.sh' "preview deploy workflow resolves pinned role runtime release manifests"
  assert_contains "$preview_workflow" 'deploy-coordinator.sh' "preview deploy workflow drives the production coordinator"
  assert_contains "$preview_workflow" 'provision-app-edge.sh' "preview deploy workflow provisions the app edge after coordinator rendering"
  assert_contains "$preview_workflow" 'canary-shared-services.sh' "preview deploy workflow runs the shared services canary"
  assert_contains "$preview_workflow" 'canary-app-host.sh' "preview deploy workflow runs the app canary"
  assert_contains "$preview_workflow" 'shared-infra-e2e_linux_amd64' "preview deploy workflow downloads the released shared-infra-e2e binary"
  assert_contains "$preview_workflow" 'role-runtime-release-lock.json' "preview deploy workflow publishes a release lock artifact"
  assert_contains "$preview_workflow" 'must not use latest tags' "preview deploy workflow rejects latest tags"

  assert_contains "$reset_preview_workflow" 'operator_stack_ami_release_tag' "preview reset workflow requires the operator stack ami tag"
  assert_contains "$reset_preview_workflow" 'upgrade-preview-inventory.sh' "preview reset workflow upgrades legacy preview inputs into the role runtime contract"
  assert_contains "$reset_preview_workflow" 'destroy-preview-role-runtime.sh' "preview reset workflow destroys the current preview role runtime before rebuild"
  assert_contains "$reset_preview_workflow" 'roll-preview-operators.sh' "preview reset workflow refreshes operators after the shared and app rebuild"
  assert_contains "$reset_preview_workflow" 'shared-infra-e2e_linux_amd64' "preview reset workflow downloads the released shared-infra-e2e binary"
  assert_contains "$reset_preview_workflow" 'role-runtime-release-lock.json' "preview reset workflow publishes a release lock artifact"
  assert_contains "$reset_preview_workflow" 'must not use latest tags' "preview reset workflow rejects latest tags"

  assert_contains "$mainnet_workflow" 'preview_run_id' "mainnet deploy workflow requires the preview workflow run id"
  assert_contains "$mainnet_workflow" 'environment: production' "mainnet deploy workflow is gated by the production environment"
  assert_contains "$mainnet_workflow" 'role-runtime-release-lock.json' "mainnet deploy workflow reads the preview release lock artifact"
  assert_contains "$mainnet_workflow" '86400' "mainnet deploy workflow enforces a 24 hour preview soak"
  assert_contains "$mainnet_workflow" 'reset-preview-role-runtime' "mainnet deploy workflow accepts the reset preview workflow as the promotion source"
  assert_contains "$mainnet_workflow" 'resolve-role-runtime-release-inputs.sh' "mainnet deploy workflow resolves pinned role runtime release manifests"
  assert_contains "$mainnet_workflow" 'deploy-coordinator.sh' "mainnet deploy workflow drives the production coordinator"
  assert_contains "$mainnet_workflow" 'must not use latest tags' "mainnet deploy workflow rejects latest tags"
}

main "$@"
