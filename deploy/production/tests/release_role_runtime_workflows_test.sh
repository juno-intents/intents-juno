#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

main() {
  local app_workflow wireguard_workflow all_workflows
  app_workflow="$(cat "$REPO_ROOT/.github/workflows/release-app-runtime-ami.yml")"
  wireguard_workflow="$(cat "$REPO_ROOT/.github/workflows/release-wireguard-role-ami.yml")"
  all_workflows="$(
    cat \
      "$REPO_ROOT/.github/workflows/release-app-runtime-ami.yml" \
      "$REPO_ROOT/.github/workflows/release-shared-proof-services-image.yml" \
      "$REPO_ROOT/.github/workflows/release-wireguard-role-ami.yml" \
      "$REPO_ROOT/.github/workflows/release-operator-stack-ami.yml" \
      "$REPO_ROOT/.github/workflows/deploy-preview-role-runtime.yml" \
      "$REPO_ROOT/.github/workflows/deploy-mainnet-role-runtime.yml" \
      "$REPO_ROOT/.github/workflows/reset-preview-role-runtime.yml"
  )"

  assert_contains "$app_workflow" 'app_binaries_release_tag' "app runtime ami workflow requires the pinned app-binaries release tag"
  assert_contains "$app_workflow" 'app-runtime-ami-manifest.json' "app runtime ami workflow publishes the app runtime manifest"
  assert_contains "$app_workflow" 'app-runtime-ami-manifest.json.sha256' "app runtime ami workflow publishes the app runtime checksum"
  assert_contains "$app_workflow" 'must not use latest tags' "app runtime ami workflow rejects latest tags"
  assert_contains "$app_workflow" 'gh release download "$app_binaries_release_tag"' "app runtime ami workflow downloads pinned app binaries"
  assert_contains "$app_workflow" 'cd /tmp/app-binaries' "app runtime ami workflow verifies app binaries before installation"
  assert_contains "$app_workflow" 'install -m 0755 /tmp/app-binaries/bridge-api_linux_amd64 /usr/local/bin/bridge-api' "app runtime ami workflow installs bridge-api after checksum verification"
  assert_contains "$app_workflow" 'snap list amazon-ssm-agent' "app runtime ami workflow detects the preinstalled snap-based SSM agent"
  assert_contains "$app_workflow" 'snap.amazon-ssm-agent.amazon-ssm-agent.service' "app runtime ami workflow manages the snap-based SSM service when present"
  assert_contains "$app_workflow" 'amazon-ssm-agent.deb' "app runtime ami workflow keeps a deb-based SSM fallback"
  assert_contains "$app_workflow" 'aws-actions/configure-aws-credentials@v4' "app runtime ami workflow configures AWS credentials"
  assert_contains "$app_workflow" "if: \${{ env.AWS_ROLE_TO_ASSUME != '' }}" "app runtime ami workflow prefers role auth when a role is configured"
  assert_contains "$app_workflow" "if: \${{ env.AWS_ROLE_TO_ASSUME == '' && env.AWS_STATIC_ACCESS_KEY_ID != '' && env.AWS_STATIC_SECRET_ACCESS_KEY != '' }}" "app runtime ami workflow only uses static keys when no role is configured"

  assert_contains "$wireguard_workflow" 'wireguard-role-ami-manifest.json' "wireguard ami workflow publishes the wireguard manifest"
  assert_contains "$wireguard_workflow" 'wireguard-role-ami-manifest.json.sha256' "wireguard ami workflow publishes the wireguard checksum"
  assert_contains "$wireguard_workflow" 'must not use latest tags' "wireguard ami workflow rejects latest tags"
  assert_contains "$wireguard_workflow" 'aws-actions/configure-aws-credentials@v4' "wireguard ami workflow configures AWS credentials"
  assert_contains "$wireguard_workflow" "if: \${{ env.AWS_ROLE_TO_ASSUME != '' }}" "wireguard ami workflow prefers role auth when a role is configured"
  assert_contains "$wireguard_workflow" "if: \${{ env.AWS_ROLE_TO_ASSUME == '' && env.AWS_STATIC_ACCESS_KEY_ID != '' && env.AWS_STATIC_SECRET_ACCESS_KEY != '' }}" "wireguard ami workflow only uses static keys when no role is configured"
  assert_contains "$wireguard_workflow" 'Create or Update Release' "wireguard ami workflow uploads release assets"

  assert_contains "$all_workflows" "if: \${{ env.AWS_ROLE_TO_ASSUME != '' }}" "AWS-backed release and deploy workflows prefer role auth when available"
  assert_contains "$all_workflows" "if: \${{ env.AWS_ROLE_TO_ASSUME == '' && env.AWS_STATIC_ACCESS_KEY_ID != '' && env.AWS_STATIC_SECRET_ACCESS_KEY != '' }}" "AWS-backed release and deploy workflows only use static keys when no role is configured"
}

main "$@"
