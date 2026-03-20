#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

main() {
  local app_workflow wireguard_workflow
  app_workflow="$(cat "$REPO_ROOT/.github/workflows/release-app-runtime-ami.yml")"
  wireguard_workflow="$(cat "$REPO_ROOT/.github/workflows/release-wireguard-role-ami.yml")"

  assert_contains "$app_workflow" 'app_binaries_release_tag' "app runtime ami workflow requires the pinned app-binaries release tag"
  assert_contains "$app_workflow" 'app-runtime-ami-manifest.json' "app runtime ami workflow publishes the app runtime manifest"
  assert_contains "$app_workflow" 'app-runtime-ami-manifest.json.sha256' "app runtime ami workflow publishes the app runtime checksum"
  assert_contains "$app_workflow" 'must not use latest tags' "app runtime ami workflow rejects latest tags"
  assert_contains "$app_workflow" 'gh release download "$app_binaries_release_tag"' "app runtime ami workflow downloads pinned app binaries"
  assert_contains "$app_workflow" 'aws-actions/configure-aws-credentials@v4' "app runtime ami workflow configures AWS credentials"

  assert_contains "$wireguard_workflow" 'wireguard-role-ami-manifest.json' "wireguard ami workflow publishes the wireguard manifest"
  assert_contains "$wireguard_workflow" 'wireguard-role-ami-manifest.json.sha256' "wireguard ami workflow publishes the wireguard checksum"
  assert_contains "$wireguard_workflow" 'must not use latest tags' "wireguard ami workflow rejects latest tags"
  assert_contains "$wireguard_workflow" 'aws-actions/configure-aws-credentials@v4' "wireguard ami workflow configures AWS credentials"
  assert_contains "$wireguard_workflow" 'Create or Update Release' "wireguard ami workflow uploads release assets"
}

main "$@"
