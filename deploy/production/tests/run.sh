#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

bash "$SCRIPT_DIR/lib_test.sh"
bash "$SCRIPT_DIR/deploy_coordinator_test.sh"
bash "$SCRIPT_DIR/deploy_operator_test.sh"
bash "$SCRIPT_DIR/rotate_operator_key_test.sh"
bash "$SCRIPT_DIR/rehearse_rollout_test.sh"
bash "$SCRIPT_DIR/package_mainnet_release_test.sh"
bash "$SCRIPT_DIR/canary_shared_services_test.sh"
bash "$SCRIPT_DIR/release_app_binaries_workflow_test.sh"
bash "$SCRIPT_DIR/canary_operator_boot_test.sh"
bash "$SCRIPT_DIR/deploy_app_host_test.sh"
bash "$SCRIPT_DIR/canary_app_host_test.sh"
bash "$SCRIPT_DIR/maintenance_scripts_test.sh"
bash "$SCRIPT_DIR/../../shared/terraform/production-shared/package_a_snapshot_test.sh"
bash "$SCRIPT_DIR/../../shared/terraform/live-e2e/package_a_snapshot_test.sh"
bash "$SCRIPT_DIR/../../shared/terraform/app-edge/package_a_snapshot_test.sh"
echo "production shell tests: PASS"
