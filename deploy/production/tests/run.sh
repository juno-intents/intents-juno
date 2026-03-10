#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

bash "$SCRIPT_DIR/lib_test.sh"
bash "$SCRIPT_DIR/deploy_coordinator_test.sh"
bash "$SCRIPT_DIR/deploy_operator_test.sh"
bash "$SCRIPT_DIR/canary_shared_services_test.sh"
bash "$SCRIPT_DIR/canary_operator_boot_test.sh"
bash "$SCRIPT_DIR/maintenance_scripts_test.sh"
echo "production shell tests: PASS"
