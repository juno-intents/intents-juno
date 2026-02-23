#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/common_test.sh"
"$SCRIPT_DIR/operator_test.sh"
"$SCRIPT_DIR/operator_export_test.sh"
"$SCRIPT_DIR/backup_package_test.sh"
"$SCRIPT_DIR/test_completion_test.sh"
"$SCRIPT_DIR/generate_witness_metadata_test.sh"
"$SCRIPT_DIR/run_testnet_e2e_test.sh"
"$SCRIPT_DIR/e2e_aws_checkpoint_deferral_test.sh"
"$SCRIPT_DIR/live_e2e_terraform_iam_test.sh"
echo "dkg shell tests: PASS"
