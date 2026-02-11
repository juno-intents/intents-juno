#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/common_test.sh"
"$SCRIPT_DIR/operator_test.sh"
"$SCRIPT_DIR/operator_export_test.sh"
"$SCRIPT_DIR/test_completion_test.sh"
echo "dkg shell tests: PASS"
