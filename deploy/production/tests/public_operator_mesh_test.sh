#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"
# shellcheck source=../lib.sh
source "$REPO_ROOT/deploy/production/lib.sh"

test_default_operator_endpoints_prefer_private_operator_hosts() {
  local workdir fake_bin inventory_json old_path endpoints_json
  workdir="$(mktemp -d)"
  fake_bin="$workdir/bin"
  inventory_json="$workdir/inventory.json"
  mkdir -p "$fake_bin"

  cat >"$inventory_json" <<'EOF'
{
  "operators": [
    {
      "index": 1,
      "operator_id": "0x1111111111111111111111111111111111111111",
      "operator_address": "0x9999999999999999999999999999999999999999",
      "operator_host": "10.0.0.11",
      "public_endpoint": "203.0.113.11",
      "aws_profile": "op1",
      "aws_region": "us-west-2"
    },
    {
      "index": 2,
      "operator_id": "0x2222222222222222222222222222222222222222",
      "operator_address": "0x8888888888888888888888888888888888888888",
      "private_endpoint": "10.0.0.22",
      "public_endpoint": "203.0.113.22",
      "aws_profile": "op2",
      "aws_region": "us-east-2"
    }
  ]
}
EOF

  cat >"$fake_bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '10.0.0.12\n'
EOF
  chmod 0755 "$fake_bin/aws"

  old_path="$PATH"
  PATH="$fake_bin:$PATH"
  endpoints_json="$(production_default_operator_endpoints_json "$inventory_json")"
  PATH="$old_path"

  assert_eq "$(jq -r '.[0]' <<<"$endpoints_json")" "0x9999999999999999999999999999999999999999=10.0.0.11:18443" "operator mesh prefers operator_host when a private host is available"
  assert_eq "$(jq -r '.[1]' <<<"$endpoints_json")" "0x8888888888888888888888888888888888888888=10.0.0.22:18444" "explicit private endpoint still wins"

  rm -rf "$workdir"
}

main() {
  test_default_operator_endpoints_prefer_private_operator_hosts
}

main "$@"
