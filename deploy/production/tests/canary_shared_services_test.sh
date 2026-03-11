#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

test_shared_services_canary_checks_postgres_kafka_and_ipfs() {
  local tmp manifest fake_bin log_file output_json
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_file="$tmp/calls.log"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin"

  cat >"$manifest" <<'JSON'
{
  "environment": "alpha",
  "shared_services": {
    "postgres": {
      "endpoint": "postgres.alpha.internal",
      "port": 5432
    },
    "kafka": {
      "bootstrap_brokers": "broker-1.alpha.internal:9094,broker-2.alpha.internal:9094"
    },
    "ipfs": {
      "api_url": "https://ipfs.alpha.internal"
    }
  }
}
JSON

  cat >"$fake_bin/pg_isready" <<EOF
#!/usr/bin/env bash
printf 'pg_isready %s\n' "\$*" >>"$log_file"
exit 0
EOF
  cat >"$fake_bin/nc" <<EOF
#!/usr/bin/env bash
printf 'nc %s\n' "\$*" >>"$log_file"
exit 0
EOF
  cat >"$fake_bin/curl" <<EOF
#!/usr/bin/env bash
printf 'curl %s\n' "\$*" >>"$log_file"
printf '{"Version":"0.25.0"}\n'
exit 0
EOF
  chmod 0755 "$fake_bin/pg_isready" "$fake_bin/nc" "$fake_bin/curl"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services.sh \
      --shared-manifest "$manifest" >"$output_json"
  )

  assert_contains "$(cat "$log_file")" "pg_isready -h postgres.alpha.internal -p 5432" "postgres canary check"
  assert_contains "$(cat "$log_file")" "nc -z broker-1.alpha.internal 9094" "first kafka broker canary check"
  assert_contains "$(cat "$log_file")" "nc -z broker-2.alpha.internal 9094" "second kafka broker canary check"
  assert_contains "$(cat "$log_file")" "curl -fsS -X POST https://ipfs.alpha.internal/api/v0/version" "ipfs canary check"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "shared canary ready flag"
  assert_eq "$(jq -r '.checks.postgres.status' "$output_json")" "passed" "shared canary postgres status"
  assert_eq "$(jq -r '.checks.kafka.status' "$output_json")" "passed" "shared canary kafka status"
  assert_eq "$(jq -r '.checks.ipfs.status' "$output_json")" "passed" "shared canary ipfs status"

  rm -rf "$tmp"
}

main() {
  test_shared_services_canary_checks_postgres_kafka_and_ipfs
}

main "$@"
