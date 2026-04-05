#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_systemctl() {
  local path="$1"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "is-active" ]]; then
  exit 0
fi
printf 'unexpected systemctl args: %s\n' "$*" >&2
exit 1
EOF
  chmod 0755 "$path"
}

write_fake_junocash_cli() {
  local path="$1"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
case "${*: -1}" in
  getblockchaininfo)
    printf '%s\n' '{"blocks":5000,"headers":5000,"verificationprogress":1,"initial_block_download_complete":true}'
    ;;
  getblockcount)
    printf '5000\n'
    ;;
  *)
    printf 'unexpected junocash-cli args: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$path"
}

write_fake_extend_signer() {
  local path="$1"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
case "${FAKE_EXTEND_MODE:-success}" in
  success)
    printf '%s\n' '{"version":"v1","status":"ok","data":{"signatures":["0x01"]}}'
    exit 0
    ;;
  missing-operator-endpoint)
    printf 'flag provided but not defined: -operator-endpoint\n'
    exit 1
    ;;
  *)
    printf 'unexpected FAKE_EXTEND_MODE=%s\n' "${FAKE_EXTEND_MODE:-}" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$path"
}

write_fake_curl() {
  local path="$1"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
out_file=""
write_fmt=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|-w|-H|-X|--data|--data-raw|--max-time)
      case "$1" in
        -o) out_file="$2" ;;
        -w) write_fmt="$2" ;;
      esac
      shift 2
      ;;
    -s|-S|-sS|-f|-fsS|-i|-D)
      shift
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

case "$url" in
  *"/readyz")
    code="${FAKE_READYZ_CODE:-200}"
    body="${FAKE_READYZ_BODY:-}"
    if [[ -n "$out_file" ]]; then
      printf '%s' "$body" >"$out_file"
    else
      printf '%s' "$body"
    fi
    if [[ -n "$write_fmt" ]]; then
      printf '%s' "${write_fmt//\%\{http_code\}/$code}"
    fi
    exit 0
    ;;
  *"/v1/health")
    printf '%s\n' "${FAKE_SCAN_HEALTH:-{\"status\":\"ok\",\"scanned_height\":4999,\"scanned_hash\":\"0001\"}}"
    exit 0
    ;;
  *)
    printf 'unexpected curl url: %s\n' "$url" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$path"
}

write_operator_stack_env() {
  local path="$1"
  local extend_signer_bin="$2"
  cat >"$path" <<EOF
WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT=1000000
WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET=240
CHECKPOINT_SIGNER_DRIVER=aws-kms
WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h
WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h
WITHDRAW_COORDINATOR_OPERATOR_ENDPOINTS=0x1111111111111111111111111111111111111111=203.0.113.11:18443,0x2222222222222222222222222222222222222222=203.0.113.12:18444
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=$extend_signer_bin
JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
CHECKPOINT_BLOB_BUCKET=test-runtime-bucket
CHECKPOINT_THRESHOLD=3
JUNO_RPC_USER=test-rpc-user
JUNO_RPC_PASS=test-rpc-pass
EOF
}

run_local_canary() {
  local env_file="$1"
  local runtime_dir="$2"
  local fake_bin="$3"
  INTENTS_JUNO_OPERATOR_STACK_ENV_PATH="$env_file" \
  INTENTS_JUNO_OPERATOR_RUNTIME_DIR="$runtime_dir" \
  INTENTS_JUNO_CLI_BIN="$fake_bin/junocash-cli" \
  PATH="$fake_bin:$PATH" \
  bash "$REPO_ROOT/deploy/production/run-operator-local-canary.sh" \
    --operator-id 0x1111111111111111111111111111111111111111
}

test_run_operator_local_canary_accepts_restore_report_and_local_signature() {
  local tmp fake_bin runtime_dir env_file output_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  runtime_dir="$tmp/runtime"
  env_file="$tmp/operator-stack.env"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin" "$runtime_dir"

  write_fake_systemctl "$fake_bin/systemctl"
  write_fake_junocash_cli "$fake_bin/junocash-cli"
  write_fake_extend_signer "$fake_bin/extend-signer"
  write_fake_curl "$fake_bin/curl"
  write_operator_stack_env "$env_file" "$fake_bin/extend-signer"
  printf '%s\n' '{"restore_version":1}' >"$runtime_dir/restore-report.json"

  (
    cd "$REPO_ROOT"
    FAKE_EXTEND_MODE=success \
    FAKE_READYZ_CODE=200 \
    FAKE_READYZ_BODY='' \
    run_local_canary "$env_file" "$runtime_dir" "$fake_bin" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "local canary ready flag"
  assert_eq "$(jq -r '.checks.txsign_runtime.status' "$output_json")" "passed" "local canary accepts a single operator-scoped signature"
  assert_contains "$(jq -r '.checks.txsign_runtime.detail' "$output_json")" "1 operator-scoped signature" "local canary reports the operator-scoped signature count"
  assert_eq "$(jq -r '.checks.kms_export.status' "$output_json")" "passed" "local canary accepts the runtime restore report"
  assert_contains "$(jq -r '.checks.kms_export.detail' "$output_json")" "restore report" "local canary reports the restore report path style"
  assert_eq "$(jq -r '.checks.deposit_relayer_ready.status' "$output_json")" "passed" "local canary accepts an empty 200 readyz response"

  rm -rf "$tmp"
}

test_run_operator_local_canary_reports_readyz_http_failure() {
  local tmp fake_bin runtime_dir env_file output_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  runtime_dir="$tmp/runtime"
  env_file="$tmp/operator-stack.env"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin" "$runtime_dir"

  write_fake_systemctl "$fake_bin/systemctl"
  write_fake_junocash_cli "$fake_bin/junocash-cli"
  write_fake_extend_signer "$fake_bin/extend-signer"
  write_fake_curl "$fake_bin/curl"
  write_operator_stack_env "$env_file" "$fake_bin/extend-signer"
  printf '%s\n' '{"restore_version":1}' >"$runtime_dir/restore-report.json"

  (
    cd "$REPO_ROOT"
    FAKE_EXTEND_MODE=success \
    FAKE_READYZ_CODE=503 \
    FAKE_READYZ_BODY='{"status":"not_ready","error":"signer balance 0 below minimum"}' \
    run_local_canary "$env_file" "$runtime_dir" "$fake_bin" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "local canary blocks on deposit readiness failures"
  assert_eq "$(jq -r '.checks.deposit_relayer_ready.status' "$output_json")" "failed" "local canary marks the readiness check as failed"
  assert_contains "$(jq -r '.checks.deposit_relayer_ready.detail' "$output_json")" "HTTP 503" "local canary reports the HTTP status"
  assert_contains "$(jq -r '.checks.deposit_relayer_ready.detail' "$output_json")" "balance 0 below minimum" "local canary reports the readiness body"

  rm -rf "$tmp"
}

test_run_operator_local_canary_reports_missing_operator_endpoint_support() {
  local tmp fake_bin runtime_dir env_file output_json
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  runtime_dir="$tmp/runtime"
  env_file="$tmp/operator-stack.env"
  output_json="$tmp/output.json"
  mkdir -p "$fake_bin" "$runtime_dir"

  write_fake_systemctl "$fake_bin/systemctl"
  write_fake_junocash_cli "$fake_bin/junocash-cli"
  write_fake_extend_signer "$fake_bin/extend-signer"
  write_fake_curl "$fake_bin/curl"
  write_operator_stack_env "$env_file" "$fake_bin/extend-signer"
  printf '%s\n' '{"restore_version":1}' >"$runtime_dir/restore-report.json"

  (
    cd "$REPO_ROOT"
    FAKE_EXTEND_MODE=missing-operator-endpoint \
    FAKE_READYZ_CODE=200 \
    FAKE_READYZ_BODY='' \
    run_local_canary "$env_file" "$runtime_dir" "$fake_bin" >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "local canary blocks on missing operator-endpoint support"
  assert_eq "$(jq -r '.checks.txsign_runtime.status' "$output_json")" "failed" "local canary marks txsign support as failed"
  assert_contains "$(jq -r '.checks.txsign_runtime.detail' "$output_json")" "flag provided but not defined: -operator-endpoint" "local canary surfaces the real txsign failure"

  rm -rf "$tmp"
}

main() {
  test_run_operator_local_canary_accepts_restore_report_and_local_signature
  test_run_operator_local_canary_reports_readyz_http_failure
  test_run_operator_local_canary_reports_missing_operator_endpoint_support
}

main "$@"
