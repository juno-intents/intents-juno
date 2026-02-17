#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

test_phase2_callback_wrapper_forwards_expected_args() {
  local tmp fake_bin marker proof_inputs deposit_seal withdraw_seal sender_key output_path
  tmp="$(mktemp -d)"
  fake_bin="$tmp/fake-bin"
  marker="$tmp/go.args"
  proof_inputs="$tmp/bridge-proof-inputs.json"
  deposit_seal="$tmp/deposit.seal.hex"
  withdraw_seal="$tmp/withdraw.seal.hex"
  sender_key="$tmp/base-funder.key"
  output_path="$tmp/callback-report.json"

  mkdir -p "$fake_bin"
  printf '{}\n' >"$proof_inputs"
  printf '0x01\n' >"$deposit_seal"
  printf '0x02\n' >"$withdraw_seal"
  printf '0x11\n' >"$sender_key"

  cat >"$fake_bin/go" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >"$marker"
EOF
  chmod 0755 "$fake_bin/go"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    deploy/operators/dkg/e2e/run-bridge-phase2-callback.sh run \
      --base-rpc-url https://sepolia.base.org \
      --base-funder-key-file "$sender_key" \
      --proof-inputs-file "$proof_inputs" \
      --deposit-seal-file "$deposit_seal" \
      --withdraw-seal-file "$withdraw_seal" \
      --base-chain-id 84532 \
      --withdraw-amount 10000 \
      --run-timeout 20m \
      --output "$output_path"
  )

  local got
  got="$(cat "$marker")"

  assert_contains "$got" "run ./cmd/bridge-callback" "go command"
  assert_contains "$got" "--rpc-url https://sepolia.base.org" "rpc url"
  assert_contains "$got" "--sender-key-file $sender_key" "sender key file"
  assert_contains "$got" "--proof-inputs-file $proof_inputs" "proof inputs"
  assert_contains "$got" "--deposit-seal-file $deposit_seal" "deposit seal"
  assert_contains "$got" "--withdraw-seal-file $withdraw_seal" "withdraw seal"
  assert_contains "$got" "--chain-id 84532" "chain id"
  assert_contains "$got" "--withdraw-amount 10000" "withdraw amount"
  assert_contains "$got" "--run-timeout 20m" "run timeout"
  assert_contains "$got" "--output $output_path" "output path"

  rm -rf "$tmp"
}

main() {
  test_phase2_callback_wrapper_forwards_expected_args
}

main "$@"
