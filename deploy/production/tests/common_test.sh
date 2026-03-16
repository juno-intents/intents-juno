#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_file_exists() {
  local path="$1"
  local msg="$2"
  if [[ ! -f "$path" ]]; then
    printf 'assert_file_exists failed: %s: %s\n' "$msg" "$path" >&2
    exit 1
  fi
}

test_default_deposit_owallet_ivk() {
  printf '0x'
  printf '1%.0s' $(seq 1 128)
  printf '\n'
}

test_default_withdraw_owallet_ovk() {
  printf '0x'
  printf '2%.0s' $(seq 1 64)
  printf '\n'
}

test_default_operator_txsign_key() {
  printf '0x'
  printf 'a%.0s' $(seq 1 64)
  printf '\n'
}

append_default_owallet_proof_keys() {
  local file="$1"
  local deposit_ivk withdraw_ovk txsign_key
  deposit_ivk="$(test_default_deposit_owallet_ivk)"
  withdraw_ovk="$(test_default_withdraw_owallet_ovk)"
  txsign_key="$(test_default_operator_txsign_key)"

  if ! grep -q '^DEPOSIT_OWALLET_IVK=' "$file"; then
    printf 'DEPOSIT_OWALLET_IVK=literal:%s\n' "$deposit_ivk" >>"$file"
  fi
  if ! grep -q '^WITHDRAW_OWALLET_OVK=' "$file"; then
    printf 'WITHDRAW_OWALLET_OVK=literal:%s\n' "$withdraw_ovk" >>"$file"
  fi
  if ! grep -q '^JUNO_TXSIGN_SIGNER_KEYS=' "$file"; then
    printf 'JUNO_TXSIGN_SIGNER_KEYS=literal:%s\n' "$txsign_key" >>"$file"
  fi
}

ensure_fake_checkpoint_signer_kms_provisioner() {
  local workdir fake_bin
  if [[ -n "${PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN:-}" ]]; then
    return 0
  fi

  workdir="$(mktemp -d)"
  fake_bin="$workdir/fake-checkpoint-kms-provisioner.sh"
  cat >"$fake_bin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
key_arn="arn:aws:kms:us-east-1:021490342184:key/provisioned"
alias_name=""
operator_address=""
reused=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-address)
      operator_address="$2"
      shift 2
      ;;
    --alias-name)
      alias_name="$2"
      shift 2
      ;;
    --key-id)
      key_arn="$2"
      reused=true
      shift 2
      ;;
    --operator-id|--aws-profile|--aws-region|--account-id|--private-key|--description)
      shift 2
      ;;
    *)
      printf 'unexpected checkpoint kms provisioner arg: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done
printf '{"keyId":"%s","keyArn":"%s","aliasName":"%s","operatorAddress":"%s","reused":%s}\n' \
  "${key_arn##*/}" \
  "$key_arn" \
  "$alias_name" \
  "$operator_address" \
  "$reused"
EOF
  chmod +x "$fake_bin"
  export PRODUCTION_CHECKPOINT_SIGNER_KMS_PROVISIONER_BIN="$fake_bin"
}

ensure_fake_checkpoint_signer_kms_provisioner
