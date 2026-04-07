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

test_certificate_sha256_hex() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -outform DER \
    | openssl dgst -sha256 \
    | awk '{print $NF}' \
    | tr 'A-F' 'a-f'
}

write_test_dkg_tls_dir() {
  local tls_dir="$1"
  local tmp_dir server_ext client_ext

  mkdir -p "$tls_dir"
  tmp_dir="$(mktemp -d)"
  server_ext="$tmp_dir/server.ext"
  client_ext="$tmp_dir/coordinator-client.ext"

  cat >"$server_ext" <<'EOF'
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

  cat >"$client_ext" <<'EOF'
basicConstraints=CA:FALSE
subjectAltName=DNS:coordinator-client
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/ca.key" \
    -out "$tls_dir/ca.pem" \
    -days 3650 \
    -subj "/CN=Test DKG CA" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/server.key" \
    -out "$tmp_dir/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req \
    -in "$tmp_dir/server.csr" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tls_dir/ca.key" \
    -CAcreateserial \
    -out "$tls_dir/server.pem" \
    -days 3650 \
    -sha256 \
    -extfile "$server_ext" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$tls_dir/coordinator-client.key" \
    -out "$tmp_dir/coordinator-client.csr" \
    -subj "/CN=coordinator-client" >/dev/null 2>&1
  openssl x509 -req \
    -in "$tmp_dir/coordinator-client.csr" \
    -CA "$tls_dir/ca.pem" \
    -CAkey "$tls_dir/ca.key" \
    -CAcreateserial \
    -out "$tls_dir/coordinator-client.pem" \
    -days 3650 \
    -sha256 \
    -extfile "$client_ext" >/dev/null 2>&1

  chmod 0600 "$tls_dir/ca.key" "$tls_dir/server.key" "$tls_dir/coordinator-client.key" || true
  rm -rf "$tmp_dir"
}

write_test_dkg_backup_zip() {
  local output_path="$1"
  local tls_source_dir="${2:-}"
  local tmp runtime bundle_tls backup_dir exports_dir client_fingerprint

  tmp="$(mktemp -d)"
  runtime="$tmp/runtime"
  bundle_tls="$runtime/bundle/tls"
  backup_dir="$tmp/backup"
  exports_dir="$tmp/exports"

  mkdir -p "$bundle_tls" "$runtime/bin" "$backup_dir" "$exports_dir"

  if [[ -n "$tls_source_dir" ]]; then
    cp "$tls_source_dir/ca.pem" "$bundle_tls/ca.pem"
    cp "$tls_source_dir/ca.key" "$bundle_tls/ca.key"
    cp "$tls_source_dir/server.pem" "$bundle_tls/server.pem"
    cp "$tls_source_dir/server.key" "$bundle_tls/server.key"
    cp "$tls_source_dir/coordinator-client.pem" "$bundle_tls/coordinator-client.pem"
    cp "$tls_source_dir/coordinator-client.key" "$bundle_tls/coordinator-client.key"
  else
    write_test_dkg_tls_dir "$bundle_tls"
  fi

  client_fingerprint="$(test_certificate_sha256_hex "$bundle_tls/coordinator-client.pem")"
  jq -n \
    --arg operator_id "0x1111111111111111111111111111111111111111" \
    --arg ceremony_id "11111111-1111-1111-1111-111111111111" \
    --arg fingerprint "$client_fingerprint" \
    '{
      operator_id: $operator_id,
      identifier: 1,
      threshold: 2,
      max_signers: 3,
      network: "testnet",
      ceremony_id: $ceremony_id,
      roster_hash_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      roster: {
        roster_version: 1,
        operators: []
      },
      state_dir: "./state",
      grpc: {
        listen_addr: "0.0.0.0:18443",
        tls_ca_cert_pem_path: "./tls/ca.pem",
        tls_server_cert_pem_path: "./tls/server.pem",
        tls_server_key_pem_path: "./tls/server.key",
        coordinator_client_cert_sha256: $fingerprint,
        tls_client_cert_pem_path: "./tls/coordinator-client.pem",
        tls_client_key_pem_path: "./tls/coordinator-client.key"
      }
    }' >"$runtime/bundle/admin-config.json"

  cat >"$runtime/bin/dkg-admin" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$runtime/bin/dkg-admin"

  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$backup_dir/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$exports_dir/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$exports_dir/keypackage-backup.json.KeyImportReceipt.json"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$backup_dir/age-identity.txt" \
      --age-backup-file "$exports_dir/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --coordinator-client-cert "$bundle_tls/coordinator-client.pem" \
      --coordinator-client-key "$bundle_tls/coordinator-client.key" \
      --output "$output_path" \
      --force
  )

  rm -rf "$tmp"
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
