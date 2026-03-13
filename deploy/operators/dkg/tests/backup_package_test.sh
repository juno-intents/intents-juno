#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_contains_line() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if ! printf '%s\n' "$haystack" | grep -Fx "$needle" >/dev/null 2>&1; then
    printf 'assert_contains_line failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

ensure_openssl_available() {
  if ! command -v openssl >/dev/null 2>&1; then
    printf 'openssl is required for backup_package_test.sh\n' >&2
    exit 1
  fi
}

write_test_signed_cert() {
  local cert_path="$1"
  local key_path="$2"
  local ca_cert_path="$3"
  local ca_key_path="$4"
  local common_name="$5"
  local ext_contents="$6"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  cat >"$tmp_dir/cert.ext" <<EOF
$ext_contents
EOF

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$key_path" \
    -out "$tmp_dir/cert.csr" \
    -subj "/CN=$common_name" >/dev/null 2>&1

  openssl x509 -req \
    -in "$tmp_dir/cert.csr" \
    -CA "$ca_cert_path" \
    -CAkey "$ca_key_path" \
    -CAcreateserial \
    -out "$cert_path" \
    -days 3650 \
    -sha256 \
    -extfile "$tmp_dir/cert.ext" >/dev/null 2>&1

  chmod 0600 "$key_path"
  rm -rf "$tmp_dir"
}

write_test_tls_bundle() {
  local tls_dir="$1"
  local coordinator_mode="${2:-client}"
  local tmp_dir coordinator_ext
  tmp_dir="$(mktemp -d)"
  mkdir -p "$tls_dir"

  cat >"$tmp_dir/server.ext" <<'EOF'
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

  case "$coordinator_mode" in
    client)
      coordinator_ext='basicConstraints=CA:FALSE
subjectAltName=DNS:coordinator-client
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth'
      ;;
    server)
      coordinator_ext='basicConstraints=CA:FALSE
subjectAltName=DNS:coordinator-client
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth'
      ;;
    *)
      printf 'unsupported coordinator cert mode: %s\n' "$coordinator_mode" >&2
      exit 1
      ;;
  esac

  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$tmp_dir/ca.key" \
    -out "$tls_dir/ca.pem" \
    -days 3650 \
    -subj "/CN=Backup Package Test CA" >/dev/null 2>&1

  write_test_signed_cert \
    "$tls_dir/server.pem" \
    "$tls_dir/server.key" \
    "$tls_dir/ca.pem" \
    "$tmp_dir/ca.key" \
    "localhost" \
    "$(cat "$tmp_dir/server.ext")"

  write_test_signed_cert \
    "$tls_dir/coordinator-client.pem" \
    "$tls_dir/coordinator-client.key" \
    "$tls_dir/ca.pem" \
    "$tmp_dir/ca.key" \
    "coordinator-client" \
    "$coordinator_ext"

  rm -rf "$tmp_dir"
}

cert_sha256_hex() {
  local cert_path="$1"
  openssl x509 -in "$cert_path" -noout -fingerprint -sha256 \
    | cut -d= -f2 \
    | tr -d ':' \
    | tr 'A-F' 'a-f'
}

assert_cert_purpose_yes() {
  local cert_path="$1"
  local purpose_label="$2"
  local msg="$3"
  if ! openssl x509 -in "$cert_path" -noout -purpose 2>/dev/null | grep -Fq "$purpose_label : Yes"; then
    printf 'assert_cert_purpose_yes failed: %s\n' "$msg" >&2
    openssl x509 -in "$cert_path" -noout -purpose >&2 || true
    exit 1
  fi
}

assert_cert_text_contains() {
  local cert_path="$1"
  local needle="$2"
  local msg="$3"
  if ! openssl x509 -in "$cert_path" -noout -text 2>/dev/null | grep -Fq "$needle"; then
    printf 'assert_cert_text_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    openssl x509 -in "$cert_path" -noout -text >&2 || true
    exit 1
  fi
}

test_backup_package_contains_required_files() {
  local tmp runtime workdir output
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  workdir="$tmp/ceremony-workdir"
  output="$tmp/operator-backup.zip"

  mkdir -p "$runtime/bundle" "$runtime/bin" "$tmp/backup" "$tmp/exports" "$workdir/reports" "$workdir/tls"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 2,
  "max_signers": 3,
  "network": "mainnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {"roster_version":1, "operators":[]}
}
JSON

  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$tmp/backup/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$tmp/exports/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$tmp/exports/keypackage-backup.json.KeyImportReceipt.json"
  printf '{"report_version":1}\n' >"$workdir/reports/test-completiton.json"
  printf 'test-ufvk\n' >"$workdir/ufvk.txt"
  printf 'coord-cert\n' >"$workdir/tls/coordinator-client.pem"
  printf 'coord-key\n' >"$workdir/tls/coordinator-client.key"
  cat >"$runtime/bin/dkg-admin" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$runtime/bin/dkg-admin"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --completion-report "$workdir/reports/test-completiton.json" \
      --ufvk-file "$workdir/ufvk.txt" \
      --coordinator-client-cert "$workdir/tls/coordinator-client.pem" \
      --coordinator-client-key "$workdir/tls/coordinator-client.key" \
      --output "$output"
  )

  local listing
  listing="$(unzip -Z1 "$output")"
  assert_contains_line "$listing" "manifest.json" "backup zip manifest"
  assert_contains_line "$listing" "payload/age-identity.txt" "backup zip age identity"
  assert_contains_line "$listing" "payload/keypackage-backup.json" "backup zip age blob"
  assert_contains_line "$listing" "payload/keypackage-backup.json.KeyImportReceipt.json" "backup zip age receipt"
  assert_contains_line "$listing" "payload/admin-config.json" "backup zip admin config"
  assert_contains_line "$listing" "payload/test-completiton.json" "backup zip completion report"
  assert_contains_line "$listing" "payload/ufvk.txt" "backup zip ufvk"
  assert_contains_line "$listing" "payload/bin/dkg-admin" "backup zip dkg-admin binary"
  assert_contains_line "$listing" "payload/tls/coordinator-client.pem" "backup zip coordinator cert"
  assert_contains_line "$listing" "payload/tls/coordinator-client.key" "backup zip coordinator key"

  rm -rf "$tmp"
}

test_backup_package_restore_reconstructs_runtime() {
  local tmp runtime output fake_bin
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  output="$tmp/operator-backup.zip"
  fake_bin="$tmp/fake-bin"

  mkdir -p "$runtime/bundle/tls" "$runtime/bin" "$tmp/backup" "$tmp/exports" "$fake_bin" "$tmp/ceremony-tls"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {"roster_version":1, "operators":[]},
  "state_dir": "./state",
  "grpc": {
    "listen_addr": "0.0.0.0:18443",
    "tls_ca_cert_pem_path": "./tls/ca.pem",
    "tls_server_cert_pem_path": "./tls/server.pem",
    "tls_server_key_pem_path": "./tls/server.key"
  }
}
JSON

  ensure_openssl_available
  write_test_tls_bundle "$tmp/ceremony-tls" "client"
  cp "$tmp/ceremony-tls/ca.pem" "$runtime/bundle/tls/ca.pem"
  cp "$tmp/ceremony-tls/server.pem" "$runtime/bundle/tls/server.pem"
  cp "$tmp/ceremony-tls/server.key" "$runtime/bundle/tls/server.key"
  chmod 0600 "$runtime/bundle/tls/server.key"
  printf 'test-ufvk\n' >"$tmp/ufvk.txt"
  cat >"$runtime/bin/dkg-admin" <<'EOF'
#!/usr/bin/env bash
printf 'fake-dkg-admin\n'
EOF
  chmod 0755 "$runtime/bin/dkg-admin"

  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$tmp/backup/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$tmp/exports/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$tmp/exports/keypackage-backup.json.KeyImportReceipt.json"

  cat >"$fake_bin/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "--decrypt" ]]; then
  echo "unexpected age args: $*" >&2
  exit 1
fi
cat <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "key_package_bytes_b64": "a3BieXRlcw==",
  "public_key_package_bytes_b64": "cGtwYnl0ZXM="
}
JSON
EOF
  chmod 0755 "$fake_bin/age"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --ufvk-file "$tmp/ufvk.txt" \
      --coordinator-client-cert "$tmp/ceremony-tls/coordinator-client.pem" \
      --coordinator-client-key "$tmp/ceremony-tls/coordinator-client.key" \
      --output "$output"
  )

  rm -rf "$runtime"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    deploy/operators/dkg/backup-package.sh restore \
      --package "$output" \
      --workdir "$runtime"
  )

  [[ -f "$runtime/bundle/admin-config.json" ]] || {
    printf 'expected restored admin-config.json\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/state/key_package.bin" ]] || {
    printf 'expected restored state key_package.bin\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/state/public_key_package.bin" ]] || {
    printf 'expected restored state public_key_package.bin\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/tls/ca.pem" ]] || {
    printf 'expected restored tls ca.pem\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/tls/server.pem" ]] || {
    printf 'expected restored tls server.pem\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/tls/server.key" ]] || {
    printf 'expected restored tls server.key\n' >&2
    exit 1
  }
  [[ -f "$runtime/ufvk.txt" ]] || {
    printf 'expected restored ufvk.txt\n' >&2
    exit 1
  }
  [[ -x "$runtime/bin/dkg-admin" ]] || {
    printf 'expected restored bin/dkg-admin\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/tls/coordinator-client.pem" ]] || {
    printf 'expected restored coordinator-client.pem\n' >&2
    exit 1
  }
  [[ -f "$runtime/bundle/tls/coordinator-client.key" ]] || {
    printf 'expected restored coordinator-client.key\n' >&2
    exit 1
  }

  local got_kp got_pkp
  got_kp="$(cat "$runtime/bundle/state/key_package.bin")"
  got_pkp="$(cat "$runtime/bundle/state/public_key_package.bin")"
  if [[ "$got_kp" != "kpbytes" ]]; then
    printf 'unexpected key_package.bin contents: %q\n' "$got_kp" >&2
    exit 1
  fi
  if [[ "$got_pkp" != "pkpbytes" ]]; then
    printf 'unexpected public_key_package.bin contents: %q\n' "$got_pkp" >&2
    exit 1
  fi
  if [[ "$(cat "$runtime/ufvk.txt")" != "test-ufvk" ]]; then
    printf 'unexpected ufvk.txt contents: %q\n' "$(cat "$runtime/ufvk.txt")" >&2
    exit 1
  fi
  if ! grep -Fq "fake-dkg-admin" "$runtime/bin/dkg-admin"; then
    printf 'unexpected dkg-admin contents: %q\n' "$(cat "$runtime/bin/dkg-admin")" >&2
    exit 1
  fi
  assert_cert_purpose_yes "$runtime/bundle/tls/coordinator-client.pem" "SSL client" "restored coordinator client cert supports tls client auth"
  assert_cert_text_contains "$runtime/bundle/tls/coordinator-client.pem" "DNS:coordinator-client" "restored coordinator client cert keeps coordinator SAN"
  if [[ "$(jq -r '.grpc.coordinator_client_cert_sha256' "$runtime/bundle/admin-config.json")" != "$(cert_sha256_hex "$runtime/bundle/tls/coordinator-client.pem")" ]]; then
    printf 'unexpected coordinator client fingerprint in admin config\n' >&2
    exit 1
  fi
  if [[ "$(jq -r '.grpc.tls_client_cert_pem_path // empty' "$runtime/bundle/admin-config.json")" != "./tls/coordinator-client.pem" ]]; then
    printf 'unexpected coordinator client cert path in admin config\n' >&2
    exit 1
  fi
  if [[ "$(jq -r '.grpc.tls_client_key_pem_path // empty' "$runtime/bundle/admin-config.json")" != "./tls/coordinator-client.key" ]]; then
    printf 'unexpected coordinator client key path in admin config\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

test_backup_package_restore_repairs_server_auth_only_coordinator_client_cert() {
  local tmp runtime output fake_bin
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  output="$tmp/operator-backup.zip"
  fake_bin="$tmp/fake-bin"

  ensure_openssl_available
  mkdir -p "$runtime/bundle/tls" "$runtime/bin" "$tmp/backup" "$tmp/exports" "$fake_bin" "$tmp/ceremony-tls"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {"roster_version":1, "operators":[]},
  "state_dir": "./state",
  "grpc": {
    "listen_addr": "0.0.0.0:18443",
    "tls_ca_cert_pem_path": "./tls/ca.pem",
    "tls_server_cert_pem_path": "./tls/server.pem",
    "tls_server_key_pem_path": "./tls/server.key",
    "coordinator_client_cert_sha256": null
  }
}
JSON

  write_test_tls_bundle "$tmp/ceremony-tls" "server"
  cp "$tmp/ceremony-tls/ca.pem" "$runtime/bundle/tls/ca.pem"
  cp "$tmp/ceremony-tls/server.pem" "$runtime/bundle/tls/server.pem"
  cp "$tmp/ceremony-tls/server.key" "$runtime/bundle/tls/server.key"
  chmod 0600 "$runtime/bundle/tls/server.key"

  cat >"$runtime/bin/dkg-admin" <<'EOF'
#!/usr/bin/env bash
printf 'fake-dkg-admin\n'
EOF
  chmod 0755 "$runtime/bin/dkg-admin"
  printf 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' >"$tmp/backup/age-identity.txt"
  printf '{"encryption_backend":"age","ciphertext_b64":"Y2lwaGVydGV4dA=="}\n' >"$tmp/exports/keypackage-backup.json"
  printf '{"receipt_version":"key_import_receipt_v1"}\n' >"$tmp/exports/keypackage-backup.json.KeyImportReceipt.json"

  cat >"$fake_bin/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "--decrypt" ]]; then
  echo "unexpected age args: $*" >&2
  exit 1
fi
cat <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "testnet",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "key_package_bytes_b64": "a3BieXRlcw==",
  "public_key_package_bytes_b64": "cGtwYnl0ZXM="
}
JSON
EOF
  chmod 0755 "$fake_bin/age"

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --coordinator-client-cert "$tmp/ceremony-tls/coordinator-client.pem" \
      --coordinator-client-key "$tmp/ceremony-tls/coordinator-client.key" \
      --output "$output"
  )

  rm -rf "$runtime"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    deploy/operators/dkg/backup-package.sh restore \
      --package "$output" \
      --workdir "$runtime"
  )

  assert_cert_purpose_yes "$runtime/bundle/tls/coordinator-client.pem" "SSL client" "restored coordinator client cert repairs mTLS client auth purpose"
  assert_cert_text_contains "$runtime/bundle/tls/coordinator-client.pem" "TLS Web Client Authentication" "restored coordinator client cert has clientAuth eku"
  assert_cert_text_contains "$runtime/bundle/tls/coordinator-client.pem" "DNS:coordinator-client" "restored coordinator client cert includes coordinator SAN"
  if [[ "$(jq -r '.grpc.coordinator_client_cert_sha256' "$runtime/bundle/admin-config.json")" != "$(cert_sha256_hex "$runtime/bundle/tls/coordinator-client.pem")" ]]; then
    printf 'unexpected repaired coordinator client fingerprint in admin config\n' >&2
    exit 1
  fi
  if [[ "$(jq -r '.grpc.tls_client_cert_pem_path // empty' "$runtime/bundle/admin-config.json")" != "./tls/coordinator-client.pem" ]]; then
    printf 'unexpected repaired coordinator client cert path in admin config\n' >&2
    exit 1
  fi
  if [[ "$(jq -r '.grpc.tls_client_key_pem_path // empty' "$runtime/bundle/admin-config.json")" != "./tls/coordinator-client.key" ]]; then
    printf 'unexpected repaired coordinator client key path in admin config\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

main() {
  test_backup_package_contains_required_files
  test_backup_package_restore_reconstructs_runtime
  test_backup_package_restore_repairs_server_auth_only_coordinator_client_cert
}

main "$@"
