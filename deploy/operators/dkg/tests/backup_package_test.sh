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

test_backup_package_contains_required_files() {
  local tmp runtime workdir output
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  workdir="$tmp/ceremony-workdir"
  output="$tmp/operator-backup.zip"

  mkdir -p "$runtime/bundle" "$tmp/backup" "$tmp/exports" "$workdir/reports"
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

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/backup-package.sh create \
      --workdir "$runtime" \
      --age-identity-file "$tmp/backup/age-identity.txt" \
      --age-backup-file "$tmp/exports/keypackage-backup.json" \
      --admin-config "$runtime/bundle/admin-config.json" \
      --completion-report "$workdir/reports/test-completiton.json" \
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

  rm -rf "$tmp"
}

test_backup_package_restore_reconstructs_runtime() {
  local tmp runtime output fake_bin
  tmp="$(mktemp -d)"
  runtime="$tmp/operator-runtime"
  output="$tmp/operator-backup.zip"
  fake_bin="$tmp/fake-bin"

  mkdir -p "$runtime/bundle/tls" "$tmp/backup" "$tmp/exports" "$fake_bin"
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

  printf 'FAKE-CA\n' >"$runtime/bundle/tls/ca.pem"
  printf 'FAKE-SERVER\n' >"$runtime/bundle/tls/server.pem"
  printf 'FAKE-KEY\n' >"$runtime/bundle/tls/server.key"
  chmod 0600 "$runtime/bundle/tls/server.key"

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

  rm -rf "$tmp"
}

main() {
  test_backup_package_contains_required_files
  test_backup_package_restore_reconstructs_runtime
}

main "$@"
