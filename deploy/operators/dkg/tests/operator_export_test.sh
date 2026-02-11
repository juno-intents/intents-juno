#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'assert_eq failed: %s: got=%q want=%q\n' "$msg" "$got" "$want" >&2
    exit 1
  fi
}

make_runtime_with_config() {
  local runtime="$1"
  mkdir -p "$runtime/bundle"
  cat >"$runtime/bundle/admin-config.json" <<'JSON'
{
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 2,
  "max_signers": 3,
  "network": "mainnet",
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "roster": {
    "roster_version": 1,
    "operators": [
      {
        "operator_id": "0x1111111111111111111111111111111111111111",
        "grpc_endpoint": "https://node.ts.net:8443"
      },
      {
        "operator_id": "0x2222222222222222222222222222222222222222",
        "grpc_endpoint": "https://node2.ts.net:8443"
      },
      {
        "operator_id": "0x3333333333333333333333333333333333333333",
        "grpc_endpoint": "https://node3.ts.net:8443"
      }
    ]
  },
  "grpc": {
    "listen_addr": "0.0.0.0:8443",
    "tls_ca_cert_pem_path": "./tls/ca.pem",
    "tls_server_cert_pem_path": "./tls/server.pem",
    "tls_server_key_pem_path": "./tls/server.key"
  }
}
JSON
}

test_backup_age_invokes_dkg_admin_with_age_only() {
  local tmp runtime out fake_dkg_admin log_file
  tmp="$(mktemp -d)"
  runtime="$tmp/runtime"
  out="$tmp/backup.json"
  log_file="$tmp/call.log"
  make_runtime_with_config "$runtime"

  fake_dkg_admin="$tmp/fake-dkg-admin.sh"
  cat >"$fake_dkg_admin" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >"$log_file"
printf '{"ok":true}\n'
EOF
  chmod 0755 "$fake_dkg_admin"

  (
    cd "$REPO_ROOT"
    JUNO_DKG_ADMIN_BIN="$fake_dkg_admin" \
    deploy/operators/dkg/operator-export-kms.sh backup-age \
      --workdir "$runtime" \
      --age-recipient age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq \
      --out "$out"
  )

  local got
  got="$(cat "$log_file")"
  case "$got" in
    *"--config $runtime/bundle/admin-config.json export-key-package --age-recipient age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq --out $out"*) ;;
    *)
      printf 'unexpected dkg-admin args: %s\n' "$got" >&2
      exit 1
      ;;
  esac

  rm -rf "$tmp"
}

test_backup_age_refuses_overwrite_without_force() {
  local tmp runtime out fake_dkg_admin
  tmp="$(mktemp -d)"
  runtime="$tmp/runtime"
  out="$tmp/backup.json"
  make_runtime_with_config "$runtime"
  printf '{}' >"$out"

  fake_dkg_admin="$tmp/fake-dkg-admin.sh"
  cat >"$fake_dkg_admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '{"ok":true}\n'
EOF
  chmod 0755 "$fake_dkg_admin"

  if (
    cd "$REPO_ROOT"
    JUNO_DKG_ADMIN_BIN="$fake_dkg_admin" \
    deploy/operators/dkg/operator-export-kms.sh backup-age \
      --workdir "$runtime" \
      --age-recipient age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq \
      --out "$out" >/dev/null 2>&1
  ); then
    printf 'expected backup-age to fail when output exists without --force\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

main() {
  test_backup_age_invokes_dkg_admin_with_age_only
  test_backup_age_refuses_overwrite_without_force
}

main "$@"
