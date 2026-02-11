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

test_rewrap_age_to_kms_uses_backup_artifacts() {
  local tmp fake_bin fake_dkg_admin admin_config age_backup age_identity
  local log_args log_cfg log_kp log_pkp expected_s3_key
  tmp="$(mktemp -d)"
  fake_bin="$tmp/fake-bin"
  mkdir -p "$fake_bin"

  admin_config="$tmp/admin-config.json"
  cat >"$admin_config" <<'JSON'
{
  "config_version": 1,
  "ceremony_id": "11111111-1111-1111-1111-111111111111",
  "operator_id": "0x1111111111111111111111111111111111111111",
  "identifier": 1,
  "threshold": 2,
  "max_signers": 3,
  "network": "mainnet",
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

  age_backup="$tmp/backup-age.json"
  cat >"$age_backup" <<'JSON'
{
  "envelope_version": "keypackage_envelope_v1",
  "created_at": "2026-02-11T17:00:00Z",
  "encryption_backend": "age",
  "recipients": [
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
  ],
  "ciphertext_b64": "Y2lwaGVydGV4dA=="
}
JSON

  age_identity="$tmp/age-identity.txt"
  cat >"$age_identity" <<'EOF'
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
EOF

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
  "threshold": 2,
  "max_signers": 3,
  "network": "mainnet",
  "roster_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "key_package_bytes_b64": "a3BieXRlcw==",
  "public_key_package_bytes_b64": "cGtwYnl0ZXM="
}
JSON
EOF
  chmod 0755 "$fake_bin/age"

  log_args="$tmp/dkg.args"
  log_cfg="$tmp/dkg.config.json"
  log_kp="$tmp/dkg.kp.bin"
  log_pkp="$tmp/dkg.pkp.bin"
  fake_dkg_admin="$tmp/fake-dkg-admin.sh"
  cat >"$fake_dkg_admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$LOG_ARGS"
cfg_path=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "--config" ]]; then
    cfg_path="$arg"
    break
  fi
  prev="$arg"
done
cp "$cfg_path" "$LOG_CFG"
state_dir="$(jq -r '.state_dir' "$cfg_path")"
cp "$state_dir/key_package.bin" "$LOG_KP"
cp "$state_dir/public_key_package.bin" "$LOG_PKP"
printf '{"ok":true}\n'
EOF
  chmod 0755 "$fake_dkg_admin"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    LOG_ARGS="$log_args" \
    LOG_CFG="$log_cfg" \
    LOG_KP="$log_kp" \
    LOG_PKP="$log_pkp" \
    JUNO_DKG_ADMIN_BIN="$fake_dkg_admin" \
    deploy/operators/dkg/operator-export-kms.sh rewrap-age-to-kms \
      --age-backup-file "$age_backup" \
      --age-identity-file "$age_identity" \
      --admin-config "$admin_config" \
      --kms-key-id arn:aws:kms:us-east-1:111111111111:key/abc \
      --s3-bucket op-bucket \
      --s3-sse-kms-key-id arn:aws:kms:us-east-1:111111111111:key/def \
      --skip-aws-preflight
  )

  expected_s3_key="dkg/keypackages/11111111-1111-1111-1111-111111111111/operator_1_0x1111111111111111111111111111111111111111.json"
  local got_args got_kp got_pkp
  got_args="$(cat "$log_args")"
  case "$got_args" in
    *"--kms-key-id arn:aws:kms:us-east-1:111111111111:key/abc --s3-bucket op-bucket --s3-key $expected_s3_key --s3-sse-kms-key-id arn:aws:kms:us-east-1:111111111111:key/def"*) ;;
    *)
      printf 'unexpected dkg-admin args: %s\n' "$got_args" >&2
      exit 1
      ;;
  esac

  assert_eq "$(jq -r '.grpc' "$log_cfg")" "null" "rewrap config omits grpc"
  assert_eq "$(jq -r '.operator_id' "$log_cfg")" "0x1111111111111111111111111111111111111111" "rewrap config operator"
  assert_eq "$(jq -r '.ceremony_id' "$log_cfg")" "11111111-1111-1111-1111-111111111111" "rewrap config ceremony"
  assert_eq "$(jq -r '.roster_hash_hex' "$log_cfg")" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "rewrap config roster hash"

  got_kp="$(cat "$log_kp")"
  got_pkp="$(cat "$log_pkp")"
  assert_eq "$got_kp" "kpbytes" "rewrap writes key_package.bin from age backup"
  assert_eq "$got_pkp" "pkpbytes" "rewrap writes public_key_package.bin from age backup"

  rm -rf "$tmp"
}

main() {
  test_backup_age_invokes_dkg_admin_with_age_only
  test_backup_age_refuses_overwrite_without_force
  test_rewrap_age_to_kms_uses_backup_artifacts
}

main "$@"
