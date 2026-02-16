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

test_operator_run_uses_bundle_cwd() {
  local tmp
  tmp="$(mktemp -d)"
  local fake_bin_dir="$tmp/fake-bin"
  local fake_dkg_admin="$tmp/fake-dkg-admin.sh"
  local runtime="$tmp/runtime"
  local bundle="$tmp/bundle"

  mkdir -p "$fake_bin_dir" "$runtime" "$bundle/tls" "$bundle/state"
  printf '{}' >"$bundle/tls/ca.pem"
  printf '{}' >"$bundle/tls/server.pem"
  printf '{}' >"$bundle/tls/server.key"
  chmod 0600 "$bundle/tls/server.key"
  cat >"$bundle/admin-config.json" <<'JSON'
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

  cat >"$fake_bin_dir/tailscale" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
  printf '{"BackendState":"Running","Self":{"Online":true}}\n'
  exit 0
fi
exit 0
EOF
  chmod 0755 "$fake_bin_dir/tailscale"

  cat >"$fake_dkg_admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
pwd
exit 0
EOF
  chmod 0755 "$fake_dkg_admin"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin_dir:$PATH" \
    JUNO_DKG_ADMIN_BIN="$fake_dkg_admin" \
    deploy/operators/dkg/operator.sh run \
      --bundle "$bundle" \
      --workdir "$runtime" \
      --daemon
  )

  local log_file="$runtime/dkg-admin.log"
  local attempt
  for attempt in $(seq 1 20); do
    if [[ -s "$log_file" ]]; then
      break
    fi
    sleep 0.1
  done

  local got want
  got="$(sed '/^$/d' "$log_file" | head -n 1 | tr -d '\r\n')"
  want="$runtime/bundle"
  assert_eq "$got" "$want" "operator run should start dkg-admin from runtime bundle dir"

  rm -rf "$tmp"
}

test_operator_run_accepts_bundle_equal_to_runtime_bundle() {
  local tmp fake_bin_dir fake_dkg_admin runtime bundle
  tmp="$(mktemp -d)"
  fake_bin_dir="$tmp/fake-bin"
  fake_dkg_admin="$tmp/fake-dkg-admin.sh"
  runtime="$tmp/runtime"
  bundle="$runtime/bundle"

  mkdir -p "$fake_bin_dir" "$bundle/tls" "$bundle/state"
  printf '{}' >"$bundle/tls/ca.pem"
  printf '{}' >"$bundle/tls/server.pem"
  printf '{}' >"$bundle/tls/server.key"
  chmod 0600 "$bundle/tls/server.key"
  cat >"$bundle/admin-config.json" <<'JSON'
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

  cat >"$fake_bin_dir/tailscale" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
  printf '{"BackendState":"Running","Self":{"Online":true}}\n'
  exit 0
fi
exit 0
EOF
  chmod 0755 "$fake_bin_dir/tailscale"

  cat >"$fake_dkg_admin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ok\n'
EOF
  chmod 0755 "$fake_dkg_admin"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin_dir:$PATH" \
    JUNO_DKG_ADMIN_BIN="$fake_dkg_admin" \
    deploy/operators/dkg/operator.sh run \
      --bundle "$bundle" \
      --workdir "$runtime" \
      --daemon
  )

  rm -rf "$tmp"
}

main() {
  test_operator_run_uses_bundle_cwd
  test_operator_run_accepts_bundle_equal_to_runtime_bundle
}

main "$@"
