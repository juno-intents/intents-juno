#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

RUNBOOK_PATH="$REPO_ROOT/deploy/shared/runbooks/build-operator-stack-ami.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

extract_block() {
  local start="$1"
  local end="$2"

  awk -v start="$start" -v end="$end" '
    index($0, start) { capture = 1; next }
    capture && $0 == end { exit }
    capture { print }
  ' "$RUNBOOK_PATH"
}

render_wrapper() {
  local start="$1"
  local end="$2"
  local target="$3"
  local env_file="$4"
  local text

  text="$(extract_block "$start" "$end")"
  text="${text//\/etc\/intents-juno\/operator-stack.env/$env_file}"
  text="${text//\/usr\/local\/bin\/withdraw-coordinator/withdraw-coordinator}"
  text="${text//\/usr\/local\/bin\/tss-host/tss-host}"
  printf '%s\n' "$text" >"$target"
  chmod 0755 "$target"
}

assert_standard_hardening() {
  local unit_text="$1"
  local unit_name="$2"

  assert_contains "$unit_text" "NoNewPrivileges=true" "$unit_name enables NoNewPrivileges"
  assert_contains "$unit_text" "PrivateTmp=true" "$unit_name enables PrivateTmp"
  assert_contains "$unit_text" "ProtectSystem=strict" "$unit_name enables ProtectSystem"
  assert_contains "$unit_text" "ProtectHome=true" "$unit_name enables ProtectHome"
  assert_contains "$unit_text" "CapabilityBoundingSet=" "$unit_name drops capabilities"
  assert_contains "$unit_text" "MemoryMax=" "$unit_name sets MemoryMax"
  assert_contains "$unit_text" "CPUQuota=" "$unit_name sets CPUQuota"
}

unit_marker_start() {
  case "$1" in
    junocashd.service) printf "%s" "cat > /tmp/junocashd.service <<'EOF_JUNOD'" ;;
    juno-scan.service) printf "%s" "cat > /tmp/juno-scan.service <<'EOF_SCAN_SERVICE'" ;;
    checkpoint-signer.service) printf "%s" "cat > /tmp/checkpoint-signer.service <<'EOF_SIGNER_SERVICE'" ;;
    checkpoint-aggregator.service) printf "%s" "cat > /tmp/checkpoint-aggregator.service <<'EOF_AGG_SERVICE'" ;;
    dkg-admin-serve.service) printf "%s" "cat > /tmp/dkg-admin-serve.service <<'EOF_DKG_SERVE_SERVICE'" ;;
    tss-host.service) printf "%s" "cat > /tmp/tss-host.service <<'EOF_TSS_SERVICE'" ;;
    base-relayer.service) printf "%s" "cat > /tmp/base-relayer.service <<'EOF_BASE_RELAYER_SERVICE'" ;;
    deposit-relayer.service) printf "%s" "cat > /tmp/deposit-relayer.service <<'EOF_DEPOSIT_RELAYER_SERVICE'" ;;
    withdraw-coordinator.service) printf "%s" "cat > /tmp/withdraw-coordinator.service <<'EOF_WITHDRAW_COORDINATOR_SERVICE'" ;;
    withdraw-finalizer.service) printf "%s" "cat > /tmp/withdraw-finalizer.service <<'EOF_WITHDRAW_FINALIZER_SERVICE'" ;;
    base-event-scanner.service) printf "%s" "cat > /tmp/base-event-scanner.service <<'EOF_BASE_EVENT_SCANNER_SERVICE'" ;;
    *) printf 'unknown unit: %s\n' "$1" >&2; exit 1 ;;
  esac
}

unit_marker_end() {
  case "$1" in
    junocashd.service) printf "%s" "EOF_JUNOD" ;;
    juno-scan.service) printf "%s" "EOF_SCAN_SERVICE" ;;
    checkpoint-signer.service) printf "%s" "EOF_SIGNER_SERVICE" ;;
    checkpoint-aggregator.service) printf "%s" "EOF_AGG_SERVICE" ;;
    dkg-admin-serve.service) printf "%s" "EOF_DKG_SERVE_SERVICE" ;;
    tss-host.service) printf "%s" "EOF_TSS_SERVICE" ;;
    base-relayer.service) printf "%s" "EOF_BASE_RELAYER_SERVICE" ;;
    deposit-relayer.service) printf "%s" "EOF_DEPOSIT_RELAYER_SERVICE" ;;
    withdraw-coordinator.service) printf "%s" "EOF_WITHDRAW_COORDINATOR_SERVICE" ;;
    withdraw-finalizer.service) printf "%s" "EOF_WITHDRAW_FINALIZER_SERVICE" ;;
    base-event-scanner.service) printf "%s" "EOF_BASE_EVENT_SCANNER_SERVICE" ;;
    *) printf 'unknown unit: %s\n' "$1" >&2; exit 1 ;;
  esac
}

test_build_operator_stack_ami_enforces_service_user_and_hardening() {
  local script_text hydrator_unit
  script_text="$(cat "$RUNBOOK_PATH")"

  assert_contains "$script_text" 'sudo groupadd --system intents-juno' "builder creates intents-juno group"
  assert_contains "$script_text" 'sudo useradd --system --gid intents-juno --home-dir /var/lib/intents-juno --shell /usr/sbin/nologin intents-juno' "builder creates intents-juno service user"
  assert_contains "$script_text" 'sudo install -d -m 0750 -o intents-juno -g intents-juno /var/lib/intents-juno' "builder provisions intents-juno runtime dir"
  assert_contains "$script_text" 'sudo chown root:intents-juno /etc/intents-juno/operator-stack.env' "builder seeds operator env with intents-juno group access"
  assert_contains "$script_text" 'install -m 0640 -o root -g intents-juno "$tmp_env" "$stack_env_file"' "hydrator preserves intents-juno group access to operator env"
  assert_contains "$script_text" "checkpoint_key=\"\\\$(sudo cat /etc/intents-juno/checkpoint-signer.key | tr -d '\\r\\n')\"" "builder reads the checkpoint signer key through sudo before stripping newlines"
  assert_contains "$script_text" 'sudo rm -f /home/$builder_user/.ssh/authorized_keys' "builder scrubs temporary SSH authorized keys before imaging"

  for unit in \
    junocashd.service \
    juno-scan.service \
    checkpoint-signer.service \
    checkpoint-aggregator.service \
    dkg-admin-serve.service \
    tss-host.service \
    base-relayer.service \
    deposit-relayer.service \
    withdraw-coordinator.service \
    withdraw-finalizer.service \
    base-event-scanner.service
  do
    local unit_text
    unit_text="$(extract_block "$(unit_marker_start "$unit")" "$(unit_marker_end "$unit")")"
    assert_contains "$unit_text" "User=intents-juno" "$unit runs as intents-juno"
    assert_contains "$unit_text" "Group=intents-juno" "$unit uses intents-juno group"
    assert_not_contains "$unit_text" "User=ubuntu" "$unit does not run as ubuntu"
    assert_standard_hardening "$unit_text" "$unit"
  done

  hydrator_unit="$(extract_block "cat > /tmp/intents-juno-config-hydrator.service <<'EOF_CONFIG_HYDRATOR_SERVICE'" "EOF_CONFIG_HYDRATOR_SERVICE")"
  assert_contains "$hydrator_unit" "User=root" "config hydrator runs as root"
  assert_contains "$hydrator_unit" "EnvironmentFile=-/etc/intents-juno/operator-stack-hydrator.env" "config hydrator loads env file"
  assert_contains "$hydrator_unit" "ReadWritePaths=/etc/intents-juno /var/lib/intents-juno" "config hydrator scopes write paths"
  assert_standard_hardening "$hydrator_unit" "intents-juno-config-hydrator.service"
}

test_build_operator_stack_ami_uses_checksum_and_env_wiring() {
  local script_text withdraw_wrapper tss_wrapper
  script_text="$(cat "$RUNBOOK_PATH")"

  assert_contains "$script_text" 'download_release_asset_with_checksum()' "runbook defines checksum downloader"
  assert_contains "$script_text" 'set -Eeuo pipefail' "runbook enables ERR trap inheritance for bootstrap failures"
  assert_contains "$script_text" 'checksum mismatch for $asset_name' "checksum mismatch aborts build"
  assert_contains "$script_text" 'download_release_asset_with_checksum "\$release_json" "\$asset_name" "\$archive"' "binary installers verify checksums before use"
  assert_contains "$script_text" 'SHA256SUMS' "runbook supports release-wide SHA256SUMS manifests"
  assert_contains "$script_text" 'escaped_asset_name="$(printf '\''%s'\'' "$asset_name" | sed '\''s/[][(){}.^$*+?|\\/]/\\&/g'\'')"' "runbook escapes asset names before SHA256SUMS lookup"
  assert_contains "$script_text" 'grep -E "(^|[[:space:]\*])${escaped_asset_name}$"' "runbook can extract an asset checksum from SHA256SUMS"
  assert_contains "$script_text" '|| true' "runbook tolerates missing SHA256SUMS matches so digest fallback can run"
  assert_contains "$script_text" '.assets[] | select(.name == $name) | .digest' "runbook reads GitHub asset digests as a checksum fallback"
  assert_contains "$script_text" 'expected="${asset_digest#sha256:}"' "runbook falls back to the asset digest when checksum files omit the asset"

  withdraw_wrapper="$(extract_block "cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'" "EOF_WITHDRAW_COORDINATOR")"
  assert_contains "$withdraw_wrapper" 'source /etc/intents-juno/operator-stack.env' "withdraw wrapper sources operator env"
  assert_contains "$withdraw_wrapper" 'export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "withdraw wrapper exports secret env vars"
  assert_contains "$withdraw_wrapper" '--postgres-dsn-env "${WITHDRAW_COORDINATOR_POSTGRES_DSN_ENV:-CHECKPOINT_POSTGRES_DSN}"' "withdraw wrapper passes DSN by env indirection"
  assert_contains "$withdraw_wrapper" '--juno-rpc-user-env JUNO_RPC_USER' "withdraw wrapper passes RPC username env name"
  assert_contains "$withdraw_wrapper" '--juno-rpc-pass-env JUNO_RPC_PASS' "withdraw wrapper passes RPC password env name"
  assert_contains "$withdraw_wrapper" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw wrapper passes base-relayer auth env name"
  assert_not_contains "$withdraw_wrapper" '--postgres-dsn "${CHECKPOINT_POSTGRES_DSN}"' "withdraw wrapper does not pass raw Postgres DSN"

  tss_wrapper="$(extract_block "cat > /tmp/intents-juno-tss-host.sh <<'EOF_TSS'" "EOF_TSS")"
  assert_contains "$tss_wrapper" '[[ -s "${TSS_CLIENT_CA_FILE:-}" ]] || {' "tss wrapper requires client CA in production"
  assert_contains "$tss_wrapper" 'args+=(--client-ca-file "${TSS_CLIENT_CA_FILE}")' "tss wrapper forwards client CA to tss-host"
  assert_contains "$tss_wrapper" 'echo "tss-host host-process mode requires JUNO_DEV_MODE=true"' "tss wrapper blocks host-process outside dev mode"
}

test_build_operator_stack_ami_digest_fallback_survives_missing_manifest_entry() {
  local tmp helper_text wrapper script_text asset_fixture manifest_fixture release_json_fixture archive_output asset_sha output
  tmp="$(mktemp -d)"
  helper_text="$(extract_block "download_release_asset_with_checksum() {" "install_junocash() {")"
  helper_text="${helper_text//\\\$/\$}"
  helper_text=$'download_release_asset_with_checksum() {\n'"$helper_text"
  wrapper="$tmp/download_release_asset_with_checksum.sh"
  asset_fixture="$tmp/junocash-0.9.9-linux64.tar.gz"
  manifest_fixture="$tmp/SHA256SUMS"
  release_json_fixture="$tmp/release.json"
  archive_output="$tmp/archive.out"

  printf 'archive-bytes\n' >"$asset_fixture"
  printf 'deadbeef  junocash-0.9.9-darwin.zip\n' >"$manifest_fixture"
  asset_sha="$(sha256sum "$asset_fixture" | awk '{print $1}')"
  jq -n \
    --arg asset_name "junocash-0.9.9-linux64.tar.gz" \
    --arg asset_url "https://example.test/junocash-0.9.9-linux64.tar.gz" \
    --arg asset_digest "sha256:$asset_sha" \
    --arg manifest_url "https://example.test/SHA256SUMS" \
    '{
      assets: [
        {
          name: $asset_name,
          browser_download_url: $asset_url,
          digest: $asset_digest
        },
        {
          name: "SHA256SUMS",
          browser_download_url: $manifest_url
        }
      ]
    }' >"$release_json_fixture"

  cat >"$wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

sha256_hex_file() {
  sha256sum "$1" | awk '{print $1}'
}

curl() {
  local out="" url=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -fsSL)
        shift
        ;;
      -o)
        out="$2"
        shift 2
        ;;
      *)
        url="$1"
        shift
        ;;
    esac
  done

  case "$url" in
    https://example.test/junocash-0.9.9-linux64.tar.gz)
      cp "__ASSET_FIXTURE__" "$out"
      ;;
    https://example.test/SHA256SUMS)
      cp "__MANIFEST_FIXTURE__" "$out"
      ;;
    *)
      printf 'unexpected curl url: %s\n' "$url" >&2
      return 1
      ;;
  esac
}
EOF
  printf '%s\n' "$helper_text" >>"$wrapper"
  cat >>"$wrapper" <<'EOF'

release_json="$(cat "__RELEASE_JSON_FIXTURE__")"
download_release_asset_with_checksum "$release_json" "junocash-0.9.9-linux64.tar.gz" "__ARCHIVE_OUTPUT__"
cat "__ARCHIVE_OUTPUT__"
EOF

  script_text="$(cat "$wrapper")"
  script_text="${script_text//__ASSET_FIXTURE__/$asset_fixture}"
  script_text="${script_text//__MANIFEST_FIXTURE__/$manifest_fixture}"
  script_text="${script_text//__RELEASE_JSON_FIXTURE__/$release_json_fixture}"
  script_text="${script_text//__ARCHIVE_OUTPUT__/$archive_output}"
  printf '%s\n' "$script_text" >"$wrapper"
  chmod 0755 "$wrapper"

  output="$("$wrapper")"
  assert_eq "$output" "archive-bytes" "digest fallback continues when SHA256SUMS omits the asset entry"

  rm -rf "$tmp"
}

test_build_operator_stack_ami_wrapper_smoke() {
  local tmp env_file fake_bin output_file stderr_file
  tmp="$(mktemp -d)"
  env_file="$tmp/operator-stack.env"
  fake_bin="$tmp/bin"
  output_file="$tmp/withdraw.args"
  stderr_file="$tmp/tss.stderr"
  mkdir -p "$fake_bin"

  render_wrapper \
    "cat > /tmp/intents-juno-tss-host.sh <<'EOF_TSS'" \
    "EOF_TSS" \
    "$tmp/intents-juno-tss-host.sh" \
    "$env_file"

  printf 'ufvk' >"$tmp/ufvk.txt"
  printf 'cert' >"$tmp/server.pem"
  printf 'key' >"$tmp/server.key"
  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
TSS_SIGNER_UFVK_FILE=$tmp/ufvk.txt
TSS_SIGNER_WORK_DIR=$tmp/work
TSS_TLS_CERT_FILE=$tmp/server.pem
TSS_TLS_KEY_FILE=$tmp/server.key
EOF

  if PATH="$fake_bin:$PATH" "$tmp/intents-juno-tss-host.sh" >"$tmp/tss.stdout" 2>"$stderr_file"; then
    printf 'expected tss wrapper to reject missing client CA in production mode\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr_file")" "tss-host production mode requires TSS_CLIENT_CA_FILE" "tss wrapper rejects non-mTLS production wiring"

  cat >"$fake_bin/withdraw-coordinator" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$output_file"
env | sort >"$tmp/withdraw.env"
exit 0
EOF
  cat >"$fake_bin/juno-txbuild" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$tmp/extend-signer" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$fake_bin/withdraw-coordinator" "$fake_bin/juno-txbuild" "$tmp/extend-signer"

  printf 'ca' >"$tmp/ca.pem"
  printf 'coord-cert' >"$tmp/coordinator-client.pem"
  printf 'coord-key' >"$tmp/coordinator-client.key"
  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://coordinator?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
BASE_RELAYER_URL=https://127.0.0.1:18081
BASE_RELAYER_AUTH_TOKEN=actual-base-relayer-secret-token
WITHDRAW_COORDINATOR_JUNO_WALLET_ID=wallet-123
WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS=utest1changeaddress
WITHDRAW_COORDINATOR_JUNO_RPC_URL=http://127.0.0.1:18232
JUNO_RPC_USER=actual-rpc-username-secret
JUNO_RPC_PASS=actual-rpc-password-secret
WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443
WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=$tmp/ca.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=$tmp/coordinator-client.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=$tmp/coordinator-client.key
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=$tmp/extend-signer
WITHDRAW_BLOB_BUCKET=withdraw-bucket
JUNO_QUEUE_KAFKA_TLS=true
EOF

  render_wrapper \
    "cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'" \
    "EOF_WITHDRAW_COORDINATOR" \
    "$tmp/intents-juno-withdraw-coordinator.sh" \
    "$env_file"

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-withdraw-coordinator.sh"

  assert_contains "$(cat "$output_file")" '--postgres-dsn-env CHECKPOINT_POSTGRES_DSN' "withdraw wrapper forwards DSN env name"
  assert_contains "$(cat "$output_file")" '--juno-rpc-user-env JUNO_RPC_USER' "withdraw wrapper forwards RPC username env name"
  assert_contains "$(cat "$output_file")" '--juno-rpc-pass-env JUNO_RPC_PASS' "withdraw wrapper forwards RPC password env name"
  assert_contains "$(cat "$output_file")" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw wrapper forwards base relayer auth env name"
  assert_not_contains "$(cat "$output_file")" 'postgres://coordinator?sslmode=require' "withdraw wrapper does not pass raw DSN in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-base-relayer-secret-token' "withdraw wrapper does not pass base relayer secret in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-rpc-username-secret' "withdraw wrapper does not pass RPC username in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-rpc-password-secret' "withdraw wrapper does not pass RPC password in argv"
  assert_contains "$(cat "$tmp/withdraw.env")" 'BASE_RELAYER_AUTH_TOKEN=actual-base-relayer-secret-token' "withdraw wrapper exports base relayer auth token"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_RPC_USER=actual-rpc-username-secret' "withdraw wrapper exports RPC user"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_RPC_PASS=actual-rpc-password-secret' "withdraw wrapper exports RPC pass"

  rm -rf "$tmp"
}

main() {
  test_build_operator_stack_ami_enforces_service_user_and_hardening
  test_build_operator_stack_ami_uses_checksum_and_env_wiring
  test_build_operator_stack_ami_digest_fallback_survives_missing_manifest_entry
  test_build_operator_stack_ami_wrapper_smoke
}

main "$@"
