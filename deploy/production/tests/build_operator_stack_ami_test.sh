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

assert_line_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"
  local first_line second_line
  first_line="$(printf '%s\n' "$haystack" | nl -ba | grep -F "$first" | head -n1 | awk '{print $1}')"
  second_line="$(printf '%s\n' "$haystack" | nl -ba | grep -F "$second" | head -n1 | awk '{print $1}')"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'assert_line_order failed: %s: first=%q second=%q first_line=%q second_line=%q\n' "$msg" "$first" "$second" "$first_line" "$second_line" >&2
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
  text="${text//\/usr\/local\/bin\/checkpoint-signer/checkpoint-signer}"
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
    juno-scan-backfill.service) printf "%s" "cat > /tmp/juno-scan-backfill.service <<'EOF_SCAN_BACKFILL_SERVICE'" ;;
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
    juno-scan-backfill.service) printf "%s" "EOF_SCAN_BACKFILL_SERVICE" ;;
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
  assert_contains "$script_text" 'sudo chown -R intents-juno:intents-juno \' "builder reowns reused runtime trees from prior source AMIs"
  assert_contains "$script_text" '/var/lib/intents-juno/junocashd \' "builder reowns junocashd state recursively"
  assert_contains "$script_text" '/var/lib/intents-juno/juno-scan \' "builder reowns juno-scan state recursively"
  assert_contains "$script_text" '/var/lib/intents-juno/juno-scan.db \' "builder reowns juno-scan rocksdb state recursively"
  assert_contains "$script_text" '/var/lib/intents-juno/operator-runtime \' "builder reowns operator runtime state recursively"
  assert_contains "$script_text" '/var/lib/intents-juno/tss-signer' "builder reowns tss signer state recursively"
  assert_contains "$script_text" 'sudo chown root:intents-juno /etc/intents-juno/operator-stack.env' "builder seeds operator env with intents-juno group access"
  assert_contains "$script_text" 'cat "$tmp" > "$file"' "hydrator rewrites temp env updates in place"
  assert_contains "$script_text" 'chmod 0640 "$file"' "hydrator restores shared-read permissions after temp env updates"
  assert_contains "$script_text" 'cat "$tmp_env" > "$stack_env_file"' "hydrator rewrites operator env in place"
  assert_contains "$script_text" 'chmod 0640 "$stack_env_file"' "hydrator restores shared-read permissions on operator env"
  assert_not_contains "$script_text" 'install -m 0600 "$tmp" "$file"' "hydrator no longer replaces env files with install"
  assert_not_contains "$script_text" 'install -m 0640 -o root -g intents-juno "$tmp_env" "$stack_env_file"' "hydrator does not require chown-capable install inside the service"
  assert_contains "$script_text" 'sudo rm -f /home/$builder_user/.ssh/authorized_keys' "builder scrubs temporary SSH authorized keys before imaging"

  for unit in \
    junocashd.service \
    juno-scan.service \
    juno-scan-backfill.service \
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

  local juno_scan_backfill_unit
  juno_scan_backfill_unit="$(extract_block "$(unit_marker_start "juno-scan-backfill.service")" "$(unit_marker_end "juno-scan-backfill.service")")"
  assert_contains "$juno_scan_backfill_unit" "ExecStart=/usr/local/bin/intents-juno-juno-scan-backfill.sh" "scanner backfill unit runs the dedicated wrapper"
  assert_contains "$juno_scan_backfill_unit" "After=juno-scan.service intents-juno-config-hydrator.service" "scanner backfill unit waits for scanner health dependencies"
  assert_contains "$juno_scan_backfill_unit" "Restart=on-failure" "scanner backfill unit retries failed historical catch-up"

  hydrator_unit="$(extract_block "cat > /tmp/intents-juno-config-hydrator.service <<'EOF_CONFIG_HYDRATOR_SERVICE'" "EOF_CONFIG_HYDRATOR_SERVICE")"
  assert_contains "$hydrator_unit" "User=root" "config hydrator runs as root"
  assert_contains "$hydrator_unit" "EnvironmentFile=-/etc/intents-juno/operator-stack-hydrator.env" "config hydrator loads env file"
  assert_contains "$hydrator_unit" "ReadWritePaths=/etc/intents-juno /var/lib/intents-juno" "config hydrator scopes write paths"
  assert_standard_hardening "$hydrator_unit" "intents-juno-config-hydrator.service"
}

test_build_operator_stack_ami_repairs_dpkg_before_apt() {
  local script_text
  script_text="$(cat "$RUNBOOK_PATH")"

  assert_contains "$script_text" 'run_with_retry sudo dpkg --configure -a' "builder repairs interrupted dpkg state before package installs"
  assert_line_order "$script_text" 'run_with_retry sudo dpkg --configure -a' 'run_with_retry sudo apt-get update -y' "builder repairs dpkg before apt update"
  assert_line_order "$script_text" 'run_with_retry sudo dpkg --configure -a' 'run_with_retry sudo apt-get install -y ca-certificates curl jq tar git golang-go build-essential make openssl unzip' "builder repairs dpkg before apt install"
}

test_build_operator_stack_ami_uses_checksum_and_env_wiring() {
  local script_text hydrator_script deposit_wrapper withdraw_wrapper tss_wrapper signer_wrapper aggregator_wrapper
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
  assert_not_contains "$script_text" '/etc/intents-juno/checkpoint-signer.key' "runbook no longer bakes a checkpoint signer key file into production AMIs"
  assert_not_contains "$script_text" 'CHECKPOINT_SIGNER_PRIVATE_KEY=' "runbook no longer bakes checkpoint signer private keys into operator env"
  assert_contains "$script_text" 'CHECKPOINT_SIGNER_DRIVER=aws-kms' "runbook defaults the baked operator env to aws-kms signer mode"
  assert_contains "$script_text" 'CHECKPOINT_SIGNER_KMS_KEY_ID=' "runbook reserves a kms key id slot in operator env"
  assert_contains "$script_text" 'CHECKPOINT_BLOB_SSE_KMS_KEY_ID=' "runbook reserves a blob sse kms key id slot in operator env"
  assert_contains "$script_text" 'OPERATOR_ADDRESS=' "runbook reserves operator address in operator env"
  assert_contains "$script_text" 'CHECKPOINT_OPERATORS=' "runbook leaves checkpoint operators to deployment-time hydration"

  hydrator_script="$(extract_block "cat > /tmp/intents-juno-config-hydrator.sh <<'EOF_CONFIG_HYDRATOR'" "EOF_CONFIG_HYDRATOR")"
  assert_contains "$hydrator_script" 'checkpoint_signer_driver="$(resolve_value "CHECKPOINT_SIGNER_DRIVER"' "config hydrator resolves checkpoint signer driver"
  assert_contains "$hydrator_script" 'checkpoint_signer_kms_key_id="$(resolve_value "CHECKPOINT_SIGNER_KMS_KEY_ID"' "config hydrator resolves checkpoint signer kms key id"
  assert_contains "$hydrator_script" 'checkpoint_blob_sse_kms_key_id="$(resolve_value "CHECKPOINT_BLOB_SSE_KMS_KEY_ID"' "config hydrator resolves checkpoint blob sse kms key id"
  assert_contains "$hydrator_script" 'operator_address="$(resolve_value "OPERATOR_ADDRESS"' "config hydrator resolves operator address"
  assert_contains "$hydrator_script" 'juno_rpc_user="$(resolve_value "JUNO_RPC_USER"' "config hydrator resolves juno rpc user"
  assert_contains "$hydrator_script" 'juno_rpc_pass="$(resolve_value "JUNO_RPC_PASS"' "config hydrator resolves juno rpc password"
  assert_contains "$hydrator_script" 'juno_rpc_bind="$(resolve_value "JUNO_RPC_BIND"' "config hydrator resolves juno rpc bind host"
  assert_contains "$hydrator_script" 'juno_rpc_allow_ips="$(resolve_value "JUNO_RPC_ALLOW_IPS"' "config hydrator resolves juno rpc allowlist"
  assert_contains "$hydrator_script" 'required_key "JUNO_RPC_USER" "$juno_rpc_user"' "config hydrator requires juno rpc user"
  assert_contains "$hydrator_script" 'required_key "JUNO_RPC_PASS" "$juno_rpc_pass"' "config hydrator requires juno rpc password"
  assert_contains "$hydrator_script" 'required_key "JUNO_RPC_BIND" "$juno_rpc_bind"' "config hydrator requires juno rpc bind host"
  assert_contains "$hydrator_script" 'required_key "CHECKPOINT_BLOB_SSE_KMS_KEY_ID" "$checkpoint_blob_sse_kms_key_id"' "config hydrator requires checkpoint blob sse kms key id"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" JUNO_RPC_USER "$juno_rpc_user"' "config hydrator persists juno rpc user"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" JUNO_RPC_PASS "$juno_rpc_pass"' "config hydrator persists juno rpc password"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" JUNO_RPC_BIND "$juno_rpc_bind"' "config hydrator persists juno rpc bind host"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" JUNO_RPC_ALLOW_IPS "$juno_rpc_allow_ips"' "config hydrator persists juno rpc allowlist"
  assert_contains "$hydrator_script" 'required_key "CHECKPOINT_SIGNER_KMS_KEY_ID when CHECKPOINT_SIGNER_DRIVER=aws-kms" "$checkpoint_signer_kms_key_id"' "config hydrator requires KMS key id for aws-kms mode"
  assert_contains "$hydrator_script" 'required_key "OPERATOR_ADDRESS when CHECKPOINT_SIGNER_DRIVER=aws-kms" "$operator_address"' "config hydrator requires operator address for aws-kms mode"
  assert_contains "$hydrator_script" 'junocashd_conf_file="/etc/intents-juno/junocashd.conf"' "config hydrator rewrites junocashd conf"
  assert_contains "$hydrator_script" 'txunpaidactionlimit=10000' "config hydrator raises unpaid action limit for shielded transactions"
  assert_contains "$hydrator_script" 'rpcbind=${juno_rpc_bind}' "config hydrator writes junocashd rpc bind host"
  assert_contains "$hydrator_script" 'rpcallowip=127.0.0.1' "config hydrator preserves loopback rpc access"
  assert_contains "$hydrator_script" 'IFS='\'','\'' read -r -a rpc_allow_ip_entries <<< "$juno_rpc_allow_ips"' "config hydrator splits rpc allowlist on commas"
  assert_contains "$hydrator_script" 'printf '\''rpcallowip=%s\n'\'' "$allow_ip"' "config hydrator appends each additional rpc allowlist entry"
  assert_contains "$hydrator_script" 'rpcuser=${juno_rpc_user}' "config hydrator writes junocashd rpc user"
  assert_contains "$hydrator_script" 'rpcpassword=${juno_rpc_pass}' "config hydrator writes junocashd rpc password"
  assert_contains "$hydrator_script" 'chown root:intents-juno "$junocashd_conf_file"' "config hydrator preserves junocashd conf ownership"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" CHECKPOINT_SIGNER_DRIVER "$checkpoint_signer_driver"' "config hydrator persists checkpoint signer driver"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" CHECKPOINT_SIGNER_KMS_KEY_ID "$checkpoint_signer_kms_key_id"' "config hydrator persists checkpoint signer kms key id"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" CHECKPOINT_BLOB_SSE_KMS_KEY_ID "$checkpoint_blob_sse_kms_key_id"' "config hydrator persists checkpoint blob sse kms key id"
  assert_contains "$hydrator_script" 'set_env_value "$tmp_env" OPERATOR_ADDRESS "$operator_address"' "config hydrator persists operator address"

  deposit_wrapper="$(extract_block "cat > /tmp/intents-juno-deposit-relayer.sh <<'EOF_DEPOSIT_RELAYER'" "EOF_DEPOSIT_RELAYER")"
  assert_contains "$deposit_wrapper" 'deposit_max_items="${DEPOSIT_RELAYER_MAX_ITEMS:-25}"' "deposit wrapper defaults to deposit-sized batches with env override"
  assert_contains "$deposit_wrapper" 'deposit_queue_topics="${DEPOSIT_RELAYER_QUEUE_TOPICS:-deposits.event.v2,checkpoints.packages.v1}"' "deposit wrapper subscribes to deposits.event.v2 by default"
  assert_contains "$deposit_wrapper" 'deposit_max_age="${DEPOSIT_RELAYER_MAX_AGE:-3m}"' "deposit wrapper sets a bounded batch max-age by default"
  assert_contains "$deposit_wrapper" 'deposit_claim_ttl="${DEPOSIT_RELAYER_CLAIM_TTL:-7m}"' "deposit wrapper sets a durable claim ttl by default"
  assert_contains "$deposit_wrapper" 'deposit_flush_interval="${DEPOSIT_RELAYER_FLUSH_INTERVAL:-1s}"' "deposit wrapper sets a bounded flush interval by default"
  assert_contains "$deposit_wrapper" 'sp1_request_timeout_seconds="${SP1_REQUEST_TIMEOUT_SECONDS:-1500}"' "deposit wrapper derives submit timeout from the SP1 request timeout"
  assert_contains "$deposit_wrapper" 'relayer_submit_timeout_seconds="$((10#$sp1_request_timeout_seconds + 300))"' "deposit wrapper adds buffer to the SP1 request timeout"
  assert_contains "$deposit_wrapper" '(( relayer_submit_timeout_seconds >= 1800 )) || relayer_submit_timeout_seconds=1800' "deposit wrapper enforces a minimum submit timeout"
  assert_contains "$deposit_wrapper" 'deposit_submit_timeout="${DEPOSIT_RELAYER_SUBMIT_TIMEOUT:-${relayer_submit_timeout_seconds}s}"' "deposit wrapper sets a derived submit timeout by default"
  assert_contains "$deposit_wrapper" '--max-items "${deposit_max_items}"' "deposit wrapper passes the deposit batch size override"
  assert_contains "$deposit_wrapper" '--max-age "${deposit_max_age}"' "deposit wrapper passes the deposit batch max-age"
  assert_contains "$deposit_wrapper" '--claim-ttl "${deposit_claim_ttl}"' "deposit wrapper passes the deposit claim ttl"
  assert_contains "$deposit_wrapper" '--flush-interval "${deposit_flush_interval}"' "deposit wrapper passes the deposit flush interval"
  assert_contains "$deposit_wrapper" '--submit-timeout "${deposit_submit_timeout}"' "deposit wrapper passes the deposit submit timeout"
  assert_contains "$deposit_wrapper" '--deposit-min-confirmations "${RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS:-1}"' "deposit wrapper passes deposit confirmation seed"
  assert_contains "$deposit_wrapper" '--withdraw-planner-min-confirmations "${RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"' "deposit wrapper passes withdraw planner confirmation seed"
  assert_contains "$deposit_wrapper" '--withdraw-batch-confirmations "${RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS:-1}"' "deposit wrapper passes withdraw batch confirmation seed"

  withdraw_wrapper="$(extract_block "cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'" "EOF_WITHDRAW_COORDINATOR")"
  assert_contains "$withdraw_wrapper" 'source /etc/intents-juno/operator-stack.env' "withdraw wrapper sources operator env"
  assert_contains "$withdraw_wrapper" 'export_optional_env_vars AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS' "withdraw wrapper exports AWS SDK env when present"
  assert_contains "$withdraw_wrapper" 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS' "withdraw wrapper exports DSN and secret env vars"
  assert_contains "$withdraw_wrapper" 'export JUNO_SCAN_BEARER_TOKEN' "withdraw wrapper exports juno scan bearer token"
  assert_contains "$withdraw_wrapper" 'export JUNO_TXSIGN_SIGNER_KEYS' "withdraw wrapper exports juno txsign signer keys"
  assert_contains "$withdraw_wrapper" '--postgres-dsn-env "${WITHDRAW_COORDINATOR_POSTGRES_DSN_ENV:-CHECKPOINT_POSTGRES_DSN}"' "withdraw wrapper passes DSN by env indirection"
  assert_contains "$withdraw_wrapper" '--claim-ttl "${WITHDRAW_COORDINATOR_CLAIM_TTL:-5m}"' "withdraw wrapper sets a production-safe claim ttl by default"
  assert_contains "$withdraw_wrapper" 'withdraw_coord_max_items="${WITHDRAW_COORDINATOR_MAX_ITEMS:-50}"' "withdraw wrapper defaults to withdraw-sized batches with env override"
  assert_contains "$withdraw_wrapper" '--max-items "${withdraw_coord_max_items}"' "withdraw wrapper passes the withdraw batch size override"
  assert_contains "$withdraw_wrapper" '--juno-scan-url "${WITHDRAW_COORDINATOR_JUNO_SCAN_URL}"' "withdraw wrapper pins juno txbuild to the scanner URL"
  assert_contains "$withdraw_wrapper" '--juno-scan-bearer-env JUNO_SCAN_BEARER_TOKEN' "withdraw wrapper passes the scanner bearer env name"
  assert_contains "$withdraw_wrapper" '--juno-rpc-user-env JUNO_RPC_USER' "withdraw wrapper passes RPC username env name"
  assert_contains "$withdraw_wrapper" '--juno-rpc-pass-env JUNO_RPC_PASS' "withdraw wrapper passes RPC password env name"
  assert_contains "$withdraw_wrapper" '--deposit-min-confirmations "${RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS:-1}"' "withdraw wrapper passes deposit confirmation seed"
  assert_contains "$withdraw_wrapper" '--juno-minconf "${RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS:-1}"' "withdraw wrapper passes withdraw planner confirmation seed"
  assert_contains "$withdraw_wrapper" '--juno-expiry-offset "${WITHDRAW_COORDINATOR_JUNO_EXPIRY_OFFSET:-240}"' "withdraw wrapper passes a safer juno expiry offset default"
  assert_contains "$withdraw_wrapper" '--juno-confirmations "${RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS:-1}"' "withdraw wrapper passes withdraw batch confirmation seed"
  assert_contains "$withdraw_wrapper" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw wrapper passes base-relayer auth env name"
  assert_contains "$withdraw_wrapper" '--expiry-safety-margin "${WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN:-6h}"' "withdraw wrapper defaults expiry safety margin within the extension bound"
  assert_contains "$withdraw_wrapper" '--max-expiry-extension "${WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION:-12h}"' "withdraw wrapper passes the max expiry extension from env"
  assert_not_contains "$withdraw_wrapper" '--postgres-dsn "${CHECKPOINT_POSTGRES_DSN}"' "withdraw wrapper does not pass raw Postgres DSN"

  local withdraw_finalizer_wrapper
  withdraw_finalizer_wrapper="$(extract_block "cat > /tmp/intents-juno-withdraw-finalizer.sh <<'EOF_WITHDRAW_FINALIZER'" "EOF_WITHDRAW_FINALIZER")"
  assert_contains "$withdraw_finalizer_wrapper" 'export_optional_env_vars AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE AWS_CA_BUNDLE AWS_EC2_METADATA_DISABLED AWS_STS_REGIONAL_ENDPOINTS' "withdraw finalizer wrapper exports AWS SDK env when present"
  assert_contains "$withdraw_finalizer_wrapper" '--blob-driver s3' "withdraw finalizer wrapper uses the S3 blobstore"
  assert_contains "$withdraw_finalizer_wrapper" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw finalizer wrapper passes base relayer auth env name"

  tss_wrapper="$(extract_block "cat > /tmp/intents-juno-tss-host.sh <<'EOF_TSS'" "EOF_TSS")"
  assert_contains "$tss_wrapper" '[[ -s "${TSS_CLIENT_CA_FILE:-}" ]] || {' "tss wrapper requires client CA in production"
  assert_contains "$tss_wrapper" 'args+=(--client-ca-file "${TSS_CLIENT_CA_FILE}")' "tss wrapper forwards client CA to tss-host"
  assert_contains "$tss_wrapper" 'export "$tss_postgres_dsn_env"' "tss wrapper exports the selected postgres dsn env var"
  assert_contains "$tss_wrapper" '--postgres-dsn-env "${TSS_HOST_POSTGRES_DSN_ENV:-CHECKPOINT_POSTGRES_DSN}"' "tss wrapper passes postgres DSN by env indirection"
  assert_contains "$tss_wrapper" 'echo "tss-host host-process mode requires JUNO_DEV_MODE=true"' "tss wrapper blocks host-process outside dev mode"

  local dkg_wrapper
  dkg_wrapper="$(extract_block "cat > /tmp/intents-juno-dkg-admin-serve.sh <<'EOF_DKG_SERVE'" "EOF_DKG_SERVE")"
  assert_contains "$dkg_wrapper" 'admin_config_dir="$(dirname "$admin_config")"' "dkg-admin wrapper derives the admin-config directory"
  assert_contains "$dkg_wrapper" 'cd "$admin_config_dir"' "dkg-admin wrapper runs from the bundle directory"
  assert_contains "$dkg_wrapper" 'exec /var/lib/intents-juno/operator-runtime/bin/dkg-admin --config "$admin_config" serve' "dkg-admin wrapper uses restored runtime binary with the expected CLI order"
  assert_not_contains "$dkg_wrapper" 'exec /usr/local/bin/dkg-admin serve --config "$admin_config"' "dkg-admin wrapper does not assume a host-installed binary"

  signer_wrapper="$(extract_block "cat > /tmp/intents-juno-checkpoint-signer.sh <<'EOF_SIGNER'" "EOF_SIGNER")"
  assert_contains "$signer_wrapper" '[[ -n "${BASE_CHAIN_ID:-}" ]] || {' "checkpoint signer requires base chain id in operator env"
  assert_contains "$signer_wrapper" '[[ -n "${BRIDGE_ADDRESS:-}" ]] || {' "checkpoint signer requires bridge address in operator env"
  assert_not_contains "$signer_wrapper" 'CHECKPOINT_SIGNER_DRIVER:-local-env' "checkpoint signer no longer defaults to local-env"
  assert_contains "$signer_wrapper" 'checkpoint-signer requires CHECKPOINT_SIGNER_KMS_KEY_ID in /etc/intents-juno/operator-stack.env when CHECKPOINT_SIGNER_DRIVER=aws-kms' "checkpoint signer requires kms key id for aws-kms mode"
  assert_contains "$signer_wrapper" 'checkpoint-signer requires CHECKPOINT_SIGNER_DRIVER=aws-kms in /etc/intents-juno/operator-stack.env' "checkpoint signer rejects non-kms production signers"
  assert_contains "$signer_wrapper" 'checkpoint-signer must not receive CHECKPOINT_SIGNER_PRIVATE_KEY when CHECKPOINT_SIGNER_DRIVER=aws-kms' "checkpoint signer rejects stale private key material"
  assert_contains "$signer_wrapper" 'checkpoint-signer requires OPERATOR_ADDRESS in /etc/intents-juno/operator-stack.env' "checkpoint signer requires operator address in operator env"
  assert_contains "$signer_wrapper" 'checkpoint_signer_lease_name="${CHECKPOINT_SIGNER_LEASE_NAME:-checkpoint-signer-${OPERATOR_ADDRESS}}"' "checkpoint signer derives a per-operator lease name"
  assert_contains "$signer_wrapper" '--signer-driver "${signer_driver}"' "checkpoint signer passes signer driver through to the binary"
  assert_contains "$signer_wrapper" '--kms-key-id "${CHECKPOINT_SIGNER_KMS_KEY_ID}"' "checkpoint signer passes kms key id through to the binary"
  assert_contains "$signer_wrapper" '--base-chain-id "${BASE_CHAIN_ID}"' "checkpoint signer reads base chain id from operator env"
  assert_contains "$signer_wrapper" '--bridge-address "${BRIDGE_ADDRESS}"' "checkpoint signer reads bridge address from operator env"
  assert_contains "$signer_wrapper" '--lease-name "${checkpoint_signer_lease_name}"' "checkpoint signer passes the per-operator lease name through to the binary"
  assert_not_contains "$signer_wrapper" '__BOOTSTRAP_BRIDGE_ADDRESS__' "checkpoint signer does not bake bootstrap bridge address into wrapper"

  aggregator_wrapper="$(extract_block "cat > /tmp/intents-juno-checkpoint-aggregator.sh <<'EOF_AGG'" "EOF_AGG")"
  assert_contains "$aggregator_wrapper" '[[ -n "${BASE_CHAIN_ID:-}" ]] || {' "checkpoint aggregator requires base chain id in operator env"
  assert_contains "$aggregator_wrapper" '[[ -n "${BRIDGE_ADDRESS:-}" ]] || {' "checkpoint aggregator requires bridge address in operator env"
  assert_contains "$aggregator_wrapper" '--base-chain-id "${BASE_CHAIN_ID}"' "checkpoint aggregator reads base chain id from operator env"
  assert_contains "$aggregator_wrapper" '--bridge-address "${BRIDGE_ADDRESS}"' "checkpoint aggregator reads bridge address from operator env"
  assert_contains "$aggregator_wrapper" '${CHECKPOINT_IPFS_API_BEARER_TOKEN:+--ipfs-api-bearer-token "$CHECKPOINT_IPFS_API_BEARER_TOKEN"}' "checkpoint aggregator forwards the optional IPFS bearer token"
  assert_not_contains "$aggregator_wrapper" '__BOOTSTRAP_BRIDGE_ADDRESS__' "checkpoint aggregator does not bake bootstrap bridge address into wrapper"

  local deposit_relayer_wrapper
  deposit_relayer_wrapper="$(extract_block "cat > /tmp/intents-juno-deposit-relayer.sh <<'EOF_DEPOSIT_RELAYER'" "EOF_DEPOSIT_RELAYER")"
  assert_contains "$deposit_relayer_wrapper" 'export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN JUNO_QUEUE_CRITICAL_KEY_ID JUNO_QUEUE_CRITICAL_HMAC_KEY' "deposit relayer exports queueauth env to the binary"

  local withdraw_wrapper
  withdraw_wrapper="$(extract_block "cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'" "EOF_WITHDRAW_COORDINATOR")"
  assert_contains "$withdraw_wrapper" 'export CHECKPOINT_POSTGRES_DSN BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN JUNO_TXSIGN_SIGNER_KEYS JUNO_QUEUE_CRITICAL_KEY_ID JUNO_QUEUE_CRITICAL_HMAC_KEY' "withdraw coordinator exports queueauth env to the binary"

  local withdraw_finalizer_wrapper
  withdraw_finalizer_wrapper="$(extract_block "cat > /tmp/intents-juno-withdraw-finalizer.sh <<'EOF_WITHDRAW_FINALIZER'" "EOF_WITHDRAW_FINALIZER")"
  assert_contains "$withdraw_finalizer_wrapper" 'export BASE_RELAYER_AUTH_TOKEN JUNO_RPC_USER JUNO_RPC_PASS JUNO_SCAN_BEARER_TOKEN JUNO_QUEUE_CRITICAL_KEY_ID JUNO_QUEUE_CRITICAL_HMAC_KEY' "withdraw finalizer exports queueauth env to the binary"

  local juno_scan_backfill_wrapper
  juno_scan_backfill_wrapper="$(extract_block "cat > /tmp/intents-juno-juno-scan-backfill.sh <<'EOF_SCAN_BACKFILL'" "EOF_SCAN_BACKFILL")"
  assert_contains "$juno_scan_backfill_wrapper" 'configured_from_height="${JUNO_SCAN_BACKFILL_FROM_HEIGHT:-0}"' "scanner backfill wrapper reads the configured floor from env"
  assert_contains "$juno_scan_backfill_wrapper" 'resume_next_height="$(jq -er --arg wallet_id "$wallet_id" --arg scan_url "$scan_url"' "scanner backfill wrapper resumes durable progress for the matching wallet"
  assert_contains "$juno_scan_backfill_wrapper" 'write_state "complete" "$next_height" "$to_height"' "scanner backfill wrapper records completion state"
  assert_contains "$juno_scan_backfill_wrapper" 'curl -fsS -X POST "${curl_headers[@]}" -H '\''Content-Type: application/json'\'' --data "$backfill_payload" "${scan_url%/}/v1/wallets/${wallet_id}/backfill"' "scanner backfill wrapper performs batched historical backfill"

  base_event_scanner_wrapper="$(extract_block "cat > /tmp/intents-juno-base-event-scanner.sh <<'EOF_BASE_EVENT_SCANNER'" "EOF_BASE_EVENT_SCANNER")"
  assert_contains "$base_event_scanner_wrapper" 'export_optional_env_vars JUNO_QUEUE_CRITICAL_KEY_ID JUNO_QUEUE_CRITICAL_HMAC_KEY JUNO_QUEUE_KAFKA_AWS_REGION' "base-event-scanner exports queueauth env to the binary"
  assert_contains "$base_event_scanner_wrapper" '[[ -n "${BASE_EVENT_SCANNER_START_BLOCK:-}" ]] || {' "base-event-scanner requires explicit start block in operator env"
  assert_contains "$base_event_scanner_wrapper" 'base-event-scanner requires BASE_EVENT_SCANNER_START_BLOCK in /etc/intents-juno/operator-stack.env' "base-event-scanner fails closed without start block"
  assert_contains "$base_event_scanner_wrapper" '--start-block "${BASE_EVENT_SCANNER_START_BLOCK}"' "base-event-scanner wrapper uses rendered start block without a genesis fallback"
  assert_not_contains "$base_event_scanner_wrapper" '--start-block "${BASE_EVENT_SCANNER_START_BLOCK:-0}"' "base-event-scanner wrapper does not fall back to genesis"
  local base_relayer_wrapper
  base_relayer_wrapper="$(extract_block "cat > /tmp/intents-juno-base-relayer.sh <<'EOF_BASE_RELAYER'" "EOF_BASE_RELAYER")"
  assert_contains "$base_relayer_wrapper" '--min-ready-balance-wei "${BASE_RELAYER_MIN_READY_BALANCE_WEI:-1000000000000000}"' "base-relayer wrapper enforces the readiness balance floor"
  assert_contains "$base_relayer_wrapper" 'base-relayer requires BASE_RELAYER_ALLOWED_SELECTORS in /etc/intents-juno/operator-stack.env' "base-relayer wrapper requires selector allowlist"
  assert_contains "$base_relayer_wrapper" '--allowed-selectors "${BASE_RELAYER_ALLOWED_SELECTORS}"' "base-relayer wrapper forwards selector allowlist"

  assert_not_contains "$script_text" 'rpc_user: $junocash_rpc_user' "bootstrap metadata does not publish RPC username"
  assert_not_contains "$script_text" 'rpc_password: $junocash_rpc_pass' "bootstrap metadata does not publish RPC password"
  assert_contains "$script_text" 'BASE_EVENT_SCANNER_START_BLOCK=' "bootstrap env leaves base-event-scanner start block unset until deploy"
  assert_not_contains "$script_text" 'BASE_EVENT_SCANNER_START_BLOCK=0' "bootstrap env does not default base-event-scanner to genesis"
  assert_contains "$script_text" 'JUNO_SCAN_BACKFILL_FROM_HEIGHT=0' "bootstrap env pins the scanner backfill floor"
  assert_contains "$script_text" 'BASE_RELAYER_MIN_READY_BALANCE_WEI=1000000000000000' "bootstrap env pins the base relayer readiness balance floor"
  assert_contains "$script_text" 'BASE_RELAYER_ALLOWED_SELECTORS=0x53a58a48,0xec70b605,0xfe097d57' "bootstrap env pins the base relayer selector allowlist"
  assert_contains "$script_text" 'WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN=6h' "bootstrap env pins the withdraw expiry safety margin"
  assert_contains "$script_text" 'WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION=12h' "bootstrap env pins the withdraw max expiry extension"
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

test_build_operator_stack_ami_juno_scan_wrapper_waits_for_rpc_readiness() {
  local tmp env_file fake_bin output_file sequence_file count_file wrapper_text
  tmp="$(mktemp -d)"
  env_file="$tmp/operator-stack.env"
  fake_bin="$tmp/bin"
  output_file="$tmp/juno-scan.args"
  sequence_file="$tmp/juno-scan.sequence"
  count_file="$tmp/juno-scan.count"
  mkdir -p "$fake_bin"

  cat >"$env_file" <<'EOF'
JUNO_RPC_USER=rpc-user
JUNO_RPC_PASS=rpc-pass
JUNO_SCAN_UA_HRP=jtest
JUNO_SCAN_CONFIRMATIONS=1
EOF

  render_wrapper \
    "cat > /tmp/intents-juno-juno-scan.sh <<'EOF_SCAN'" \
    "EOF_SCAN" \
    "$tmp/intents-juno-juno-scan.sh" \
    "$env_file"
  python3 - "$tmp/intents-juno-juno-scan.sh" "$fake_bin/juno-scan" <<'EOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text(path.read_text().replace("/usr/local/bin/juno-scan", sys.argv[2]))
EOF

  cat >"$fake_bin/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$count_file" ]]; then
  count="\$(cat "$count_file")"
fi
count="\$((count + 1))"
printf '%s\n' "\$count" >"$count_file"
printf 'curl-%s\n' "\$count" >>"$sequence_file"
case "\$count" in
  1)
    exit 7
    ;;
  2)
    printf '%s\n' '{"result":null,"error":{"code":-28,"message":"Loading block index..."},"id":"juno-scan-ready"}'
    ;;
  *)
    printf '%s\n' '{"result":123,"error":null,"id":"juno-scan-ready"}'
    ;;
esac
EOF

  cat >"$fake_bin/sleep" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'sleep-%s\n' "\${1:-}" >>"$sequence_file"
EOF

  cat >"$fake_bin/juno-scan" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >"$output_file"
printf 'scan\n' >>"$sequence_file"
EOF
  chmod 0755 "$fake_bin/curl" "$fake_bin/sleep" "$fake_bin/juno-scan"

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-juno-scan.sh"

  assert_eq "$(cat "$count_file")" "3" "juno-scan wrapper retries until junocashd rpc is ready"
  assert_eq "$(cat "$sequence_file")" $'curl-1\nsleep-5\ncurl-2\nsleep-5\ncurl-3\nscan' "juno-scan wrapper waits through transport and loading-block-index failures before starting the scanner"
  assert_contains "$(cat "$output_file")" '-db-path /var/lib/intents-juno/juno-scan.db' "juno-scan wrapper uses the dedicated rocksdb state directory"

  rm -rf "$tmp"
}

test_build_operator_stack_ami_juno_scan_backfill_wrapper_resumes_progress() {
  local tmp env_file fake_bin state_dir curl_log state_file
  tmp="$(mktemp -d)"
  env_file="$tmp/operator-stack.env"
  fake_bin="$tmp/bin"
  state_dir="$tmp/state"
  curl_log="$tmp/curl.log"
  state_file="$state_dir/state.json"
  mkdir -p "$fake_bin" "$state_dir"

  cat >"$env_file" <<EOF
DEPOSIT_SCAN_JUNO_SCAN_URL=http://127.0.0.1:8080
DEPOSIT_SCAN_JUNO_SCAN_WALLET_ID=wallet-op1
JUNO_SCAN_BACKFILL_FROM_HEIGHT=100000
JUNO_SCAN_BACKFILL_STATE_DIR=$state_dir
JUNO_SCAN_BACKFILL_UFVK_FILE=$tmp/ufvk.txt
EOF
  printf 'uview1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n' >"$tmp/ufvk.txt"
  jq -n \
    --arg wallet_id "wallet-op1" \
    --arg scan_url "http://127.0.0.1:8080" \
    --arg status "running" \
    --arg ufvk_file "$tmp/ufvk.txt" \
    --arg updated_at "2026-03-20T00:00:00Z" \
    --argjson configured_from_height 100000 \
    --argjson next_height 110000 \
    --argjson to_height 118298 \
    '{
      wallet_id: $wallet_id,
      scan_url: $scan_url,
      status: $status,
      ufvk_file: $ufvk_file,
      configured_from_height: $configured_from_height,
      next_height: $next_height,
      to_height: $to_height,
      updated_at: $updated_at
    }' >"$state_file"

  render_wrapper \
    "cat > /tmp/intents-juno-juno-scan-backfill.sh <<'EOF_SCAN_BACKFILL'" \
    "EOF_SCAN_BACKFILL" \
    "$tmp/intents-juno-juno-scan-backfill.sh" \
    "$env_file"

  cat >"$fake_bin/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >>"$curl_log"
if [[ "\$*" == *"/v1/health"* ]]; then
  printf '%s\n' '{"status":"ok","scanned_height":118298,"scanned_hash":"0001"}'
elif [[ "\$*" == *"/v1/wallets/wallet-op1/backfill"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1","from_height":110000,"to_height":118298,"next_height":118299,"inserted_notes":1,"inserted_events":2}'
elif [[ "\$*" == *"/v1/wallets"* ]]; then
  printf '%s\n' '{"status":"ok","wallet_id":"wallet-op1"}'
else
  printf 'unexpected curl call: %s\n' "\$*" >&2
  exit 1
fi
EOF
  chmod 0755 "$fake_bin/curl"

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-juno-scan-backfill.sh"

  assert_contains "$(cat "$curl_log")" '/v1/health' "scanner backfill wrapper waits for scanner health before backfilling"
  assert_contains "$(cat "$curl_log")" '/v1/wallets' "scanner backfill wrapper registers the wallet before backfill"
  assert_contains "$(cat "$curl_log")" '"from_height":110000' "scanner backfill wrapper resumes from durable progress instead of the configured floor"
  assert_eq "$(jq -r '.status' "$state_file")" "complete" "scanner backfill wrapper records completion in durable state"
  assert_eq "$(jq -r '.next_height' "$state_file")" "118299" "scanner backfill wrapper persists the next resume height"

  rm -rf "$tmp"
}

test_build_operator_stack_ami_wrapper_smoke() {
  local tmp env_file fake_bin output_file stderr_file signer_output_file signer_stderr_file
  local spendauth_output_file spendauth_pwd_file
  tmp="$(mktemp -d)"
  env_file="$tmp/operator-stack.env"
  fake_bin="$tmp/bin"
  output_file="$tmp/withdraw.args"
  stderr_file="$tmp/tss.stderr"
  signer_output_file="$tmp/signer.args"
  signer_stderr_file="$tmp/signer.stderr"
  spendauth_output_file="$tmp/spendauth.args"
  spendauth_pwd_file="$tmp/spendauth.pwd"
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

  cat >"$fake_bin/tss-host" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$tmp/tss.args"
env | sort >"$tmp/tss.env"
exit 0
EOF
  cat >"$tmp/nitro-signer" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$fake_bin/tss-host" "$tmp/nitro-signer"

  printf 'ca' >"$tmp/ca.pem"
  printf 'eif' >"$tmp/spendauth.eif"
  printf 'attestation' >"$tmp/attestation.json"
  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://tss?sslmode=require
TSS_SIGNER_UFVK_FILE=$tmp/ufvk.txt
TSS_SIGNER_WORK_DIR=$tmp/work
TSS_TLS_CERT_FILE=$tmp/server.pem
TSS_TLS_KEY_FILE=$tmp/server.key
TSS_CLIENT_CA_FILE=$tmp/ca.pem
TSS_NITRO_SPENDAUTH_SIGNER_BIN=$tmp/nitro-signer
TSS_NITRO_ENCLAVE_EIF_FILE=$tmp/spendauth.eif
TSS_NITRO_ATTESTATION_FILE=$tmp/attestation.json
TSS_NITRO_EXPECTED_PCR0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
TSS_NITRO_EXPECTED_PCR1=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
TSS_NITRO_EXPECTED_PCR2=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
TSS_NITRO_ATTESTATION_MAX_AGE_SECONDS=300
EOF

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-tss-host.sh"
  assert_contains "$(cat "$tmp/tss.args")" '--postgres-dsn-env CHECKPOINT_POSTGRES_DSN' "tss wrapper forwards the postgres env name"
  assert_not_contains "$(cat "$tmp/tss.args")" 'postgres://tss?sslmode=require' "tss wrapper does not pass raw postgres dsn in argv"
  assert_contains "$(cat "$tmp/tss.env")" 'CHECKPOINT_POSTGRES_DSN=postgres://tss?sslmode=require' "tss wrapper preserves postgres dsn in env"

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
WITHDRAW_COORDINATOR_JUNO_SCAN_URL=http://127.0.0.1:8080
JUNO_RPC_USER=actual-rpc-username-secret
JUNO_RPC_PASS=actual-rpc-password-secret
JUNO_SCAN_BEARER_TOKEN=actual-juno-scan-bearer-secret
WITHDRAW_COORDINATOR_TSS_URL=https://127.0.0.1:9443
WITHDRAW_COORDINATOR_TSS_SERVER_CA_FILE=$tmp/ca.pem
WITHDRAW_COORDINATOR_TSS_SERVER_NAME=10.0.0.11
WITHDRAW_COORDINATOR_TSS_CLIENT_CERT_FILE=$tmp/coordinator-client.pem
WITHDRAW_COORDINATOR_TSS_CLIENT_KEY_FILE=$tmp/coordinator-client.key
WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN=$tmp/extend-signer
WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
RUNTIME_SETTINGS_DEPOSIT_MIN_CONFIRMATIONS=2
RUNTIME_SETTINGS_WITHDRAW_PLANNER_MIN_CONFIRMATIONS=3
RUNTIME_SETTINGS_WITHDRAW_BATCH_CONFIRMATIONS=4
JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WITHDRAW_COORDINATOR_CLAIM_TTL=7m
WITHDRAW_BLOB_BUCKET=withdraw-bucket
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
AWS_PROFILE=alpha-testnet
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  render_wrapper \
    "cat > /tmp/intents-juno-withdraw-coordinator.sh <<'EOF_WITHDRAW_COORDINATOR'" \
    "EOF_WITHDRAW_COORDINATOR" \
    "$tmp/intents-juno-withdraw-coordinator.sh" \
    "$env_file"
  python3 - "$tmp/intents-juno-withdraw-coordinator.sh" "$fake_bin/withdraw-coordinator" <<'EOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text(path.read_text().replace("/usr/local/bin/withdraw-coordinator", sys.argv[2]))
EOF

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-withdraw-coordinator.sh"

  assert_contains "$(cat "$output_file")" '--postgres-dsn-env CHECKPOINT_POSTGRES_DSN' "withdraw wrapper forwards DSN env name"
  assert_contains "$(cat "$output_file")" '--claim-ttl 7m' "withdraw wrapper forwards the configured claim ttl"
  assert_contains "$(cat "$output_file")" '--juno-scan-url http://127.0.0.1:8080' "withdraw wrapper forwards the scanner URL"
  assert_contains "$(cat "$output_file")" '--juno-scan-bearer-env JUNO_SCAN_BEARER_TOKEN' "withdraw wrapper forwards the scanner bearer env name"
  assert_contains "$(cat "$output_file")" '--juno-rpc-user-env JUNO_RPC_USER' "withdraw wrapper forwards RPC username env name"
  assert_contains "$(cat "$output_file")" '--juno-rpc-pass-env JUNO_RPC_PASS' "withdraw wrapper forwards RPC password env name"
  assert_contains "$(cat "$output_file")" '--deposit-min-confirmations 2' "withdraw wrapper forwards deposit confirmation seed"
  assert_contains "$(cat "$output_file")" '--juno-minconf 3' "withdraw wrapper forwards withdraw planner confirmation seed"
  assert_contains "$(cat "$output_file")" '--juno-expiry-offset 240' "withdraw wrapper forwards the safer default juno expiry offset"
  assert_contains "$(cat "$output_file")" '--juno-confirmations 4' "withdraw wrapper forwards withdraw batch confirmation seed"
  assert_contains "$(cat "$output_file")" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw wrapper forwards base relayer auth env name"
  assert_contains "$(cat "$output_file")" '--expiry-safety-margin 6h' "withdraw wrapper forwards the bounded expiry safety margin"
  assert_contains "$(cat "$output_file")" '--max-expiry-extension 12h' "withdraw wrapper forwards the max expiry extension"
  assert_contains "$(cat "$output_file")" '--tss-server-name 10.0.0.11' "withdraw wrapper forwards optional tss server name override"
  assert_not_contains "$(cat "$output_file")" 'postgres://coordinator?sslmode=require' "withdraw wrapper does not pass raw DSN in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-base-relayer-secret-token' "withdraw wrapper does not pass base relayer secret in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-rpc-username-secret' "withdraw wrapper does not pass RPC username in argv"
  assert_not_contains "$(cat "$output_file")" 'actual-rpc-password-secret' "withdraw wrapper does not pass RPC password in argv"
  assert_contains "$(cat "$tmp/withdraw.env")" 'CHECKPOINT_POSTGRES_DSN=postgres://coordinator?sslmode=require' "withdraw wrapper exports Postgres DSN"
  assert_contains "$(cat "$tmp/withdraw.env")" 'BASE_RELAYER_AUTH_TOKEN=actual-base-relayer-secret-token' "withdraw wrapper exports base relayer auth token"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_RPC_USER=actual-rpc-username-secret' "withdraw wrapper exports RPC user"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_RPC_PASS=actual-rpc-password-secret' "withdraw wrapper exports RPC pass"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_SCAN_BEARER_TOKEN=actual-juno-scan-bearer-secret' "withdraw wrapper exports the scanner bearer token"
  assert_contains "$(cat "$tmp/withdraw.env")" 'JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "withdraw wrapper exports the isolated juno txsign signer key"
  assert_contains "$(cat "$tmp/withdraw.env")" 'AWS_REGION=us-east-1' "withdraw wrapper exports AWS region"
  assert_contains "$(cat "$tmp/withdraw.env")" 'AWS_DEFAULT_REGION=us-east-1' "withdraw wrapper exports AWS default region"
  assert_contains "$(cat "$tmp/withdraw.env")" 'AWS_PROFILE=alpha-testnet' "withdraw wrapper exports AWS profile"

  local extend_output_file
  extend_output_file="$tmp/extend.args"
  cat >"$fake_bin/extend-signer" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$extend_output_file"
env | sort >"$tmp/extend.env"
printf '{"version":"v1","status":"ok","data":{"signatures":["0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b"]}}\n'
exit 0
EOF
  chmod 0755 "$fake_bin/extend-signer"

  cat >"$tmp/intents-juno-multikey-extend-signer.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$1"
shift
extend_signer_keys="${WITHDRAW_COORDINATOR_EXTEND_SIGNER_KEYS:-${JUNO_TXSIGN_SIGNER_KEYS:-}}"
export JUNO_TXSIGN_SIGNER_KEYS="$extend_signer_keys"
exec "$1" "$@"
EOF
  chmod 0755 "$tmp/intents-juno-multikey-extend-signer.sh"
  "$tmp/intents-juno-multikey-extend-signer.sh" "$env_file" "$fake_bin/extend-signer" sign-digest --digest 0x1111111111111111111111111111111111111111111111111111111111111111 --json >/dev/null
  assert_contains "$(cat "$tmp/extend.env")" 'JUNO_TXSIGN_SIGNER_KEYS=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "withdraw extend signer wrapper exports the full signer roster"

  local finalizer_output_file
  finalizer_output_file="$tmp/finalizer.args"
  cat >"$fake_bin/withdraw-finalizer" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$finalizer_output_file"
env | sort >"$tmp/finalizer.env"
exit 0
EOF
  chmod 0755 "$fake_bin/withdraw-finalizer"

  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://finalizer?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
CHECKPOINT_OPERATORS=0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333
CHECKPOINT_THRESHOLD=2
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
WITHDRAW_IMAGE_ID=deadbeef
BASE_RELAYER_URL=https://127.0.0.1:18081
BASE_RELAYER_AUTH_TOKEN=actual-base-relayer-secret-token
WITHDRAW_BLOB_BUCKET=withdraw-bucket
WITHDRAW_FINALIZER_JUNO_SCAN_URL=http://127.0.0.1:8080
WITHDRAW_FINALIZER_JUNO_SCAN_WALLET_ID=wallet-123
WITHDRAW_FINALIZER_JUNO_RPC_URL=http://127.0.0.1:18232
JUNO_RPC_USER=actual-rpc-username-secret
JUNO_RPC_PASS=actual-rpc-password-secret
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
AWS_PROFILE=alpha-testnet
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  render_wrapper \
    "cat > /tmp/intents-juno-withdraw-finalizer.sh <<'EOF_WITHDRAW_FINALIZER'" \
    "EOF_WITHDRAW_FINALIZER" \
    "$tmp/intents-juno-withdraw-finalizer.sh" \
    "$env_file"
  python3 - "$tmp/intents-juno-withdraw-finalizer.sh" "$fake_bin/withdraw-finalizer" <<'EOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_text(path.read_text().replace("/usr/local/bin/withdraw-finalizer", sys.argv[2]))
EOF

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-withdraw-finalizer.sh"

  assert_contains "$(cat "$finalizer_output_file")" '--blob-driver s3' "withdraw finalizer wrapper uses the S3 blobstore"
  assert_contains "$(cat "$finalizer_output_file")" '--base-relayer-auth-env BASE_RELAYER_AUTH_TOKEN' "withdraw finalizer wrapper forwards base relayer auth env name"
  assert_contains "$(cat "$tmp/finalizer.env")" 'AWS_REGION=us-east-1' "withdraw finalizer wrapper exports AWS region"
  assert_contains "$(cat "$tmp/finalizer.env")" 'AWS_DEFAULT_REGION=us-east-1' "withdraw finalizer wrapper exports AWS default region"
  assert_contains "$(cat "$tmp/finalizer.env")" 'AWS_PROFILE=alpha-testnet' "withdraw finalizer wrapper exports AWS profile"

  cat >"$fake_bin/checkpoint-signer" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--help" ]]; then
  cat <<'EOF_HELP'
Usage of /usr/local/bin/checkpoint-signer:
  -lease-name string
  -signer-driver string
  -kms-key-id string
EOF_HELP
  exit 0
fi
printf '%s\n' "\$*" >"$signer_output_file"
exit 0
EOF
  chmod 0755 "$fake_bin/checkpoint-signer"

  render_wrapper \
    "cat > /tmp/intents-juno-checkpoint-signer.sh <<'EOF_SIGNER'" \
    "EOF_SIGNER" \
    "$tmp/intents-juno-checkpoint-signer.sh" \
    "$env_file"

  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://signer?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
CHECKPOINT_SIGNATURE_TOPIC=checkpoints.signatures.v1
CHECKPOINT_THRESHOLD=1
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
CHECKPOINT_SIGNER_DRIVER=aws-kms
CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:111111111111:key/abc
OPERATOR_ADDRESS=0x2222222222222222222222222222222222222222
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-checkpoint-signer.sh"
  assert_contains "$(cat "$signer_output_file")" '--signer-driver aws-kms' "checkpoint signer wrapper forwards aws-kms signer driver"
  assert_contains "$(cat "$signer_output_file")" '--kms-key-id arn:aws:kms:us-east-1:111111111111:key/abc' "checkpoint signer wrapper forwards kms key id"
  assert_contains "$(cat "$signer_output_file")" '--lease-name checkpoint-signer-0x2222222222222222222222222222222222222222' "checkpoint signer wrapper uses a unique lease name per operator"

  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://signer?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
CHECKPOINT_SIGNATURE_TOPIC=checkpoints.signatures.v1
CHECKPOINT_THRESHOLD=1
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
CHECKPOINT_SIGNER_DRIVER=local-env
CHECKPOINT_SIGNER_PRIVATE_KEY=4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a
OPERATOR_ADDRESS=0x3333333333333333333333333333333333333333
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  if PATH="$fake_bin:$PATH" "$tmp/intents-juno-checkpoint-signer.sh" >"$tmp/signer.stdout" 2>"$signer_stderr_file"; then
    printf 'expected checkpoint-signer wrapper to reject local-env in production\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$signer_stderr_file")" "checkpoint-signer requires CHECKPOINT_SIGNER_DRIVER=aws-kms" "checkpoint signer wrapper rejects local-env compatibility mode"

  cat >"$fake_bin/checkpoint-signer" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--help" ]]; then
  cat <<'EOF_HELP'
Usage of /usr/local/bin/checkpoint-signer:
  -lease-name string
EOF_HELP
  exit 0
fi
printf '%s\n' "\$*" >"$signer_output_file"
exit 0
EOF
  chmod 0755 "$fake_bin/checkpoint-signer"

  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://signer?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
CHECKPOINT_SIGNATURE_TOPIC=checkpoints.signatures.v1
CHECKPOINT_THRESHOLD=1
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
CHECKPOINT_SIGNER_DRIVER=aws-kms
CHECKPOINT_SIGNER_KMS_KEY_ID=arn:aws:kms:us-east-1:111111111111:key/abc
OPERATOR_ADDRESS=0x3333333333333333333333333333333333333333
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  if PATH="$fake_bin:$PATH" "$tmp/intents-juno-checkpoint-signer.sh" >"$tmp/signer.stdout" 2>"$signer_stderr_file"; then
    printf 'expected checkpoint-signer wrapper to reject legacy binaries without --signer-driver support in aws-kms mode\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$signer_stderr_file")" "checkpoint-signer binary does not support CHECKPOINT_SIGNER_DRIVER=aws-kms" "checkpoint signer wrapper fails closed on legacy binaries"

  cat >"$env_file" <<EOF
JUNO_DEV_MODE=false
CHECKPOINT_POSTGRES_DSN=postgres://signer?sslmode=require
CHECKPOINT_KAFKA_BROKERS=b-1.example:9094
CHECKPOINT_SIGNATURE_TOPIC=checkpoints.signatures.v1
CHECKPOINT_THRESHOLD=1
BASE_CHAIN_ID=84532
BRIDGE_ADDRESS=0x1111111111111111111111111111111111111111
CHECKPOINT_SIGNER_DRIVER=aws-kms
OPERATOR_ADDRESS=0x4444444444444444444444444444444444444444
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
JUNO_QUEUE_KAFKA_TLS=true
JUNO_QUEUE_KAFKA_AUTH_MODE=aws-msk-iam
EOF

  if PATH="$fake_bin:$PATH" "$tmp/intents-juno-checkpoint-signer.sh" >"$tmp/signer.stdout" 2>"$signer_stderr_file"; then
    printf 'expected checkpoint-signer wrapper to reject missing kms env in aws-kms mode\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$signer_stderr_file")" "checkpoint-signer requires CHECKPOINT_SIGNER_KMS_KEY_ID" "checkpoint signer wrapper rejects missing kms key id in aws-kms mode"

  cat >"$fake_bin/dkg-admin" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$spendauth_output_file"
pwd >"$spendauth_pwd_file"
exit 0
EOF
  chmod 0755 "$fake_bin/dkg-admin"

  mkdir -p "$tmp/operator-runtime/bundle"
  printf '{"network":"testnet"}\n' >"$tmp/operator-runtime/bundle/admin-config.json"
  cat >"$env_file" <<EOF
JUNO_DEV_MODE=true
TSS_SIGNER_RUNTIME_MODE=host-process
TSS_SPENDAUTH_SIGNER_BIN=$fake_bin/dkg-admin
DKG_ADMIN_CONFIG_FILE=$tmp/operator-runtime/bundle/admin-config.json
EOF

  render_wrapper \
    "cat > /tmp/intents-juno-spendauth-signer.sh <<'EOF_TSS_SPENDAUTH'" \
    "EOF_TSS_SPENDAUTH" \
    "$tmp/intents-juno-spendauth-signer.sh" \
    "$env_file"

  PATH="$fake_bin:$PATH" "$tmp/intents-juno-spendauth-signer.sh" \
    sign-spendauth --session-id test-session --requests /tmp/requests.json --out /tmp/out.json

  assert_contains "$(cat "$spendauth_output_file")" "--config $tmp/operator-runtime/bundle/admin-config.json" "spendauth wrapper passes admin config explicitly in host-process mode"
  assert_contains "$(cat "$spendauth_output_file")" "sign-spendauth --session-id test-session --requests /tmp/requests.json --out /tmp/out.json" "spendauth wrapper forwards the sign-spendauth request args"
  assert_eq "$(cat "$spendauth_pwd_file")" "$tmp/operator-runtime/bundle" "spendauth wrapper runs from the admin config directory in host-process mode"

  rm -f "$spendauth_output_file" "$spendauth_pwd_file"
  cat >"$fake_bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
  printf '%s\n' "${FAKE_ID_RESULT:-0}"
  exit 0
fi
exec /usr/bin/id "$@"
EOF
  chmod 0755 "$fake_bin/id"
  cat >"$fake_bin/sudo" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" != "-u" || "${2:-}" != "intents-juno" ]]; then
  printf 'unexpected sudo args: %s\n' "$*" >&2
  exit 1
fi
shift 2
FAKE_ID_RESULT=1000 exec "$@"
EOF
  chmod 0755 "$fake_bin/sudo"

  PATH="$fake_bin:$PATH" FAKE_ID_RESULT=0 "$tmp/intents-juno-spendauth-signer.sh" \
    sign-spendauth --session-id root-session --requests /tmp/root-requests.json --out /tmp/root-out.json

  assert_contains "$(cat "$spendauth_output_file")" "--config $tmp/operator-runtime/bundle/admin-config.json" "spendauth wrapper still passes admin config after dropping root"
  assert_contains "$(cat "$spendauth_output_file")" "sign-spendauth --session-id root-session --requests /tmp/root-requests.json --out /tmp/root-out.json" "spendauth wrapper preserves request args after dropping root"
  assert_eq "$(cat "$spendauth_pwd_file")" "$tmp/operator-runtime/bundle" "spendauth wrapper still runs from the bundle directory after dropping root"

  rm -rf "$tmp"
}

main() {
  test_build_operator_stack_ami_enforces_service_user_and_hardening
  test_build_operator_stack_ami_repairs_dpkg_before_apt
  test_build_operator_stack_ami_uses_checksum_and_env_wiring
  test_build_operator_stack_ami_digest_fallback_survives_missing_manifest_entry
  test_build_operator_stack_ami_juno_scan_wrapper_waits_for_rpc_readiness
  test_build_operator_stack_ami_juno_scan_backfill_wrapper_resumes_progress
  test_build_operator_stack_ami_wrapper_smoke
}

main "$@"
